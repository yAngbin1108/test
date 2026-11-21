// FairPlayCore.c — 来源 iPadn (github.com/mengangs/ipadn) 的 iPadn-iOS/FairPlayCore，GPL-2.0-or-later。
//
// 本仓库用法与上游不同：
//   * 不作为独立模块（framework）编译，直接编进 AppDump 主 target；
//   * Swift 侧只在 fairplaydecrypt.swift 里通过 fp_decrypt_file/fp_parse 调用；
//   * 上游的 fp_attempt（内存回读）保留但未使用，仍可单独调试。
//
#include "FairPlayCore.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <math.h>
#include <mach/mach.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/fcntl.h>
#include <time.h>
#include <unistd.h>

#if __has_include(<libkern/OSByteOrder.h>)
#include <libkern/OSByteOrder.h>
#endif

#pragma mark - mremap_encrypted

typedef int (*fp_mremap_fn)(void *, size_t, uint32_t, uint32_t, uint32_t);

// xnu: int mremap_encrypted(void *addr, size_t len, uint32_t cryptid,
//                           cpu_type_t cpu_type, cpu_subtype_t cpu_subtype);
// Not exported by libsystem_kernel on every release, so fall back to the raw
// syscall (489 on arm64 Darwin).
static int fp_raw_mremap_encrypted(void *addr, size_t len, uint32_t cryptid,
                                   uint32_t cputype, uint32_t cpusubtype) {
#if defined(__arm64__)
    register uint64_t x0 __asm__("x0") = (uint64_t)addr;
    register uint64_t x1 __asm__("x1") = (uint64_t)len;
    register uint64_t x2 __asm__("x2") = (uint64_t)cryptid;
    register uint64_t x3 __asm__("x3") = (uint64_t)cputype;
    register uint64_t x4 __asm__("x4") = (uint64_t)cpusubtype;
    register uint64_t x16 __asm__("x16") = 489; // SYS_mremap_encrypted
    uint64_t carry;
    __asm__ volatile("svc #0x80\n\tcset %[c], cs"
                     : "+r"(x0), "+r"(x1), [c] "=r"(carry)
                     : "r"(x2), "r"(x3), "r"(x4), "r"(x16)
                     : "memory", "cc");
    if (carry) {
        errno = (int)x0;
        return -1;
    }
    return (int)x0;
#else
    (void)addr; (void)len; (void)cryptid; (void)cputype; (void)cpusubtype;
    errno = ENOTSUP;
    return -1;
#endif
}

static fp_mremap_fn fp_mremap_fn_ptr = NULL;
static pthread_once_t fp_mremap_once = PTHREAD_ONCE_INIT;

static void fp_resolve_mremap_encrypted(void) {
    fp_mremap_fn_ptr = (fp_mremap_fn)dlsym(RTLD_DEFAULT, "mremap_encrypted");
}

static int fp_mremap_encrypted(void *addr, size_t len, uint32_t cryptid,
                               uint32_t cputype, uint32_t cpusubtype) {
    pthread_once(&fp_mremap_once, fp_resolve_mremap_encrypted);
    if (fp_mremap_fn_ptr) return fp_mremap_fn_ptr(addr, len, cryptid, cputype, cpusubtype);
    return fp_raw_mremap_encrypted(addr, len, cryptid, cputype, cpusubtype);
}

#pragma mark - helpers

static void fp_log(fp_log_t log, void *ctx, const char *fmt, ...)
    __attribute__((format(printf, 3, 4)));
static void fp_log(fp_log_t log, void *ctx, const char *fmt, ...) {
    if (!log) return;
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof buf, fmt, ap);
    va_end(ap);
    log(ctx, buf);
}

static double fp_now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000.0 + ts.tv_nsec / 1e6;
}

static double fp_entropy_from_histogram(const uint64_t histogram[256], uint64_t n) {
    if (!n) return 0;
    double e = 0;
    for (int i = 0; i < 256; i++) {
        if (!histogram[i]) continue;
        double q = (double)histogram[i] / (double)n;
        e -= q * log2(q);
    }
    return e;
}

static void fp_accumulate_histogram(uint64_t histogram[256], const uint8_t *p, size_t n) {
    for (size_t i = 0; i < n; i++) histogram[p[i]]++;
}

// ARM64 code landmarks. Encrypted text contains them at random rate ~2^-32;
// decrypted code has thousands.
static uint32_t fp_code_words(const uint8_t *p, size_t n) {
    uint32_t count = 0;
    for (size_t i = 0; i + 4 <= n; i += 4) {
        uint32_t w;
        memcpy(&w, p + i, 4);
        if (w == 0xd65f03c0 /* ret */ || w == 0xd503237f /* pacibsp */ ||
            w == 0xd65f0fff /* retab */) {
            count++;
        }
    }
    return count;
}

static bool fp_pread_full(int fd, void *buf, size_t n, off_t off) {
    uint8_t *p = buf;
    while (n) {
        ssize_t r = pread(fd, p, n, off);
        if (r <= 0) {
            if (r < 0 && errno == EINTR) continue;
            return false;
        }
        p += r; n -= (size_t)r; off += r;
    }
    return true;
}

static bool fp_pwrite_full(int fd, const void *buf, size_t n, off_t off) {
    const uint8_t *p = buf;
    while (n) {
        ssize_t r = pwrite(fd, p, n, off);
        if (r <= 0) {
            if (r < 0 && errno == EINTR) continue;
            return false;
        }
        p += r; n -= (size_t)r; off += r;
    }
    return true;
}

const char *fp_mode_name(int mode) {
    switch (mode) {
        case FP_MODE_R_CID2: return "READ/cryptid2";
        case FP_MODE_RX_CID1: return "READ|EXEC/cryptid1";
        case FP_MODE_R_CID1: return "READ/cryptid1";
    }
    return "unknown";
}

#pragma mark - parsing

bool fp_is_macho(const char *path) {
    if (!path) return false;
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return false;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return false;
    }
    uint32_t magic = 0;
    bool ok = fp_pread_full(fd, &magic, sizeof magic, 0);
    close(fd);
    if (!ok) return false;
    return magic == MH_MAGIC_64 || magic == MH_MAGIC || magic == FAT_CIGAM ||
           magic == FAT_CIGAM_64;
}

static int fp_parse_thin(int fd, uint64_t off, uint64_t size, fp_slice_t *s,
                         char *err, size_t errlen) {
    if (size < sizeof(struct mach_header_64) || off > (uint64_t)INT64_MAX - size) {
        snprintf(err, errlen, "short slice (header)");
        return -1;
    }
    struct mach_header_64 mh;
    if (!fp_pread_full(fd, &mh, sizeof mh, (off_t)off)) {
        snprintf(err, errlen, "short read (header)");
        return -1;
    }
    if (mh.magic != MH_MAGIC_64) {
        snprintf(err, errlen, "unsupported magic 0x%x", mh.magic);
        return -1;
    }
    memset(s, 0, sizeof *s);
    s->slice_off = off;
    s->slice_size = size;
    s->cputype = mh.cputype;
    s->cpusubtype = mh.cpusubtype;
    s->filetype = mh.filetype;
    if (mh.sizeofcmds > 16u * 1024u * 1024u ||
        (uint64_t)mh.sizeofcmds > size - sizeof(struct mach_header_64)) {
        snprintf(err, errlen, "sizeofcmds out of slice bounds");
        return -1;
    }
    uint8_t *cmds = malloc(mh.sizeofcmds ? mh.sizeofcmds : 1);
    if (!cmds || !fp_pread_full(fd, cmds, mh.sizeofcmds, (off_t)(off + sizeof mh))) {
        free(cmds);
        snprintf(err, errlen, "short read (load commands)");
        return -1;
    }
    uint64_t pos = 0;
    uint64_t limit = mh.sizeofcmds;
    for (uint32_t i = 0; i < mh.ncmds && pos + sizeof(struct load_command) <= limit; i++) {
        struct load_command lc;
        memcpy(&lc, cmds + pos, sizeof lc);
        if (lc.cmdsize < sizeof(struct load_command) ||
            (lc.cmdsize & 3u) != 0 ||
            (uint64_t)lc.cmdsize > limit - pos) {
            break;
        }
        if (lc.cmd == LC_ENCRYPTION_INFO_64 || lc.cmd == LC_ENCRYPTION_INFO) {
            size_t min_size = (lc.cmd == LC_ENCRYPTION_INFO_64)
                ? sizeof(struct encryption_info_command_64)
                : sizeof(struct encryption_info_command);
            if (lc.cmdsize < min_size) break;
            struct encryption_info_command e;
            memcpy(&e, cmds + pos, sizeof e);
            if (!s->has_enc || s->cryptid == 0 || e.cryptid != 0) {
                s->has_enc = true;
                s->enc_lc_off = off + sizeof mh + pos;
                s->cryptoff = e.cryptoff;
                s->cryptsize = e.cryptsize;
                s->cryptid = e.cryptid;
            }
        } else if (lc.cmd == LC_CODE_SIGNATURE) {
            if (lc.cmdsize < sizeof(struct linkedit_data_command)) break;
            struct linkedit_data_command l;
            memcpy(&l, cmds + pos, sizeof l);
            s->cs_off = l.dataoff;
            s->cs_size = l.datasize;
        }
        pos += lc.cmdsize;
    }
    free(cmds);
    return 0;
}

int fp_parse(const char *path, fp_slice_t *slices, int max, int *count,
             char *err, size_t errlen) {
    if (!path || !slices || !count || max <= 0) return -1;
    *count = 0;
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) {
        snprintf(err, errlen, "open: %s", strerror(errno));
        return -1;
    }
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0) {
        snprintf(err, errlen, "stat: %s", errno ? strerror(errno) : "not a regular file");
        close(fd);
        return -1;
    }
    uint32_t magic = 0;
    if (!fp_pread_full(fd, &magic, 4, 0)) {
        snprintf(err, errlen, "short read");
        close(fd);
        return -1;
    }
    int rc = 0;
    if (magic == FAT_CIGAM || magic == FAT_CIGAM_64) {
        bool is64 = (magic == FAT_CIGAM_64);
        struct fat_header fh;
        if (!fp_pread_full(fd, &fh, sizeof fh, 0)) {
            snprintf(err, errlen, "short read (fat header)");
            close(fd);
            return -1;
        }
        uint32_t n = OSSwapBigToHostInt32(fh.nfat_arch);
        if (n > 64) n = 64;
        uint64_t p = sizeof fh;
        for (uint32_t i = 0; i < n && *count < max; i++) {
            uint64_t o = 0, sz = 0;
            uint32_t ct = 0;
            if (is64) {
                struct fat_arch_64 fa;
                if (!fp_pread_full(fd, &fa, sizeof fa, (off_t)p)) break;
                p += sizeof fa;
                o = OSSwapBigToHostInt64(fa.offset);
                sz = OSSwapBigToHostInt64(fa.size);
                ct = OSSwapBigToHostInt32(fa.cputype);
            } else {
                struct fat_arch fa;
                if (!fp_pread_full(fd, &fa, sizeof fa, (off_t)p)) break;
                p += sizeof fa;
                o = OSSwapBigToHostInt32(fa.offset);
                sz = OSSwapBigToHostInt32(fa.size);
                ct = OSSwapBigToHostInt32(fa.cputype);
            }
            if (!(ct & CPU_ARCH_ABI64)) continue; // 32-bit slices never execute here
            if (st.st_size < 0 || o > (uint64_t)st.st_size || sz > (uint64_t)st.st_size - o) continue;
            char detail[128] = {0};
            if (fp_parse_thin(fd, o, sz, &slices[*count], detail, sizeof detail) == 0) {
                (*count)++;
            }
        }
    } else if (magic == MH_MAGIC_64) {
        rc = fp_parse_thin(fd, 0, (uint64_t)st.st_size, &slices[0], err, errlen);
        if (rc == 0) *count = 1;
    } else {
        snprintf(err, errlen, "not a 64-bit Mach-O (magic 0x%08x)", magic);
        rc = -1;
    }
    close(fd);
    return rc;
}

#pragma mark - plaintext probe

// 「假加密壳」检测：签名被剥掉、正文其实已经是明文的包，cryptid 还写着 1，
// 加密区往往只剩一页（工具重签时缩小的占位）。这类包内核 mremap 必定失败
// （未页对齐），但根本不需要解密——直接清标志按明文出包即可。
// 判据必须保守：真加密包的 __TEXT 整个在声明区间里，我们跳过它采样到的是
// 头部/__LINKEDIT（也是低熵），所以**只有声明区间小到不像真加密区时**才走这条路。

static bool fp_probe_window(int fd, uint64_t off, size_t len,
                            uint64_t hist[256], uint32_t *landmarks,
                            uint64_t *bytes, int *samples, int *plain_samples) {
    if (!len) return false;
    uint8_t *buf = malloc(len);
    if (!buf) return false;
    if (!fp_pread_full(fd, buf, len, (off_t)off)) {
        free(buf);
        return false;
    }
    uint64_t local[256] = {0};
    fp_accumulate_histogram(local, buf, len);
    double e = fp_entropy_from_histogram(local, len);
    if (e < 7.3) (*plain_samples)++;
    *landmarks += fp_code_words(buf, len);
    *bytes += len;
    for (int k = 0; k < 256; k++) hist[k] += local[k];
    (*samples)++;
    free(buf);
    return true;
}

// 在 [base, base+size) 内取 3 个窗口采样，跳过 [skip_start, skip_end)（可传 0/0）。
static int fp_probe_span(int fd, uint64_t base, uint64_t size,
                         uint64_t skip_start, uint64_t skip_end,
                         fp_plain_probe_t *out) {
    uint64_t hist[256] = {0};
    uint32_t landmarks = 0;
    uint64_t bytes = 0;
    int samples = 0, plain_samples = 0;
    if (size >= 0x1000) {
        uint64_t limit = base + size;
        size_t chunk = size < 0x10000 ? (size_t)size : 0x10000;
        const double fractions[3] = {0.10, 0.50, 0.90};
        for (int k = 0; k < 3; k++) {
            uint64_t point = base + (uint64_t)((double)size * fractions[k]);
            if (point + chunk > limit) point = limit - chunk;
            if (skip_end > skip_start && point < skip_end && point + chunk > skip_start) {
                if (skip_end + chunk <= limit) {
                    point = skip_end;
                } else if (skip_start >= base + chunk) {
                    point = skip_start - chunk;
                } else {
                    continue;
                }
            }
            fp_probe_window(fd, point, chunk, hist, &landmarks, &bytes, &samples, &plain_samples);
        }
    } else if (size) {
        fp_probe_window(fd, base, (size_t)size, hist, &landmarks, &bytes, &samples, &plain_samples);
    }
    out->samples = samples;
    out->plain_samples = plain_samples;
    out->bytes = bytes;
    out->landmarks = landmarks;
    out->entropy = fp_entropy_from_histogram(hist, bytes);
    return samples ? 0 : -1;
}

int fp_probe_plaintext(const char *path, const fp_slice_t *s,
                       fp_plain_probe_t *body, fp_plain_probe_t *region) {
    if (!path || !s) return -1;
    if (body) memset(body, 0, sizeof *body);
    if (region) memset(region, 0, sizeof *region);
    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size <= 0) {
        close(fd);
        return -1;
    }
    uint64_t fsz = (uint64_t)st.st_size;
    uint64_t crypt_start = s->slice_off + s->cryptoff;
    uint64_t crypt_end = crypt_start + (uint64_t)s->cryptsize;
    int rc = -1;
    if (body && s->slice_off < fsz) {
        uint64_t avail = fsz - s->slice_off;
        uint64_t slice_size = s->slice_size < avail ? s->slice_size : avail;
        if (slice_size >= 0x1000 &&
            fp_probe_span(fd, s->slice_off, slice_size, crypt_start, crypt_end, body) == 0) {
            rc = 0;
        }
    }
    if (region && crypt_end > crypt_start && crypt_start < fsz) {
        uint64_t avail = fsz - crypt_start;
        uint64_t n = crypt_end - crypt_start < avail ? crypt_end - crypt_start : avail;
        fp_probe_span(fd, crypt_start, n, 0, 0, region);
    }
    close(fd);
    return rc;
}

bool fp_probe_is_plain(const fp_plain_probe_t *probe) {
    if (!probe || probe->samples <= 0) return false;
    return probe->plain_samples * 2 > probe->samples;
}

#pragma mark - attempt

// 硬条件：内核调用成功、每一页都回读成功、字节确实和密文不同。
// 半解半不解的映射一个都满足不了。
static bool fp_attempt_hard_ok(const fp_attempt_t *a) {
    return a->mremap_ret == 0 && a->pages_ok == a->pages_total && a->changed;
}

bool fp_attempt_looks_decrypted(const fp_attempt_t *a) {
    // 只按「熵掉下来了没有」判，不再数 ARM64 地标词（ret/pacibsp）。
    // 实测（iPadn 2026-11-19 真机样本）：真正解开 17 个文件，峰值熵 7.06；
    // 旧地标规则判错的 14 个其实是数据型/重度混淆载荷，熵只有 0.53–6.19、
    // code 0→0。数地标会把它们当失败，白试其余模式，还出 -PARTIAL。
    // 未解开的密文始终停在 ~8.0，半解开的页 > 7.8。
    if (!fp_attempt_hard_ok(a)) return false;
    if (!(a->ent_before > 7.9)) return false;
    if (a->ent_after >= 7.5) return false;
    if ((a->ent_before - a->ent_after) < 0.5) return false;
    // ret_after / ret_before 仍留在日志里当地标诊断，不参与判定。
    return true;
}

/// 判据没通过时的一句话原因，写进日志便于定位。
static const char *fp_attempt_reason(const fp_attempt_t *a) {
    if (!fp_attempt_hard_ok(a)) {
        if (a->mremap_ret != 0) return "mremap";
        if (a->pages_ok != a->pages_total) return "pages";
        return "unchanged";
    }
    if (!(a->ent_before > 7.9)) return "src_plain";
    if (a->ent_after >= 7.5) return "ent_high";
    if ((a->ent_before - a->ent_after) < 0.5) return "drop_small";
    return "pass";
}

void fp_attempt_describe(const fp_attempt_t *a, char *buf, size_t len) {
    // 一页都没读回来时 ent_after 是初始值 0.00，打出来会让人误以为
    // 「熵掉到 0 = 解开了」，所以那种情况一律写 n/a。
    char entropy[64];
    if (a->pages_total == 0) {
        snprintf(entropy, sizeof entropy, "%.2f->n/a", a->ent_before);
    } else {
        snprintf(entropy, sizeof entropy, "%.2f->%.2f", a->ent_before, a->ent_after);
    }
    snprintf(buf, len,
             "%s%s%s mremap=%d(%s) mmap=%s pages=%llu/%llu changed=%d "
             "code %u->%u entropy %s %.0fms verdict=%s",
             fp_mode_name(a->mode), a->addsigs ? "+sigs" : "",
             a->subtype_masked ? "+sub0" : "",
             a->mremap_ret,
             a->mremap_ret == 0 ? "ok" : strerror(a->mremap_errno ? a->mremap_errno : EINVAL),
             a->mmap_errno ? strerror(a->mmap_errno) : "ok",
             (unsigned long long)a->pages_ok, (unsigned long long)a->pages_total,
             a->changed ? 1 : 0, a->ret_before, a->ret_after,
             entropy, a->ms, fp_attempt_reason(a));
}

static int fp_attempt_internal(const char *path, const fp_slice_t *s, int mode, bool addsigs,
                               uint8_t *out, int out_fd, fp_attempt_t *res) {
    if (!path || !s || !res) return -1;
    memset(res, 0, sizeof *res);
    res->mode = mode;
    res->addsigs = addsigs;
    res->mremap_ret = -1;
    res->mmap_errno = 0;
    res->sig_errno = 0;
    double t0 = fp_now_ms();

    int pg = getpagesize();
    if (pg <= 0) { res->mmap_errno = EINVAL; return -1; }
    const uint64_t page = (uint64_t)pg;
    if (!s->has_enc || s->cryptsize == 0) return -1;
    if (s->slice_off % page) { res->mmap_errno = EINVAL; return -1; }
    if (s->cryptoff % page) { res->mremap_errno = EINVAL; return -1; }

    int fd = open(path, O_RDONLY | O_NOFOLLOW);
    if (fd < 0) { res->mmap_errno = errno; return -1; }

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 0) {
        res->mmap_errno = errno ? errno : EINVAL;
        close(fd);
        return -1;
    }
    uint64_t fsz = (uint64_t)st.st_size;
    if (s->slice_off > fsz || s->slice_size > fsz - s->slice_off ||
        (uint64_t)s->cryptoff > s->slice_size ||
        (uint64_t)s->cryptsize > s->slice_size - (uint64_t)s->cryptoff) {
        res->mmap_errno = EINVAL;
        close(fd);
        return -1;
    }

    if (addsigs && s->cs_size &&
        (uint64_t)s->cs_off <= s->slice_size &&
        (uint64_t)s->cs_size <= s->slice_size - (uint64_t)s->cs_off) {
        fsignatures_t fs = {
            .fs_file_start = (off_t)s->slice_off,
            .fs_blob_start = (void *)(uintptr_t)s->cs_off,
            .fs_blob_size = s->cs_size,
        };
        if (fcntl(fd, F_ADDFILESIGS_RETURN, &fs) == -1) res->sig_errno = errno;
    }

    uint64_t crypt_end = (uint64_t)s->cryptoff + (uint64_t)s->cryptsize;
    if (crypt_end > UINT64_MAX - (page - 1)) {
        res->mmap_errno = EOVERFLOW;
        close(fd);
        return -1;
    }
    uint64_t map_len = (crypt_end + page - 1) & ~(page - 1);
    if (map_len == 0 || map_len > SIZE_MAX || (uint64_t)s->cryptsize > SIZE_MAX) {
        res->mmap_errno = EOVERFLOW;
        close(fd);
        return -1;
    }
    int prot = PROT_READ | (mode == FP_MODE_RX_CID1 ? PROT_EXEC : 0);
    uint8_t *base = mmap(NULL, (size_t)map_len, prot, MAP_PRIVATE, fd, (off_t)s->slice_off);
    if (base == MAP_FAILED) {
        res->mmap_errno = errno;
        close(fd);
        res->ms = fp_now_ms() - t0;
        return -1;
    }

    // Stream in 4 MB page-aligned windows (8 MB total heap instead of 2 x cryptsize)
    // so multi-hundred-MB game executables never trigger Jetsam OOM.
    uint64_t window = 4u * 1024u * 1024u;
    if (window < page) window = page;
    window = (window / page) * page;
    size_t buf_cap = (size_t)((uint64_t)s->cryptsize < window ? (uint64_t)s->cryptsize : window);
    uint8_t *orig_chunk = malloc(buf_cap);
    uint8_t *plain_chunk = out ? NULL : malloc(buf_cap);
    if (!orig_chunk || (!out && !plain_chunk)) {
        free(orig_chunk);
        free(plain_chunk);
        munmap(base, (size_t)map_len);
        close(fd);
        res->mmap_errno = ENOMEM;
        res->ms = fp_now_ms() - t0;
        return -1;
    }

    uint64_t hist_before[256] = {0};
    uint64_t hist_after[256] = {0};
    bool io_ok = true;
    for (uint64_t off = 0; off < (uint64_t)s->cryptsize; off += window) {
        size_t chunk_len = (size_t)(((uint64_t)s->cryptsize - off < window)
                                    ? ((uint64_t)s->cryptsize - off) : window);
        if (!fp_pread_full(fd, orig_chunk, chunk_len, (off_t)(s->slice_off + s->cryptoff + off))) {
            io_ok = false;
            break;
        }
        fp_accumulate_histogram(hist_before, orig_chunk, chunk_len);
        res->ret_before += fp_code_words(orig_chunk, chunk_len);
    }
    if (!io_ok) {
        free(orig_chunk);
        free(plain_chunk);
        munmap(base, (size_t)map_len);
        close(fd);
        res->mmap_errno = EIO;
        res->ms = fp_now_ms() - t0;
        return -1;
    }
    res->ent_before = fp_entropy_from_histogram(hist_before, s->cryptsize);

    uint32_t cryptid = (mode == FP_MODE_R_CID2) ? 2 : 1;
    errno = 0;
    res->mremap_ret = fp_mremap_encrypted(base + s->cryptoff, s->cryptsize, cryptid,
                                          s->cputype, s->cpusubtype);
    res->mremap_errno = res->mremap_ret == 0 ? 0 : errno;

    bool write_ok = true;
    if (res->mremap_ret == 0) {
        // vm_read_overwrite turns a failed page-in (FairPlay refused this page)
        // into a kern_return_t instead of a SIGBUS.
        uint64_t total = ((uint64_t)s->cryptsize + page - 1) / page;
        res->pages_total = total;
        for (uint64_t off = 0; off < (uint64_t)s->cryptsize; off += window) {
            size_t chunk_len = (size_t)(((uint64_t)s->cryptsize - off < window)
                                        ? ((uint64_t)s->cryptsize - off) : window);
            if (!fp_pread_full(fd, orig_chunk, chunk_len, (off_t)(s->slice_off + s->cryptoff + off))) {
                write_ok = false;
                break;
            }
            uint8_t *dst = out ? (out + off) : plain_chunk;
            for (size_t p_off = 0; p_off < chunk_len; p_off += (size_t)page) {
                size_t n = (p_off + (size_t)page <= chunk_len) ? (size_t)page : (chunk_len - p_off);
                vm_size_t got = 0;
                kern_return_t kr = vm_read_overwrite(
                    mach_task_self(),
                    (vm_address_t)(base + s->cryptoff + off + p_off),
                    (vm_size_t)n,
                    (vm_address_t)(dst + p_off),
                    &got);
                if (kr == KERN_SUCCESS && got == n) {
                    res->pages_ok++;
                } else {
                    if (!res->first_fail_kr) {
                        res->first_fail_kr = kr ? (int)kr : -1;
                        res->first_fail_off = s->cryptoff + off + p_off;
                    }
                    memset(dst + p_off, 0, n);
                }
            }
            if (!res->changed && memcmp(orig_chunk, dst, chunk_len) != 0) {
                res->changed = true;
            }
            res->ret_after += fp_code_words(dst, chunk_len);
            fp_accumulate_histogram(hist_after, dst, chunk_len);
            if (out_fd >= 0 &&
                !fp_pwrite_full(out_fd, dst, chunk_len, (off_t)(s->slice_off + s->cryptoff + off))) {
                write_ok = false;
                break;
            }
        }
        res->ent_after = fp_entropy_from_histogram(hist_after, s->cryptsize);
    }

    free(orig_chunk);
    free(plain_chunk);
    munmap(base, (size_t)map_len);
    close(fd);
    res->ms = fp_now_ms() - t0;
    return (write_ok && res->mremap_ret == 0 && res->pages_ok == res->pages_total && res->changed) ? 0 : -1;
}

int fp_attempt(const char *path, const fp_slice_t *s, int mode, bool addsigs,
               uint8_t *out, fp_attempt_t *res) {
    return fp_attempt_internal(path, s, mode, addsigs, out, -1, res);
}

#pragma mark - decrypt to file

static int fp_copy_file(const char *src, const char *dst) {
    int in = open(src, O_RDONLY | O_NOFOLLOW);
    if (in < 0) return -1;
    struct stat st;
    if (fstat(in, &st) != 0 || !S_ISREG(st.st_mode)) { close(in); return -1; }
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, (st.st_mode & 0777) | 0600);
    if (out < 0) { close(in); return -1; }
    uint8_t *buf = malloc(1 << 20);
    if (!buf) { close(in); close(out); unlink(dst); return -1; }
    ssize_t r;
    off_t written = 0;
    int rc = 0;
    for (;;) {
        r = read(in, buf, 1 << 20);
        if (r == 0) break;
        if (r < 0) {
            if (errno == EINTR) continue;
            rc = -1;
            break;
        }
        if (!fp_pwrite_full(out, buf, (size_t)r, written)) { rc = -1; break; }
        written += r;
    }
    free(buf);
    close(in);
    close(out);
    if (rc != 0) unlink(dst);
    return rc;
}

int fp_decrypt_file(const char *in_path, const char *out_path, fp_log_t log, void *ctx) {
    return fp_decrypt_file_ex(in_path, in_path, out_path, log, ctx, NULL);
}

// map_path 与 in_path 可以不同：把"从哪个文件映射并回读明文"和"写回哪个文件"
// 拆开。已安装应用可以直接映射原始路径（fairplayd 读得到别人的安装包），
// 明文再写进我们自己的暂存副本，这样拷贝位置就不会影响 fairplayd 的判定。
int fp_decrypt_file_ex(const char *in_path, const char *map_path,
                       const char *out_path, fp_log_t log, void *ctx,
                       fp_file_stats_t *stats) {
    if (!in_path || !map_path || !out_path) return -1;
    if (stats) memset(stats, 0, sizeof *stats);
    fp_slice_t slices[FP_MAX_SLICES];
    int count = 0;
    char err[256] = {0};
    if (fp_parse(map_path, slices, FP_MAX_SLICES, &count, err, sizeof err) != 0) {
        fp_log(log, ctx, "  parse failed: %s", err);
        return -1;
    }

    bool encrypted = false;
    for (int i = 0; i < count; i++) {
        if (slices[i].has_enc && slices[i].cryptid != 0) encrypted = true;
        if (slices[i].has_enc && slices[i].cryptid != 0 && slices[i].cryptsize > 0 && stats) {
            stats->slices_total++;
        }
    }
    bool same_path = strcmp(in_path, out_path) == 0;
    if (!encrypted) {
        if (!same_path && fp_copy_file(in_path, out_path) != 0) return -1;
        return 1;
    }

    char *work_path = NULL;
    const char *target_path = out_path;
    if (same_path) {
        size_t len = strlen(out_path) + 16;
        work_path = malloc(len);
        if (!work_path) return -1;
        snprintf(work_path, len, "%s.fptmp", out_path);
        unlink(work_path);
        target_path = work_path;
    }
    if (fp_copy_file(in_path, target_path) != 0) {
        fp_log(log, ctx, "  copy failed: %s", strerror(errno));
        free(work_path);
        return -1;
    }

    int out = open(target_path, O_RDWR | O_NOFOLLOW);
    if (out < 0) {
        fp_log(log, ctx, "  open output: %s", strerror(errno));
        unlink(target_path);
        free(work_path);
        return -1;
    }

    // The READ/cryptid2 attempt is the one that works without PROT_EXEC; the
    // others are fallbacks for releases where the model-encryption path is not
    // reachable.
    // 最后两条把 cpusubtype 的 ABI/PAC 位抹掉再试：arm64e 二进制上 fairplayd
    // 有时按 (cputype, cpusubtype) 找不到解密会话，退回纯 arm64 反而能过。
    const struct { int mode; bool addsigs; bool mask; } order[] = {
        {FP_MODE_R_CID2, false, false},
        {FP_MODE_R_CID2, true, false},
        {FP_MODE_R_CID2, false, true},
        {FP_MODE_RX_CID1, false, false},
        {FP_MODE_RX_CID1, true, false},
        {FP_MODE_RX_CID1, false, true},
    };

    int rc = 0;
    for (int i = 0; i < count && rc == 0; i++) {
        const fp_slice_t *s = &slices[i];
        if (!s->has_enc || s->cryptid == 0) continue;
        uint64_t cid_off = s->enc_lc_off + offsetof(struct encryption_info_command, cryptid);
        if (cid_off < s->slice_off || cid_off + 4 > s->slice_off + s->slice_size) {
            fp_log(log, ctx, "  slice[%d] invalid encryption command offset", i);
            rc = -1;
            break;
        }

        // cryptid != 0 但没有声明任何加密区间：没有明文要产出，只需要把标志清零。
        // 以前这里直接 continue，胖二进制/多加密命令时另一个切片会让整个文件
        // 保持 cryptid != 0，校验就会报「仍加密」并出 -PARTIAL。
        if (s->cryptsize == 0) {
            uint32_t zero = 0;
            if (!fp_pwrite_full(out, &zero, 4, (off_t)cid_off)) {
                fp_log(log, ctx, "  slice[%d] flag clear failed: %s", i, strerror(errno));
                rc = -1;
                break;
            }
            if (stats) stats->slices_plain++;
            fp_log(log, ctx, "  slice[%d] cryptid=%u cryptsize=0: flag cleared, no plaintext",
                   i, s->cryptid);
            continue;
        }

        // ---- 假加密壳：签名被剥掉，正文根本就是明文，只有 cryptid 还写着 1 ----
        // 常见于各种重签工具/改壳工具（换图标、换主题、装助手）落地到设备上的副本：
        // 加密区被缩成一页，cryptoff 只按 4 KB 对齐 ⇒ 内核 mremap 必 EINVAL。
        // 但内容本来就是明文，不需要解密：清掉 cryptid，按明文出包。
        // 判据保守到只对「声明区间 ≤ 1 个 16 KB 页」的切片生效，避免把真加密包
        // （头部/__LINKEDIT 采样也是低熵）误当成明文。
        if (s->cryptsize <= 0x4000) {
            fp_plain_probe_t body, region;
            if (fp_probe_plaintext(map_path, s, &body, &region) == 0 &&
                fp_probe_is_plain(&body)) {
                uint32_t zero = 0;
                if (!fp_pwrite_full(out, &zero, 4, (off_t)cid_off)) {
                    fp_log(log, ctx, "  slice[%d] flag clear failed: %s", i, strerror(errno));
                    rc = -1;
                    break;
                }
                if (stats) stats->slices_fake_plain++;
                fp_log(log, ctx,
                       "  slice[%d] [OK] 假加密壳：正文熵 %.2f（明文 %d/%d 窗口，地标 %u），"
                       "声明区间 0x%x @0x%x 熵 %.2f ⇒ 已是明文，跳过解密、清 cryptid 出包",
                       i, body.entropy, body.plain_samples, body.samples, body.landmarks,
                       s->cryptsize, s->cryptoff, region.entropy);
                if (!fp_probe_is_plain(&region)) {
                    if (stats) stats->residue_cipher++;
                    fp_log(log, ctx,
                           "  slice[%d] ⚠️ 声明区间那 0x%x 字节仍是密文且解不开（未页对齐），"
                           "已按原样保留；出包后若这个应用崩溃，说明那一段是真实代码，请改用 A · 内核砸壳",
                           i, s->cryptsize);
                }
                continue;
            }
        }

        bool done = false;
        for (size_t k = 0; k < sizeof order / sizeof order[0] && !done; k++) {
            fp_attempt_t attempt;
            char line[512];
            fp_slice_t variant = *s;
            if (order[k].mask) variant.cpusubtype &= ~0xFF000000u;
            int attempt_rc = fp_attempt_internal(map_path, &variant, order[k].mode, order[k].addsigs,
                                                 NULL, out, &attempt);
            attempt.subtype_masked = order[k].mask;
            bool hard_ok = fp_attempt_hard_ok(&attempt);
            fp_attempt_describe(&attempt, line, sizeof line);
            done = (attempt_rc == 0) && fp_attempt_looks_decrypted(&attempt);
            fp_log(log, ctx, "  slice[%d] %s %s", i, done ? "[OK]" : "[--]", line);
            if (hard_ok && !done) {
                // 内核成功了、每一页都回来了、字节也确实变了，只是判据判否：
                // 其余模式解的是同一段，不可能更好，直接放弃这一轮。
                if (stats) stats->heuristic_rejected++;
                fp_log(log, ctx,
                       "  slice[%d] heuristic rejected: kernel ok, pages %llu/%llu, "
                       "entropy %.2f->%.2f (%s), code %u->%u",
                       i, (unsigned long long)attempt.pages_ok,
                       (unsigned long long)attempt.pages_total,
                       attempt.ent_before, attempt.ent_after,
                       fp_attempt_reason(&attempt),
                       attempt.ret_before, attempt.ret_after);
                break;
            }
        }
        if (!done) { rc = -1; break; }
        uint32_t zero = 0;
        if (!fp_pwrite_full(out, &zero, 4, (off_t)cid_off)) {
            fp_log(log, ctx, "  write failed: %s", strerror(errno));
            rc = -1;
        } else if (stats) {
            stats->slices_ok++;
        }
    }
    close(out);
    if (rc == 0 && same_path) {
        if (rename(target_path, out_path) != 0) {
            unlink(target_path);
            rc = -1;
        }
    } else if (rc != 0) {
        unlink(target_path);
    }
    free(work_path);
    return rc;
}
