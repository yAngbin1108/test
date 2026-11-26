// FairPlayCore — on-device FairPlay (App Store DRM) decryption primitives.
//
// 来源：iPadn (github.com/mengangs/ipadn) 的 iPadn-iOS/FairPlayCore，GPL-2.0-or-later。
// 与本仓库（AGPL）兼容；修改处已在文件内注明。
//
// Mechanism (independent implementation; described by morzelowski/FairPlayed):
//   * mremap_encrypted() has no privilege check, so any process can ask the
//     kernel to run a mapped range through FairPlay (text_crypter_create ->
//     FairPlayIOKit -> fairplayd).
//   * cryptid = 2 (CRYPTID_MODEL_ENCRYPTION) picks the vm_map_apple_protected
//     path that does NOT require the mapping to be executable, so a plain
//     PROT_READ mmap is enough and AMFI library validation never runs.
//   * fairplayd resolves the license by path: <dir>/SC_Info/<name>.sinf next to
//     the binary, so the caller only has to put the SINF beside the Mach-O.
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define FP_MAX_SLICES 8

typedef void (*fp_log_t)(void *ctx, const char *msg);

enum {
    FP_MODE_R_CID2 = 1,   // PROT_READ, cryptid 2 (works without PROT_EXEC)
    FP_MODE_RX_CID1 = 2,  // PROT_READ|PROT_EXEC, cryptid 1 (what dyld does)
    FP_MODE_R_CID1 = 3,   // PROT_READ, cryptid 1 (control: VM layer rejects)
};

typedef struct {
    uint64_t slice_off;
    uint64_t slice_size;
    uint32_t cputype;
    uint32_t cpusubtype;
    uint32_t filetype;
    uint64_t enc_lc_off;   // absolute file offset of the cryptid field
    uint32_t cryptoff;
    uint32_t cryptsize;
    uint32_t cryptid;
    uint32_t cs_off;
    uint32_t cs_size;
    bool has_enc;
} fp_slice_t;

typedef struct {
    int mode;
    bool addsigs;
    bool subtype_masked;
    int sig_errno;
    int mmap_errno;
    int mremap_ret;
    int mremap_errno;
    uint64_t pages_total;
    uint64_t pages_ok;
    int first_fail_kr;
    uint64_t first_fail_off;
    bool changed;
    uint32_t ret_before;
    uint32_t ret_after;
    double ent_before;
    double ent_after;
    double ms;
} fp_attempt_t;

/// True when the file starts with a 64-bit Mach-O or a FAT Mach-O magic.
bool fp_is_macho(const char *path);

/// Parses the slices of `path` that carry LC_ENCRYPTION_INFO(_64).
int fp_parse(const char *path, fp_slice_t *slices, int max, int *count, char *err, size_t errlen);

/// Runs one decryption attempt on one slice. `out` (size >= cryptsize) receives
/// the bytes read back from the remapped range; pass NULL to discard them.
int fp_attempt(const char *path, const fp_slice_t *slice, int mode, bool addsigs,
               uint8_t *out, fp_attempt_t *result);

/// 0 = success, 1 = not encrypted (copied as-is), -1 = failure.
int fp_decrypt_file(const char *in_path, const char *out_path, fp_log_t log, void *ctx);

/// 一段字节的「明文程度」探测结果。
typedef struct {
    int samples;          ///< 成功采样的窗口数
    int plain_samples;    ///< 熵 < 7.3 的窗口数
    uint64_t bytes;       ///< 采样总字节
    double entropy;       ///< 合并直方图后的整体熵
    uint32_t landmarks;   ///< ARM64 地标词（ret / pacibsp / retab）计数
} fp_plain_probe_t;

/// 采样一个切片的正文（跳过声明的加密区）与声明的加密区本身。
/// body / region 任一个可为 NULL。0 = 至少 body 采到过数据。
int fp_probe_plaintext(const char *path, const fp_slice_t *slice,
                       fp_plain_probe_t *body, fp_plain_probe_t *region);

/// 采样结果像不像明文：过半窗口熵 < 7.3 即认为明文。
/// 未解开的密文每个窗口都停在 ~7.95，所以这个判据对密文是安全的（不会误判）。
bool fp_probe_is_plain(const fp_plain_probe_t *probe);

/// 每个文件的分类计数。用来区分「内核真的拒绝（授权问题）」和
/// 「内核已经把页解开了、我们自己的判据没通过」——后者绝不能拿去
/// 告诉用户"没有解密授权 / 去 App Store 登录"。
typedef struct {
    int slices_total;        ///< 带非零 cryptsize 的加密切片数
    int slices_ok;           ///< 明文已写回并清了 cryptid 的切片数
    int slices_plain;        ///< cryptid != 0 但 cryptsize == 0：只清标志，没有明文要产出
    int slices_fake_plain;   ///< 声明加密但正文已是明文（假加密壳）：跳过解密、清 cryptid 直接出包
    int slices_residue_ok;   ///< 正文明文但声明区间是真密文（iOS 17 商店布局）：已按对齐窗口解开该小段
    int residue_cipher;      ///< 声明区间那一小段仍是密文（对齐窗口也解不开），已按原样保留
    int heuristic_rejected;  ///< 内核成功、全部页回读成功、字节已变化，但判据判否
} fp_file_stats_t;

/// 同 fp_decrypt_file，但映射/读取走 map_path（可以是只读的原始安装路径），
/// 明文写回由 in_path 复制出来的 out_path。map_path 传 in_path 即普通用法。
/// stats 可为 NULL。
int fp_decrypt_file_ex(const char *in_path, const char *map_path,
                       const char *out_path, fp_log_t log, void *ctx,
                       fp_file_stats_t *stats);

/// Formats one attempt as a single diagnostic line.
const char *fp_mode_name(int mode);
void fp_attempt_describe(const fp_attempt_t *a, char *buf, size_t len);

/// True when the attempt produced plausible plaintext (entropy collapsed).
/// ARM64 landmark counts stay in the log as diagnostics but no longer decide it.
bool fp_attempt_looks_decrypted(const fp_attempt_t *a);
