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
    uint32_t page_slack;   // cryptoff 距页首的偏移（非页对齐包才有）
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

/// 同 fp_decrypt_file，但映射/读取走 map_path（可以是只读的原始安装路径），
/// 明文写回由 in_path 复制出来的 out_path。map_path 传 in_path 即普通用法。
int fp_decrypt_file_ex(const char *in_path, const char *map_path,
                       const char *out_path, fp_log_t log, void *ctx);

/// Formats one attempt as a single diagnostic line.
const char *fp_mode_name(int mode);
void fp_attempt_describe(const fp_attempt_t *a, char *buf, size_t len);

/// True when the attempt produced plausible decrypted ARM64 code.
bool fp_attempt_looks_decrypted(const fp_attempt_t *a);
