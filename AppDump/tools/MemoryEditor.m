//
//  SKMemoryEditor.m
//  SandboxKit — in-process memory search / edit / lock
//

#import "MemoryEditor.h"
#import "utils.h"
#import "vm.h"
#import "offsets.h"
#import "AppDumpKernelLock.h"
#import "darksword.h"

#include <mach/mach.h>
#include <string.h>

// vmmapremotepage() creates a memory-entry port and hands it back in
// shmem.port, but never releases it. Each call therefore leaks one Mach port,
// and a scan touches thousands of pages — the task's port namespace runs out
// part-way through and the app is killed. Release both the mapping and the
// port every time.
static inline void sk_release_shmem(uint64_t vmMap, struct vmshmem *s) {
    // AppDump 的 vmshmemrelease 已经处理：解映射 + 释放 port + 交还
    // vmcreateshmemwithobj() 手工加的那一个 vm_object 引用。
    // 这里绝不能再手工 mach_vm_deallocate / mach_port_deallocate，否则端口和
    // 引用计数会被减两次（历史上每页净 -1 把目标 vm_object 打死，直接 panic）。
    vmshmemrelease(vmMap, s);
}

// Scanning is bounded because each page fetch costs proportionally to the
// backing object. These caps keep a search responsive; large regions (the dyld
// shared cache, big __TEXT segments) are skipped rather than stalling the app.
static const uint64_t SKMemMaxRegionBytes = 8ull * 1024 * 1024;
static const uint64_t SKMemMaxTotalBytes  = 32ull * 1024 * 1024;
static const uint64_t SKMemChunkBytes     = 64ull * 1024;
// See the fail-fast comment in scanForValue:.
static const NSUInteger SKMemMaxConsecutiveFailures = 64;

// ─────────────────────────────────────────────────────────────────────────────
@implementation SKMemRegion
- (NSString *)description {
    return [NSString stringWithFormat:@"0x%llx-0x%llx (%.1f KB)",
            (unsigned long long)self.start, (unsigned long long)self.end,
            (self.end - self.start) / 1024.0];
}
@end

@implementation SKMemHit
@end

// ─────────────────────────────────────────────────────────────────────────────
@interface SKMemoryEngine ()
@property (nonatomic, readwrite) pid_t pid;
@property (nonatomic, readwrite) uint64_t vmMap;
@property (nonatomic, strong) NSArray<SKMemRegion *> *cachedRegions;
@property (nonatomic, strong) NSMutableArray<SKMemHit *> *hits;
// Guards `hits`. It is read by the lock timer on the main thread and rewritten
// by a scan on a background thread; mutating it while the timer enumerates it
// raises "collection was mutated while being enumerated".
@property (nonatomic, strong) NSLock *hitsLock;
@end

@implementation SKMemoryEngine

+ (instancetype)engineForPID:(pid_t)pid {
    if (pid <= 0 || !ds_is_ready()) return nil;

    uint64_t proc = procbypid(pid);
    if (!proc) return nil;
    uint64_t task = taskbyproc(proc);
    if (!task) return nil;
    uint64_t vmMap = task_get_vm_map(task);
    if (!vmMap) return nil;

    SKMemoryEngine *e = [SKMemoryEngine new];
    e.pid = pid;
    e.vmMap = vmMap;
    e.hits = [NSMutableArray array];
    e.hitsLock = [[NSLock alloc] init];
    return e;
}

// ── regions ────────────────────────────────────────────────────────────────
- (NSArray<SKMemRegion *> *)regions {
    if (self.cachedRegions) return self.cachedRegions;

    NSMutableArray *out = [NSMutableArray array];
    __block uint64_t budget = SKMemMaxTotalBytes;

    // vmmapiterateentries walks the target's vm_map by reading kernel memory.
    // This used to run WITHOUT the kernel lock, so it could interleave with
    // SKSandboxKeeper re-applying sbx_escape() (which writes kernel memory) and
    // with the .app ownership walk. Everything else in this file takes the lock;
    // this was the one hole.
    [AppDumpKernelLock() lock];
    vmmapiterateentries(self.vmMap, ^(uint64_t start, uint64_t end, uint64_t entry, BOOL *stop) {
        if (start == 0 || end <= start) return;
        if (start >= 0xffffff8000000000ULL) return;   // kernel side
        if (start < 0x100000000ULL) return;           // low guard pages
        uint64_t size = end - start;
        if (size > SKMemMaxRegionBytes) return;
        if (size > budget) return;
        budget -= size;

        SKMemRegion *r = [SKMemRegion new];
        r.start = start;
        r.end = end;
        [out addObject:r];
    });
    [AppDumpKernelLock() unlock];

    [out sortUsingComparator:^NSComparisonResult(SKMemRegion *a, SKMemRegion *b) {
        uint64_t sa = a.end - a.start, sb = b.end - b.start;
        return sa > sb ? NSOrderedAscending : (sa < sb ? NSOrderedDescending : NSOrderedSame);
    }];

    self.cachedRegions = out;
    return out;
}

// ── raw page access ────────────────────────────────────────────────────────
// ── SAFETY: validate the backing vm_object before touching it ──────────────
//
// vmmapremotepage() ends in vmcreateshmemwithobj(), which does
//
//     refcount = kread32(object->address + off_vm_object_ref_count);
//     kwrite32(object->address + off_vm_object_ref_count, refcount + 1);
//
// i.e. it WRITES to `object->address`. vmgetptr() derives that pointer by
// unpacking `entry.vme_object_or_delta`, and performs no validation at all.
// For entries that are not backed by an object (submaps, delta-encoded and
// anonymous entries) the unpacked value is not a pointer, so the kernel ends up
// writing a refcount into a garbage kernel address — kernel memory corruption
// and a panic.
//
// Broad scanning walks exactly those entries. We therefore refuse to hand any
// page to vmmapremotepage() unless its vm_map entry demonstrably describes a
// real, plausible vm_object.
#define SK_PACK_BITS   31
#define SK_PACK_SHIFT  6

static inline BOOL skIsKernelPtr(uint64_t p) {
    if (p == 0 || p == 0xFFFFFFFFFFFFFFFFULL) return NO;
    uint16_t top = (uint16_t)(p >> 48);
    return top == 0xFFFF || top == 0xFFFE;
}

// Returns the validated vm_object address, or 0 when the page must be skipped.
static uint64_t skValidatedObject(uint64_t vmMap, uint64_t address) {
    uint64_t entryAddr = vmmapfindentry(vmMap, address);
    if (!entryAddr) return 0;

    struct vmmapentry e;
    memset(&e, 0, sizeof(e));
    ds_kreadbuf(entryAddr, &e, sizeof(e));

    // A submap or a kernel object is not something we may alias.
    if (e.vme_ctx_is_sub_map) return 0;
    if (e.vme_kernel_object)    return 0;
    if (e.vme_object_or_delta == 0) return 0;

    struct vmpackingparams p;
    memset(&p, 0, sizeof(p));
    p.vmpp_base  = VM_MIN_KERNEL_ADDRESS;
    p.vmpp_bits  = SK_PACK_BITS;
    p.vmpp_shift = SK_PACK_SHIFT;
    p.vmpp_base_relative = VM_PACKING_IS_BASE_RELATIVE(&p) ? 1 : 0;

    uint64_t obj = vmunpackptr((uint64_t)e.vme_object_or_delta, &p);
    if (!skIsKernelPtr(obj)) return 0;

    // The candidate must look like a vm_object: a sane size and a live
    // refcount. A bogus pointer has to satisfy all of these to slip through.
    uint64_t size = ds_kread64(obj + off_vm_object_vo_un1_vou_size);
    if (size == 0 || size > (256ull << 20)) return 0;

    uint32_t rc = ds_kread32(obj + off_vm_object_ref_count);
    if (rc == 0 || rc > 1000000u) return 0;

    return obj;
}

- (nullable NSData *)readAt:(uint64_t)address length:(NSUInteger)length {
    uint8_t *buf = malloc(length);
    if (!buf) return nil;

    NSUInteger got = 0;
    while (got < length) {
        uint64_t cur  = address + got;
        uint64_t page = cur & ~((uint64_t)PAGE_SIZE - 1);
        uint64_t poff = cur - page;

        // Validation and the page aliasing both touch the kernel primitive, so
        // they must be atomic with respect to every other user of it.
        [AppDumpKernelLock() lock];
        if (skValidatedObject(self.vmMap, page) == 0) {
            [AppDumpKernelLock() unlock];
            free(buf);
            return nil;
        }
        struct vmshmem shmem = vmmapremotepage(self.vmMap, page);
        if (!shmem.used) {
            [AppDumpKernelLock() unlock];
            free(buf);
            return nil;
        }
        NSUInteger n = (NSUInteger)(PAGE_SIZE - poff);
        if (n > length - got) n = length - got;
        memcpy(buf + got, (void *)(uintptr_t)shmem.localAddress + poff, n);
        sk_release_shmem(self.vmMap, &shmem);
        [AppDumpKernelLock() unlock];
        got += n;
    }
    return [NSData dataWithBytesNoCopy:buf length:length freeWhenDone:YES];
}

- (BOOL)writeData:(NSData *)data to:(uint64_t)address {
    const uint8_t *src = data.bytes;
    NSUInteger len = data.length, done = 0;

    while (done < len) {
        uint64_t cur  = address + done;
        uint64_t page = cur & ~((uint64_t)PAGE_SIZE - 1);
        uint64_t poff = cur - page;

        [AppDumpKernelLock() lock];
        if (skValidatedObject(self.vmMap, page) == 0) {
            [AppDumpKernelLock() unlock];
            return NO;
        }
        struct vmshmem shmem = vmmapremotepage(self.vmMap, page);
        if (!shmem.used) {
            [AppDumpKernelLock() unlock];
            return NO;
        }
        NSUInteger n = (NSUInteger)(PAGE_SIZE - poff);
        if (n > len - done) n = len - done;

        // The entry is mapped VM_PROT_READ|VM_PROT_WRITE and aliases the
        // target's physical page, so this is a real write into the process.
        memcpy((void *)(uintptr_t)shmem.localAddress + poff, src + done, n);
        sk_release_shmem(self.vmMap, &shmem);
        [AppDumpKernelLock() unlock];
        done += n;
    }
    return YES;
}

- (BOOL)writeValue:(double)value type:(SKMemType)type to:(uint64_t)address {
    switch (type) {
        case SKMemTypeInt32: {
            int32_t v = (int32_t)value;
            return [self writeData:[NSData dataWithBytes:&v length:4] to:address];
        }
        case SKMemTypeInt64: {
            int64_t v = (int64_t)value;
            return [self writeData:[NSData dataWithBytes:&v length:8] to:address];
        }
        case SKMemTypeFloat: {
            float v = (float)value;
            return [self writeData:[NSData dataWithBytes:&v length:4] to:address];
        }
        case SKMemTypeDouble: {
            double v = value;
            return [self writeData:[NSData dataWithBytes:&v length:8] to:address];
        }
    }
    return NO;
}

// ── scan ───────────────────────────────────────────────────────────────────
static NSUInteger typeSize(SKMemType t) {
    switch (t) {
        case SKMemTypeInt32:  return 4;
        case SKMemTypeInt64:  return 8;
        case SKMemTypeFloat:  return 4;
        case SKMemTypeDouble: return 8;
    }
    return 4;
}

// ── value formatting ───────────────────────────────────────────────────────
//
// Values used to be shown with %.6g, which was wrong in two separate ways:
//
//   * it renders 13371337 as "1.33713e+07", which nobody reads as a number;
//   * it keeps only six SIGNIFICANT digits, so what is displayed is not what is
//     in memory — the string above stands for 13371300.
//
// The second one is the dangerous half. That same string seeded the edit field,
// so opening a hit and pressing write without typing anything would store a
// different number than the one that was there. It also made a large value
// impossible to search for a second time, because the magic the user was told
// to look for had been silently rounded when it was first displayed.
//
// Integers are therefore printed as integers, and floats with enough digits to
// round-trip.

static NSString *formatValue(double v, SKMemType t) {
    switch (t) {
        case SKMemTypeInt32:  return [NSString stringWithFormat:@"%d",  (int32_t)v];
        case SKMemTypeInt64:  return [NSString stringWithFormat:@"%lld",(int64_t)v];
        case SKMemTypeFloat:  return [NSString stringWithFormat:@"%.9g", v];
        case SKMemTypeDouble: return [NSString stringWithFormat:@"%.17g", v];
    }
    return [NSString stringWithFormat:@"%g", v];
}

static double decodeValue(const uint8_t *p, SKMemType t) {
    switch (t) {
        case SKMemTypeInt32:  { int32_t v;  memcpy(&v, p, 4); return (double)v; }
        case SKMemTypeInt64:  { int64_t v;  memcpy(&v, p, 8); return (double)v; }
        case SKMemTypeFloat:  { float v;    memcpy(&v, p, 4); return (double)v; }
        case SKMemTypeDouble: { double v;   memcpy(&v, p, 8); return v; }
    }
    return 0;
}

// Accepts a hex address with an optional trailing +N / -N offset.
//
// The offset matters more than it looks: the interesting address is often
// "the hit I just found, plus eight bytes", and doing that addition in your
// head in hex is exactly where mistakes come from. Typing "0x...df8 + 8" is
// harder to get wrong than computing 0x...e00.
static BOOL parseAddress(NSString *text, uint64_t *out) {
    NSCharacterSet *ws = NSCharacterSet.whitespaceCharacterSet;
    NSString *t = [text stringByTrimmingCharactersInSet:ws];
    if (!t.length) return NO;

    int64_t delta = 0;
    NSRange r = [t rangeOfString:@"+" options:NSBackwardsSearch];
    if (r.location == NSNotFound || r.location == 0) {
        r = [t rangeOfString:@"-" options:NSBackwardsSearch];
    }
    if (r.location != NSNotFound && r.location > 0) {
        NSString *sign = [t substringWithRange:NSMakeRange(r.location, 1)];
        NSString *num = [[t substringFromIndex:r.location + 1] stringByTrimmingCharactersInSet:ws];
        delta = (int64_t)strtoll(num.UTF8String, NULL, 0);
        if ([sign isEqualToString:@"-"]) delta = -delta;
        t = [[t substringToIndex:r.location] stringByTrimmingCharactersInSet:ws];
    }

    const char *cs = t.UTF8String;
    if (cs[0] == '0' && (cs[1] == 'x' || cs[1] == 'X')) cs += 2;
    uint64_t base = strtoull(cs, NULL, 16);
    if (base == 0) return NO;

    *out = (uint64_t)((int64_t)base + delta);
    return YES;
}

static BOOL valueMatches(const uint8_t *p, SKMemType t, double want) {
    switch (t) {
        case SKMemTypeInt32: {
            int32_t v; memcpy(&v, p, 4); return (double)v == want;
        }
        case SKMemTypeInt64: {
            int64_t v; memcpy(&v, p, 8); return (double)v == want;
        }
        case SKMemTypeFloat: {
            // Approximate compare: float rarely lands exactly on the typed value.
            float v; memcpy(&v, p, 4);
            float w = (float)want;
            float d = v - w;
            if (d < 0) d = -d;
            float tol = (w < 0 ? -w : w) * 0.0001f + 0.0001f;
            return d <= tol;
        }
        case SKMemTypeDouble: {
            double v; memcpy(&v, p, 8);
            double d = v - want;
            if (d < 0) d = -d;
            double tol = (want < 0 ? -want : want) * 0.0000001 + 0.0000001;
            return d <= tol;
        }
    }
    return NO;
}

- (NSArray<SKMemHit *> *)scanForValue:(double)value
                                 type:(SKMemType)type
                             progress:(void (^)(double))progress {
    // Accumulate into a local array. Writing straight into self.hits while the
    // lock timer is enumerating it is what crashed the app.
    NSMutableArray<SKMemHit *> *found = [NSMutableArray array];

    NSArray<SKMemRegion *> *regs = [self regions];
    NSLog(@"memscan: start type=%ld size=%lu value=%.17g regions=%lu",
          (long)type, (unsigned long)typeSize(type), value, (unsigned long)regs.count);
    uint64_t total = 0;
    for (SKMemRegion *r in regs) total += (r.end - r.start);
    if (total == 0) return @[];

    uint64_t processed = 0;
    NSUInteger esz = typeSize(type);
    NSUInteger consecutiveFailures = 0;
    BOOL scanAborted = NO;

    for (SKMemRegion *r in regs) {
        @autoreleasepool {
            for (uint64_t a = r.start; a + esz <= r.end; a += SKMemChunkBytes) {
                NSUInteger len = (NSUInteger)MIN((uint64_t)SKMemChunkBytes, r.end - a);
                NSData *chunk = [self readAt:a length:len];
                if (!chunk) {
                    // A page we cannot map is normal. A *run* of them means the
                    // primitive or the target's map is in a state we do not
                    // understand — keep hammering it and we corrupt something.
                    // Give up on this region and report it.
                    consecutiveFailures++;
                    if (consecutiveFailures >= SKMemMaxConsecutiveFailures) {
                        NSLog(@"memscan: %lu consecutive page failures at 0x%llx — aborting scan",
                              (unsigned long)consecutiveFailures, (unsigned long long)a);
                        scanAborted = YES;
                        break;
                    }
                    processed += len;
                    continue;
                }
                consecutiveFailures = 0;
                if (chunk) {
                    const uint8_t *bytes = chunk.bytes;
                    NSUInteger n = chunk.length;
                    for (NSUInteger i = 0; i + esz <= n; i += esz) {
                        if (valueMatches(bytes + i, type, value)) {
                            SKMemHit *h = [SKMemHit new];
                            h.address = a + i;
                            h.value = value;
                            [found addObject:h];
                            if (found.count >= 5000) break;
                        }
                    }
                }
                processed += len;
                if (found.count >= 5000) break;
                if (progress) progress((double)processed / (double)total);
            }
        }
        if (found.count >= 5000) break;
        if (scanAborted) break;
    }

    if (scanAborted) {
        NSLog(@"memscan: aborted early — results are partial");
    }
    NSLog(@"memscan: done type=%ld hits=%lu aborted=%d",
          (long)type, (unsigned long)found.count, scanAborted);
    if (progress) progress(1.0);
    [self replaceHits:found];
    return [found copy];
}

- (NSArray<SKMemHit *> *)refineWithValue:(double)value type:(SKMemType)type {
    NSMutableArray *kept = [NSMutableArray array];
    NSUInteger esz = typeSize(type);

    // Snapshot first: the lock timer must not see a half-rebuilt array.
    NSArray<SKMemHit *> *snapshot = [self snapshotHits];
    for (SKMemHit *h in snapshot) {
        NSData *d = [self readAt:h.address length:esz];
        if (!d) continue;
        if (valueMatches(d.bytes, type, value)) {
            h.value = value;
            [kept addObject:h];
        }
    }
    [self replaceHits:kept];
    return [kept copy];
}

- (NSArray<SKMemHit *> *)snapshotHits {
    [self.hitsLock lock];
    NSArray *copy = [self.hits copy];
    [self.hitsLock unlock];
    return copy;
}

- (void)replaceHits:(NSArray<SKMemHit *> *)newHits {
    [self.hitsLock lock];
    self.hits = [newHits mutableCopy] ?: [NSMutableArray array];
    [self.hitsLock unlock];
}

- (NSArray<SKMemHit *> *)currentHits { return [self snapshotHits]; }
- (void)clearHits { [self replaceHits:@[]]; }
- (NSUInteger)cachedRegionCount { return self.cachedRegions.count; }

- (void)applyLocksWithType:(SKMemType)type {
    // Iterate a snapshot so a scan replacing the array cannot invalidate the
    // enumeration mid-loop.
    for (SKMemHit *h in [self snapshotHits]) {
        if (h.locked) [self writeValue:h.value type:type to:h.address];
    }
}

@end

// ═════════════════════════════════════════════════════════════════════════════
#pragma mark - Editor UI
// ═════════════════════════════════════════════════════════════════════════════

@interface SKMemoryEditorViewController () <UITableViewDataSource, UITableViewDelegate, UISearchBarDelegate>
@property (nonatomic, strong) SKMemoryEngine *engine;
@property (nonatomic, copy) NSString *processName;
@property (nonatomic, strong) UISegmentedControl *typeSeg;
@property (nonatomic, strong) UISearchBar *searchBar;
@property (nonatomic, strong) UIProgressView *progress;
@property (nonatomic, strong) UITableView *tableView;
@property (nonatomic, strong) UILabel *status;
@property (nonatomic, strong) NSTimer *lockTimer;
@property (nonatomic, assign) SKMemType type;
// Snapshot backing the table. numberOfRows and cellForRow must see the SAME
// array, otherwise a scan finishing between the two calls makes the row index
// out of range and the app crashes.
@property (nonatomic, strong) NSArray<SKMemHit *> *displayed;
@property (nonatomic, strong) UISegmentedControl *modeSeg;
@end

@implementation SKMemoryEditorViewController

- (instancetype)initWithPID:(pid_t)pid processName:(NSString *)name {
    self = [super init];
    if (self) {
        _engine = [SKMemoryEngine engineForPID:pid];
        _processName = [name copy];
        _type = SKMemTypeInt32;
    }
    return self;
}

- (void)viewDidLoad {
    [super viewDidLoad];
    self.title = self.processName;
    self.view.backgroundColor = UIColor.systemGroupedBackgroundColor;

    if (!self.engine) {
        UILabel *l = [[UILabel alloc] initWithFrame:self.view.bounds];
        l.numberOfLines = 0; l.textAlignment = NSTextAlignmentCenter;
        l.textColor = UIColor.secondaryLabelColor;
        l.text = @"无法附加到该进程\n（内核读写未就绪，或进程已退出）";
        self.view = l;
        return;
    }

    CGFloat w = self.view.bounds.size.width;
    UIView *header = [[UIView alloc] initWithFrame:CGRectMake(0, 0, w, 158)];
    header.backgroundColor = UIColor.systemGroupedBackgroundColor;

    self.typeSeg = [[UISegmentedControl alloc] initWithItems:@[@"i32", @"i64", @"f32", @"f64"]];
    self.typeSeg.selectedSegmentIndex = 0;
    self.typeSeg.frame = CGRectMake(12, 8, (w - 24 - 8) / 2, 32);
    [self.typeSeg addTarget:self action:@selector(typeChanged) forControlEvents:UIControlEventValueChanged];
    [header addSubview:self.typeSeg];

    // Without an explicit mode the old code refined whenever a previous result
    // existed, so searching for a new value silently searched inside a stale
    // set and appeared to find nothing.
    self.modeSeg = [[UISegmentedControl alloc] initWithItems:@[@"搜索", @"筛选"]];
    self.modeSeg.selectedSegmentIndex = 0;
    self.modeSeg.frame = CGRectMake((w - 24 - 8) / 2 + 20, 8, (w - 24 - 8) / 2, 32);
    [header addSubview:self.modeSeg];

    self.searchBar = [[UISearchBar alloc] initWithFrame:CGRectMake(0, 44, w, 50)];
    self.searchBar.delegate = self;
    self.searchBar.placeholder = @"输入数值后点搜索";
    self.searchBar.keyboardType = UIKeyboardTypeNumbersAndPunctuation;
    self.searchBar.searchBarStyle = UISearchBarStyleMinimal;
    [header addSubview:self.searchBar];

    self.progress = [[UIProgressView alloc] initWithFrame:CGRectMake(12, 104, w - 24, 4)];
    self.progress.progress = 0;
    [header addSubview:self.progress];

    self.status = [[UILabel alloc] initWithFrame:CGRectMake(12, 114, w - 24, 34)];
    self.status.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
    self.status.numberOfLines = 2;
    self.status.textColor = UIColor.secondaryLabelColor;
    [header addSubview:self.status];

    self.tableView = [[UITableView alloc] initWithFrame:CGRectZero style:UITableViewStyleInsetGrouped];
    self.tableView.dataSource = self;
    self.tableView.delegate = self;
    self.tableView.rowHeight = 54;
    self.tableView.tableHeaderView = header;
    [self.view addSubview:self.tableView];

    self.navigationItem.leftBarButtonItem =
        [[UIBarButtonItem alloc] initWithTitle:@"转到地址"
                                         style:UIBarButtonItemStylePlain
                                        target:self action:@selector(promptGoToAddress)];

    self.navigationItem.rightBarButtonItem =
        [[UIBarButtonItem alloc] initWithBarButtonSystemItem:UIBarButtonSystemItemRefresh
                                                      target:self action:@selector(clearAll)];

    [self updateStatus];

    // Build the region list once, off the main thread.
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        [self.engine regions];
        dispatch_async(dispatch_get_main_queue(), ^{ [self updateStatus]; });
    });

    // Locked values are re-written periodically so the game cannot overwrite them.
    self.lockTimer = [NSTimer scheduledTimerWithTimeInterval:0.5 repeats:YES block:^(NSTimer *t) {
        [self.engine applyLocksWithType:self.type];
    }];
}

- (void)viewDidLayoutSubviews {
    [super viewDidLayoutSubviews];
    self.tableView.frame = self.view.bounds;
}

- (void)dealloc { [self.lockTimer invalidate]; }

- (void)typeChanged {
    self.type = (SKMemType)self.typeSeg.selectedSegmentIndex;
    [self updateStatus];
}

- (void)updateStatus {
    NSUInteger n = self.displayed.count;
    self.status.text = [NSString stringWithFormat:@"pid %d  ·  %lu 个结果\n区域 %lu 个（扫描有上限）",
                        self.engine.pid, (unsigned long)n,
                        (unsigned long)self.engine.cachedRegionCount];
}

- (void)clearAll {
    [self.engine clearHits];
    [self reloadTable];
}

// ── search ─────────────────────────────────────────────────────────────────
- (void)searchBarSearchButtonClicked:(UISearchBar *)sb {
    [sb resignFirstResponder];
    NSString *text = sb.text;
    if (!text.length) return;

    double v = text.doubleValue;
    SKMemType t = self.type;
    // Mode is explicit: segment 0 = fresh scan, 1 = narrow the previous hits.
    BOOL refining = (self.modeSeg.selectedSegmentIndex == 1) && self.engine.currentHits.count > 0;

    self.progress.progress = 0;
    self.status.text = refining ? @"筛选中…" : @"搜索中…";

    __weak typeof(self) weakSelf = self;
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        NSArray *hits;
        if (refining) {
            hits = [weakSelf.engine refineWithValue:v type:t];
        } else {
            hits = [weakSelf.engine scanForValue:v type:t progress:^(double p) {
                dispatch_async(dispatch_get_main_queue(), ^{
                    weakSelf.progress.progress = (float)p;
                });
            }];
        }
        dispatch_async(dispatch_get_main_queue(), ^{
            weakSelf.progress.progress = 1.0;
            [weakSelf reloadTable];
        });
    });
}

- (void)searchBar:(UISearchBar *)sb textDidChange:(NSString *)t { /* search on submit */ }

// ── table ──────────────────────────────────────────────────────────────────
- (void)reloadTable {
    self.displayed = [self.engine currentHits] ?: @[];
    [self.tableView reloadData];
    [self updateStatus];
}

- (NSInteger)tableView:(UITableView *)tv numberOfRowsInSection:(NSInteger)s {
    return self.displayed.count;
}

- (UITableViewCell *)tableView:(UITableView *)tv cellForRowAtIndexPath:(NSIndexPath *)ip {
    static NSString *cid = @"hit";
    UITableViewCell *c = [tv dequeueReusableCellWithIdentifier:cid];
    if (!c) c = [[UITableViewCell alloc] initWithStyle:UITableViewCellStyleSubtitle reuseIdentifier:cid];

    SKMemHit *h = self.displayed[ip.row];
    c.textLabel.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightMedium];
    c.textLabel.text = [NSString stringWithFormat:@"0x%llx", (unsigned long long)h.address];
    c.detailTextLabel.font = [UIFont monospacedSystemFontOfSize:11 weight:UIFontWeightRegular];
    c.detailTextLabel.textColor = UIColor.secondaryLabelColor;
    c.detailTextLabel.text = formatValue(h.value, self.type);
    c.accessoryType = UITableViewCellAccessoryDisclosureIndicator;
    return c;
}

- (void)tableView:(UITableView *)tv didSelectRowAtIndexPath:(NSIndexPath *)ip {
    [tv deselectRowAtIndexPath:ip animated:YES];
    SKMemHit *h = self.displayed[ip.row];

    UIAlertController *sheet = [UIAlertController
        alertControllerWithTitle:[NSString stringWithFormat:@"0x%llx", (unsigned long long)h.address]
                         message:[NSString stringWithFormat:@"当前值 %@", formatValue(h.value, self.type)]
                  preferredStyle:UIAlertControllerStyleActionSheet];

    __weak typeof(self) weakSelf = self;

    [sheet addAction:[UIAlertAction actionWithTitle:@"修改数值" style:UIAlertActionStyleDefault
        handler:^(UIAlertAction *a) { [weakSelf promptEdit:h]; }]];

    [sheet addAction:[UIAlertAction actionWithTitle:(h.locked ? @"取消锁定" : @"锁定数值")
        style:UIAlertActionStyleDefault
        handler:^(UIAlertAction *a) {
        h.locked = !h.locked;
        [weakSelf reloadTable];
    }]];

    [sheet addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    sheet.popoverPresentationController.sourceView = tv;
    sheet.popoverPresentationController.sourceRect = [tv rectForRowAtIndexPath:ip];
    [self presentViewController:sheet animated:YES completion:nil];
}

- (void)promptEdit:(SKMemHit *)h {
    UIAlertController *al = [UIAlertController alertControllerWithTitle:@"修改数值"
                                                                message:nil
                                                         preferredStyle:UIAlertControllerStyleAlert];
    SKMemType t = self.type;
    [al addTextFieldWithConfigurationHandler:^(UITextField *tf) {
        tf.keyboardType = UIKeyboardTypeNumbersAndPunctuation;
        tf.text = formatValue(h.value, t);
    }];
    __weak typeof(self) weakSelf = self;
    [al addAction:[UIAlertAction actionWithTitle:@"写入" style:UIAlertActionStyleDefault
        handler:^(UIAlertAction *a) {
        double v = al.textFields.firstObject.text.doubleValue;
        BOOL ok = [weakSelf.engine writeValue:v type:weakSelf.type to:h.address];
        if (ok) h.value = v;
        [weakSelf reloadTable];
    }]];
    [al addAction:[UIAlertAction actionWithTitle:@"取消" style:UIAlertActionStyleCancel handler:nil]];
    [self presentViewController:al animated:YES completion:nil];
}

// ── go to address ──────────────────────────────────────────────────────────
//
// Searching lands you at the right neighbourhood; this is how you land on the
// right byte. It accepts plain hex, 0x-prefixed hex, and a trailing +N / -N
// offset, because the address worth visiting is usually "the hit I just found,
// plus eight".
- (void)promptGoToAddress {
    UIAlertController *al = [UIAlertController
        alertControllerWithTitle:@"转到地址"
                         message:@"十六进制。可以带偏移，例如  0x10000cdf8 + 8"
                  preferredStyle:UIAlertControllerStyleAlert];

    [al addTextFieldWithConfigurationHandler:^(UITextField *tf) {
        tf.placeholder = @"0x10000cdf8 + 8";
        tf.autocapitalizationType = UITextAutocapitalizationTypeNone;
        tf.autocorrectionType = UITextAutocorrectionTypeNo;
        tf.spellCheckingType = UITextSpellCheckingTypeNo;
        tf.keyboardType = UIKeyboardTypeASCIICapable;
        tf.font = [UIFont monospacedSystemFontOfSize:15 weight:UIFontWeightRegular];
    }];

    [al addAction:[UIAlertAction actionWithTitle:@"取消"
                                           style:UIAlertActionStyleCancel handler:nil]];
    __weak typeof(self) ws = self;
    [al addAction:[UIAlertAction actionWithTitle:@"查看" style:UIAlertActionStyleDefault
        handler:^(UIAlertAction *a) {
        uint64_t addr = 0;
        if (!parseAddress(al.textFields.firstObject.text, &addr)) {
            [ws showSimple:@"地址无法解析" body:@"用十六进制写，例如 0x10000cdf8 或 0x10000cdf8 + 8"];
            return;
        }
        [ws showAddress:addr];
    }]];

    [self presentViewController:al animated:YES completion:nil];
}

- (void)showAddress:(uint64_t)addr {
    NSUInteger len = typeSize(self.type);
    NSData *d = [self.engine readAt:addr length:len];

    if (!d || d.length < len) {
        [self showSimple:@"读不出来" body:[NSString stringWithFormat:
            @"0x%llx 处没有可读内存。地址写对了吗？进程还在吗？",
            (unsigned long long)addr]];
        return;
    }

    double v = decodeValue((const uint8_t *)d.bytes, self.type);

    UIAlertController *sheet = [UIAlertController
        alertControllerWithTitle:[NSString stringWithFormat:@"0x%llx",
                                  (unsigned long long)addr]
                         message:[NSString stringWithFormat:
                                  @"类型 %@\n值 %@\n字节 %@",
                                  @[@"i32", @"i64", @"f32", @"f64"][(NSUInteger)self.type],
                                  formatValue(v, self.type),
                                  [self hexOf:d]]
                  preferredStyle:UIAlertControllerStyleActionSheet];

    __weak typeof(self) ws = self;
    [sheet addAction:[UIAlertAction actionWithTitle:@"修改数值"
                                              style:UIAlertActionStyleDefault
                                            handler:^(UIAlertAction *a) {
        [ws promptWriteTo:addr current:v];
    }]];
    [sheet addAction:[UIAlertAction actionWithTitle:@"取消"
                                              style:UIAlertActionStyleCancel handler:nil]];

    sheet.popoverPresentationController.sourceView = self.view;
    sheet.popoverPresentationController.sourceRect = self.view.bounds;
    [self presentViewController:sheet animated:YES completion:nil];
}

- (void)promptWriteTo:(uint64_t)addr current:(double)v {
    UIAlertController *al = [UIAlertController alertControllerWithTitle:@"写入数值"
                                                                message:[NSString stringWithFormat:
                                                                         @"0x%llx", (unsigned long long)addr]
                                                         preferredStyle:UIAlertControllerStyleAlert];
    SKMemType t = self.type;
    [al addTextFieldWithConfigurationHandler:^(UITextField *tf) {
        tf.keyboardType = UIKeyboardTypeNumbersAndPunctuation;
        tf.text = formatValue(v, t);
    }];
    __weak typeof(self) ws = self;
    [al addAction:[UIAlertAction actionWithTitle:@"写入"
                                           style:UIAlertActionStyleDefault
                                         handler:^(UIAlertAction *a) {
        double nv = al.textFields.firstObject.text.doubleValue;
        BOOL ok = [ws.engine writeValue:nv type:t to:addr];
        [ws showSimple:(ok ? @"已写入" : @"写入失败")
                  body:[NSString stringWithFormat:@"0x%llx = %@",
                        (unsigned long long)addr, formatValue(nv, t)]];
    }]];
    [al addAction:[UIAlertAction actionWithTitle:@"取消"
                                           style:UIAlertActionStyleCancel handler:nil]];
    [self presentViewController:al animated:YES completion:nil];
}

- (NSString *)hexOf:(NSData *)d {
    const uint8_t *p = d.bytes;
    NSMutableString *m = [NSMutableString string];
    for (NSUInteger i = 0; i < d.length; i++) {
        if (i) [m appendString:@" "];
        [m appendFormat:@"%02x", p[i]];
    }
    return m;
}

- (void)showSimple:(NSString *)title body:(NSString *)body {
    UIAlertController *a = [UIAlertController alertControllerWithTitle:title
                                                               message:body
                                                        preferredStyle:UIAlertControllerStyleAlert];
    [a addAction:[UIAlertAction actionWithTitle:@"OK" style:UIAlertActionStyleDefault handler:nil]];
    [self presentViewController:a animated:YES completion:nil];
}

@end
