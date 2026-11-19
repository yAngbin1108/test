//
//  SKMemoryEditor.h
//  SandboxKit — in-process memory search / edit / lock
//
//  HOW IT READS AND WRITES ANOTHER PROCESS
//  ---------------------------------------
//  task_for_pid() is not available to us, but it is not needed: we hold kernel
//  R/W. kexploit's vm layer exposes vmmapremotepage(), which takes the target's
//  vm_map and an address and re-binds a freshly created memory entry onto the
//  target's vm_object. The entry is made with VM_PROT_READ | VM_PROT_WRITE, so
//  the returned mapping aliases the target's physical pages: reading from it
//  reads the process, and *writing to it writes the process*. There is no
//  copy-on-write, so an edit is a real edit.
//
//  The per-call cost is proportional to the backing object, so scans are
//  deliberately bounded (see SKMemScanBudget).
//

#import <UIKit/UIKit.h>
#include <sys/types.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, SKMemType) {
    SKMemTypeInt32 = 0,
    SKMemTypeInt64,
    SKMemTypeFloat,
    SKMemTypeDouble,
};

@interface SKMemRegion : NSObject
@property (nonatomic, assign) uint64_t start;
@property (nonatomic, assign) uint64_t end;
@end

@interface SKMemHit : NSObject
@property (nonatomic, assign) uint64_t address;
@property (nonatomic, assign) double value;      // widened; see type
@property (nonatomic, assign) BOOL locked;
@end

@interface SKMemoryEngine : NSObject

/// Attach to a pid. Returns nil when the process or its vm_map cannot be found.
+ (nullable instancetype)engineForPID:(pid_t)pid;

@property (nonatomic, readonly) pid_t pid;
@property (nonatomic, readonly) uint64_t vmMap;

/// Readable, non-kernel regions, largest first. Bounded by the budget below.
- (NSArray<SKMemRegion *> *)regions;

/// Scan every region for `value` of `type`. Calls `progress` with 0..1.
/// Sets the internal candidate set, which `refineWithValue:` narrows.
- (NSArray<SKMemHit *> *)scanForValue:(double)value
                                 type:(SKMemType)type
                             progress:(void (^ _Nullable)(double))progress;

/// Narrow the previous result set to entries that still hold `value`.
- (NSArray<SKMemHit *> *)refineWithValue:(double)value type:(SKMemType)type;

- (NSArray<SKMemHit *> *)currentHits;
- (void)clearHits;

/// Number of regions already enumerated. Does NOT build the list (building it
/// walks the target vm_map under the kernel lock, so it must stay off the main
/// thread).
- (NSUInteger)cachedRegionCount;

/// Read / write raw bytes. Both go through the aliasing mapping.
- (nullable NSData *)readAt:(uint64_t)address length:(NSUInteger)length;
- (BOOL)writeData:(NSData *)data to:(uint64_t)address;
- (BOOL)writeValue:(double)value type:(SKMemType)type to:(uint64_t)address;

/// Re-write all locked hits. Called on a timer by the editor.
- (void)applyLocksWithType:(SKMemType)type;

@end

// ─────────────────────────────────────────────────────────────────────────────
/// Search / edit / lock UI for one process.
@interface SKMemoryEditorViewController : UIViewController
- (instancetype)initWithPID:(pid_t)pid processName:(NSString *)name;
@end

NS_ASSUME_NONNULL_END
