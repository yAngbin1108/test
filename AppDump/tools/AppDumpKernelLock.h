//
//  AppDumpKernelLock.h
//  AppDump — 串行化对内核读写原语的访问
//
//  漏洞利用的 kread/kwrite 和 vm 层不是线程安全的：vmmapremotepage() 会新建
//  memory entry、改写 vm_map entry、并给目标 vm_object 加引用计数，这些操作
//  并发执行会破坏内核状态（表现为 panic）。砸壳、内存扫描、结束进程、沙盒
//  策略重放都会用到原语，所以它们必须持有同一把锁。
//

#ifndef AppDumpKernelLock_h
#define AppDumpKernelLock_h

#import <Foundation/Foundation.h>

/*
 * 必须是递归锁。
 *
 * 属主修复会在持锁状态下遍历目录；遍历过程中若又走回需要内核原语的路径
 * （沙盒策略重放、另一层属主修复），同一线程会再次申请同一把锁。非递归锁
 * 在这里就是自锁死：主线程永久阻塞，被看门狗杀掉，表现就是「闪退」。
 * NSRecursiveLock 在同一线程重入时直接通过，互斥语义不变。
 */
static inline NSRecursiveLock *AppDumpKernelLock(void) {
    static NSRecursiveLock *lock;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ lock = [[NSRecursiveLock alloc] init]; });
    return lock;
}

/// 给 Swift 用的包装（static inline 函数不保证能被 Swift 导入）。
void AppDumpKernelLockAcquire(void);
void AppDumpKernelLockRelease(void);

#endif /* AppDumpKernelLock_h */