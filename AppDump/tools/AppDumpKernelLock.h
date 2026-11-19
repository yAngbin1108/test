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

static inline NSLock *AppDumpKernelLock(void) {
    static NSLock *lock;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ lock = [[NSLock alloc] init]; });
    return lock;
}

/// 给 Swift 用的包装（static inline 函数不保证能被 Swift 导入）。
void AppDumpKernelLockAcquire(void);
void AppDumpKernelLockRelease(void);

#endif /* AppDumpKernelLock_h */