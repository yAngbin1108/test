//
//  AppDumpKernelLock.m
//  AppDump
//

#import "AppDumpKernelLock.h"

void AppDumpKernelLockAcquire(void) {
    [AppDumpKernelLock() lock];
}

void AppDumpKernelLockRelease(void) {
    [AppDumpKernelLock() unlock];
}