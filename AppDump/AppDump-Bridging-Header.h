//
//  AppDump-Bridging-Header.h
//  AppDump
//

@import UIKit;
#import <Foundation/Foundation.h>

#import "darksword.h"
#import "offsets.h"
#import "utils.h"
#import "vnode.h"
#import "apfs.h"
#import "vfs.h"
#import "sbx.h"
#import "decrypt.h"
#import "kcdowngrade.h"
#import "kcblock.h"
#import "AppDumpKernelLock.h"
#import "MemoryEditor.h"

#import <zlib.h>

long findcachedataoff(const char *mgkey);

@interface UIDevice(Private)
+ (BOOL)_hasHomeButton;
@end
