//
//  WriteAccessRepair.swift
//  AppDump
//
//  「修复写权限」：沙盒逃逸改的是内核里这份进程的 sandbox 标签，内核会按
//  磁盘上的 profile 重新推导策略，写权限可能悄悄消失。重新跑一遍漏洞利用
//  能恢复，但风险没必要——只要再把一次 sbx_escape() 的策略写回去就行。
//
//  判定方式不是 open()（读权限可能在写权限消失后仍然存在），而是真的在系统
//  受保护目录里创建、写入、删除一个文件。必须用受保护目录，自己的容器本来
//  就可写，测不出任何东西。
//

import Foundation

enum WriteAccessRepair {
    /// 系统受保护位置，故意不用本 App 容器。
    static let probeDir = "/private/var/mobile/Library/Preferences"
    static let probeFile = "/private/var/mobile/Library/Preferences/.appdump_alive"

    /// 创建 + 写入 + 删除一个探测文件，真正验证写权限。
    static func hasWriteAccess() -> Bool {
        let marker: [UInt8] = Array("alive\n".utf8)
        let fd = open(probeFile, O_WRONLY | O_CREAT | O_TRUNC, 0o600)
        if fd < 0 { return false }
        let n = marker.withUnsafeBytes { write(fd, $0.baseAddress, $0.count) }
        close(fd)
        unlink(probeFile)
        return n == marker.count
    }

    struct Result {
        var before: Bool
        var after: Bool
        var escapeReturn: Int32
    }

    /// 探测 → 需要时重放沙盒策略 → 再探测。同步执行，必须放在后台线程。
    static func ensure() -> Result {
        let before = hasWriteAccess()
        if before {
            return Result(before: true, after: true, escapeReturn: 0)
        }
        guard ds_is_ready() else {
            return Result(before: false, after: false, escapeReturn: -1)
        }

        // sbx_escape 内部要读写内核内存，不能和砸壳 / 内存扫描并发。
        AppDumpKernelLockAcquire()
        let rc = sbx_escape(ds_get_our_proc())
        AppDumpKernelLockRelease()

        let after = hasWriteAccess()
        return Result(before: before, after: after, escapeReturn: rc)
    }
}