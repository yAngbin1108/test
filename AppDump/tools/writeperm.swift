//
//  writeperm.swift
//  AppDump
//
//  修复写权限：把容器内文件的属主在内核里改写成 501:501(mobile)。
//
//  为什么需要它
//  ------------
//  沙盒逃逸只解除 MAC(sandbox) 限制；/var/containers/... 下的文件还要过普通
//  UNIX 属主/权限检查。.app 包里的文件所有者通常不是本进程的 uid，于是即使
//  已有完整读写沙盒扩展，open(O_WRONLY) 仍然 EACCES。
//
//  做法与 FilzaJailedDS 一致：沿 vnode -> v_data -> apfs_fsnode 在内核里
//  改写 uid/gid。apfs_fsnode 位于普通可写 zone，内核写原语够得到它
//  （proc_ro/ucred 则是页表保护的，根本写不进去）。
//
//  重要限制：这只让文件可写，不会让改过的可执行文件可加载 ——
//  改 .app 里的 Mach-O 会破坏签名，AMFI 会拒绝。改数据文件/资源/plist 是安全的。
//

import Foundation

enum WritePerm {
    /// 本进程的 uid/gid（mobile）
    static let targetUID: uid_t = 501
    static let targetGID: gid_t = 501

    private static let maxEntries = 200_000
    private static let maxDepth = 48

    /// 签名相关目录必须跳过：改属主没有意义，动内容会破坏签名/FairPlay。
    private static func shouldSkip(_ name: String) -> Bool {
        name == "_CodeSignature" || name == "SC_Info"
    }

    /// 找出「属主修复应该作用在哪个根」：
    ///   /private/var/containers/Bundle/Application/<UUID>/Foo.app[/...] -> 该 .app
    ///   /private/var/mobile/Containers/Data/Application/<UUID>[/...]    -> 该数据容器
    /// 不在容器里则返回 nil（不需要修）。
    static func ownershipRoot(for path: String) -> String? {
        guard !path.isEmpty else { return nil }
        let bundlePrefix = "/private/var/containers/Bundle/Application/"
        let bundlePrefixAlt = "/var/containers/Bundle/Application/"
        let dataPrefix = "/private/var/mobile/Containers/Data/Application/"
        let dataPrefixAlt = "/var/mobile/Containers/Data/Application/"

        if path.hasPrefix(bundlePrefix) || path.hasPrefix(bundlePrefixAlt) {
            let comps = (path as NSString).pathComponents
            for (i, c) in comps.enumerated() where c.hasSuffix(".app") {
                return NSString.path(withComponents: Array(comps.prefix(i + 1)))
            }
            return nil
        }
        if path.hasPrefix(dataPrefix) || path.hasPrefix(dataPrefixAlt) {
            let comps = (path as NSString).pathComponents
            // "/" var mobile Containers Data Application <UUID> == 7 段
            if comps.count >= 7 {
                return NSString.path(withComponents: Array(comps.prefix(7)))
            }
            return nil
        }
        return nil
    }

    /// 递归把 root 的属主在内核里改成 501:501。
    /// - Returns: (成功数, 失败数)
    @discardableResult
    static func chownTree(_ root: String, onProgress: ((Int) -> Void)? = nil) -> (ok: Int, fail: Int) {
        var ok = 0, fail = 0, visited = 0
        walk(root, depth: 0, ok: &ok, fail: &fail, visited: &visited, onProgress: onProgress)
        return (ok, fail)
    }

    private static func walk(_ path: String, depth: Int,
                             ok: inout Int, fail: inout Int, visited: inout Int,
                             onProgress: ((Int) -> Void)?) {
        if depth > maxDepth || visited > maxEntries { return }
        visited += 1

        let fm = FileManager.default
        var isDir: ObjCBool = false
        guard fm.fileExists(atPath: path, isDirectory: &isDir) else { return }

        // 已经是我们的就跳过（省一次内核写）
        var st = stat()
        let ours = stat(path, &st) == 0 && st.st_uid == targetUID

        if !ours {
            let rc = path.withCString { apfs_own($0, targetUID, targetGID) }
            if rc == 0 { ok += 1 } else { fail += 1 }
        } else {
            ok += 1
        }
        onProgress?(visited)

        guard isDir.boolValue else { return }
        let children = (try? fm.contentsOfDirectory(atPath: path)) ?? []
        for name in children where !shouldSkip(name) {
            walk(path + "/" + name, depth: depth + 1,
                 ok: &ok, fail: &fail, visited: &visited, onProgress: onProgress)
        }
    }
}
