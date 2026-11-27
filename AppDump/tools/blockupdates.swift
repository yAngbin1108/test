//
//  blockupdates.swift
//  AppDump
//
//  阻止 App Store 更新（UI 与状态管理层）。
//
//  真正的"阻止"动作由 kexploit/kcblock.m 在 installd 进程内完成：
//  在 .app 的父目录下建立名为 com.apple.mobileinstallation.placeholder
//  的目录并把权限设为 0000，安装服务看到后就会跳过该应用的更新。
//
//  这里只负责：
//    • 把 bundleID 换算成 placeholder 完整路径
//    • 判断当前是否已被阻止（目录是否存在）
//    • 调用 kcb_apply 并汇报结果
//

import Foundation

enum blockupdates {

    /// placeholder 目录名
    static let placeholderName = "com.apple.mobileinstallation.placeholder"

    private static func log(_ m: String) { AppDumpmgr.shared.logmsg("(block) \(m)") }

    // MARK: - 状态

    private static let defaultsKey = "AppDump.blockedUpdates"

    /// 已知被阻止的 bundleID（用于 UI 徽章）
    static func blockedList() -> [String] {
        (UserDefaults.standard.array(forKey: defaultsKey) as? [String]) ?? []
    }

    private static func setBlocked(_ list: [String]) {
        UserDefaults.standard.set(list, forKey: defaultsKey)
    }

    // MARK: - 路径换算

    /// .app 的父目录 —— placeholder 就建在这一层
    private static func placeholderPath(forBundlePath bundlePath: String) -> String? {
        guard !bundlePath.isEmpty else { return nil }
        let parent = (bundlePath as NSString).deletingLastPathComponent
        guard !parent.isEmpty else { return nil }
        return parent + "/" + placeholderName
    }

    private static func bundlePath(for bundleid: String) -> String? {
        vfsfs.listappbundles().first { $0.bundleid == bundleid }?.path
    }

    /// 该应用当前是否已被阻止（placeholder 目录存在）
    static func isBlocked(bundleid: String) -> Bool {
        guard let bp = bundlePath(for: bundleid),
              let ph = placeholderPath(forBundlePath: bp) else { return false }
        if FileManager.default.fileExists(atPath: ph) { return true }
        // VFS 兜底（沙盒未逃逸时）
        if AppDumpmgr.shared.vfsready,
           AppDumpmgr.shared.vfslistdir(path: ph) != nil { return true }
        return false
    }

    // MARK: - 执行

    static func block(_ bundleids: [String]) -> (ok: [String], failed: [String], message: String) {
        run(bundleids, block: true)
    }

    static func unblock(_ bundleids: [String]) -> (ok: [String], failed: [String], message: String) {
        run(bundleids, block: false)
    }

    private static func run(_ bundleids: [String], block: Bool) -> (ok: [String], failed: [String], message: String) {
        guard AppDumpmgr.shared.sbxready || AppDumpmgr.shared.vfsready else {
            return ([], bundleids, "请先初始化系统（需要沙盒逃逸读取应用目录）")
        }
        guard AppDumpmgr.shared.dsready else {
            return ([], bundleids, "内核读写未就绪，请先运行漏洞利用")
        }

        var paths: [String] = []
        var resolved: [String] = []
        var failed: [String] = []
        var detail: [String] = []

        for bid in bundleids {
            guard let bp = bundlePath(for: bid),
                  let ph = placeholderPath(forBundlePath: bp) else {
                failed.append(bid)
                detail.append("\(bid)：找不到应用目录")
                continue
            }
            paths.append(ph)
            resolved.append(bid)
        }

        guard !paths.isEmpty else {
            return ([], failed, "没有可处理的路径\n" + detail.prefix(4).joined(separator: "\n"))
        }

        log("开始 \(block ? "阻止" : "恢复") \(paths.count) 项")
        let rc = kcb_apply(paths, block, nil)

        switch rc {
        case 0:
            updateState(resolved, blocked: block)
            return (resolved, failed, block
                    ? "已阻止 \(resolved.count) 个应用的更新"
                    : "已恢复 \(resolved.count) 个应用的更新")

        case 1:
            return ([], bundleids, "内核原语未就绪")

        case 2:
            return ([], bundleids,
                    "无法附着 installd。\n\n请到 App Store 点任意 App 的「获取」把它唤醒，然后回来重试。")

        default:
            // 部分失败：仍更新状态，但提示
            updateState(resolved, blocked: block)
            return (resolved, failed,
                    "完成 \(resolved.count) 项，部分失败。\n详见日志 (block) 开头的记录。")
        }
    }

    private static func updateState(_ ids: [String], blocked: Bool) {
        var set = Set(blockedList())
        for b in ids {
            if blocked { set.insert(b) } else { set.remove(b) }
        }
        setBlocked(Array(set))
    }
}
