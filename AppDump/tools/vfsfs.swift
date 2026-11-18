//
//  vfsfs.swift
//  AppDump
//
//  WHY THIS FILE EXISTS
//  --------------------
//  你的日志里沙箱逃逸(patch ext_set 那条路)是失败的:
//
//      (sbx) patched 5 extensions
//      (sbx) changed 14 extension classes
//      (sbx) filled 0 empty hash slots
//      (sbx) sandbox escape verification failed (errno=1: Operation not permitted)
//      sandbox escape failed.
//
//  同一份日志里这两条是成功的:
//
//      (ds) exploit success!   /  (ds) kernel r/w is ready!
//      (vfs) file overwrite ready!  /  vfs ready!
//
//  也就是说:**内核读写能用,VFS(内核级文件读写)能用,只有沙箱逃逸不能用。**
//  而原来代码里凡是碰系统文件的地方几乎都走普通 POSIX(FileManager / open()),
//  那些是要过沙箱的,所以全挂:
//
//    * getbmhash()  enumerates /private/preboot   -> 拿不到 boot manifest hash
//                   -> syskcpath() 返回 nil -> fetchkcache() 失败  ("无法获取内核缓存")
//    * loadApps() / getAppList() 列 /private/var/... -> 应用列表空  ("无法初始化系统"之后全废)
//    * 提取/砸壳时拷 bundle 也是 FileManager      -> 拷不动
//
//  修法:把「读系统目录 / 读系统文件」全部改走 VFS。VFS 是内核级的,不过沙箱,
//  这条路在同一台设备上已经证明可用。沙箱逃逸从此只是加速项,不再是必需项。
//

import Foundation
import UIKit

enum vfsfs {

    private static func log(_ m: String) { AppDumpmgr.shared.logmsg("(vfsfs) \(m)") }

    // MARK: - 读

    /// 用 VFS 读一个 plist（不需要沙箱逃逸）
    static func readdict(_ path: String, maxSize: Int = 8 * 1024 * 1024) -> NSDictionary? {
        guard AppDumpmgr.shared.vfsready else { return nil }
        guard let data = AppDumpmgr.shared.vfsread(path: path, maxSize: maxSize), !data.isEmpty else { return nil }
        return (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) as? NSDictionary
    }

    static func readexists(_ path: String) -> Bool {
        guard AppDumpmgr.shared.vfsready else { return false }
        return AppDumpmgr.shared.vfssize(path: path) > 0
    }

    // MARK: - Mach-O cryptid（为了不走 POSIX 也能判断有没有加密）

    private static func u32le(_ d: Data, _ o: Int) -> UInt32? {
        guard o >= 0, o + 4 <= d.count else { return nil }
        let b = [UInt8](d[o..<(o + 4)])
        return UInt32(b[0]) | (UInt32(b[1]) << 8) | (UInt32(b[2]) << 16) | (UInt32(b[3]) << 24)
    }
    private static func u32be(_ d: Data, _ o: Int) -> UInt32? {
        guard o >= 0, o + 4 <= d.count else { return nil }
        let b = [UInt8](d[o..<(o + 4)])
        return (UInt32(b[0]) << 24) | (UInt32(b[1]) << 16) | (UInt32(b[2]) << 8) | UInt32(b[3])
    }

    /// 从 Mach-O 头部数据里读 cryptid。
    ///   >0 = 有 FairPlay 加密（需要砸壳）
    ///    0 = 未加密（自签/侧载，直接提取即可）
    ///   -1 = 解析不出来
    static func cryptid(_ data: Data) -> Int {
        guard let magic = u32le(data, 0) else { return -1 }
        // FAT_MAGIC / FAT_CIGAM：找一个 arm64 slice 再看
        if magic == 0xcafebabe || magic == 0xbebafeca {
            guard let narch = u32be(data, 4) else { return -1 }
            for i in 0..<Int(min(narch, 16)) {
                let base = 8 + i * 20
                guard let cputype = u32be(data, base), let off = u32be(data, base + 8) else { break }
                if cputype == 0x0100000C {   // CPU_TYPE_ARM64
                    let o = Int(off)
                    guard o > 0, o < data.count else { return -1 }
                    return cryptid(data.subdata(in: o..<data.count))
                }
            }
            return -1
        }
        let is64 = (magic == 0xfeedfacf)     // MH_MAGIC_64
        let is32 = (magic == 0xfeedface)     // MH_MAGIC
        guard is64 || is32 else { return -1 }
        guard let ncmds = u32le(data, 16) else { return -1 }
        var off = is64 ? 32 : 28
        for _ in 0..<Int(min(ncmds, 4096)) {
            guard let cmd = u32le(data, off), let cmdsize = u32le(data, off + 4) else { break }
            // LC_ENCRYPTION_INFO_64 = 0x2C, LC_ENCRYPTION_INFO = 0x21
            if cmd == 0x2C || cmd == 0x21 {
                guard let cid = u32le(data, off + 12) else { return -1 }
                return Int(cid)
            }
            if cmdsize == 0 { break }
            off += Int(cmdsize)
        }
        return -1
    }

    // MARK: - 应用列表

    struct bundleapp {
        let bundleid: String
        let name: String
        let executable: String
        let path: String
        let icon: UIImage?
    }

    private static func loadicon(appdir: String, info: NSDictionary) -> UIImage? {
        var names: [String] = []
        if let icons = info["CFBundleIcons"] as? [String: Any],
           let primary = icons["CFBundlePrimaryIcon"] as? [String: Any],
           let files = primary["CFBundleIconFiles"] as? [String] {
            names = files
        }
        if names.isEmpty, let files = info["CFBundleIconFiles"] as? [String] {
            names = files
        }
        for base in names.reversed() {
            for suffix in ["@3x.png", "@2x.png", ".png", ""] {
                let p = appdir + "/" + base + suffix
                if let data = AppDumpmgr.shared.vfsread(path: p, maxSize: 4 * 1024 * 1024),
                   let img = UIImage(data: data) {
                    return img
                }
            }
        }
        return nil
    }

    /// 列出 /private/var/containers/Bundle/Application 下的全部 .app
    static func listappbundles() -> [bundleapp] {
        guard AppDumpmgr.shared.vfsready else { return [] }
        let root = "/private/var/containers/Bundle/Application"
        guard let containers = AppDumpmgr.shared.vfslistdir(path: root) else {
            log("listdir failed: \(root)")
            return []
        }

        var out: [bundleapp] = []
        for c in containers where c.isDir {
            let cpath = root + "/" + c.name
            guard let contents = AppDumpmgr.shared.vfslistdir(path: cpath) else { continue }
            for item in contents where item.name.hasSuffix(".app") {
                let appdir = cpath + "/" + item.name
                guard let info = readdict(appdir + "/Info.plist") else { continue }
                let ex = info["CFBundleExecutable"] as? String ?? ""
                if ex.isEmpty { continue }
                let bid = info["CFBundleIdentifier"] as? String ?? ""
                let name = (info["CFBundleDisplayName"] as? String)
                    ?? (info["CFBundleName"] as? String)
                    ?? (item.name as NSString).deletingPathExtension
                out.append(bundleapp(bundleid: bid, name: name, executable: ex,
                                     path: appdir, icon: loadicon(appdir: appdir, info: info)))
                break
            }
        }
        log("listed \(out.count) app bundles via VFS")
        return out
    }

    /// 列目录：优先 VFS（内核级、不过沙盒）；VFS 未就绪但已逃逸时退回 FileManager。
    /// 列目录：VFS（内核级、不过沙盒）与 FileManager 双通道，任一成功即返回。
    ///
    /// 注意不能写成「vfsready 就直接 return VFS 结果」：本 App 的 VFS 只能列出
    /// 已经进 namecache 的目录，`/private/var/mobile/...`、`/private/var/containers/...`
    /// 这类从未被访问过的路径 resolvepath 会失败（日志 'mobile'/'containers' not in
    /// ncache），此时即使 vfsready == true 也必须回退到 FileManager —— 沙盒逃逸
    /// 成功后那条路是通的。
    private static func listdir(_ path: String) -> [(name: String, isDir: Bool)]? {
        if AppDumpmgr.shared.vfsready, let via = AppDumpmgr.shared.vfslistdir(path: path) {
            return via
        }
        guard AppDumpmgr.shared.sbxready || AppDumpmgr.shared.vfsready else { return nil }

        // 回退一：FileManager 直接列（需要沙盒逃逸已生效）
        if let names = try? FileManager.default.contentsOfDirectory(atPath: path) {
            var out: [(name: String, isDir: Bool)] = []
            out.reserveCapacity(names.count)
            for n in names {
                var isDir: ObjCBool = false
                _ = FileManager.default.fileExists(atPath: path + "/" + n, isDirectory: &isDir)
                out.append((n, isDir.boolValue))
            }
            return out
        }

        // 回退二：先让内核把这条路径读进 namecache，再重试 VFS 列表
        if AppDumpmgr.shared.vfsready, warmnamecache(path),
           let again = AppDumpmgr.shared.vfslistdir(path: path) {
            return again
        }
        return nil
    }

    /// 用一次内核 stat 触发 VFS 的路径解析，使目标目录及其父链进入 namecache。
    /// resolvepath() 会逐级 stat 祖先目录，因此这一步能把 "not in ncache" 救回来。
    private static func warmnamecache(_ path: String) -> Bool {
        let probe = path + "/.com.apple.mobile_container_manager.metadata.plist"
        return AppDumpmgr.shared.vfssize(path: probe) >= 0
            || AppDumpmgr.shared.vfssize(path: path) >= 0
    }

    /// 读 plist：VFS 优先，失败再走 FileManager（同样不能提前 return）
    private static func readplist(_ path: String) -> NSDictionary? {
        if AppDumpmgr.shared.vfsready, let d = readdict(path, maxSize: 1024 * 1024) { return d }
        guard AppDumpmgr.shared.sbxready || AppDumpmgr.shared.vfsready else { return nil }
        if let d = NSDictionary(contentsOfFile: path) { return d }
        // 最后再试一次 VFS（此时 namecache 可能已被上面的访问预热）
        if AppDumpmgr.shared.vfsready { return readdict(path, maxSize: 1024 * 1024) }
        return nil
    }

    /// 依次尝试多个候选根，返回第一个能列出的 (root, entries)。
    ///
    /// 为什么需要多候选：本 App 的 VFS 靠 namecache 逐级解析路径。日志显示
    /// `/private/var/containers/Bundle/Application` 能解析（应用列表正常），但
    /// `/private/var/mobile/...` 报 `'mobile' not in ncache` —— 同一个设备上
    /// 两种写法可达性不同。iOS 的数据容器同时可通过 /var/containers/Data 与
    /// /var/mobile/Containers/Data 访问，因此逐个试而不是写死一个。
    private static func firstReadableRoot(_ candidates: [String]) -> (root: String, entries: [(name: String, isDir: Bool)])? {
        for r in candidates {
            if let e = listdir(r), !e.isEmpty { return (r, e) }
        }
        return nil
    }

    /// 数据容器根目录候选（按可达性优先级排列）
    private static let dataRoots = [
        "/private/var/containers/Data/Application",
        "/private/var/mobile/Containers/Data/Application",
        "/var/containers/Data/Application",
        "/var/mobile/Containers/Data/Application",
    ]

    /// 数据容器（按 bundle id）→ UUID
    static func datacontainers() -> [String: String] {
        guard let hit = firstReadableRoot(dataRoots) else {
            log("datacontainers: 所有候选根都无法列出")
            return [:]
        }
        var out: [String: String] = [:]
        for d in hit.entries where d.isDir {
            let p = hit.root + "/" + d.name + "/.com.apple.mobile_container_manager.metadata.plist"
            if let plist = readplist(p),
               let bid = plist["MCMMetadataIdentifier"] as? String {
                out[bid] = d.name
            }
        }
        log("datacontainers: root=\(hit.root) 命中 \(out.count)")
        return out
    }

    /// 数据容器完整路径（按 bundle id），找不到返回 nil
    static func datacontainerPath(for bundleID: String) -> String? {
        guard let hit = firstReadableRoot(dataRoots),
              let uuid = bundleIDLookup(hit.root, bundleID) else { return nil }
        return hit.root + "/" + uuid
    }

    /// 在指定根下按 bundle id 找容器 UUID
    private static func bundleIDLookup(_ root: String, _ bundleID: String) -> String? {
        guard !bundleID.isEmpty else { return nil }
        guard let dirs = listdir(root) else { return nil }
        for d in dirs where d.isDir {
            let p = root + "/" + d.name + "/.com.apple.mobile_container_manager.metadata.plist"
            if let plist = readplist(p),
               let ident = plist["MCMMetadataIdentifier"] as? String,
               ident == bundleID {
                return d.name
            }
        }
        return nil
    }

    /// Group 容器路径（按 bundle id）
    ///
    /// App Group 容器分散在两个根下，metadata 里的 MCMMetadataIdentifier
    /// 形如 `group.com.xxx.yyy`，或直接用团队 ID 作前缀，因此这里按
    /// “包含 bundleID” 做匹配；多个命中时取第一个。
    static func groupcontainerPath(for bundleID: String) -> String? {
        guard !bundleID.isEmpty else { return nil }
        let roots = [
            "/private/var/containers/Shared/AppGroup",
            "/private/var/mobile/Containers/Shared/AppGroup",
            "/var/containers/Shared/AppGroup",
            "/var/mobile/Containers/Shared/AppGroup",
        ]
        let needle = bundleID.lowercased()
        for root in roots {
            guard let dirs = listdir(root), !dirs.isEmpty else { continue }
            for d in dirs where d.isDir {
                let base = root + "/" + d.name
                let meta = base + "/.com.apple.mobile_container_manager.metadata.plist"
                if let plist = readplist(meta),
                   let ident = plist["MCMMetadataIdentifier"] as? String,
                   ident.lowercased().contains(needle) {
                    log("groupcontainer: \(ident) -> \(base)")
                    return base
                }
            }
        }
        log("groupcontainer: 未找到 \(bundleID)")
        return nil
    }


    // MARK: - 递归拷贝（读走 VFS，写走本地）

    /// 把系统路径下的一整个目录拷到本地可写目录，供打包 ipa 用。
    /// - Returns: (文件数, 字节数, 失败数)
    @discardableResult
    static func copytree(from src: String, to dst: String, maxFileSize: Int = 1024 * 1024 * 1024) -> (files: Int, bytes: Int, failed: Int) {
        var files = 0, bytes = 0, failed = 0
        let fm = FileManager.default
        try? fm.createDirectory(atPath: dst, withIntermediateDirectories: true)

        guard let entries = AppDumpmgr.shared.vfslistdir(path: src) else {
            log("copytree: cannot list \(src)")
            return (0, 0, 1)
        }

        for e in entries {
            let s = src + "/" + e.name
            let d = dst + "/" + e.name
            if e.isDir {
                let sub = copytree(from: s, to: d, maxFileSize: maxFileSize)
                files += sub.files; bytes += sub.bytes; failed += sub.failed
            } else {
                let size = AppDumpmgr.shared.vfssize(path: s)
                if size <= 0 {
                    // 可能是符号链接 / 0 字节文件，建个空文件占位
                    if !fm.fileExists(atPath: d) { fm.createFile(atPath: d, contents: Data()) }
                    files += 1
                    continue
                }
                if size > Int64(maxFileSize) {
                    log("copytree: skip \(e.name) (\(size) bytes, over cap)")
                    failed += 1
                    continue
                }
                guard let data = AppDumpmgr.shared.vfsread(path: s, maxSize: Int(size)) else {
                    log("copytree: read failed \(s)")
                    failed += 1
                    continue
                }
                do {
                    try data.write(to: URL(fileURLWithPath: d))
                    files += 1
                    bytes += data.count
                } catch {
                    log("copytree: write failed \(e.name): \(error.localizedDescription)")
                    failed += 1
                }
            }
        }
        return (files, bytes, failed)
    }
}
