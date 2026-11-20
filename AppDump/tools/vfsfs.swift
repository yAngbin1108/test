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

// Assets.car 没有公开 API：按名字取图的是私有的 CGImageSourceCopyNamedImageAtIndex
// （ImageIO 内部有，但头文件不导出）。这里自己声明一下，运行时直接 dlsym 找到。
private typealias namedimagefn = @convention(c) (CGImageSource, Int, CFString?, UnsafeRawPointer?) -> Unmanaged<CGImage>?

private final class imageiohelper {
    static let named = unsafeBitCast(dlsym(UnsafeMutableRawPointer(bitPattern: -2), "CGImageSourceCopyNamedImageAtIndex"), to: namedimagefn?.self)
}

enum vfsfs {

    private static func log(_ m: String) { AppDumpmgr.shared.logmsg("(vfsfs) \(m)") }

    // MARK: - 读

    /// 用 VFS 读一个 plist（不需要沙箱逃逸）
    static func readdict(_ path: String, maxSize: Int = 8 * 1024 * 1024) -> NSDictionary? {
        // VFS 对未进 namecache 的路径会失败（日志 "'containers' not in ncache"），
        // 而沙盒逃逸后 FileManager 能正常读。只走 VFS 会让整列应用「无 plist」而消失。
        // 沙盒已逃逸时 POSIX 是首选。注意：不能用 `sbxready && POSIX 成功` 当条件再
        // 落到 VFS 上 —— POSIX 一读不出来就掉进 vfsread，而 vfsread 是 open(2)+pread，
        // 照样吃沙箱，日志只会多一条 "vfs_read open failed"，然后继续往下走。
        // （图标那一路以前就是这么丢的：*每次* 都先去 VFS 试 @3x.png，文件不存在时
        //  每次打印一条失败日志并多一次内核 resolvepath。）
        if AppDumpmgr.shared.sbxready,
           let d = NSDictionary(contentsOfFile: path) { return d }
        guard AppDumpmgr.shared.sbxready || AppDumpmgr.shared.vfsready else { return nil }

        // 回退一：VFS 读（内核级。vfsread 内部是 open/pread，所以排在上面 POSIX 之后）
        if AppDumpmgr.shared.vfsready,
           let data = AppDumpmgr.shared.vfsread(path: path, maxSize: maxSize), !data.isEmpty {
            if let d = (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) as? NSDictionary {
                return d
            }
        }

        // 回退二：FileManager 取 Data 再解析（有些二进制 plist contentsOfFile 读不了）
        if let data = FileManager.default.contents(atPath: path), !data.isEmpty,
           let d = (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) as? NSDictionary {
            return d
        }
        return nil
    }

    static func readexists(_ path: String) -> Bool {
        if AppDumpmgr.shared.vfsready, AppDumpmgr.shared.vfssize(path: path) > 0 { return true }
        guard AppDumpmgr.shared.sbxready || AppDumpmgr.shared.vfsready else { return false }
        return FileManager.default.fileExists(atPath: path)
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

    // MARK: - 图标

    private static let iconcache = NSCache<NSString, UIImage>()

    /// 直接读一个图片文件：POSIX 优先，失败再问 VFS。
    /// 以前这里是 VFS 优先，且每试一个候选就调一次 vfsread ——
    /// 候选大多不存在，于是每个 App 都要打一串 "vfs_read open failed: No such file or directory"
    /// （日志被灌满），还要多做几次内核 resolvepath。
    private static func readimage(_ path: String) -> UIImage? {
        if let img = UIImage(contentsOfFile: path) { return img }
        guard AppDumpmgr.shared.vfsready else { return nil }
        if let data = AppDumpmgr.shared.vfsread(path: path, maxSize: 4 * 1024 * 1024),
           let img = UIImage(data: data) { return img }
        return nil
    }

    /// 从 bundle 里挑一个像图标的 PNG（主图标名字对不上时的兜底）。
    /// 自签 / 未签名的侧载包常见问题：Info.plist 里 CFBundleIconFiles 写的是
    /// "AppIcon60x60"，但包里实际叫 "AppIcon60x60@2x.png"、"icon-1024.png"、
    /// 或者只有 iOS 11+ 的 CFBundlePrimaryIcon 之外还多一层 UISettings 变体。
    /// 这里把 bundle 根目录的 PNG 全列一遍，按名字打分取最高的一个。
    private static func findiconfile(appdir: String) -> String? {
        let names: [String]
        if let via = AppDumpmgr.shared.vfslistdir(path: appdir), !via.isEmpty {
            names = via.map { $0.name }
        } else if let via = try? FileManager.default.contentsOfDirectory(atPath: appdir) {
            names = via
        } else {
            return nil
        }
        var best: (String, Int)? = nil
        for n in names {
            let lower = n.lowercased()
            guard lower.hasSuffix(".png") || lower.hasSuffix(".jpg") || lower.hasSuffix(".jpeg") else { continue }
            var score = 0
            if lower.contains("appicon") { score += 100 }
            if lower.contains("icon") { score += 50 }
            if lower.contains("@3x") { score += 30 } else if lower.contains("@2x") { score += 20 }
            if lower.contains("1024") { score += 10 }
            if lower.contains("small") || lower.contains("settings") || lower.contains("notification")
                || lower.contains("spotlight") || lower.contains("tile") || lower.contains("marketing") {
                score -= 40
            }
            if score > (best?.1 ?? -1) { best = (appdir + "/" + n, score) }
        }
        return best?.0
    }

    /// 从 Assets.car 里取图标：拷到 App 自己的 tmp，再交给 ImageIO。
    /// Assets.car 只有 ImageIO 认识（UIImage(data:) / CGImageSourceCreateImageAtIndex
    /// 对 car 都只返回失败），要用 CGImageSourceCopyNamedImageAtIndex 按名字取。
    private static func loadiconfromcatalogs(appdir: String) -> UIImage? {
        let fm = FileManager.default
        for catalog in ["Assets.car", "AppIcon60x60.car"] {
            let src = appdir + "/" + catalog
            let size = AppDumpmgr.shared.vfssize(path: src)
            let local = NSTemporaryDirectory() + "appd-\(abs(src.hashValue)).car"
            // 先 POSIX（沙盒逃逸后可用），再 VFS。vfsread 内部是 open/pread，同样吃沙箱，
            // 所以顺序不能反：反了就是每个没逃逸的 App 都多一条 open failed。
            var ok = false
            if let d = FileManager.default.contents(atPath: src), !d.isEmpty {
                ok = (try? d.write(to: URL(fileURLWithPath: local))) != nil
            } else if size > 0, let d = AppDumpmgr.shared.vfsread(path: src, maxSize: 64 * 1024 * 1024) {
                ok = (try? d.write(to: URL(fileURLWithPath: local))) != nil
            }
            if ok,
               let s = CGImageSourceCreateWithURL(URL(fileURLWithPath: local) as CFURL, nil) {
                // 先按图标名试，再按资产表下标试（下标 0 通常就是最大那张）
                let keys = ["AppIcon60x60@3x", "AppIcon60x60@2x", "AppIcon60x60",
                            "AppIcon", "Icon60x60", "AppIcon76x76@2x"]
                if let fn = imageiohelper.named {
                    for i in 0..<max(CGImageSourceGetCount(s), 1) {
                        let key: CFString? = i < keys.count ? keys[i] as CFString : nil
                        if let cg = fn(s, i, key, nil)?.takeRetainedValue() {
                            try? fm.removeItem(atPath: local)
                            return UIImage(cgImage: cg)
                        }
                    }
                }
            }
            try? fm.removeItem(atPath: local)
        }
        return nil
    }

    /// 给视图层用的图标入口（带缓存）
    static func iconforapp(appdir: String, info: NSDictionary) -> UIImage? {
        loadicon(appdir: appdir, info: info)
    }

    private static func loadicon(appdir: String, info: NSDictionary) -> UIImage? {
        let ck = appdir as NSString
        if let cached = iconcache.object(forKey: ck) { return cached }

        var names: [String] = []
        // iOS 11+ 主图标
        if let icons = info["CFBundleIcons"] as? [String: Any],
           let primary = icons["CFBundlePrimaryIcon"] as? [String: Any],
           let files = primary["CFBundleIconFiles"] as? [String] {
            names = files
        }
        // iOS 5~10
        if let files = info["CFBundleIconFiles"] as? [String], !files.isEmpty {
            names += files
        }
        // CFBundleIconName 是 iOS 11+ 的 Assets.car 键，包里未必有同名 PNG，
        // 但很多侧载包把它写成了 PNG 的文件名，试一下不吃亏。
        if let n = info["CFBundleIconName"] as? String, !n.isEmpty {
            names.append(n)
        }

        let candidates = names.reversed()   // 最大尺寸在数组末尾
        for base in candidates {
            var tried = Set<String>()
            for suffix in ["@3x.png", "@2x.png", ".png", "@3x.jpg", ".jpg"] {
                let p = appdir + "/" + base + suffix
                if tried.contains(p) { continue }
                tried.insert(p)
                if let img = readimage(p) {
                    iconcache.setObject(img, forKey: ck)
                    return img
                }
            }
        }

        // 最后兜底：bundle 里挑一个像图标的 PNG
        if let p = findiconfile(appdir: appdir), let img = readimage(p) {
            log("图标兜底：\(p)")
            iconcache.setObject(img, forKey: ck)
            return img
        }

        // 再兜底：很多包只留 Assets.car，没有散装 PNG。
        // 先拷到本地再让 ImageIO 读 —— UIImage(contentsOfFile:) 直接读系统路径会吃沙箱。
        if let img = loadiconfromcatalogs(appdir: appdir) {
            iconcache.setObject(img, forKey: ck)
            return img
        }
        log("图标缺失：\(appdir)（plist 候选 \(names.joined(separator: ","))）")
        return nil
    }

    /// 列出 /private/var/containers/Bundle/Application 下的全部 .app
    static func listappbundles() -> [bundleapp] {
        // 用 listdir()（VFS 失败会回退 FileManager，并对 namecache 做预热）。
        // 之前直接调用 vfslistdir：当 vfsready 为真但该路径尚未进入 namecache 时
        // 会返回 nil（日志 "vfs_listdir resolvepath failed ... dvn=0x0"，
        // 或 "'containers' not in ncache"），导致应用列表整列为空 ——
        // 解密页之所以正常，是因为它在沙盒逃逸后走的是 FileManager 直读。
        let vfsok = AppDumpmgr.shared.vfsready
        let sbxok = AppDumpmgr.shared.sbxready
        log("listappbundles 开始 vfs=\(vfsok) sbx=\(sbxok)")
        guard vfsok || sbxok else {
            log("listappbundles 中止：VFS 与 SBX 均未就绪")
            return []
        }
        let root = "/private/var/containers/Bundle/Application"
        guard let containers = listdir(root) else {
            log("listdir failed: \(root)")
            return []
        }
        log("根目录容器数：\(containers.count)")

        // 第一遍只列目录 + 读 Info.plist（不做图标），第二遍并行加载图标。
        // 负责地串行解图标时，一旦解码失败就会走 Assets.car 兜底（要读整个 car），
        // 96 个 App 串下来界面会卡好几百毫秒；并行 + 缓存后一遍就热。
        struct pending { let appdir: String; let info: NSDictionary; let bundleid: String
                         let name: String; let ex: String }
        var pendingapps: [pending] = []
        var subnil = 0, noapp = 0, noplist = 0
        var firsterr = ""
        for c in containers where c.isDir {
            let cpath = root + "/" + c.name
            guard let contents = listdir(cpath) else {
                subnil += 1
                if firsterr.isEmpty { firsterr = "listdir nil: \(cpath)" }
                continue
            }
            var foundapp = false
            for item in contents where item.name.hasSuffix(".app") {
                foundapp = true
                let appdir = cpath + "/" + item.name
                guard let info = readdict(appdir + "/Info.plist") else {
                    noplist += 1
                    if firsterr.isEmpty { firsterr = "no plist: \(appdir)" }
                    continue
                }
                let ex = info["CFBundleExecutable"] as? String ?? ""
                if ex.isEmpty { continue }
                let bid = info["CFBundleIdentifier"] as? String ?? ""
                let name = (info["CFBundleDisplayName"] as? String)
                    ?? (info["CFBundleName"] as? String)
                    ?? (item.name as NSString).deletingPathExtension
                pendingapps.append(pending(appdir: appdir, info: info, bundleid: bid,
                                           name: name, ex: ex))
                break
            }
            if !foundapp {
                noapp += 1
                if firsterr.isEmpty {
                    let sample = contents.prefix(4).map { $0.name }.joined(separator: ",")
                    firsterr = "no .app in \(cpath) (\(contents.count) items: \(sample))"
                }
            }
        }

        var icons = [UIImage?](repeating: nil, count: pendingapps.count)
        let lock = NSLock()
        var cursor = 0
        let total = pendingapps.count
        DispatchQueue.concurrentPerform(iterations: max(1, min(total, 8))) { _ in
            while true {
                lock.lock()
                let idx = cursor
                cursor += 1
                lock.unlock()
                guard idx < total else { return }
                let p = pendingapps[idx]
                let img = loadicon(appdir: p.appdir, info: p.info)
                lock.lock()
                icons[idx] = img
                lock.unlock()
            }
        }
        let out: [bundleapp] = pendingapps.enumerated().map { i, p in
            bundleapp(bundleid: p.bundleid, name: p.name, executable: p.ex,
                      path: p.appdir, icon: icons[i])
        }
        let noicon = icons.filter { $0 == nil }.count
        log("listappbundles 统计：容器=\(containers.count) 读不到=\(subnil) 无app=\(noapp) 无plist=\(noplist) 结果=\(out.count) 无图标=\(noicon)")
        if !firsterr.isEmpty { log("首个异常：\(firsterr)") }
        log("listed \(out.count) app bundles")
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
        // VFS 对未进 namecache 的路径不一定返回 nil —— 实测会返回【空数组】，
        // 于是「有值就 return」会直接吞掉后续的 FileManager 回退，
        // 表现为「容器=138 读不到=0 无app=138」。所以只有【非空】才采信。
        if AppDumpmgr.shared.vfsready,
           let via = AppDumpmgr.shared.vfslistdir(path: path), !via.isEmpty {
            return via
        }
        guard AppDumpmgr.shared.sbxready || AppDumpmgr.shared.vfsready else { return nil }

        // 回退一：FileManager 直接列（需要沙盒逃逸已生效）
        if let names = try? FileManager.default.contentsOfDirectory(atPath: path) {
            var out: [(name: String, isDir: Bool)] = []
            out.reserveCapacity(names.count)
            for n in names {
                // 不能用 fileExists(atPath:isDirectory:)：沙盒受限时它对子路径
                // 不报错、直接返回 false，会让所有容器目录被标成「非目录」，
                // 外层 `where c.isDir` 一次都不执行（PDF 里踩过的同一个坑）。
                // 用 resourceValues 判定，读不到时默认按目录处理（当作文件也安全：
                // 读 Info.plist 必然失败，会被跳过）。
                let child = path + "/" + n
                var isDir = true
                if let v = try? URL(fileURLWithPath: child)
                    .resourceValues(forKeys: [.isDirectoryKey]).isDirectory {
                    isDir = v
                }
                out.append((n, isDir))
            }
            return out
        }

        // 回退二：先让内核把这条路径读进 namecache，再重试 VFS 列表
        if AppDumpmgr.shared.vfsready, warmnamecache(path),
           let again = AppDumpmgr.shared.vfslistdir(path: path), !again.isEmpty {
            return again
        }
        log("listdir 全部失败：\(path)")
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
