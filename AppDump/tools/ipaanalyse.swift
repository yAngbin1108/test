//
//  ipaanalyse.swift
//  AppDump
//
//  IPA 分析（对应 dump 仓库 Objective-C 的 SKIPAManager）：
//  不解压整包，只读 zip 的中央目录 + 需要看的条目开头几 KB，
//  得出 bundle id / 版本 / 最低系统 / 架构 / 每个二进制的 cryptid / 签名 / 扩展。
//
//    · EOCD 尾部扫描（兼容 ZIP64 locator）
//    · 中央目录顺序解析 → 「条目名 → 本地头偏移」
//    · 本地头 → 数据起点，STORE 直接读，DEFLATE 就地 inflate 前 N 字节
//    · Mach-O：fat 32/64（含字节序）、LC_ENCRYPTION_INFO(_64).cryptid
//

import Foundation

// MARK: - 模型

struct ipabinaryinfo: Identifiable, Hashable {
    var id: String { path }
    let path: String          // 包内相对路径
    let name: String          // 文件名
    let archs: [String]       // arm64 / arm64e …
    let encrypted: Bool       // 任一切片 cryptid != 0
    let hasCryptInfo: Bool    // 是否有 LC_ENCRYPTION_INFO
    let size: UInt64
}

enum ipaintegrity {
    case unknown      // 不是合法 zip
    case broken(String)
    case ok

    var text: String {
        switch self {
        case .ok:
            return "完整"
        case .unknown:
            return "无法读取"
        case .broken(let reason):
            return "异常 — \(reason)"
        }
    }

    var isOK: Bool {
        if case .ok = self { return true }
        return false
    }

    var isUnknown: Bool {
        if case .unknown = self { return true }
        return false
    }
}

struct ipaanalysis {
    var appName: String?
    var bundleID: String?
    var version: String?
    var minimumOS: String?
    var executable: String?
    var integrity: ipaintegrity = .unknown
    var signed = false
    var entryCount = 0
    var uncompressedTotal: UInt64 = 0
    var archs: [String] = []
    var binaries: [ipabinaryinfo] = []
    var encrypted = false
    var extensionSummary: String?
    var hasWatchApp = false
    var notes: [String] = []

    /// 列表里的一行摘要，例如「arm64 · 已解密」
    var variant: String {
        var parts: [String] = []
        if !archs.isEmpty { parts.append(archs.joined(separator: "+")) }
        if !binaries.isEmpty { parts.append(encrypted ? "未解密" : "已解密") }
        if !integrity.isOK { parts.append("结构异常") }
        return parts.joined(separator: " · ")
    }

    /// 是否能直接安装
    var installable: Bool { integrity.isOK && !encrypted && !binaries.isEmpty }
}

// MARK: - 极简 zip 读取器

final class ipazipreader {
    struct Entry {
        let size: UInt64
        let localOffset: UInt64
    }

    private let handle: FileHandle
    private(set) var entries: [String: Entry] = [:]
    private(set) var entryCount = 0
    private(set) var uncompressedTotal: UInt64 = 0
    private let fileSize: UInt64

    init?(path: String) {
        guard let h = FileHandle(forReadingAtPath: path) else { return nil }
        handle = h
        let attrs = (try? FileManager.default.attributesOfItem(atPath: path)) ?? [:]
        fileSize = (attrs[.size] as? NSNumber)?.uint64Value ?? h.seekToEnd()
        guard fileSize >= 22, readCentralDirectory() else {
            try? handle.close()
            return nil
        }
    }

    deinit { try? handle.close() }

    var isEmpty: Bool { entries.isEmpty }

    private func pread(_ len: Int, at off: UInt64) -> Data? {
        guard off < fileSize, len > 0 else { return nil }
        let n = Int(min(UInt64(len), fileSize - off))
        do {
            try handle.seek(toOffset: off)
            let d = try handle.read(upToCount: n) ?? Data()
            return d.isEmpty ? nil : d
        } catch {
            return nil
        }
    }

    private func u16(_ d: Data, _ i: Int) -> UInt16 {
        guard i + 2 <= d.count else { return 0 }
        return d.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: i, as: UInt16.self) }.littleEndian
    }
    private func u32(_ d: Data, _ i: Int) -> UInt32 {
        guard i + 4 <= d.count else { return 0 }
        return d.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: i, as: UInt32.self) }.littleEndian
    }
    private func u64(_ d: Data, _ i: Int) -> UInt64 {
        guard i + 8 <= d.count else { return 0 }
        return d.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: i, as: UInt64.self) }.littleEndian
    }

    @discardableResult
    private func readCentralDirectory() -> Bool {
        let tailsize = Int(min(65557, fileSize))
        guard let tail = pread(tailsize, at: fileSize - UInt64(tailsize)), tail.count >= 22 else { return false }
        guard let eocd = Self.findEOCD(tail) else { return false }
        let eocdAbs = fileSize - UInt64(tailsize) + UInt64(eocd)

        var count = UInt64(u16(tail, eocd + 10))
        var cdSize = UInt64(u32(tail, eocd + 12))
        var cdOff = UInt64(u32(tail, eocd + 16))

        if count == 0xffff || cdSize == 0xffff_ffff || cdOff == 0xffff_ffff, eocdAbs >= 20,
           let loc = pread(20, at: eocdAbs - 20), loc.count == 20, u32(loc, 0) == 0x0706_4b50 {
            let z64 = u64(loc, 8)
            if let rec = pread(56, at: z64), rec.count >= 56, u32(rec, 0) == 0x0606_4b50 {
                count = u64(rec, 32)
                cdSize = u64(rec, 40)
                cdOff = u64(rec, 48)
            }
        }
        guard cdOff < fileSize else { return false }
        if cdSize == 0 || cdOff + cdSize > fileSize { cdSize = fileSize - cdOff }
        guard let cd = pread(Int(min(cdSize, 64 << 20)), at: cdOff) else { return false }

        var pos = 0
        var got = 0
        while pos + 46 <= cd.count, UInt64(got) < count {
            guard u32(cd, pos) == 0x0201_4b50 else { break }
            let nameLen = Int(u16(cd, pos + 28))
            let extraLen = Int(u16(cd, pos + 30))
            let cmtLen = Int(u16(cd, pos + 32))
            var usize = UInt64(u32(cd, pos + 24))
            let csize = UInt64(u32(cd, pos + 20))
            var localOff = UInt64(u32(cd, pos + 42))
            let next = pos + 46 + nameLen + extraLen + cmtLen
            guard next <= cd.count else { break }

            if usize == 0xffff_ffff || csize == 0xffff_ffff || localOff == 0xffff_ffff {
                var f = pos + 46 + nameLen
                let fend = f + extraLen
                while f + 4 <= fend {
                    let tag = u16(cd, f)
                    let sz = Int(u16(cd, f + 2))
                    if tag == 0x0001 {
                        var d = f + 4
                        let dend = min(d + sz, fend)
                        if usize == 0xffff_ffff, d + 8 <= dend { usize = u64(cd, d); d += 8 }
                        if csize == 0xffff_ffff, d + 8 <= dend { d += 8 }
                        if localOff == 0xffff_ffff, d + 8 <= dend { localOff = u64(cd, d) }
                        break
                    }
                    f += 4 + sz
                }
            }

            let nameData = cd.subdata(in: (pos + 46)..<(pos + 46 + nameLen))
            if let name = String(data: nameData, encoding: .utf8), !name.isEmpty {
                entries[name] = Entry(size: usize == 0xffff_ffff ? 0 : usize, localOffset: localOff)
                if usize != 0xffff_ffff { uncompressedTotal += usize }
                got += 1
            }
            pos = next
        }
        entryCount = got
        return !entries.isEmpty
    }

    private static func findEOCD(_ d: Data) -> Int? {
        guard d.count >= 22 else { return nil }
        var i = d.count - 22
        while i >= 0 {
            if d[i] == 0x50, d[i + 1] == 0x4b, d[i + 2] == 0x05, d[i + 3] == 0x06 {
                let clen = Int(d[i + 20]) | (Int(d[i + 21]) << 8)
                if i + 22 + clen <= d.count { return i }
            }
            i -= 1
        }
        return nil
    }

    /// 读条目数据起点开始的连续字节（至多 maxBytes）。method：0 = STORE，8 = DEFLATE。
    func read(_ name: String, maxBytes: Int) -> (data: Data, method: UInt16)? {
        guard let e = entries[name] else { return nil }
        guard let lh = pread(30, at: e.localOffset), lh.count >= 30, u32(lh, 0) == 0x0403_4b50 else { return nil }
        let nm = Int(u16(lh, 26))
        let ex = Int(u16(lh, 28))
        let method = u16(lh, 8)
        var cs = UInt64(u32(lh, 18))
        let dataOff = e.localOffset + 30 + UInt64(nm + ex)
        guard dataOff < fileSize else { return nil }
        if cs == 0 || cs == 0xffff_ffff { cs = fileSize - dataOff }
        guard let raw = pread(Int(min(UInt64(maxBytes), cs)), at: dataOff) else { return nil }
        return (raw, method)
    }

    /// 解出条目（最多 maxBytes 解压后）。只用于看头部 / plist，不做全文件解压。
    /// 注意名字不能叫 inflate：会和 zlib 的全局函数 inflate() 撞名，
    /// 同一类型里的 static func 调它就解析成实例方法了。
    func entryData(_ name: String, maxBytes: Int) -> Data? {
        guard let (raw, method) = read(name, maxBytes: maxBytes) else { return nil }
        if method == 0 { return raw }
        guard method == 8 else { return nil }
        return Self.decompressRaw(raw, limit: maxBytes)
    }

    static func decompressRaw(_ raw: Data, limit: Int) -> Data? {
        guard !raw.isEmpty, limit > 0 else { return nil }
        var strm = z_stream()
        // zlibVersion() 即 C 里的 zlibVersion 常量字符串
        guard inflateInit2_(&strm, -MAX_WBITS, zlibVersion(),
                            Int32(MemoryLayout<z_stream>.size)) == Z_OK else { return nil }
        defer { inflateEnd(&strm) }

        var out = Data()
        var chunk = [UInt8](repeating: 0, count: 64 << 10)
        _ = raw.withUnsafeBytes { (src: UnsafeRawBufferPointer) -> Void in
            strm.next_in = UnsafeMutablePointer(mutating: src.bindMemory(to: Bytef.self).baseAddress)
            strm.avail_in = uInt(src.count)
            var rc: Int32 = Z_OK
            repeat {
                var produced = 0
                _ = chunk.withUnsafeMutableBufferPointer { buf -> Void in
                    strm.next_out = buf.baseAddress
                    strm.avail_out = uInt(buf.count)
                    rc = inflate(&strm, Z_NO_FLUSH)
                    produced = buf.count - Int(strm.avail_out)
                }
                if produced > 0 {
                    let room = limit - out.count
                    if room > 0 { out.append(contentsOf: chunk.prefix(min(produced, room))) }
                }
                if out.count >= limit || rc == Z_STREAM_END { break }
            } while rc == Z_OK
        }
        return out.isEmpty ? nil : out
    }
}

// MARK: - Mach-O

enum ipamacho {
    /// 遍历每个切片：回调 (切片数据, 架构名)
    static func slices(_ data: Data, _ body: (Data, String) -> Void) {
        guard data.count >= 28 else { return }
        let magic = data.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }
        if magic == 0xcafe_babe || magic == 0xbeba_feca || magic == 0xcafe_babf || magic == 0xbebf_cafe {
            let swap = (magic == 0xbeba_feca || magic == 0xbebf_cafe)
            let is64 = (magic == 0xcafe_babf || magic == 0xbebf_cafe)
            func rd32(_ i: Int) -> UInt32 {
                let v = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: i, as: UInt32.self) }
                return swap ? v.byteSwapped : v
            }
            let n = Int(rd32(4))
            let entsz = is64 ? 32 : 20
            guard n > 0, n <= 16, 8 + n * entsz <= data.count else { return }
            for i in 0..<n {
                let base = 8 + i * entsz
                let cputype = Int32(bitPattern: rd32(base))
                let cpusub = Int32(bitPattern: rd32(base + 4))
                var ofs: UInt64
                var size: UInt64
                if is64 {
                    let o = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: base + 8, as: UInt64.self) }
                    let s = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: base + 16, as: UInt64.self) }
                    ofs = swap ? o.byteSwapped : o
                    size = swap ? s.byteSwapped : s
                } else {
                    ofs = UInt64(rd32(base + 8))
                    size = UInt64(rd32(base + 12))
                }
                guard ofs + size <= UInt64(data.count), size >= 28 else { continue }
                let slice = data.subdata(in: Int(ofs)..<Int(ofs + size))
                body(slice, archName(cputype: cputype, cpusubtype: cpusub))
            }
            return
        }
        if magic == 0xfeed_face || magic == 0xfeed_facf || magic == 0xfeedfacf {
            let cputype = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 4, as: Int32.self) }
            let sub = data.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 8, as: Int32.self) }
            body(data, archName(cputype: cputype, cpusubtype: sub))
        }
    }

    static func archName(cputype: Int32, cpusubtype: Int32) -> String {
        if cputype == 0x0100_000C {          // CPU_TYPE_ARM64
            let s = cpusubtype & 0x00ff_ffff
            if s == 2 { return "arm64e" }
            if s == 1 { return "arm64v8" }
            return "arm64"
        }
        if cputype == 12 { return "arm" }
        if cputype == 0x0100_0007 { return "x86_64" }
        return "cpu(\(cputype),\(cpusubtype))"
    }

    /// 返回 (仍是密文?, 有 LC_ENCRYPTION_INFO?)
    static func encryptionState(_ d: Data) -> (Bool, Bool) {
        guard d.count >= 32 else { return (false, false) }
        let magic = d.withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }
        let is64 = (magic == 0xfeed_facf)
        guard is64 || magic == 0xfeed_face else { return (false, false) }
        let hdrsize = is64 ? 32 : 28
        let ncmds = Int(d.withUnsafeBytes { $0.loadUnaligned(fromByteOffset: 16, as: UInt32.self) })
        guard ncmds > 0, ncmds <= 8192 else { return (false, false) }

        return d.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> (Bool, Bool) in
            var p = hdrsize
            for _ in 0..<ncmds {
                guard p + 8 <= raw.count else { break }
                let cmd = raw.loadUnaligned(fromByteOffset: p, as: UInt32.self)
                let cmdsize = Int(raw.loadUnaligned(fromByteOffset: p + 4, as: UInt32.self))
                guard cmdsize >= 8, p + cmdsize <= raw.count else { break }
                if cmd == 0x21 || cmd == 0x2C {          // LC_ENCRYPTION_INFO / _64
                    if cmdsize >= 20 {
                        let cryptid = raw.loadUnaligned(fromByteOffset: p + 16, as: UInt32.self)
                        return (cryptid != 0, true)
                    }
                }
                p += cmdsize
            }
            return (false, false)
        }
    }
}

// MARK: - 分析入口

enum ipaanalyzer {

    /// 包内一级条目（逐层浏览用）
    struct diritem: Identifiable {
        var id: String { (isDir ? "d:" : "f:") + name }
        let name: String
        let isDir: Bool
        let count: Int
    }

    /// 读一个包内 plist（STORE 直接解，DEFLATE 就地 inflate）。
    static func plist(_ zip: ipazipreader, _ name: String) -> [String: Any]? {
        guard let data = zip.entryData(name, maxBytes: 4 << 20), data.count >= 8 else { return nil }
        return (try? PropertyListSerialization.propertyList(from: data, options: [], format: nil)) as? [String: Any]
    }

    /// 全量分析。调用方应在后台线程执行。
    static func analyze(path: String) -> ipaanalysis {
        var a = ipaanalysis()
        let attrs = (try? FileManager.default.attributesOfItem(atPath: path)) ?? [:]
        let fileSize = (attrs[.size] as? NSNumber)?.uint64Value ?? 0

        guard let zip = ipazipreader(path: path) else {
            a.integrity = .unknown
            a.notes.append(fileSize == 0 ? "文件是空的" : "不是有效的 IPA（zip 结构损坏或已截断）")
            return a
        }
        a.entryCount = zip.entryCount
        a.uncompressedTotal = zip.uncompressedTotal
        let names = Array(zip.entries.keys)

        // ── 1. 定位 Payload 下的 .app ──
        var mainPrefix: String?
        var extPrefixes: [String] = []
        for name in names where name.lowercased().hasSuffix(".app/info.plist") {
            let parts = name.split(separator: "/").map(String.init)
            guard let payload = parts.firstIndex(where: { $0.lowercased() == "payload" }),
                  payload + 2 < parts.count else { continue }
            // 最后一个「后面还跟着一级」的 *.app 就是当前 Info.plist 所属的 bundle
            var appIdx = payload
            var scan = payload + 1
            while scan + 1 < parts.count {
                if parts[scan].lowercased().hasSuffix(".app") { appIdx = scan }
                scan += 1
            }
            guard appIdx > payload else { continue }
            let prefix = parts[0...appIdx].joined(separator: "/")
            if prefix.contains("/Watch/") { a.hasWatchApp = true }
            if appIdx == payload + 1 {
                if mainPrefix == nil { mainPrefix = prefix }
            } else if !extPrefixes.contains(prefix) {
                extPrefixes.append(prefix)
            }
        }
        guard let main = mainPrefix else {
            a.integrity = .broken("包里没有 Payload/*.app")
            a.notes.append("包里没有 Payload/*.app")
            return a
        }

        // ── 2. 签名 / 主 Info.plist ──
        a.signed = names.contains { $0.hasPrefix(main + "/") && $0.hasSuffix("/_CodeSignature/CodeResources") }
        let infoName = names.first { $0.lowercased() == (main + "/Info.plist").lowercased() }
        let info = infoName.flatMap { plist(zip, $0) }
        if let info {
            let disp = info["CFBundleDisplayName"] as? String
            let nm = info["CFBundleName"] as? String
            if let d = disp, !d.isEmpty { a.appName = d } else if let n = nm, !n.isEmpty { a.appName = n }
            a.bundleID = info["CFBundleIdentifier"] as? String
            let sv = info["CFBundleShortVersionString"] as? String
            let bv = info["CFBundleVersion"] as? String
            if let s = sv, let b = bv, b != s { a.version = "\(s) (\(b))" }
            else { a.version = (sv?.isEmpty == false ? sv : bv) }
            a.minimumOS = info["MinimumOSVersion"] as? String
            a.executable = info["CFBundleExecutable"] as? String
        } else {
            a.notes.append("主程序 Info.plist 读取失败")
        }

        // ── 3. 扩展类型 ──
        var kinds: [String: Int] = [:]
        for prefix in extPrefixes where !prefix.contains("/Watch/") {
            let key = (prefix + "/Info.plist").lowercased()
            let ei = names.first { $0.lowercased() == key }.flatMap { plist(zip, $0) }
            let point = (ei?["NSExtension"] as? [String: Any])?["NSExtensionPointIdentifier"] as? String ?? ""
            let kind: String
            if point.contains("share") { kind = "共享扩展" }
            else if point.contains("widget") { kind = "Widget" }
            else if point.contains("notification") { kind = "通知" }
            else if point.contains("intent") { kind = "快捷指令" }
            else if point.contains("keyboard") { kind = "键盘" }
            else if point.contains("audio") { kind = "音频" }
            else if point.contains("fileprovider") { kind = "文件提供器" }
            else { kind = "扩展" }
            kinds[kind, default: 0] += 1
        }
        if !kinds.isEmpty {
            let order = ["共享扩展", "Widget", "通知", "快捷指令", "键盘", "音频", "文件提供器", "扩展"]
            a.extensionSummary = order.compactMap { k in kinds[k].map { "\(k) ×\($0)" } }.joined(separator: "、")
        }
        if a.hasWatchApp { a.notes.append("包含 Apple Watch 配套包") }

        // ── 4. 主程序 + 扩展二进制 ──
        var exeKeys: [String] = []
        let stem = ((main as NSString).lastPathComponent as NSString).deletingPathExtension
        let exe = (a.executable?.isEmpty == false ? a.executable! : stem)
        if let key = names.first(where: { $0.lowercased() == (main + "/" + exe).lowercased() }) { exeKeys.append(key) }
        for prefix in extPrefixes where !prefix.contains("/Watch/") {
            let ps = ((prefix as NSString).lastPathComponent as NSString).deletingPathExtension
            if let key = names.first(where: { $0.lowercased() == (prefix + "/" + ps).lowercased() }) { exeKeys.append(key) }
        }

        var archSet: [String] = []
        for key in exeKeys {
            // 512KB 够覆盖 mach header + 全部 load commands（AppDump 实测 ~5KB）
            let head = zip.entryData(key, maxBytes: 512 << 10)
            var archs: [String] = []
            var encrypted = false
            var hasCrypt = false
            if let head {
                ipamacho.slices(head) { slice, arch in
                    archs.append(arch)
                    let (enc, hc) = ipamacho.encryptionState(slice)
                    if enc { encrypted = true }
                    if hc { hasCrypt = true }
                }
            } else {
                a.notes.append("\((key as NSString).lastPathComponent) 无法解析（只支持 STORE / DEFLATE）")
            }
            let size = zip.entries[key]?.size ?? 0
            a.binaries.append(ipabinaryinfo(path: key,
                                            name: (key as NSString).lastPathComponent,
                                            archs: archs, encrypted: encrypted,
                                            hasCryptInfo: hasCrypt, size: size))
            for ar in archs where !archSet.contains(ar) { archSet.append(ar) }
            if encrypted { a.encrypted = true }
        }
        a.archs = archSet
        if exeKeys.isEmpty { a.notes.append("包里找不到主程序二进制") }

        // ── 5. 结论 ──
        if a.binaries.isEmpty {
            a.integrity = .broken("包里没有可解析的 Mach-O")
        } else if !a.signed {
            a.integrity = .broken("缺少 _CodeSignature（未签名或签名被删）")
        } else {
            a.integrity = .ok
        }
        if case .broken(let why) = a.integrity { a.notes.append(why) }
        if a.encrypted {
            let n = a.binaries.filter { $0.encrypted }.count
            a.notes.append("仍有 \(n)/\(a.binaries.count) 个二进制带 cryptid，装上启动大概率闪退")
        } else if !a.binaries.isEmpty {
            a.notes.append("全部二进制已清 cryptid，可直接安装")
        }
        return a
    }

    /// 包内一级条目列表（逐层浏览用）。
    static func listEntries(_ zip: ipazipreader, prefix: String) -> [diritem] {
        let base = prefix.isEmpty ? "" : prefix + "/"
        var dirs: [String: Int] = [:]
        var files: [String] = []
        for name in zip.entries.keys {
            guard base.isEmpty || name.hasPrefix(base) else { continue }
            let rest = base.isEmpty ? name : String(name.dropFirst(base.count))
            guard !rest.isEmpty else { continue }
            if let slash = rest.firstIndex(of: "/") {
                let d = String(rest[rest.startIndex..<slash])
                dirs[d, default: 0] += 1
            } else {
                files.append(rest)
            }
        }
        let d = dirs.keys.sorted().map { diritem(name: $0, isDir: true, count: dirs[$0] ?? 0) }
        let f = files.sorted().map { diritem(name: $0, isDir: false, count: 0) }
        return d + f
    }

    /// 分析报告纯文本（分享用）。
    static func report(name: String, size: UInt64, date: Date, a: ipaanalysis) -> String {
        func bytes(_ n: UInt64) -> String {
            ByteCountFormatter.string(fromByteCount: Int64(n), countStyle: .file)
        }
        var s = """
        文件：\(name)
        大小：\(bytes(size))
        修改：\(date.formatted(date: .abbreviated, time: .shortened))
        应用：\(a.appName ?? "—")
        Bundle ID：\(a.bundleID ?? "—")
        版本：\(a.version ?? "—")
        最低系统：iOS \(a.minimumOS ?? "—")
        架构：\(a.archs.isEmpty ? "—" : a.archs.joined(separator: ", "))
        结构：\(a.integrity.text)
        签名：\(a.signed ? "有 _CodeSignature" : "无")
        加密：\(a.encrypted ? "仍有密文" : (a.binaries.isEmpty ? "未检测" : "已解密"))
        条目：\(a.entryCount) 个，解压后 \(bytes(a.uncompressedTotal))

        """
        if let e = a.extensionSummary { s += "扩展：\(e)\n" }
        if a.hasWatchApp { s += "含 Watch 包\n" }
        for b in a.binaries {
            s += "  · \(b.path)  [\(b.archs.joined(separator: ","))]  \(b.encrypted ? "cryptid≠0" : "明文")  \(bytes(b.size))\n"
        }
        if !a.notes.isEmpty {
            s += "\n提示：\n"
            for n in a.notes { s += "  - \(n)\n" }
        }
        return s
    }
}
