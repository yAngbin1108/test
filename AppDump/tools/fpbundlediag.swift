import Foundation

/// 应用包体检：判断这份 .app 到底是不是商店原装包。
///
/// 只看 `embedded.mobileprovision` 不够：开发者证书重签一定会带描述文件，
/// 但 ad-hoc（ldid 那种假签名）**不需要**描述文件，所以"没有描述文件"
/// 不能证明"是商店原包"。真正可靠的判据是：
///   1. 主程序的 CodeDirectory 签名类型（ad-hoc / 有 team / 苹果平台）；
///   2. 加密区占 __TEXT_EXEC 的比例（商店原包接近 100%，改壳包只剩一页）；
///   3. 正文抽样的熵与 ARM64 地标词（正文已是明文 ⇒ 这份包被解过）。
enum FPBundleAudit {

    // MARK: - 对外入口

    static func run(appDir: URL,
                    rows: [(path: String, slices: [FPMachO.Slice])],
                    installDir: URL? = nil,
                    log: @escaping (String) -> Void) {
        let manager = FileManager.default
        log("（体检）目录：\(appDir.lastPathComponent)"
            + (installDir.map { "（暂存副本；原始安装目录 \($0.lastPathComponent)）" } ?? ""))

        // 1. 描述文件
        let profile = appDir.appendingPathComponent("embedded.mobileprovision")
        if let attrs = try? manager.attributesOfItem(atPath: profile.path),
           let size = attrs[.size] as? NSNumber {
            let team = profileTeamIdentifier(profile)
            log("（体检）embedded.mobileprovision：有（\(size.intValue) B，team=\(team ?? "读不到")）"
                + " ⇒ 用开发者/企业证书重签过")
        } else {
            log("（体检）embedded.mobileprovision：无（商店原包或 ad-hoc 假签名都可能这样，看下面两条）")
        }

        // 2. iTunes 元数据
        // iOS 17 起商店把 iTunesMetadata.plist 写在**容器目录**（.app 的父目录）里，
        // 老版本才放在 .app 内。两个位置、两套目录（暂存副本 + 原始安装目录）都要查：
        // 暂存拷贝可能漏文件，原始安装目录才是真相。
        var metaHits: [String] = []
        var metaSeenInInstall = false, metaSeenInStage = false
        var locations: [(String, URL)] = [("暂存", appDir)]
        if let installDir, installDir.path != appDir.path { locations.append(("安装目录", installDir)) }
        for (label, dir) in locations {
            for (place, candidate) in [("包内", dir.appendingPathComponent("iTunesMetadata.plist")),
                                       ("容器目录", dir.deletingLastPathComponent()
                                                     .appendingPathComponent("iTunesMetadata.plist"))] {
                guard let attrs = try? manager.attributesOfItem(atPath: candidate.path),
                      let size = attrs[.size] as? NSNumber else { continue }
                metaHits.append("\(label)/\(place) \(size.intValue) B")
                if label == "安装目录" { metaSeenInInstall = true } else { metaSeenInStage = true }
            }
        }
        if metaHits.isEmpty {
            log("（体检）iTunesMetadata.plist：包内与容器目录都没有（商店包一般有，重签/改壳常被删）")
        } else {
            log("（体检）iTunesMetadata.plist：有（" + metaHits.joined(separator: "、") + "）")
            if metaSeenInInstall && !metaSeenInStage {
                log("（体检）注意：安装目录里有、暂存副本里没有 ⇒ 是拷贝漏了，不是被删")
            }
        }
        for (label, dir) in locations {
            let container = dir.deletingLastPathComponent()
            var marks: [String] = []
            for name in ["BundleMetadata.plist", ".com.apple.mobile_container_manager.metadata.plist"] {
                if manager.fileExists(atPath: container.appendingPathComponent(name).path) {
                    marks.append(name)
                }
            }
            if !marks.isEmpty {
                log("（体检）容器元数据（\(label)）：有（" + marks.joined(separator: "、") + "）"
                    + " ⇒ 这个容器是 installd 建的（不是手工拷进来的目录）")
            }
        }

        // 2b. 时间线：区分「拷进设备时就是这样」和「装完之后被改的」
        logTimes(appDir: appDir, installDir: installDir, log: log)

        // 3. 签名封条
        let resources = appDir.appendingPathComponent("_CodeSignature/CodeResources")
        if let attrs = try? manager.attributesOfItem(atPath: resources.path),
           let size = attrs[.size] as? NSNumber {
            log("（体检）_CodeSignature/CodeResources：有（\(size.intValue) B）")
        } else {
            log("（体检）_CodeSignature/CodeResources：无（签名封条被删过）")
        }

        // 4. 主程序签名类型
        guard let exeName = bundleExecutable(appDir), !exeName.isEmpty else {
            log("（体检）读不到 CFBundleExecutable，跳过签名检查")
            return
        }
        // 主程序优先读原始安装目录里的那一份：暂存副本可能是拷贝出问题的那一份，
        // 「签名段越界」这类结论必须基于原始字节。
        var exe = appDir.appendingPathComponent(exeName)
        if let installDir {
            let original = installDir.appendingPathComponent(exeName)
            if manager.fileExists(atPath: original.path) {
                exe = original
                log("（体检）主程序读取自：原始安装目录（避开暂存副本）")
            }
        }
        guard let facts = binaryFacts(exe) else {
            log("（体检）主程序 \(exeName)：Mach-O 解析失败"
                + (manager.fileExists(atPath: exe.path) ? "" : "（文件不存在）"))
            return
        }
        log("（体检）主程序签名：\(facts.signatureText)")
        log("（体检）签名结构：\(facts.signatureStructure)")

        // 5. 加密区占比 + 正文抽样
        guard let slice = rows.first(where: { $0.path == exeName })?.slices.first else {
            log("（体检）主程序不在扫描结果里，跳过加密区检查")
            return
        }
        let cryptSize = slice.cryptsize
        let textExec = facts.textExecFileSize ?? facts.fileSize
        if textExec > 0 {
            let percent = Double(cryptSize) / Double(textExec) * 100
            log(String(format: "（体检）加密区：0x%llx / __TEXT_EXEC 0x%llx（%.2f%%）· cryptid=%u",
                       cryptSize, textExec, percent, slice.cryptid))
        }

        guard let sample = sampleText(exe, slice: slice, facts: facts) else {
            log("（体检）正文抽样：读不到（文件过大或结构异常）")
            log("（体检）结论：签名\(facts.hasCodeDirectory ? "完整" : "被剥掉")，正文未能采样，无法判断是否被解过")
            return
        }
        log("（体检）正文抽样（加密区之外）：\(sample.detail)")

        // 没有签名时，"代码没被动过"的保证根本不存在；这时正文是不是明文
        // 只决定"改的人有没有顺便解开"，不决定"这包可不可信"。
        if !facts.hasCodeDirectory {
            // 只说事实：这份副本没有签名、正文状态如何。
            // 不再断言「是谁改的」——用户可能在 App Store 里点下载，但真正落地的
            // 字节被设备上的签名工具/主题工具/安装助手改过，这从包里看不出来。
            log("（体检）结论：这份副本**没有签名**（无 CodeDirectory），正文"
                + "\(sample.isPlain ? "是明文" : "仍是密文")"
                + (sample.isPlain
                   ? " ⇒ 它与商店原包不再一致，但也**不需要砸壳**：正文本来就能读，"
                     + "AppDump 会直接清掉 cryptid 按明文出包。"
                   : " ⇒ 加密且无签名，属于半残包，建议改用 A · 内核砸壳。")
                + "\n（体检）如果要干净的原厂字节：App Store 里删掉这个应用再重新下载，"
                + "并且全程不要经过任何签名/主题/安装助手工具。")
        } else {
            log("（体检）结论：\(sample.verdict)")
        }
    }

    // MARK: - 时间线

    /// 打印能回答「谁改的、什么时候改的」的时间戳。
    /// 只看暂存副本没意义（那一层的目录是刚创建的），所以按「安装目录」和
    /// 「暂存副本」分别打，并且明确标注哪一行是安装容器。
    private static func logTimes(appDir: URL, installDir: URL?, log: @escaping (String) -> Void) {
        let manager = FileManager.default
        let big = DateFormatter()
        big.dateFormat = "MM-dd HH:mm:ss"
        func date(_ url: URL) -> Date? {
            (try? manager.attributesOfItem(atPath: url.path))?[.modificationDate] as? Date
        }
        func stamp(_ url: URL) -> String {
            guard let attrs = try? manager.attributesOfItem(atPath: url.path) else { return "读不到" }
            let modified = attrs[.modificationDate] as? Date
            let created = attrs[.creationDate] as? Date
            let text = modified.map { big.string(from: $0) } ?? "—"
            if let created, let modified, abs(created.timeIntervalSince(modified)) > 60 {
                return text + "（创建 " + big.string(from: created) + "）"
            }
            return text
        }
        func dump(_ label: String, _ dir: URL) {
            let container = dir.deletingLastPathComponent()
            log("（体检）时间线（\(label)）：容器 \(stamp(container)) · .app \(stamp(dir))"
                + " · Info.plist \(stamp(dir.appendingPathComponent("Info.plist")))"
                + " · _CodeSignature \(stamp(dir.appendingPathComponent("_CodeSignature/CodeResources")))")
            if let exeName = bundleExecutable(dir) {
                log("（体检）时间线（\(label)）：主程序 \(exeName) \(stamp(dir.appendingPathComponent(exeName)))")
            }
        }

        if let installDir, installDir.path != appDir.path {
            dump("安装目录", installDir)
            // 判读：商店网络安装会把文件写成安装时刻；文件 mtime 比容器创建早很多，
            // 说明这些字节来自一个更早打好的包（本地 IPA / 助手 / 旧副本覆盖安装）。
            let container = installDir.deletingLastPathComponent()
            if let created = (try? manager.attributesOfItem(atPath: container.path))?[.creationDate] as? Date,
               let exeName = bundleExecutable(installDir),
               let exeDate = date(installDir.appendingPathComponent(exeName)),
               created.timeIntervalSince(exeDate) > 3600 {
                let hours = created.timeIntervalSince(exeDate) / 3600
                log(String(format: "（体检）判读：主程序 mtime 比容器创建早 %.0f 小时 ⇒ "
                           + "这些字节来自一个更早打包好的 IPA（商店网络安装会写成安装时刻），"
                           + "不是本次下载刚解出来的原厂字节", hours))
            }
            dump("暂存副本", appDir)
        } else {
            dump("暂存副本", appDir)
        }
    }

    // MARK: - 签名

    private struct Facts {
        var fileSize: UInt64 = 0
        var textExecFileOffset: UInt64 = 0
        var textExecFileSize: UInt64 = 0
        var hasTextExec = false
        var csFlags: UInt32 = 0
        var team: String?
        var hasCodeDirectory = false
        // 签名结构的原始事实：LC_CODE_SIGNATURE 有没有、指向哪、superblob 里有什么。
        // 只说「没有 CodeDirectory」用户没法复核，把数字摊开才算证据。
        var hasCSCommand = false
        var csOffset: UInt64 = 0
        var csSize: UInt64 = 0
        var superblobMagic: UInt32?
        var blobTypes: [UInt32] = []

        private static func blobName(_ type: UInt32) -> String {
            switch type {
            case 0: return "CodeDirectory"
            case 1: return "Requirements"
            case 2: return "Entitlements"
            case 3: return "ResourceDir"
            case 4: return "Application"
            case 5: return "EntitlementsDER"
            case 7: return "LaunchConstraint"
            case 0x1000: return "分析槽"
            default: return "\(type)"
            }
        }

        var signatureStructure: String {
            guard hasCSCommand else {
                return "没有 LC_CODE_SIGNATURE 命令 ⇒ 整段签名（含 CodeDirectory）被删掉了"
            }
            var text = String(format: "LC_CODE_SIGNATURE off=0x%llx size=0x%llx · 文件 0x%llx",
                              csOffset, csSize, fileSize)
            if csSize == 0 { return text + "，size=0（空签名）" }
            if csOffset >= fileSize || csOffset + csSize > fileSize {
                // 签名段指向文件末尾之外：字节被切掉了（典型的「剥签名」做法是
                // 直接把文件尾部裁掉，却忘了把这条 load command 清零）。
                let want = csOffset + csSize
                let excess = want > fileSize ? want - fileSize : 0
                text += String(format: " ⇒ 越界 0x%llx 字节，签名段被切掉了"
                              + "（文件尾部缺失，不是我们读不到）", excess)
                return text
            }
            if let magic = superblobMagic, magic == 0xFADE_0CC0 || magic == 0xFADE_0CC1 {
                text += String(format: " · superblob 0x%x，%d 个 blob", magic, blobTypes.count)
                if !blobTypes.isEmpty {
                    text += "（" + blobTypes.prefix(8).map { Self.blobName($0) }.joined(separator: "、") + "）"
                }
            } else if let magic = superblobMagic {
                text += String(format: " · blob 魔数 0x%x 不是 embedded-signature superblob", magic)
            } else {
                text += " · blob 读不到（csSize 太小或越界）"
            }
            text += hasCodeDirectory ? " · 有 CodeDirectory" : " · 没有 CodeDirectory"
            return text
        }

        var isAdHoc: Bool { hasCodeDirectory && (csFlags & 0x2) != 0 }

        var signatureText: String {
            if !hasCodeDirectory { return "没有 CodeDirectory（未签名/签名被剥掉）" }
            if isAdHoc { return "ad-hoc 假签名（不需要描述文件，常见于自签/免越狱工具）" }
            if let team, !team.isEmpty { return "开发者/企业证书签名（team=\(team)）" }
            return "苹果平台签名（非 ad-hoc、无 team，商店原包特征）"
        }
    }

    private static func bundleExecutable(_ appDir: URL) -> String? {
        let info = appDir.appendingPathComponent("Info.plist")
        guard let data = try? Data(contentsOf: info),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil),
              let dict = plist as? [String: Any],
              let exe = dict["CFBundleExecutable"] as? String else { return nil }
        return exe
    }

    private static func readAt(_ handle: FileHandle, _ offset: UInt64, _ length: Int) -> Data? {
        guard length > 0 else { return nil }
        do {
            try handle.seek(toOffset: offset)
            let data = try handle.read(upToCount: length)
            return data
        } catch {
            return nil
        }
    }

    // 手动拼字节：Data 的底层地址不保证 8 字节对齐，load(as:) 会崩。
    private static func u32(_ data: Data, _ off: Int) -> UInt32? {
        guard off >= 0, off + 4 <= data.count else { return nil }
        return data.withUnsafeBytes { raw -> UInt32 in
            let b = raw.bindMemory(to: UInt8.self)
            return UInt32(b[off]) | (UInt32(b[off + 1]) << 8)
                | (UInt32(b[off + 2]) << 16) | (UInt32(b[off + 3]) << 24)
        }
    }

    private static func u64(_ data: Data, _ off: Int) -> UInt64? {
        guard off >= 0, off + 8 <= data.count else { return nil }
        return data.withUnsafeBytes { raw -> UInt64 in
            let b = raw.bindMemory(to: UInt8.self)
            var value: UInt64 = 0
            for index in 0..<8 { value |= UInt64(b[off + index]) << (8 * UInt64(index)) }
            return value
        }
    }

    /// 解析主程序：__TEXT_EXEC 尺寸 + CodeDirectory 的 flags/team。
    private static func binaryFacts(_ url: URL) -> Facts? {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }
        let attrs = try? FileManager.default.attributesOfItem(atPath: url.path)
        let size = (attrs?[.size] as? NSNumber)?.uint64Value ?? 0
        guard size > 32 else { return nil }
        var facts = Facts()
        facts.fileSize = size

        guard let head = readAt(handle, 0, 4096) else { return nil }
        guard let magic = u32(head, 0) else { return nil }
        var sliceOff: UInt64 = 0
        if magic == FPMachO.fatMagic || magic == FPMachO.fatMagic64 {
            // 取第一个 64 位切片（arm64 / arm64e）
            let is64 = magic == FPMachO.fatMagic64
            guard let count = u32(head, 4) else { return nil }
            let stride = is64 ? 32 : 20
            for index in 0..<Int(min(count, 16)) {
                let base = 8 + index * stride
                guard let cputype = u32(head, base) else { break }
                guard (cputype & 0x0100_0000) != 0 else { continue }
                if is64 {
                    guard let off = u64(head, base + 8) else { continue }
                    sliceOff = off
                } else {
                    guard let off = u32(head, base + 8) else { continue }
                    sliceOff = UInt64(off)
                }
                break
            }
        } else if magic != FPMachO.magic64 {
            return nil
        }

        guard let header = readAt(handle, sliceOff, 32),
              let ncmds = u32(header, 16),
              let sizeofcmds = u32(header, 20) else { return nil }
        guard sizeofcmds > 0, sizeofcmds <= 16 * 1024 * 1024,
              Int(sizeofcmds) + 32 <= 16 * 1024 * 1024 + 32 else { return nil }
        guard let cmds = readAt(handle, sliceOff + 32, Int(sizeofcmds)) else { return nil }

        var position = 0
        var csOffset: UInt64?
        var csSize: UInt64 = 0
        for _ in 0..<Int(min(ncmds, 4096)) {
            guard position + 8 <= cmds.count else { break }
            guard let cmd = u32(cmds, position), let cmdsize = u32(cmds, position + 4) else { break }
            guard cmdsize >= 8, position + Int(cmdsize) <= cmds.count else { break }
            if cmd == 0x19 { // LC_SEGMENT_64
                let nameStart = position + 8
                if nameStart + 16 <= cmds.count {
                    let raw = cmds.subdata(in: nameStart..<(nameStart + 16))
                    let segname = String(data: raw.prefix(while: { $0 != 0 }), encoding: .utf8) ?? ""
                    if segname == "__TEXT_EXEC" {
                        if let fileoff = u64(cmds, nameStart + 32),
                           let filesize = u64(cmds, nameStart + 40) {
                            facts.textExecFileOffset = fileoff
                            facts.textExecFileSize = filesize
                            facts.hasTextExec = true
                        }
                    }
                }
            } else if cmd == 0x1d { // LC_CODE_SIGNATURE
                if let dataoff = u32(cmds, position + 8), let datasize = u32(cmds, position + 12) {
                    csOffset = sliceOff + UInt64(dataoff)
                    csSize = UInt64(datasize)
                    facts.hasCSCommand = true
                    facts.csOffset = sliceOff + UInt64(dataoff)
                    facts.csSize = UInt64(datasize)
                }
            }
            position += Int(cmdsize)
        }

        if let csOffset, csSize > 12, let blob = readAt(handle, csOffset, Int(min(csSize, 128 * 1024))) {
            if let magicSb = u32(blob, 0), magicSb == 0xFADE_0CC0 || magicSb == 0xFADE_0CC1 {
                facts.superblobMagic = magicSb
                let count = Int(u32(blob, 8) ?? 0)
                for index in 0..<min(count, 32) {
                    let base = 12 + index * 8
                    guard let type = u32(blob, base), let offset = u32(blob, base + 4) else { break }
                    facts.blobTypes.append(type)
                    guard type == 0 else { continue } // CSSLOT_CODEDIRECTORY
                    let cdStart = Int(offset)
                    guard cdStart + 44 <= blob.count, let cdMagic = u32(blob, cdStart),
                          cdMagic == 0xFADE_0C02 else { continue }
                    facts.hasCodeDirectory = true
                    facts.csFlags = u32(blob, cdStart + 12) ?? 0
                    let version = u32(blob, cdStart + 8) ?? 0
                    if version >= 0x0002_0200, cdStart + 52 <= blob.count,
                       let teamOffset = u32(blob, cdStart + 48), teamOffset > 0 {
                        let start = cdStart + Int(teamOffset)
                        if start < blob.count {
                            let tail = blob.subdata(in: start..<min(blob.count, start + 64))
                            facts.team = String(data: tail.prefix(while: { $0 != 0 }), encoding: .utf8)
                        }
                    }
                    break
                }
            }
        }
        return facts
    }

    private static func profileTeamIdentifier(_ url: URL) -> String? {
        guard let data = try? Data(contentsOf: url), data.count < 2 * 1024 * 1024 else { return nil }
        // 描述文件是 CMS 包装的 plist，直接找 TeamIdentifier 后面的 <string>
        guard let marker = "<key>TeamIdentifier</key>".data(using: .utf8),
              let range = data.range(of: marker) else { return nil }
        let tail = data.subdata(in: range.upperBound..<min(data.count, range.upperBound + 256))
        guard let text = String(data: tail, encoding: .utf8),
              let start = text.range(of: "<string>"),
              let end = text.range(of: "</string>", range: start.upperBound..<text.endIndex) else { return nil }
        return String(text[start.upperBound..<end.lowerBound])
    }

    // MARK: - 正文抽样

    private struct Sample {
        let detail: String
        let verdict: String
        let isPlain: Bool
    }

    private static func sampleText(_ url: URL, slice: FPMachO.Slice, facts: Facts) -> Sample? {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return nil }
        defer { try? handle.close() }

        let start = slice.sliceOffset + (facts.hasTextExec ? facts.textExecFileOffset : 0)
        guard facts.fileSize > start else { return nil }
        let length = facts.hasTextExec ? facts.textExecFileSize : (facts.fileSize - start)
        guard length > 0x20000 else { return nil }

        // 三个采样点：跳过表头和加密区，避免把高熵数据段当成代码
        let cryptStart = slice.sliceOffset + slice.cryptoff
        let cryptEnd = cryptStart + slice.cryptsize
        var points: [UInt64] = []
        for fraction in [0.10, 0.50, 0.90] {
            var point = start + UInt64(Double(length) * fraction)
            if point >= cryptStart && point < cryptEnd {
                point = cryptEnd + 0x10000 < start + length ? cryptEnd + 0x10000 : start
            }
            if point + 0x10000 <= start + length { points.append(point) }
        }
        guard !points.isEmpty else { return nil }

        var details: [String] = []
        var lowEntropy = 0, codey = 0
        for point in points {
            guard let chunk = readAt(handle, point, 0x10000) else { continue }
            let stats = FPCodeStats()
            chunk.withUnsafeBytes { raw in
                if let base = raw.bindMemory(to: UInt8.self).baseAddress {
                    stats.feed(base, raw.count)
                }
            }
            guard stats.total > 0 else { continue }
            if stats.entropy < 7.3 { lowEntropy += 1 }
            if stats.codeWords > 20 { codey += 1 }
            details.append(String(format: "@0x%llx 熵 %.2f 地标 %d", point, stats.entropy, stats.codeWords))
        }
        guard !details.isEmpty else { return nil }

        let verdict: String
        if codey == details.count && lowEntropy == details.count {
            verdict = "正文已是明文代码 ⇒ 这份包被解过/改过壳，不是商店原样"
        } else if lowEntropy == 0 {
            verdict = "正文仍是密文（熵 ~8.0）⇒ 看起来是商店原样加密包"
        } else {
            verdict = "正文部分明文、部分密文 ⇒ 混合包（多半被解过一部分）"
        }
        return Sample(detail: details.joined(separator: " · "), verdict: verdict,
                      isPlain: lowEntropy == details.count)
    }
}