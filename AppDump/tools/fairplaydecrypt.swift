//
//  fairplaydecrypt.swift
//  AppDump
//
//  FairPlay（App Store DRM）本机解密 —— 我们的第二条解密路线，不需要内核漏洞。
//
//  机制（详见 fairplay/FairPlayCore.h）：
//    把加密 Mach-O 以 PROT_READ 映射进来，调 mremap_encrypted(cryptid 2)，
//    内核会走 vm_map_apple_protected → FairPlayIOKit → fairplayd 就地解密；
//    fairplayd 按 <dir>/SC_Info/<name>.sinf 就近取授权，所以只需把 SINF
//    摆到二进制旁边。之后用 vm_read_overwrite 回读明文（分页失败返回
//    kern_return_t 而不是 SIGBUS）。
//
//  与内核砸壳（decrypt.m）的分工：
//    * 内核砸壳：只有已安装应用、没有 IPA 时用；需要漏洞链，风险在内核里。
//    * FairPlay：有原始加密 IPA 时用；不需要漏洞，失败只是 errno。
//
//  本文件包含：流式 ZIP 读写封装、Mach-O 切片扫描、SINF 复制、解密流水线、
//  产物校验。ZIP 解包全部走 pread + 流式 inflate，避免把几 GB 的包读进内存。
//

import Foundation
import Darwin
import zlib

// MARK: - 错误

enum FPError: LocalizedError {
    case noStaging
    case badArchive(String)
    case noPayload
    case alreadyPlain
    case refused(String)
    case packFailed(String)
    case noSpace(Int64, Int64)
    case cancelled
    case busy
    case unsupported(String)

    var errorDescription: String? {
        switch self {
        case .noStaging:
            return "没有可写的暂存目录。fairplayd 只接受 App Group 容器；本 App 签名没有 App Group 权限时，可开启「允许写入 App 包内暂存（会临时破坏签名封条）」。"
        case .badArchive(let detail):
            return "安装包解压失败：\(detail)"
        case .noPayload:
            return "安装包里没有 Payload/*.app"
        case .alreadyPlain:
            return "包内所有 Mach-O 都是明文（cryptid = 0），无需解密"
        case .refused(let detail):
            return "FairPlay 拒绝解密：\(detail)"
        case .packFailed(let detail):
            return "重新打包失败：\(detail)"
        case .noSpace(let free, let need):
            return "空间不足：可用 \(fpSizeText(free))，预计需要 \(fpSizeText(need))"
        case .cancelled:
            return "已取消"
        case .busy:
            return "已有解密任务在进行"
        case .unsupported(let detail):
            return detail
        }
    }
}

// MARK: - C 日志回调

/// 每次调用一个实例，作为 C 回调的上下文，避免并发时日志串台。
final class FPLogSink {
    private let lock = NSLock()
    private var buffer: [String] = []
    private let handler: (String) -> Void

    init(handler: @escaping (String) -> Void) { self.handler = handler }

    func append(_ line: String) {
        lock.lock()
        buffer.append(line)
        lock.unlock()
        handler(line)
    }

    var last: String? {
        lock.lock()
        defer { lock.unlock() }
        return buffer.last
    }
}

private let fpCoreLogTrampoline: @convention(c) (UnsafeMutableRawPointer?, UnsafePointer<CChar>?) -> Void = { ctx, message in
    guard let ctx = ctx, let message = message else { return }
    Unmanaged<FPLogSink>.fromOpaque(ctx).takeUnretainedValue().append(String(cString: message))
}

// MARK: - CRC32（增量，自己算，避免依赖 zlib 的 crc32 签名）

private let fpCRCTable: [UInt32] = {
    var table = [UInt32](repeating: 0, count: 256)
    for i in 0..<256 {
        var c = UInt32(i)
        for _ in 0..<8 {
            c = (c & 1) != 0 ? (0xEDB88320 ^ (c >> 1)) : (c >> 1)
        }
        table[i] = c
    }
    return table
}()

private func fpCRCUpdate(_ crc: UInt32, _ ptr: UnsafePointer<UInt8>, _ count: Int) -> UInt32 {
    var c = crc
    for i in 0..<count {
        c = fpCRCTable[Int((c ^ UInt32(ptr[i])) & 0xFF)] ^ (c >> 8)
    }
    return c
}

// MARK: - 小端读取

private func fpLE16(_ d: Data, _ offset: Int) -> UInt16 {
    guard offset >= 0, offset + 2 <= d.count else { return 0 }
    return d.withUnsafeBytes { UInt16(littleEndian: $0.loadUnaligned(fromByteOffset: offset, as: UInt16.self)) }
}

private func fpLE32(_ d: Data, _ offset: Int) -> UInt32 {
    guard offset >= 0, offset + 4 <= d.count else { return 0 }
    return d.withUnsafeBytes { UInt32(littleEndian: $0.loadUnaligned(fromByteOffset: offset, as: UInt32.self)) }
}

private func fpLE64(_ d: Data, _ offset: Int) -> UInt64 {
    guard offset >= 0, offset + 8 <= d.count else { return 0 }
    return d.withUnsafeBytes { UInt64(littleEndian: $0.loadUnaligned(fromByteOffset: offset, as: UInt64.self)) }
}

private func fpBE32(_ d: Data, _ offset: Int) -> UInt32 {
    guard offset >= 0, offset + 4 <= d.count else { return 0 }
    return d.withUnsafeBytes { UInt32(bigEndian: $0.loadUnaligned(fromByteOffset: offset, as: UInt32.self)) }
}

// MARK: - ZIP 条目 / 流式读取

struct FPZipEntry {
    let path: String
    let method: UInt16
    let crc: UInt32
    let compressedSize: UInt64
    let uncompressedSize: UInt64
    let localHeaderOffset: UInt64
    let externalAttrs: UInt32

    var isDirectory: Bool { path.hasSuffix("/") }
    var unixMode: UInt16 { UInt16(truncatingIfNeeded: (externalAttrs >> 16) & 0xFFFF) }
    var isSymlink: Bool { (unixMode & 0xF000) == 0xA000 }
    var isExecutable: Bool { (unixMode & 0o111) != 0 }
}

/// 只读、流式的 ZIP 读取器：中央目录一次读入（很小），条目内容按需 pread +
/// 流式 inflate，内存占用与包体积无关。
final class FPZipReader {
    private let url: URL
    private let handle: FileHandle
    private let fileSize: UInt64
    private(set) var entries: [FPZipEntry] = []

    init(url: URL) throws {
        self.url = url
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: url.path),
              let sizeValue = attrs[.size] as? NSNumber else {
            throw FPError.badArchive("无法读取文件大小")
        }
        let size = sizeValue.uint64Value
        guard size >= 22 else { throw FPError.badArchive("文件太小，不是 zip") }
        self.fileSize = size
        self.handle = try FileHandle(forReadingFrom: url)
        try parseCentralDirectory()
    }

    deinit { try? handle.close() }

    // MARK: 底层读取

    private func readAt(_ offset: UInt64, _ length: Int) throws -> Data {
        guard offset <= fileSize, length >= 0 else { return Data() }
        let capped = Int(min(UInt64(length), fileSize - offset))
        guard capped > 0 else { return Data() }
        try handle.seek(toOffset: offset)
        return try handle.read(upToCount: capped) ?? Data()
    }

    private func decodeName(_ raw: Data, utf8Flag: Bool) -> String {
        if utf8Flag, let text = String(data: raw, encoding: .utf8) { return text }
        if let text = String(data: raw, encoding: .utf8) { return text }
        return String(cp437: raw)
    }

    // MARK: 中央目录

    private func parseCentralDirectory() throws {
        let tailLength = Int(min(fileSize, 65557 + 22))
        let tail = try readAt(fileSize - UInt64(tailLength), tailLength)
        var eocd = -1
        var scan = tail.count - 22
        while scan >= 0 {
            if fpLE32(tail, scan) == 0x06054b50 { eocd = scan; break }
            scan -= 1
        }
        guard eocd >= 0 else { throw FPError.badArchive("找不到 zip 中央目录（文件可能不完整）") }

        var total = UInt64(fpLE16(tail, eocd + 10))
        var cdSize = UInt64(fpLE32(tail, eocd + 12))
        var cdOffset = UInt64(fpLE32(tail, eocd + 16))

        if total == 0xFFFF || cdSize == 0xFFFF_FFFF || cdOffset == 0xFFFF_FFFF {
            // zip64：EOCD 前 20 字节是 locator
            if eocd >= 20, fpLE32(tail, eocd - 20) == 0x07064b50 {
                let z64Offset = fpLE64(tail, eocd - 20 + 8)
                let record = try readAt(z64Offset, 56)
                if record.count >= 56, fpLE32(record, 0) == 0x06064b50 {
                    total = fpLE64(record, 32)
                    cdSize = fpLE64(record, 40)
                    cdOffset = fpLE64(record, 48)
                }
            }
        }

        guard cdSize > 0, cdSize <= 512 * 1024 * 1024, cdOffset <= fileSize else {
            throw FPError.badArchive("中央目录越界")
        }
        let directory = try readAt(cdOffset, Int(cdSize))
        var position = 0
        var guardCount = 0
        while position + 46 <= directory.count {
            guardCount += 1
            if guardCount > 2_000_000 { break }
            guard fpLE32(directory, position) == 0x02014b50 else { break }

            let flags = fpLE16(directory, position + 8)
            let method = fpLE16(directory, position + 10)
            let crc = fpLE32(directory, position + 16)
            var compressed = UInt64(fpLE32(directory, position + 20))
            var uncompressed = UInt64(fpLE32(directory, position + 24))
            let nameLength = Int(fpLE16(directory, position + 28))
            let extraLength = Int(fpLE16(directory, position + 30))
            let commentLength = Int(fpLE16(directory, position + 32))
            let attributes = fpLE32(directory, position + 38)
            var headerOffset = UInt64(fpLE32(directory, position + 42))

            let nameStart = position + 46
            let nameEnd = nameStart + nameLength
            let extraEnd = nameEnd + extraLength
            guard extraEnd + commentLength <= directory.count else { break }
            let nameData = directory.subdata(in: nameStart..<nameEnd)

            if uncompressed == 0xFFFF_FFFF || compressed == 0xFFFF_FFFF || headerOffset == 0xFFFF_FFFF {
                let extra = directory.subdata(in: nameEnd..<extraEnd)
                var cursor = 0
                while cursor + 4 <= extra.count {
                    let tag = fpLE16(extra, cursor)
                    let length = Int(fpLE16(extra, cursor + 2))
                    if cursor + 4 + length > extra.count { break }
                    if tag == 0x0001 {
                        var field = cursor + 4
                        let limit = cursor + 4 + length
                        if uncompressed == 0xFFFF_FFFF, field + 8 <= limit {
                            uncompressed = fpLE64(extra, field); field += 8
                        }
                        if compressed == 0xFFFF_FFFF, field + 8 <= limit {
                            compressed = fpLE64(extra, field); field += 8
                        }
                        if headerOffset == 0xFFFF_FFFF, field + 8 <= limit {
                            headerOffset = fpLE64(extra, field); field += 8
                        }
                    }
                    cursor += 4 + length
                }
            }

            entries.append(FPZipEntry(path: decodeName(nameData, utf8Flag: (flags & 0x0800) != 0),
                                      method: method,
                                      crc: crc,
                                      compressedSize: compressed,
                                      uncompressedSize: uncompressed,
                                      localHeaderOffset: headerOffset,
                                      externalAttrs: attributes))
            position = extraEnd + commentLength
        }

        guard !entries.isEmpty else { throw FPError.badArchive("压缩包里没有任何条目") }
    }

    // MARK: 条目数据

    private func dataOffset(of entry: FPZipEntry) throws -> UInt64 {
        let header = try readAt(entry.localHeaderOffset, 30)
        guard header.count >= 30, fpLE32(header, 0) == 0x04034b50 else {
            throw FPError.badArchive("本地文件头损坏：\(entry.path)")
        }
        let nameLength = UInt64(fpLE16(header, 26))
        let extraLength = UInt64(fpLE16(header, 28))
        return entry.localHeaderOffset + 30 + nameLength + extraLength
    }

    /// 把条目解压后 [from, from+length) 这段数据按块交给 consume。
    /// consume 参数：数据指针 / 长度 / 该块在解压后数据里的绝对偏移。
    func stream(_ entry: FPZipEntry, from: UInt64, length: UInt64,
                consume: (UnsafePointer<UInt8>, Int, UInt64) -> Void) throws {
        let dataStart = try dataOffset(of: entry)
        let end = from &+ length

        if entry.method == 0 {
            var offset = min(from, entry.compressedSize)
            let stop = min(end, entry.compressedSize)
            let capacity = 1 << 20
            let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: capacity)
            defer { buffer.deallocate() }
            while offset < stop {
                let want = Int(min(UInt64(capacity), stop - offset))
                let chunk = try readAt(dataStart + offset, want)
                if chunk.isEmpty { break }
                chunk.withUnsafeBytes { raw in
                    if let base = raw.baseAddress?.assumingMemoryBound(to: UInt8.self) {
                        consume(base, chunk.count, offset)
                    }
                }
                offset += UInt64(chunk.count)
            }
            return
        }

        guard entry.method == 8 else {
            throw FPError.unsupported("不支持的压缩方式 \(entry.method)（条目 \(entry.path)）")
        }

        var zs = z_stream()
        let initResult = inflateInit2_(&zs, -15, ZLIB_VERSION, Int32(MemoryLayout<z_stream>.size))
        guard initResult == Z_OK else {
            throw FPError.badArchive("zlib 初始化失败（\(initResult)）")
        }
        defer { inflateEnd(&zs) }

        let inCapacity = 256 * 1024
        let outCapacity = 512 * 1024
        let inBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: inCapacity)
        let outBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: outCapacity)
        defer {
            inBuffer.deallocate()
            outBuffer.deallocate()
        }

        var remaining = entry.compressedSize
        var producedTotal: UInt64 = 0
        try handle.seek(toOffset: dataStart)

        while true {
            if zs.avail_in == 0, remaining > 0 {
                let want = Int(min(UInt64(inCapacity), remaining))
                let chunk = try handle.read(upToCount: want) ?? Data()
                if chunk.isEmpty { throw FPError.badArchive("压缩数据被截断：\(entry.path)") }
                chunk.copyBytes(to: inBuffer, count: chunk.count)
                zs.next_in = inBuffer
                zs.avail_in = uInt(chunk.count)
                remaining -= UInt64(chunk.count)
            }

            zs.next_out = outBuffer
            zs.avail_out = uInt(outCapacity)
            let result = inflate(&zs, Z_NO_FLUSH)
            let produced = outCapacity - Int(zs.avail_out)

            if produced > 0 {
                let chunkStart = producedTotal
                let chunkEnd = producedTotal + UInt64(produced)
                producedTotal = chunkEnd
                let overlapStart = max(from, chunkStart)
                let overlapEnd = min(end, chunkEnd)
                if overlapEnd > overlapStart {
                    let skip = Int(overlapStart - chunkStart)
                    consume(UnsafePointer<UInt8>(outBuffer + skip), Int(overlapEnd - overlapStart), overlapStart)
                }
                if chunkEnd >= end { return }
            }

            if result == Z_STREAM_END { return }
            if result != Z_OK && result != Z_BUF_ERROR {
                throw FPError.badArchive("解压失败（\(result)）：\(entry.path)")
            }
            if result == Z_BUF_ERROR, remaining == 0, zs.avail_in == 0, produced == 0 {
                throw FPError.badArchive("压缩数据提前结束：\(entry.path)")
            }
        }
    }

    /// 解压整个条目到磁盘，并校验 CRC / 大小。
    @discardableResult
    func extract(_ entry: FPZipEntry, to destination: URL) throws -> UInt64 {
        let manager = FileManager.default
        try? manager.removeItem(at: destination)
        guard manager.createFile(atPath: destination.path, contents: nil) else {
            throw FPError.badArchive("无法创建文件：\(destination.lastPathComponent)")
        }
        let output = try FileHandle(forWritingTo: destination)
        defer { try? output.close() }

        var crc: UInt32 = 0xFFFF_FFFF
        var written: UInt64 = 0
        try stream(entry, from: 0, length: entry.uncompressedSize) { pointer, count, _ in
            output.write(Data(bytes: pointer, count: count))
            crc = fpCRCUpdate(crc, pointer, count)
            written += UInt64(count)
        }
        let finalCRC = crc ^ 0xFFFF_FFFF
        guard written == entry.uncompressedSize, finalCRC == entry.crc else {
            throw FPError.badArchive("条目校验失败：\(entry.path)")
        }
        return written
    }
}

// MARK: - 体积显示

func fpSizeText(_ bytes: Int64) -> String {
    let units = ["B", "KB", "MB", "GB"]
    var value = Double(max(bytes, 0))
    var index = 0
    while value >= 1024, index < units.count - 1 {
        value /= 1024
        index += 1
    }
    return index == 0 ? "\(Int(value)) \(units[index])" : String(format: "%.1f %@", value, units[index])
}

// MARK: - Mach-O 扫描

enum FPMachO {
    struct Slice {
        let sliceOffset: UInt64
        let cputype: UInt32
        let cpusubtype: UInt32
        let cryptoff: UInt64
        let cryptsize: UInt64
        let cryptid: UInt32
    }

    static let magic64: UInt32 = 0xFEED_FACF
    static let fatMagic: UInt32 = 0xBEBA_FECA      // FAT_CIGAM
    static let fatMagic64: UInt32 = 0xBFBA_FECA    // FAT_CIGAM_64

    private static let lcEncryptionInfo: UInt32 = 0x21
    private static let lcEncryptionInfo64: UInt32 = 0x2C

    /// 从随机读闭包里解析一个 thin slice。base = slice 在数据里的起始偏移。
    private static func parseThin(read: (UInt64, Int) throws -> Data,
                                  base: UInt64,
                                  limit: UInt64) throws -> Slice? {
        let header = try read(base, 32)
        guard header.count >= 32, fpLE32(header, 0) == magic64 else { return nil }
        let cputype = fpLE32(header, 4)
        let cpusubtype = fpLE32(header, 8)
        let ncmds = fpLE32(header, 16)
        let sizeofcmds = fpLE32(header, 20)
        guard sizeofcmds > 0, sizeofcmds < 16 * 1024 * 1024, UInt64(sizeofcmds) <= limit else { return nil }
        let commands = try read(base + 32, Int(sizeofcmds))
        guard commands.count == Int(sizeofcmds) else { return nil }

        var position = 0
        var found: (cryptoff: UInt32, cryptsize: UInt32, cryptid: UInt32)? = nil
        for _ in 0..<ncmds {
            guard position + 8 <= commands.count else { break }
            let cmd = fpLE32(commands, position)
            let size = fpLE32(commands, position + 4)
            guard size >= 8, (size & 3) == 0, position + Int(size) <= commands.count else { break }
            if cmd == lcEncryptionInfo || cmd == lcEncryptionInfo64 {
                let needed = cmd == lcEncryptionInfo64 ? 24 : 20
                if Int(size) >= needed, position + needed <= commands.count {
                    let candidate = (fpLE32(commands, position + 8),
                                     fpLE32(commands, position + 12),
                                     fpLE32(commands, position + 16))
                    if found == nil || (found!.cryptid == 0 && candidate.2 != 0) {
                        found = candidate
                    }
                }
            }
            position += Int(size)
        }
        guard let result = found else { return nil }
        return Slice(sliceOffset: base,
                     cputype: cputype,
                     cpusubtype: cpusubtype,
                     cryptoff: UInt64(result.cryptoff),
                     cryptsize: UInt64(result.cryptsize),
                     cryptid: result.cryptid)
    }

    /// 通用入口：thin 或 FAT（只收 64 位切片）。
    static func slices(read: (UInt64, Int) throws -> Data, size: UInt64) throws -> [Slice] {
        guard size >= 32 else { return [] }
        let head = try read(0, 8)
        guard head.count >= 8 else { return [] }
        let magic = fpLE32(head, 0)
        if magic == magic64 {
            if let slice = try parseThin(read: read, base: 0, limit: size) { return [slice] }
            return []
        }
        guard magic == fatMagic || magic == fatMagic64 else { return [] }

        let is64 = magic == fatMagic64
        let stride = is64 ? 32 : 20
        let count = Int(min(fpBE32(head, 4), 64))
        guard count > 0 else { return [] }
        let table = try read(8, count * stride)
        guard table.count == count * stride else { return [] }

        var result: [Slice] = []
        for index in 0..<count {
            let row = index * stride
            let cputype = fpBE32(table, row)
            guard cputype & 0x0100_0000 != 0 else { continue }
            let offset: UInt64
            let sliceSize: UInt64
            if is64 {
                offset = table.withUnsafeBytes { UInt64(bigEndian: $0.loadUnaligned(fromByteOffset: row + 8, as: UInt64.self)) }
                sliceSize = table.withUnsafeBytes { UInt64(bigEndian: $0.loadUnaligned(fromByteOffset: row + 16, as: UInt64.self)) }
            } else {
                offset = UInt64(fpBE32(table, row + 8))
                sliceSize = UInt64(fpBE32(table, row + 12))
            }
            guard offset < size else { continue }
            let limit = sliceSize > 0 ? min(sliceSize, size - offset) : (size - offset)
            if let slice = try parseThin(read: read, base: offset, limit: limit) {
                result.append(slice)
            }
        }
        return result
    }

    /// 文件版：只读头部，几 MB 的小文件也不会整读。
    static func slices(ofFileAt url: URL) -> [Slice] {
        guard let attrs = try? FileManager.default.attributesOfItem(atPath: url.path),
              let sizeValue = attrs[.size] as? NSNumber,
              sizeValue.uint64Value >= 32,
              let handle = try? FileHandle(forReadingFrom: url) else { return [] }
        defer { try? handle.close() }
        let size = sizeValue.uint64Value
        let read: (UInt64, Int) throws -> Data = { offset, length in
            guard offset <= size else { return Data() }
            let capped = Int(min(UInt64(length), size - offset))
            guard capped > 0 else { return Data() }
            try handle.seek(toOffset: offset)
            return try handle.read(upToCount: capped) ?? Data()
        }
        return (try? slices(read: read, size: size)) ?? []
    }

    static func isMachO(_ url: URL) -> Bool {
        guard let handle = try? FileHandle(forReadingFrom: url) else { return false }
        defer { try? handle.close() }
        guard let head = try? handle.read(upToCount: 4), head.count == 4 else { return false }
        let magic = fpLE32(head, 0)
        return magic == magic64 || magic == fatMagic || magic == fatMagic64
    }

    /// 扫描整个 bundle，返回每个 Mach-O 的切片及 cryptid。
    static func scanTree(_ root: URL) -> [(path: String, slices: [Slice])] {
        let manager = FileManager.default
        guard let walker = manager.enumerator(atPath: root.path) else { return [] }
        var rows: [(String, [Slice])] = []
        while let relative = walker.nextObject() as? String {
            let components = relative.split(separator: "/", omittingEmptySubsequences: true)
            if components.contains(where: { $0.hasPrefix(".") }) {
                if let type = walker.fileAttributes?[.type] as? FileAttributeType, type == .typeDirectory {
                    walker.skipDescendants()
                }
                continue
            }
            if let type = walker.fileAttributes?[.type] as? FileAttributeType, type != .typeRegular { continue }
            let normalized = components.joined(separator: "/")
            guard !normalized.isEmpty else { continue }
            let url = root.appendingPathComponent(normalized)
            guard isMachO(url) else { continue }
            let found = slices(ofFileAt: url)
            guard !found.isEmpty else { continue }
            rows.append((normalized, found))
        }
        return rows.sorted { $0.0 < $1.0 }
    }
}

// MARK: - 路径安全

enum FPPaths {
    /// 拒绝绝对路径、反斜杠、NUL、以及任何 "." / ".." / 空段。
    static func isSafeRelative(_ raw: String) -> Bool {
        guard !raw.isEmpty, !raw.hasPrefix("/"), !raw.contains("\\"), !raw.contains("\0") else { return false }
        var normalized = raw
        while normalized.contains("//") { normalized = normalized.replacingOccurrences(of: "//", with: "/") }
        if normalized.hasSuffix("/") { normalized.removeLast() }
        guard !normalized.isEmpty else { return false }
        let parts = normalized.split(separator: "/", omittingEmptySubsequences: false)
        return !parts.isEmpty && parts.allSatisfy { !$0.isEmpty && $0 != "." && $0 != ".." }
    }

    static func join(_ root: URL, _ relative: String) -> URL? {
        guard isSafeRelative(relative) else { return nil }
        var current = root.standardizedFileURL
        for part in relative.split(separator: "/") {
            current = current.appendingPathComponent(String(part))
        }
        return current
    }
}

// MARK: - SINF 复制

enum FPSinf {
    /// fairplayd 按 `<dir>/SC_Info/<name>.sinf` 就近取授权：包里每个加密的
    /// Mach-O 旁边都必须有同名 SINF。商店 IPA 只带一份 SINF 加一份
    /// SinfReplicationPaths 清单（installd 安装时才展开），这里手动展开，
    /// 并且对真实树上每个加密二进制补齐 —— 清单里的历史路径常写成
    /// `Extensions/...`，实际是 `PlugIns/...`，只按清单铺会漏掉嵌套 appex。
    @discardableResult
    static func replicate(appDir: URL,
                          machos: [(path: String, slices: [FPMachO.Slice])],
                          log: (String) -> Void) -> Int {
        let manager = FileManager.default
        guard let manifestURL = FPPaths.join(appDir, "SC_Info/Manifest.plist"),
              let data = try? Data(contentsOf: manifestURL),
              let plist = try? PropertyListSerialization.propertyList(from: data, format: nil),
              let manifest = plist as? [String: Any] else {
            log("没有 SC_Info/Manifest.plist，跳过 SINF 复制")
            return 0
        }

        let declaredSources = (manifest["SinfPaths"] as? [String]) ?? []
        guard let firstName = declaredSources.first,
              let sourceURL = FPPaths.join(appDir, firstName),
              let values = try? sourceURL.resourceValues(forKeys: [.isRegularFileKey, .isSymbolicLinkKey]),
              values.isRegularFile == true,
              values.isSymbolicLink != true else {
            log("主 SINF 不可读（SinfPaths 共 \(declaredSources.count) 条）")
            return 0
        }

        var targets = (manifest["SinfReplicationPaths"] as? [String]) ?? []
        for macho in machos where macho.slices.contains(where: { $0.cryptid != 0 }) {
            let parent = (macho.path as NSString).deletingLastPathComponent
            let name = (macho.path as NSString).lastPathComponent
            targets.append(parent.isEmpty ? "SC_Info/\(name).sinf" : "\(parent)/SC_Info/\(name).sinf")
        }

        var copied = 0
        var seen = Set<String>()
        for target in targets {
            guard target.lowercased().hasSuffix(".sinf"), seen.insert(target).inserted,
                  let destination = FPPaths.join(appDir, target) else { continue }
            if manager.fileExists(atPath: destination.path) { continue }
            try? manager.createDirectory(at: destination.deletingLastPathComponent(),
                                         withIntermediateDirectories: true)
            if (try? manager.copyItem(at: sourceURL, to: destination)) != nil { copied += 1 }
        }
        return copied
    }
}

// MARK: - 暂存目录

enum FPStage {
    static var documents: URL {
        FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
    }

    static var decryptedDirectory: URL {
        documents.appendingPathComponent("Decrypted", isDirectory: true)
    }

    /// 签名时写入的 embedded.mobileprovision 所授权的 App Group。
    static func profileGroups() -> [String] {
        guard let url = Bundle.main.url(forResource: "embedded", withExtension: "mobileprovision"),
              let raw = try? Data(contentsOf: url),
              let start = raw.range(of: Data("<?xml".utf8)),
              let end = raw.range(of: Data("</plist>".utf8), options: .backwards),
              start.lowerBound < end.upperBound,
              let plist = try? PropertyListSerialization.propertyList(
                    from: raw.subdata(in: start.lowerBound..<end.upperBound), format: nil),
              let dictionary = plist as? [String: Any],
              let entitlements = dictionary["Entitlements"] as? [String: Any],
              let groups = entitlements["com.apple.security.application-groups"] as? [String]
        else { return [] }
        return groups
    }

    static func groupIdentifiers() -> [String] {
        var values: [String] = []
        if let configured = Bundle.main.object(forInfoDictionaryKey: "FairPlayAppGroup") as? String,
           !configured.isEmpty {
            values.append(configured)
        }
        values.append(contentsOf: profileGroups())
        values.append(contentsOf: ["group.b049540b2af108ef.1", "group.b049540b2af108ef.2"])
        var seen = Set<String>()
        return values.filter { seen.insert($0).inserted }
    }

    static func isWritable(_ url: URL) -> Bool {
        let probe = url.appendingPathComponent(".fp-probe-\(UUID().uuidString)")
        do {
            try Data("ok".utf8).write(to: probe, options: .atomic)
            try FileManager.default.removeItem(at: probe)
            return true
        } catch {
            return false
        }
    }

    /// 返回 (说明, 根目录)。fairplayd 只认 App Group 容器，所以优先用它；
    /// 没有 App Group 权限时退到 App 包内（运行期可写，但会破坏签名封条，
    /// 只有用户显式允许才用，且运行结束会删掉）；最后才试 Documents。
    static func prepare(allowBundle: Bool) -> (String, URL)? {
        let manager = FileManager.default
        for group in groupIdentifiers() {
            if let url = manager.containerURL(forSecurityApplicationGroupIdentifier: group) {
                try? manager.createDirectory(at: url, withIntermediateDirectories: true)
                if isWritable(url) { return ("App Group \(group)", url) }
            }
        }
        if allowBundle {
            let bundleRoot = Bundle.main.bundleURL.appendingPathComponent("fpstage", isDirectory: true)
            try? manager.createDirectory(at: bundleRoot, withIntermediateDirectories: true)
            if isWritable(bundleRoot) { return ("App 包内（临时，结束即删）", bundleRoot) }
        }
        try? manager.createDirectory(at: documents, withIntermediateDirectories: true)
        if isWritable(documents) { return ("Documents（fairplayd 可能拒绝）", documents) }
        return nil
    }

    /// 崩溃残留的 fpwork-* 清理。必须覆盖 App Group 容器，否则真实暂存目录里的
    /// 垃圾永远清不掉；调用方要保证此刻没有任务在跑。
    static func cleanupStaleWork() {
        let manager = FileManager.default
        var roots: [URL] = [documents,
                            Bundle.main.bundleURL.appendingPathComponent("fpstage", isDirectory: true)]
        for group in groupIdentifiers() {
            if let url = manager.containerURL(forSecurityApplicationGroupIdentifier: group) {
                roots.append(url)
            }
        }
        for root in roots {
            guard let items = try? manager.contentsOfDirectory(at: root, includingPropertiesForKeys: nil) else { continue }
            for item in items where item.lastPathComponent.hasPrefix("fpwork-") {
                try? manager.removeItem(at: item)
            }
        }
    }

    /// 环境自检：解密前先看一眼，失败时不用猜。
    static func describe() -> [String] {
        let manager = FileManager.default
        var lines: [String] = []
        let version = ProcessInfo.processInfo.operatingSystemVersion
        var info = utsname()
        uname(&info)
        let machine = withUnsafeBytes(of: &info.machine) { raw -> String in
            String(decoding: raw.prefix { $0 != 0 }, as: UTF8.self)
        }
        lines.append("iOS \(version.majorVersion).\(version.minorVersion).\(version.patchVersion) / \(machine)")

        let symbol = dlopen(nil, RTLD_NOW).flatMap { dlsym($0, "mremap_encrypted") }
        lines.append("mremap_encrypted：\(symbol != nil ? "dyld 符号" : "原始系统调用 489")")

        let groups = groupIdentifiers()
        var groupFound = false
        for group in groups {
            if let url = manager.containerURL(forSecurityApplicationGroupIdentifier: group) {
                lines.append("App Group：\(group) → \(url.lastPathComponent)")
                lines.append("  可写：\(isWritable(url) ? "是" : "否")")
                groupFound = true
                break
            }
        }
        if !groupFound {
            lines.append("App Group：签名未授权（\(groups.count) 个候选都不可用）")
        }
        let bundleRoot = Bundle.main.bundleURL.appendingPathComponent("fpstage", isDirectory: true)
        try? manager.createDirectory(at: bundleRoot, withIntermediateDirectories: true)
        lines.append("App 包内暂存可写：\(isWritable(bundleRoot) ? "是" : "否")")
        lines.append("Documents 可写：\(isWritable(documents) ? "是" : "否")")
        return lines
    }
}

// MARK: - 内容统计（熵 + ARM64 地标词）

/// 密文的熵约 8.0 bit/byte，真实 ARM64 代码明显低于 7.5，并且每几千字节
/// 就会出现一条 RET / PACIBSP。用它判断"到底解出东西没有"，比"写入了多少
/// 字节 / 变化了多少字节"可靠得多。
final class FPCodeStats {
    private var histogram = [UInt64](repeating: 0, count: 256)
    private var wordBytes = [UInt8](repeating: 0, count: 4)
    private var fill = 0
    private(set) var total: UInt64 = 0
    private(set) var codeWords = 0

    func feed(_ pointer: UnsafePointer<UInt8>, _ count: Int) {
        var index = 0
        while index < count {
            let byte = pointer[index]
            histogram[Int(byte)] += 1
            wordBytes[fill] = byte
            fill += 1
            if fill == 4 {
                let value = UInt32(wordBytes[0])
                    | (UInt32(wordBytes[1]) << 8)
                    | (UInt32(wordBytes[2]) << 16)
                    | (UInt32(wordBytes[3]) << 24)
                if value == 0xd65f_03c0 || value == 0xd503_237f || value == 0xd65f_0fff {
                    codeWords += 1
                }
                fill = 0
            }
            index += 1
        }
        total += UInt64(count)
    }

    var entropy: Double {
        guard total > 0 else { return 0 }
        var value = 0.0
        for count in histogram where count > 0 {
            let q = Double(count) / Double(total)
            value -= q * log2(q)
        }
        return value
    }
}

// MARK: - 产物校验

enum FPVerifier {
    struct Result {
        let machOCount: Int
        let remaining: Int
        let contentChecked: Int
        let failures: [String]

        var clean: Bool { remaining == 0 && failures.isEmpty }

        var summary: String {
            var text = "Mach-O \(machOCount) 个，仍加密 \(remaining) 个，内容抽查 \(contentChecked) 个"
            if !failures.isEmpty { text += "，校验失败 \(failures.count) 个" }
            return text
        }
    }

    /// 打包之后再打开导出的 IPA 逐条目检查：cryptid 必须为 0，被解过的切片
    /// 内容必须像真实代码。只校验真正导出的文件，不校验内存里的中间态。
    static func run(ipa: URL, encryptedKeys: Set<String>, contentSample: Int = 6) throws -> Result {
        let reader = try FPZipReader(url: ipa)
        var machOCount = 0
        var remaining = 0
        var contentChecked = 0
        var failures: [String] = []
        var visited = 0

        for entry in reader.entries {
            if entry.isDirectory { continue }
            if entry.method != 0 && entry.method != 8 { continue }
            if entry.uncompressedSize < 32 { continue }
            visited += 1
            if visited > 20000 { break }

            let size = entry.uncompressedSize
            let read: (UInt64, Int) throws -> Data = { offset, length in
                var buffer = Data()
                let capped = min(UInt64(length), size > offset ? size - offset : 0)
                guard capped > 0 else { return buffer }
                buffer.reserveCapacity(Int(capped))
                try reader.stream(entry, from: offset, length: capped) { pointer, count, _ in
                    buffer.append(Data(bytes: pointer, count: count))
                }
                return buffer
            }

            let slices = (try? FPMachO.slices(read: read, size: size)) ?? []
            guard !slices.isEmpty else { continue }
            machOCount += 1

            for slice in slices where slice.cryptid != 0 {
                remaining += 1
                failures.append("仍加密（cryptid \(slice.cryptid)）：\(entry.path)")
                break
            }
            guard encryptedKeys.contains(entry.path) else { continue }
            guard contentChecked < contentSample else { continue }

            if let slice = slices.first(where: { $0.cryptsize > 0 }) {
                let start = slice.sliceOffset + slice.cryptoff
                guard start < size else { continue }
                let length = min(slice.cryptsize, size - start)
                let stats = FPCodeStats()
                try reader.stream(entry, from: start, length: length) { pointer, count, _ in
                    stats.feed(pointer, count)
                }
                contentChecked += 1
                // 只看熵：未解开的密文始终停在 ~8.0，解开的代码/数据落在 0.5–7.1。
                // 数 ARM64 地标词会把数据型、重度混淆的载荷判成「不像明文」
                // （实测 14 个假失败熵 0.53–6.19、地标词 0→0），所以地标只当日志。
                if stats.total > 0 && stats.entropy >= 7.5 {
                    failures.append(String(format: "内容不像明文：%@（熵 %.2f，地标词 %d）",
                                           entry.path, stats.entropy, stats.codeWords))
                }
            }
        }

        return Result(machOCount: machOCount, remaining: remaining,
                      contentChecked: contentChecked, failures: failures)
    }
}

// MARK: - 解密流水线

enum FPDecryptor {
    struct Outcome {
        let output: URL
        let decrypted: Int
        let plain: Int
        let failed: Int
        let machO: Int
        let elapsed: TimeInterval
        let clean: Bool
        let verifySummary: String
        let staging: String
        /// 内核成功、全部页回读成功、字节已变化，但本地判据判否的切片数。
        /// 只要这个数大于 0，就不能把失败说成「没有授权」，UI 也不能引导去商店登录。
        let heuristicRejected: Int
        /// cryptid != 0 但 cryptsize == 0、只把标志清零的切片数。
        let flagsCleared: Int
    }

    /// 解密一个加密 IPA → Documents/Decrypted/<名字>-fairplay.ipa。
    /// 阻塞执行，必须在后台队列调用。
    static func decrypt(ipa: URL,
                        allowBundleStaging: Bool,
                        isCancelled: () -> Bool,
                        progress: (String, Double, String) -> Void,
                        log: @escaping (String) -> Void) throws -> Outcome {
        let started = Date()
        let manager = FileManager.default

        guard let (stageLabel, root) = FPStage.prepare(allowBundle: allowBundleStaging) else {
            throw FPError.noStaging
        }
        log("暂存目录：\(stageLabel)")
        if stageLabel.hasPrefix("Documents") {
            log("⚠️ 没有 App Group 容器：fairplayd 很可能直接拒绝解密，失败时请改用带 App Group 的签名，或开启「App 包内暂存」")
        }

        let stem = ipa.deletingPathExtension().lastPathComponent
        let work = root.appendingPathComponent("fpwork-\(UUID().uuidString)", isDirectory: true)
        try manager.createDirectory(at: work, withIntermediateDirectories: true)
        defer { try? manager.removeItem(at: work) }

        // ── 1. 预检：路径安全 / 体积上限 / 空间 ────────────────────────
        progress("读取安装包", 0, ipa.lastPathComponent)
        let reader = try FPZipReader(url: ipa)
        var declared: Int64 = 0
        var symlinks = 0
        for entry in reader.entries {
            guard FPPaths.isSafeRelative(entry.path) else {
                throw FPError.badArchive("包含不安全的路径条目：\(entry.path)")
            }
            if entry.isSymlink {
                symlinks += 1
                continue
            }
            declared += Int64(clamping: entry.uncompressedSize)
            if declared > 16 * 1024 * 1024 * 1024 {
                throw FPError.badArchive("解压后体积超过 16 GB 安全上限")
            }
        }
        var sourceSize: Int64 = 0
        if let attrs = try? manager.attributesOfItem(atPath: ipa.path),
           let value = attrs[.size] as? NSNumber {
            sourceSize = value.int64Value
        }
        if let capacity = try? root.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey])
            .volumeAvailableCapacityForImportantUsage {
            let need = max(sourceSize * 3, declared + sourceSize + 256 * 1024 * 1024)
            if capacity < need {
                throw FPError.noSpace(capacity, need)
            }
        }
        log("条目 \(reader.entries.count) 个，解压后约 \(fpSizeText(declared))\(symlinks > 0 ? "，跳过 \(symlinks) 个符号链接" : "")")

        // ── 2. 解包（流式，内存与包体积无关）──────────────────────────
        progress("解包安装包", 0.02, "\(reader.entries.count) 个条目")
        var extracted: Int64 = 0
        var lastReport = 0.0
        for entry in reader.entries {
            if isCancelled() { throw FPError.cancelled }
            guard !entry.isSymlink else { continue }
            guard let destination = FPPaths.join(work, entry.path) else {
                throw FPError.badArchive("路径无效：\(entry.path)")
            }
            if entry.isDirectory {
                try? manager.createDirectory(at: destination, withIntermediateDirectories: true)
                continue
            }
            try? manager.createDirectory(at: destination.deletingLastPathComponent(),
                                         withIntermediateDirectories: true)
            try reader.extract(entry, to: destination)
            if entry.isExecutable {
                try? manager.setAttributes([.posixPermissions: 0o755], ofItemAtPath: destination.path)
            }
            extracted += Int64(clamping: entry.uncompressedSize)

            let now = Date().timeIntervalSince1970
            if now - lastReport > 0.4 {
                lastReport = now
                let fraction = declared > 0 ? min(0.05, 0.05 * Double(extracted) / Double(declared)) : 0.02
                progress("解包安装包", fraction, "\(fpSizeText(extracted)) / \(fpSizeText(declared))")
            }
        }

        let payloadDir = work.appendingPathComponent("Payload", isDirectory: true)
        let payloadEntries = (try? manager.contentsOfDirectory(atPath: payloadDir.path)) ?? []
        guard let bundleName = payloadEntries.first(where: { $0.hasSuffix(".app") }) else {
            throw FPError.noPayload
        }
        log("Payload：\(bundleName)")

        return try finish(work: work, stem: stem, staging: stageLabel, started: started,
                          originalAppDir: nil,
                          isCancelled: isCancelled, progress: progress, log: log)
    }

    /// 已安装应用直砸：不需要 IPA，也不需要内核漏洞。
    ///
    /// 磁盘上的二进制本来就是密文（内核只在缺页时解密"映射"，不解密文件），
    /// 而安装目录里本来就带着 SC_Info/<名字>.sinf。所以只要把整个包拷到
    /// fairplayd 认可的位置（App Group / App 包内暂存），再让内核替我们把
    /// 映射解密、回读即可 —— 和用 IPA 走的是同一条路。
    static func decryptInstalledApp(bundlePath: String,
                                    appName: String,
                                    allowBundleStaging: Bool,
                                    isCancelled: () -> Bool,
                                    progress: (String, Double, String) -> Void,
                                    copyBundle: (URL) -> Int,
                                    log: @escaping (String) -> Void) throws -> Outcome {
        let started = Date()
        let manager = FileManager.default
        guard let (stageLabel, root) = FPStage.prepare(allowBundle: allowBundleStaging) else {
            throw FPError.noStaging
        }
        log("暂存目录：\(stageLabel)")

        let work = root.appendingPathComponent("fpwork-\(UUID().uuidString)", isDirectory: true)
        let payload = work.appendingPathComponent("Payload", isDirectory: true)
        let destination = payload.appendingPathComponent((bundlePath as NSString).lastPathComponent,
                                                         isDirectory: true)
        try manager.createDirectory(at: destination, withIntermediateDirectories: true)
        defer { try? manager.removeItem(at: work) }

        progress("拷贝应用包", 0.02, appName)
        let copied = copyBundle(destination)
        guard copied > 0 else { throw FPError.refused("无法读取应用包（需要先初始化系统 / 沙箱逃逸）") }
        log("拷贝完成：\(copied) 个文件")
        if isCancelled() { throw FPError.cancelled }

        let stem = appName
            .replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "\t", with: "")
        return try finish(work: work, stem: stem, staging: stageLabel, started: started,
                          originalAppDir: URL(fileURLWithPath: bundlePath),
                          isCancelled: isCancelled, progress: progress, log: log)
    }

    /// 后面的流水线（解包或拷贝之后共用）：清点 → 铺 SINF → 逐个解密 →
    /// 重新打包 → 校验导出的文件。
    private static func finish(work: URL,
                               stem: String,
                               staging: String,
                               started: Date,
                               originalAppDir: URL?,
                               isCancelled: () -> Bool,
                               progress: (String, Double, String) -> Void,
                               log: @escaping (String) -> Void) throws -> Outcome {
        let manager = FileManager.default

        let payloadDir = work.appendingPathComponent("Payload", isDirectory: true)
        let payloadEntries = (try? manager.contentsOfDirectory(atPath: payloadDir.path)) ?? []
        guard let bundleName = payloadEntries.first(where: { $0.hasSuffix(".app") }) else {
            throw FPError.noPayload
        }
        let appDir = payloadDir.appendingPathComponent(bundleName, isDirectory: true)
        let appPrefix = "Payload/\(bundleName)/"
        log("Payload：\(bundleName)")
        // ── 3. 清点加密的 Mach-O + 铺 SINF ───────────────────────────
        progress("准备解密", 0.05, bundleName)
        let inventory = FPMachO.scanTree(appDir)
        let encryptedFiles = inventory.filter { $0.slices.contains { $0.cryptid != 0 } }
        guard !encryptedFiles.isEmpty else { throw FPError.alreadyPlain }
        let sinfCopied = FPSinf.replicate(appDir: appDir, machos: inventory, log: log)
        log("Mach-O \(inventory.count) 个，其中加密 \(encryptedFiles.count) 个；SINF 补齐 \(sinfCopied) 个")

        var encryptedKeys = Set<String>()
        for row in encryptedFiles { encryptedKeys.insert(appPrefix + row.path) }

        // ── 4. 逐个解密 ──────────────────────────────────────────────
        var decrypted = 0
        var plain = 0
        var failed = 0
        var heuristicRejected = 0
        var flagsCleared = 0
        var firstFailure: String?
        let total = max(encryptedFiles.count, 1)

        for (index, row) in encryptedFiles.enumerated() {
            if isCancelled() { throw FPError.cancelled }
            guard let url = FPPaths.join(appDir, row.path) else {
                failed += 1
                log("路径无效，跳过：\(row.path)")
                continue
            }
            progress("正在解密", 0.06 + 0.74 * Double(index) / Double(total),
                     "\(index + 1)/\(encryptedFiles.count) · \(row.path)")

            log(sliceSummary(row: row, appDir: appDir))

            let sink = FPLogSink { line in
                log(line.trimmingCharacters(in: .whitespaces))
            }
            var stats = fp_file_stats_t()
            var status = callCore(url.path, url.path, sink, &stats)

            // 拷贝出来的副本 fairplayd 有时不认（"Cannot allocate memory"）。
            // 已安装应用时直接映射原始安装路径再解一次：fairplayd 读得到别的
            // App 的安装包，明文照样写进我们自己的副本。
            if status != 0, status != 1, let originalRoot = originalAppDir,
               let originalPath = FPPaths.join(originalRoot, row.path)?.path,
               manager.fileExists(atPath: originalPath) {
                log("改用原始安装路径重试：\(row.path)")
                var retryStats = fp_file_stats_t()
                status = callCore(url.path, originalPath, sink, &retryStats)
                if status == 0 { stats = retryStats }
            }
            heuristicRejected += Int(stats.heuristic_rejected)
            flagsCleared += Int(stats.slices_plain)

            switch status {
            case 0:
                // 只清了 cryptid 标志、没有明文要产出的文件，不能算一次解密。
                if stats.slices_ok == 0 && stats.slices_plain > 0 {
                    plain += 1
                    log("仅清标志（cryptsize=0）\(row.path)")
                } else {
                    decrypted += 1
                    log("✅ 已解密 \(row.path)")
                }
            case 1:
                plain += 1
            default:
                failed += 1
                if firstFailure == nil { firstFailure = sink.last }
                log("❌ \(row.path) — \(sink.last ?? "未知原因")")
            }
        }

        if flagsCleared > 0 {
            log("清了 \(flagsCleared) 个 cryptsize=0 切片的 cryptid 标志（没有明文要产出）")
        }
        if heuristicRejected > 0 {
            // 绝不能报成「FairPlay 拒绝」：内核已经把页解开了。
            log("⚠️ 本地判据拒绝了 \(heuristicRejected) 个切片：内核成功、每页都回读、字节已变化，"
                + "只是熵判据没过（见上面 verdict= 行）。这不是授权问题。")
        }

        // ── 5. 打包前再扫一遍 ────────────────────────────────────────
        let after = FPMachO.scanTree(appDir)
        let stillEncrypted = after.flatMap { $0.slices }.filter { $0.cryptid != 0 }.count
        log("打包前：Mach-O \(after.count) 个，仍加密切片 \(stillEncrypted) 个")

        guard decrypted > 0 || flagsCleared > 0 else {
            throw FPError.refused(diagnose(firstFailure: firstFailure, failed: failed,
                                          stillEncrypted: stillEncrypted,
                                          heuristicRejected: heuristicRejected,
                                          fromInstalledApp: originalAppDir != nil))
        }
        if isCancelled() { throw FPError.cancelled }

        // ── 6. 重新打包 ──────────────────────────────────────────────
        progress("重新打包", 0.84, "\(stem)-fairplay.ipa")
        let outDir = FPStage.decryptedDirectory
        try? manager.createDirectory(at: outDir, withIntermediateDirectories: true)
        let partial = failed > 0 || stillEncrypted > 0
        let suffix = partial ? "-fairplay-PARTIAL" : "-fairplay"
        let output = outDir.appendingPathComponent("\(stem)\(suffix).ipa")
        let temp = outDir.appendingPathComponent("\(stem)\(suffix).ipa.tmp")
        try? manager.removeItem(at: temp)
        do {
            try createZipArchive(fromDirectory: work, to: temp)
        } catch {
            try? manager.removeItem(at: temp)
            throw FPError.packFailed(error.localizedDescription)
        }
        if isCancelled() {
            try? manager.removeItem(at: temp)
            throw FPError.cancelled
        }
        try? manager.removeItem(at: output)
        do {
            try manager.moveItem(at: temp, to: output)
        } catch {
            try? manager.removeItem(at: temp)
            throw FPError.packFailed(error.localizedDescription)
        }
        var outputSize: Int64 = 0
        if let attrs = try? manager.attributesOfItem(atPath: output.path),
           let value = attrs[.size] as? NSNumber {
            outputSize = value.int64Value
        }
        log("写出 \(output.lastPathComponent)（\(fpSizeText(outputSize))）")

        // ── 7. 校验导出的文件本身 ────────────────────────────────────
        progress("校验产物", 0.94, output.lastPathComponent)
        var verifySummary = "未校验"
        var clean = !partial
        do {
            let result = try FPVerifier.run(ipa: output, encryptedKeys: encryptedKeys)
            verifySummary = result.summary
            clean = clean && result.clean
            log("校验：\(result.summary)")
            for failure in result.failures.prefix(8) {
                log("校验失败：\(failure)")
            }
        } catch {
            log("校验跳过：\(error.localizedDescription)")
        }

        progress("完成", 1, output.lastPathComponent)
        return Outcome(output: output, decrypted: decrypted, plain: plain, failed: failed,
                       machO: after.count, elapsed: Date().timeIntervalSince(started),
                       clean: clean, verifySummary: verifySummary, staging: staging,
                       heuristicRejected: heuristicRejected, flagsCleared: flagsCleared)
    }

    /// 调 C 核心；mapPath 与写入路径相同时走普通版本。
    private static func callCore(_ inPath: String, _ mapPath: String, _ sink: FPLogSink,
                                 _ stats: inout fp_file_stats_t) -> Int32 {
        withExtendedLifetime(sink) {
            let context = Unmanaged.passUnretained(sink).toOpaque()
            return inPath.withCString { input in
                inPath.withCString { output in
                    if mapPath == inPath {
                        return fp_decrypt_file_ex(input, input, output,
                                                  fpCoreLogTrampoline, context, &stats)
                    }
                    return mapPath.withCString { mapped in
                        fp_decrypt_file_ex(input, mapped, output,
                                           fpCoreLogTrampoline, context, &stats)
                    }
                }
            }
        }
    }

    /// 每个加密切片一行诊断：内核参数、CPU 类型、旁边的 SC_Info 是否存在。
    /// 失败时这些数字就是唯一能定位问题的线索。
    private static func sliceSummary(row: (path: String, slices: [FPMachO.Slice]), appDir: URL) -> String {
        guard let slice = row.slices.first(where: { $0.cryptid != 0 }) else { return row.path }
        let name = (row.path as NSString).lastPathComponent
        let parent = (row.path as NSString).deletingLastPathComponent
        let sinfRelative = parent.isEmpty
            ? "SC_Info/\(name).sinf"
            : "\(parent)/SC_Info/\(name).sinf"
        var sinfText = "缺失"
        if let sinf = FPPaths.join(appDir, sinfRelative),
           let attrs = try? FileManager.default.attributesOfItem(atPath: sinf.path),
           let size = attrs[.size] as? NSNumber {
            sinfText = "\(size.intValue) B"
        }
        // cryptoff 不是 16 KB 页对齐时，内核 mremap_encrypted 根本不会接受
        // 那个地址。C 层现在会从页首重试，这里把情况标出来，便于看日志。
        var alignNote = ""
        let kernelPage = UInt64(getpagesize() > 0 ? getpagesize() : 16384)
        if slice.cryptoff % kernelPage != 0 {
            alignNote = String(format: " · ⚠️ cryptoff 未按 %llu KB 页对齐，内核会拒绝 FairPlay（这类文件只能走内核砸壳）",
                               kernelPage / 1024)
        }
        return String(format: "%@ · cpu=0x%x/0x%x cryptoff=0x%llx cryptsize=0x%llx cryptid=%u · SC_Info %@%@",
                      row.path,
                      slice.cputype,
                      slice.cpusubtype,
                      slice.cryptoff,
                      slice.cryptsize,
                      slice.cryptid,
                      sinfText,
                      alignNote)
    }

    /// 把 C 层的失败行翻成能照做的建议。最常见的其实是"这台设备没有该账号的
    /// 解密授权"：用哪个账号下载的，就得让那个账号在系统 App Store 登录一次。
    private static func diagnose(firstFailure: String?, failed: Int, stillEncrypted: Int,
                                 heuristicRejected: Int,
                                 fromInstalledApp: Bool) -> String {
        var text = "\(failed) 个文件失败，\(stillEncrypted) 个切片仍加密。"

        // 内核干了活、我们自己的判据判否：这不能算「没有授权」，更不能引用户去商店。
        if heuristicRejected > 0 {
            return text + "\n\n其中 \(heuristicRejected) 个切片其实是内核解开的"
                + "（mremap 成功、每一页都回读成功、密文熵已经掉下来），"
                + "只是本地判据没过。这不是账号或授权问题，也不该去 App Store 登录。"
                + "\n请把日志里 verdict= 那几行一起反馈，按样本调判据。"
        }

        guard let raw = firstFailure?.trimmingCharacters(in: .whitespaces), !raw.isEmpty else {
            return text
        }
        let lower = raw.lowercased()
        // 只有主路径（READ/cryptid2，不带 EXEC）的 errno 才能下结论：
        // READ|EXEC/cryptid1 在无特权进程上必然 mmap EPERM，把它读成
        // 「账号没有授权」正是以前把用户赶去 App Store 白折腾的原因。
        let mainPath = lower.contains("cid2") && !lower.contains("exec")

        if mainPath && lower.contains("cannot allocate memory") {
            return "fairplayd 无法为该文件建立解密会话（内核返回 ENOMEM，不是账号授权问题）。\n\n"
                + "常见原因：\n"
                + "· 这个二进制是 arm64e，或者 SINF 与文件版本对不上（应用刚更新过、或从别的账号/工具装进来的）；\n"
                + "· 副本位置不被接受。日志里若出现「改用原始安装路径重试」，那是第二条映射路径，也失败了就说明是前者。\n\n"
                + "这种应用请改用 A · 内核砸壳（它不经过 fairplayd，只要能让目标进程跑起来就能读内存）。"
        }
        if mainPath && (lower.contains("permission denied") || lower.contains("not permitted")) {
            return "这台设备没有该 Apple 账号的解密授权，系统拒绝了 FairPlay 解密。\n\n"
                + "请用下载这个应用时所用的 Apple 账号登录一次系统「App Store」"
                + "（App Store → 右上角头像 → 登录，或 设置 → 你的名字 → 媒体与购买项目），"
                + "然后回来重新解密。同一账号在这台设备上登录过一次即可，授权会保存在本机。"
        }
        if !mainPath && (lower.contains("permission denied") || lower.contains("not permitted")) {
            return text + "\n\n失败来自 READ|EXEC/cryptid1 这条备选路径，它在无特权进程上必然 mmap EPERM，"
                + "不能据此判断账号授权。请把完整日志反馈，按主路径（cid2）的结果分析。"
        }

        text += "\n内核返回：\(raw)"
        if lower.contains("invalid argument") {
            if fromInstalledApp {
                text += "\n映射参数被拒绝：cryptoff 不是 16 KB 页对齐（日志里带 ⚠️ 的行）。"
                    + "\n这份「已安装应用」多半被别人重签/重打包过（主二进制只有 1 个加密页，"
                    + "而官方包是上万页），这种包 fairplayd 一律拒绝。"
                    + "\n请改用上面的「导入加密 IPA」：导入从 App Store 下载的原始 IPA 再解。"
            } else {
                text += "\n映射参数被拒绝：这个 IPA 里的二进制 cryptoff 不是 16 KB 页对齐"
                    + "（日志里带 ⚠️ 的行），内核只接受页对齐的 mremap_encrypted 地址。"
                    + "这类包 FairPlay 路径无解，请改用 A · 内核砸壳。"
            }
        }
        return text
    }
}