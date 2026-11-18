//
//  getbmhash.swift
//  AppDump
//
//  Created by ruter on 12.05.26.
//

import Foundation

func getbmhash() -> String? {
    let path = "/private/preboot"
    let regex = try! NSRegularExpression(pattern: "^[A-Fa-f0-9]{64,128}$")

    // 沙箱逃逸在部分设备上会失败（日志: "sandbox escape verification failed (errno=1)"），
    // 那种情况下 FileManager 读不到 /private/preboot，会直接导致「无法获取内核缓存」。
    // 所以优先用 VFS（内核级目录读取，不过沙箱）。
    if AppDumpmgr.shared.vfsready {
        if let entries = AppDumpmgr.shared.vfslistdir(path: path) {
            for e in entries {
                let name = e.name
                let range = NSRange(name.startIndex..<name.endIndex, in: name)
                if regex.firstMatch(in: name, range: range) != nil {
                    globallogger.log("(getbmhash) vfs match: \(name)")
                    return name
                }
            }
            globallogger.log("(getbmhash) vfs: no hash entry under \(path)")
        } else {
            globallogger.log("(getbmhash) vfs listdir failed for \(path)")
        }
    }

    // 回退：普通 POSIX（需要沙箱逃逸成功）
    let fm = FileManager.default

    guard let enumerator = fm.enumerator(atPath: path) else {
        globallogger.log("(getbmhash) failed to enumerate path: \(path)")
        return nil
    }

    for case let file as String in enumerator {
        let name = (file as NSString).lastPathComponent
        let range = NSRange(name.startIndex..<name.endIndex, in: name)

        if regex.firstMatch(in: name, range: range) != nil {
            globallogger.log("(getbmhash) matching hash found: \(name)")
            return name
        }
    }

    globallogger.log("(getbmhash) no matching hash found")
    return nil
}
