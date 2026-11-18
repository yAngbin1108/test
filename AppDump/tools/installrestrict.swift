//
//  installrestrict.swift
//  AppDump
//
//  去除设备限制 / 修改系统版本限制
//
//  AppsDump3 exposes this as "修改系统版本限制" (its own strings say
//  "修改后最低ios10.0可安装" / "签名后所有设备均可安装") and
//  "删除设备安装限制". Both are Info.plist edits on the bundle:
//
//    * MinimumOSVersion                 -> lowered so older iOS will install it
//    * UIRequiredDeviceCapabilities     -> removed (arm64 / metal / camera gates)
//    * UISupportedDevices               -> removed (explicit device allow-list)
//
//  IMPORTANT: this is applied to the *staged copy* of a bundle while we are
//  building an ipa, never to an app that is already installed — editing an
//  installed bundle invalidates its code signature and it would stop launching.
//  (AppsDump3 can edit installed apps because TrollStore bypasses signature
//  validation; a normal self-signed app cannot.)
//

import Foundation

enum installrestrict {

    static let defaultminimum = "10.0"

    /// Patch the staged app bundle (plus any appex plugins) in place.
    /// - Returns: a short human readable summary.
    @discardableResult
    static func apply(toAppAt appdir: String, minimum: String) -> (ok: Bool, message: String) {
        let fm = FileManager.default

        var targets: [String] = [appdir + "/Info.plist"]
        let pluginsdir = appdir + "/PlugIns"
        if let plugins = try? fm.contentsOfDirectory(atPath: pluginsdir) {
            for p in plugins where p.hasSuffix(".appex") {
                targets.append(pluginsdir + "/" + p + "/Info.plist")
            }
        }

        var patched = 0
        var strippedcaps = 0
        var errors: [String] = []

        for path in targets {
            guard fm.fileExists(atPath: path) else { continue }
            guard let dict = NSMutableDictionary(contentsOfFile: path) else {
                errors.append((path as NSString).lastPathComponent + ": unreadable")
                continue
            }

            dict["MinimumOSVersion"] = minimum

            if dict["UIRequiredDeviceCapabilities"] != nil {
                dict.removeObject(forKey: "UIRequiredDeviceCapabilities")
                strippedcaps += 1
            }
            if dict["UISupportedDevices"] != nil {
                dict.removeObject(forKey: "UISupportedDevices")
                strippedcaps += 1
            }

            do {
                let data = try PropertyListSerialization.data(fromPropertyList: dict, format: .binary, options: 0)
                try data.write(to: URL(fileURLWithPath: path))
                patched += 1
            } catch {
                errors.append((path as NSString).lastPathComponent + ": \(error.localizedDescription)")
            }
        }

        if patched == 0 {
            return (false, "没有可修改的 Info.plist" + (errors.isEmpty ? "" : " — " + errors.joined(separator: "; ")))
        }

        var msg = "已修改 \(patched) 个 Info.plist，MinimumOSVersion → \(minimum)"
        if strippedcaps > 0 { msg += "，去掉 \(strippedcaps) 项设备能力限制" }
        if !errors.isEmpty { msg += "；失败: " + errors.joined(separator: "; ") }
        return (true, msg)
    }

    /// What a bundle currently asks for — handy in the UI before/after.
    static func describe(appdir: String) -> String {
        let path = appdir + "/Info.plist"
        guard let dict = NSDictionary(contentsOfFile: path) else { return "读不到 Info.plist" }
        let minos = dict["MinimumOSVersion"] as? String ?? "(未设置)"
        let caps = dict["UIRequiredDeviceCapabilities"] as? [String] ?? []
        return "MinimumOSVersion = \(minos), 设备能力要求 = \(caps.isEmpty ? "无" : caps.joined(separator: ", "))"
    }
}
