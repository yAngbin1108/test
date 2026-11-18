//
//  keychainmgr.swift
//  AppDump
//
//  刷新并清理本 App 自己的 Keychain
//
//  纯用户态：Security.framework 的 SecItemDelete，遍历五类：
//    kSecClassGenericPassword / kSecClassInternetPassword
//    kSecClassCertificate    / kSecClassKey / kSecClassIdentity
//
//  注意：只清理本 App 自己 keychain-access-group 里的条目（删掉后系统重新生成）。
//  系统级 keychain（/private/var/Keychains/keychain-2.db）受 securityd 专属保护，
//  在 iOS 17.5.1 + DarkSword 自签环境下读不到，原「备份 / 扫描系统 Keychain」
//  功能已移除。
//

import Foundation
import Security

enum keychainmgr {

    /// 文档里点名的五类
    static let classes: [(label: String, cls: CFString)] = [
        ("通用密码 GenericPassword", kSecClassGenericPassword),
        ("网络密码 InternetPassword", kSecClassInternetPassword),
        ("证书 Certificate", kSecClassCertificate),
        ("密钥 Key", kSecClassKey),
        ("身份 Identity", kSecClassIdentity),
    ]

    private static func log(_ m: String) { AppDumpmgr.shared.logmsg("(kc) \(m)") }

    /// 遍历五类逐个 SecItemDelete。返回 (类别, 结果) 供界面显示。
    static func refreshown() -> [(label: String, result: String)] {
        var out: [(label: String, result: String)] = []
        for item in classes {
            let query: [CFString: Any] = [kSecClass: item.cls]
            let status = SecItemDelete(query as CFDictionary)
            let text: String
            switch status {
            case errSecSuccess:      text = "已清理"
            case errSecItemNotFound: text = "没有条目（本来就是干净的）"
            default:                 text = "返回状态 \(status)"
            }
            log("\(item.label): \(text)")
            out.append((label: item.label, result: text))
        }
        return out
    }
}
