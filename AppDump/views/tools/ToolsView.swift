//
//  ToolsView.swift
//  AppDump
//
//  第六个 tab：辅助工具（只保留已确认可用的功能）
//
//  已移除（iOS 17.5.1 + DarkSword 自签环境下不可用：这些功能依赖 tccd/securityd
//  专属保护的 TCC.db / keychain-2.db，沙箱逃逸读不到，且没有可用的内核
//  vnode_lookup 原语）：
//    * 精细化权限管理
//    * 强制允许粘贴
//    * 广告标识符刷新（重置 ATT 授权）
//    * 系统 Keychain 备份 / 扫描
//
//  保留（纯用户态，已实测可用）：
//    * 去除设备限制（打包 ipa 时改写 MinimumOSVersion / 去掉设备能力要求）
//    * 显示当前广告标识 (IDFA)
//    * 刷新并清理本 App 自己的 Keychain（SecItemDelete 遍历五类）
//

import SwiftUI
// AdSupport is deprecated and may be absent from newer SDKs; the whole file
// still compiles without it, only the "show IDFA" button degrades.
#if canImport(AdSupport)
import AdSupport
#endif

struct ToolsView: View {
    @ObservedObject private var mgr = AppDumpmgr.shared

    @AppStorage("stripInstallLimits") private var striplimits: Bool = false
    @AppStorage("minimumOSOverride") private var minimumos: String = installrestrict.defaultminimum

    @State private var busy = false

    private let minoptions = ["10.0", "12.0", "13.0", "14.0", "15.0", "16.0", "17.0", "18.0"]

    var body: some View {
        NavigationStack {
            List {
                // ---------- 去除设备限制 ----------
                Section {
                    Toggle("打包 ipa 时去除设备限制", isOn: $striplimits)
                    Picker("最低 iOS 版本", selection: $minimumos) {
                        ForEach(minoptions, id: \.self) { Text($0).tag($0) }
                    }
                    .pickerStyle(.menu)
                } header: {
                    HeaderLabel(text: "去除设备限制", icon: "iphone.gen3")
                } footer: {
                    Text("开启后，砸壳 / 提取的 ipa 会改写 Info.plist 的 MinimumOSVersion 并去掉设备能力要求，老系统也能装。")
                }

                // ---------- 广告标识 ----------
                Section {
                    Button("显示当前广告标识 (IDFA)") { showidfa() }
                } header: {
                    HeaderLabel(text: "广告标识", icon: "hand.raised")
                } footer: {
                    Text("只读显示。IDFA 重置需要重置 ATT 授权（TCC 库），在当前环境不可用，已移除。")
                }

                // ---------- Keychain ----------
                Section {
                    Button("刷新并清理本 App 的 Keychain") { refreshkeychain() }
                        .disabled(busy)
                } header: {
                    HeaderLabel(text: "钥匙串", icon: "key")
                } footer: {
                    Text("用 SecItemDelete 清掉本 App 自己的五类 keychain 条目（通用/网络密码、证书、密钥、身份），系统会重新生成。")
                }
            }
            .scrollContentBackground(.hidden)
            .navigationTitle("工具")
            .toolbarBackground(.hidden, for: .navigationBar)
        }
        .background(AppTheme.background)
    }

    // MARK: - actions

    private func showidfa() {
        #if canImport(AdSupport)
        let id = ASIdentifierManager.shared().advertisingIdentifier.uuidString
        let zeroed = id == "00000000-0000-0000-0000-000000000000"
        let hint = "全 0 说明「允许 App 请求跟踪」当前是关闭的，或者 ATT 还没授权。"
            + "可以去 设置 → 隐私与安全性 → 跟踪 里打开。"
        Alertinator.shared.alert(
            title: "当前广告标识 (IDFA)",
            body: zeroed ? id + "\n\n" + hint : id,
            actionLabel: "好",
            action: {}
        )
        #else
        Alertinator.shared.alert(
            title: "当前广告标识 (IDFA)",
            body: "这个 SDK 里没有 AdSupport 框架，读不到 IDFA。",
            actionLabel: "好",
            action: {}
        )
        #endif
    }

    private func refreshkeychain() {
        busy = true
        DispatchQueue.global(qos: .userInitiated).async {
            let res = keychainmgr.refreshown()
            let body = res.map { "\($0.label)：\($0.result)" }.joined(separator: "\n")
            DispatchQueue.main.async {
                busy = false
                Alertinator.shared.alert(title: "Keychain 已刷新", body: body, actionLabel: "好", action: {})
            }
        }
    }
}
