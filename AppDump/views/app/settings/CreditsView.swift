//
//  CreditsView.swift
//  AppDump
//
//  Created by lunginspector on 5/9/26.
//

import SwiftUI

struct CreditsView: View {
    var body: some View {
        NavigationStack {
            List {
                LinkCreditCell(name: "Taylor eDward", description: "砸壳 AB、应用降级、阻止更新、去除限制、钥匙串", url: "https://github.com/yAngbin1108") {
                    LinkCreditIcon(url: "https://github.com/yAngbin1108.png")
                }
                LinkCreditCell(name: "Famed", description: "内核利用链、进程管理、修复写权限、修复思路", url: "https://github.com/nssxhtq4qs-blip") {
                    LinkCreditIcon(url: "https://github.com/nssxhtq4qs-blip.png")
                }
                LinkCreditCell(name: "roooot", description: "lara 开发者", url: "https://github.com/rooootdev") {
                    LinkCreditIcon(url: "https://github.com/rooootdev.png")
                }
                LinkCreditCell(name: "wh1te4ever", description: "开发了 darksword-kexploit-fun", url: "https://github.com/wh1te4ever") {
                    LinkCreditIcon(url: "https://github.com/wh1te4ever.png")
                }
                LinkCreditCell(name: "Duy Tran", description: "RemoteCall 相关改进与功能", url: "https://github.com/khanhduytran0") {
                    LinkCreditIcon(url: "https://github.com/khanhduytran0.png")
                }
                LinkCreditCell(name: "AppInstalleriOS", description: "在偏移量等方面提供了帮助", url: "https://github.com/AppInstalleriOSGH") {
                    LinkCreditIcon(url: "https://github.com/AppInstalleriOSGH.png")
                }
                LinkCreditCell(name: "lunginspector", description: "前端重写", url: "https://github.com/lunginspector") {
                    LinkCreditIcon(url: "https://github.com/lunginspector.png")
                }
                LinkCreditCell(name: "neon", description: "Respring 脚本、zipmgr、修复 Passcode 主题并新增应用解密", url: "https://github.com/neonmodder123") {
                    LinkCreditIcon(url: "https://github.com/neonmodder123.png")
                }
                LinkCreditCell(name: "hxhlb", description: "多项 bug 修复", url: "https://github.com/hxhlb") {
                    LinkCreditIcon(url: "https://github.com/hxhlb.png")
                }
            }
            .navigationTitle("致谢")
        }
    }
}
