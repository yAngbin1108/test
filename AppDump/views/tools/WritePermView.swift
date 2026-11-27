//
//  WritePermView.swift
//  AppDump
//
//  修复写权限 —— 两件事：
//    1. 「修复写权限」：探针检查特权路径是否可写，丢了就只重放一次沙盒策略
//       （不重跑漏洞链），并显示探针前后状态、修复次数、自动修复开关。
//    2. 「容器属主」：在内核里把某个 /var 下的路径（可递归整树）的 uid/gid
//       改成指定值（默认 501:501 mobile），即「属主 / 属组 (chown)」，
//       只是这里允许一次改一整棵容器。
//

import SwiftUI

struct WritePermView: View {
    @ObservedObject private var mgr = AppDumpmgr.shared
    @ObservedObject private var keeper = SandboxKeeper.shared

    @State private var path = "/private/var/containers/Bundle/Application"
    @State private var uid = "501"
    @State private var gid = "501"
    @State private var recursive = true
    @State private var running = false
    @State private var result: String?

    private var kernelReady: Bool { mgr.dsready }

    var body: some View {
        List {
            // ───────────── 写权限状态与修复 ─────────────
            Section {
                HStack {
                    Text("内核读写")
                    Spacer()
                    Text(kernelReady ? "就绪" : "未就绪")
                        .foregroundStyle(kernelReady ? .green : .orange)
                }
                HStack {
                    Text("特权写权限")
                    Spacer()
                    if keeper.lastProbeOK {
                        Text("正常").foregroundStyle(.green)
                    } else {
                        Text("不可写 · errno \(keeper.lastProbeErrno)")
                            .foregroundStyle(.red)
                    }
                }
                if !keeper.lastProbeOK {
                    Text(SandboxKeeper.strerror(keeper.lastProbeErrno))
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Toggle("自动修复（后台每 7 秒）", isOn: $keeper.autoRepair)
                HStack {
                    Text("修复成功 / 尝试")
                    Spacer()
                    Text("\(keeper.repairCount) / \(keeper.repairAttempts)")
                        .foregroundStyle(.secondary)
                }
                if keeper.consecutiveFailures > 0 {
                    Text("连续失败 \(keeper.consecutiveFailures) 次（到 5 次停止自动修复）")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
                if let ev = keeper.lastEvent {
                    Text(ev)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } header: {
                HeaderLabel(text: "写权限", icon: "lock.shield")
            } footer: {
                Text("沙盒逃逸改的是内核里的策略，内核会把它覆盖回去。修复只重放那一次策略写，不重跑漏洞利用。")
            }

            Section {
                Button {
                    repair()
                } label: {
                    HStack {
                        Text("修复写权限")
                        Spacer()
                        if running { ProgressView() }
                    }
                }
                .disabled(!kernelReady)

                Button("立即探测") {
                    let ok = SandboxKeeper.probe()
                    result = ok ? "特权写权限：可写" : "特权写权限：不可写（errno \(SandboxKeeper.writeAccessProbeErrno)）"
                }
                .disabled(!kernelReady)
            }

            if let result {
                Section {
                    Text(result)
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                } header: {
                    HeaderLabel(text: "结果", icon: "checkmark.seal")
                }
            }

            // ───────────── 容器属主（内核 chown） ─────────────
            Section {
                TextField("路径", text: $path)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .font(.system(.footnote, design: .monospaced))

                HStack {
                    TextField("UID", text: $uid)
                        .keyboardType(.numberPad)
                        .frame(width: 90)
                    TextField("GID", text: $gid)
                        .keyboardType(.numberPad)
                        .frame(width: 90)
                    Spacer()
                    Toggle("递归", isOn: $recursive)
                        .labelsHidden()
                    Text("递归").font(.footnote).foregroundStyle(.secondary)
                }
                .font(.system(.footnote, design: .monospaced))

                Button {
                    chown()
                } label: {
                    HStack {
                        Text(running ? "处理中…" : "内核改属主")
                        Spacer()
                        if running { ProgressView() }
                    }
                }
                .disabled(running || !kernelReady || path.isEmpty)
            } header: {
                HeaderLabel(text: "容器属主（chown）", icon: "person.badge.key")
            } footer: {
                Text("只允许 /var 下的路径（字面路径和 realpath 都要过）。递归会跳过 _CodeSignature 与 SC_Info。改 .app 里的 Mach-O 不会让程序可加载 —— 这只让文件可写。")
            }
        }
        .themedBackground()
        .navigationTitle("修复写权限")
        .onAppear {
            if kernelReady { _ = SandboxKeeper.probe() }
        }
    }

    private func repair() {
        running = true
        result = nil
        DispatchQueue.global(qos: .userInitiated).async {
            let ok = SandboxKeeper.shared.repairNow()
            DispatchQueue.main.async {
                running = false
                result = ok
                    ? "写权限已恢复（第 \(SandboxKeeper.shared.repairCount) 次重放）。"
                    : "重放完成但探针仍不可写（errno \(SandboxKeeper.shared.lastProbeErrno)）。"
            }
        }
    }

    private func chown() {
        guard let u = uid_t(uid), let g = gid_t(gid) else {
            result = "UID / GID 必须是数字"
            return
        }
        running = true
        result = nil
        let target = path
        let deep = recursive
        DispatchQueue.global(qos: .userInitiated).async {
            var msg: String
            if deep {
                let r = WritePerm.chownTree(target, uid: u, gid: g)
                msg = "整树完成：\(r.entries) 项已是 \(u):\(g)，\(r.failed) 项失败，\(r.skipped) 项跳过。"
            } else {
                let ok = WritePerm.kernelTakeOwnership(target, uid: u, gid: g)
                msg = ok ? "\(target) 属主已改为 \(u):\(g)" : "chown 失败：\(target)"
            }
            DispatchQueue.main.async {
                running = false
                result = msg
            }
        }
    }
}
