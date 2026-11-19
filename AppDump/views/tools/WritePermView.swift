//
//  WritePermView.swift
//  AppDump
//
//  修复写权限：把指定容器目录（可递归）的属主在内核里改写为 501:501，
//  使沙盒逃逸之后仍被 UNIX 属主检查拦住的 open(O_WRONLY) 能够成功。
//

import SwiftUI

struct WritePermView: View {
    @ObservedObject private var mgr = AppDumpmgr.shared

    @State private var path = "/private/var/containers/Bundle/Application"
    @State private var running = false
    @State private var visited = 0
    @State private var result: String? = nil

    private var kernelReady: Bool { mgr.dsready }
    private var fsReady: Bool { mgr.sbxready || mgr.vfsready }

    var body: some View {
        List {
            Section {
                if !kernelReady {
                    PlainAlert(title: "内核读写未就绪", icon: "bolt.slash.fill",
                               text: "请先在「内核」页运行漏洞利用，之后才能改写内核里的 apfs_fsnode。",
                               color: .orange)
                } else if !fsReady {
                    PlainAlert(title: "文件枚举受限", icon: "exclamationmark.triangle.fill",
                               text: "沙盒尚未逃逸，只能改到指定目录本身，无法递归到子项。建议先初始化系统。",
                               color: .orange)
                } else {
                    Text("沙盒逃逸只解除 MAC 限制；容器里文件的属主通常不是本进程的 uid，所以仍然写不进去。这里直接在内核里把 apfs_fsnode 的 uid/gid 改成 501:501 来放行写入。")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }

            Section {
                TextField("目录路径", text: $path)
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .font(.system(.footnote, design: .monospaced))

                Button {
                    run()
                } label: {
                    HStack {
                        Text(running ? "正在修复…" : "开始修复")
                        Spacer()
                        if running { ProgressView() }
                    }
                }
                .disabled(running || !kernelReady || path.isEmpty)
            } header: {
                HeaderLabel(text: "目标目录", icon: "folder.badge.gearshape")
            } footer: {
                Text("会跳过 _CodeSignature 与 SC_Info（改动它们会破坏签名）。修改 .app 里的 Mach-O 也不会让程序可加载 —— 那只让文件可写。")
            }

            if running {
                Section {
                    HStack {
                        ProgressView()
                        Text("已处理 \(visited) 项")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
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
        }
        .themedBackground()
        .navigationTitle("修复写权限")
    }

    private func run() {
        running = true
        visited = 0
        result = nil
        let target = path

        DispatchQueue.global(qos: .userInitiated).async {
            let root = WritePerm.ownershipRoot(for: target) ?? target
            let res = WritePerm.chownTree(root) { n in
                DispatchQueue.main.async { visited = n }
            }
            DispatchQueue.main.async {
                running = false
                result = "完成：\(res.ok) 项成功，\(res.fail) 项失败。\n目标根：\(root)"
                AppDumpmgr.shared.logmsg("(writeperm) \(root) ok=\(res.ok) fail=\(res.fail)")
            }
        }
    }
}
