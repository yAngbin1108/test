//
//  ContentView.swift
//  AppDump
//
//  Created by ruter on 23.03.26.
//

import SwiftUI
import UniformTypeIdentifiers

struct ContentView: View {
    @EnvironmentObject private var mgr: AppDumpmgr
    @ObservedObject private var logger = globallogger
    @AppStorage("selectedMethod") private var selectedmethod: method = .hybrid
    @AppStorage("logsdisplaymode") private var selectedlogsdisplaymode: logsdisplaymode = .toolbar
    @AppStorage("loggerNoBS") private var loggernobs: Bool = true

    @State private var showSettings: Bool = false
    @State private var dlingkcache: Bool = false

    init() {
        globallogger.capture()
    }

    var body: some View {
        NavigationStack {
            List {
                AlertsSection
                KRWSection
                DebugSection
                InlineLogsSection
            }
            .navigationTitle("砸壳")
            .toolbar {
                if selectedlogsdisplaymode == .toolbar {
                    Button(action: {
                        mgr.showLogs.toggle()
                    }) {
                        Image(systemName: "terminal")
                    }
                }
                Button(action: {
                    showSettings.toggle()
                }) {
                    Image(systemName: "gear")
                }
            }
            .sheet(isPresented: $showSettings) {
                SettingsView()
            }
        }
        .background(AppTheme.background)
    }

    private var AlertsSection: some View {
        Section {
            if !mgr.hasOffsets {
                PlainAlert(title: "未找到偏移量！", icon: "exclamationmark.triangle.fill", text: "缺少 Kernelcache 偏移量。请先点击“运行漏洞利用”，然后获取偏移量。")
            }
        }
    }

    private var KRWSection: some View {
        Section {
            LabeledContent(content: {
                if mgr.dsready {
                    Image(systemName: "checkmark.circle")
                } else if mgr.dsrunning {
                    HStack {
                        Text("\(Int(mgr.dsprogress * 100))%")
                        ProgressView()
                    }
                } else if mgr.dsattempted && mgr.dsfailed {
                    Image(systemName: "xmark.circle")
                }
            }) {
                Button("运行漏洞利用", action: {
                    offsets_init()
                    // 偏移量缺失时先尝试重新解析缓存；仍失败就不要带病跑漏洞利用，
                    // 否则会用不完整/错误的偏移读写内核，导致利用失败或异常。
                    if !mgr.hasOffsets {
                        globallogger.log("(run) hasOffsets=false，尝试重新解析内核缓存")
                        mgr.hasOffsets = loadkernelcache()
                    }
                    guard mgr.hasOffsets else {
                        Alertinator.shared.alert(
                            title: "偏移量不完整",
                            body: "当前内核缓存无法解析出完整偏移量（常见于缓存来自其它设备或系统版本）。\n\n请在「设置 → 内核缓存」中删除后重新获取，或直接点下方「获取内核缓存」，再试一次。为避免用不完整偏移执行漏洞利用，本次未运行。",
                            actionLabel: "知道了",
                            action: {})
                        return
                    }
                    mgr.run()
                })
                .disabled(mgr.dsready || mgr.dsrunning || isdebugged())
            }

            if !mgr.hasOffsets {
                Button {
                    guard !dlingkcache else { return }
                    dlingkcache = true

                    DispatchQueue.global(qos: .userInitiated).async {
                        // 内核缓存已存在时直接用缓存，不再走 preboot / 下载
                        let ok = loadkernelcache()
                        DispatchQueue.main.async {
                            mgr.hasOffsets = ok
                            dlingkcache = false
                        }
                    }
                } label: {
                    if dlingkcache {
                        HStack {
                            Text("正在获取内核缓存...")
                            Spacer()
                            ProgressView()
                        }
                    } else {
                        Text("获取内核缓存")
                    }
                }
                .disabled(dlingkcache || !mgr.dsready)
            } else {
                if selectedmethod == .hybrid {
                    LabeledContent(content: {
                        if mgr.vfsready && mgr.sbxready {
                            Image(systemName: "checkmark.circle")
                        } else if mgr.vfsrunning || mgr.sbxrunning {
                            HStack {
                                Text("执行中...")
                                ProgressView()
                            }
                        } else if (mgr.vfsattempted && mgr.vfsfailed) || (mgr.sbxattempted && mgr.sbxfailed) {
                            Image(systemName: "xmark.circle")
                        }
                    }) {
                        Button("初始化系统", action: {
                            mgr.vfsinit()
                            mgr.sbxescape()
                        })
                        .disabled(!mgr.hasOffsets || !mgr.dsready || mgr.vfsrunning || mgr.sbxrunning || (mgr.vfsready && mgr.sbxready))
                    }
                }

                // initalize vfs
                if selectedmethod == .vfs {
                    LabeledContent(content: {
                        if mgr.vfsready {
                            Image(systemName: "checkmark.circle")
                        } else if mgr.vfsrunning {
                            HStack {
                                Text("\(Int(mgr.dsprogress * 100))%")
                                ProgressView()
                            }
                        } else if mgr.vfsattempted && mgr.vfsfailed {
                            Image(systemName: "xmark.circle")
                        }
                    }) {
                        Button("初始化 VFS", action: {
                            mgr.vfsinit()
                        })
                        .disabled(!mgr.dsready || mgr.vfsready || mgr.vfsrunning || isdebugged())
                    }
                }

                // escape sandbox
                if selectedmethod == .sbx {
                    LabeledContent(content: {
                        if mgr.sbxready {
                            Image(systemName: "checkmark.circle")
                        } else if mgr.sbxrunning {
                            HStack {
                                Text("执行中...")
                                ProgressView()
                            }
                        } else if mgr.sbxattempted && mgr.sbxfailed {
                            Image(systemName: "xmark.circle")
                        }
                    }) {
                        Button("脱离沙盒", action: {
                            mgr.sbxescape()
                        })
                        .disabled(!mgr.dsready || mgr.sbxready || mgr.sbxrunning || isdebugged())
                    }
                }
            }
        } header: {
            HeaderLabel(text: "内核读写", icon: "externaldrive")
        } footer: {
            if isdebugged() {
                Text("调试器连接期间不可用。")
            }
        }
    }

    private var DebugSection: some View {
        Group {
            if weonadebugbuild_pjbweouttahereexclamationmark {
                if mgr.dsready {
                    Section(header: HeaderLabel(text: "仅调试", icon: "ant")) {
                        LabeledContent("kernel_base") {
                            Text(String(format: "0x%llx", mgr.kernbase))
                                .font(.system(.body, design: .monospaced))
                                .foregroundColor(.secondary)
                        }
                        LabeledContent("kernel_slide") {
                            Text(String(format: "0x%llx", mgr.kernslide))
                                .font(.system(.body, design: .monospaced))
                                .foregroundColor(.secondary)
                        }
                    }
                }
            }
        }
    }

    @ViewBuilder
    private var InlineLogsSection: some View {
        if selectedlogsdisplaymode == .content {
            Section {
                ScrollView {
                    if loggernobs {
                        let combined = logger.logs.joined(separator: "\n")
                        Text(combined)
                            .font(.system(size: 13, design: .monospaced))
                            .lineSpacing(1)
                            .textSelection(.enabled)
                            .onTapGesture {
                                UIPasteboard.general.string = combined
                                UIImpactFeedbackGenerator(style: .light).impactOccurred()
                            }
                    } else {
                        ForEach(Array(logger.logs.enumerated()), id: \.offset) { _, log in
                            Text(log)
                                .font(.system(size: 13, design: .monospaced))
                                .lineSpacing(1)
                                .textSelection(.enabled)
                                .onTapGesture {
                                    UIPasteboard.general.string = log
                                    UIImpactFeedbackGenerator(style: .light).impactOccurred()
                                }
                        }
                    }
                }
                .frame(height: 250)

                Button("复制全部") {
                    UIPasteboard.general.string = logger.logs.joined(separator: "\n\n")
                    UIImpactFeedbackGenerator(style: .medium).impactOccurred()
                }

                Button("清空") {
                    logger.clear()
                }
                .foregroundColor(.red)
            } header: {
                HeaderLabel(text: "日志", icon: "terminal")
            }
        }
    }
}

#Preview {
    ContentView()
        .environmentObject(AppDumpmgr())
}
