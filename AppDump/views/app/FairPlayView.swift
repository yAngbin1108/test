//
//  FairPlayView.swift
//  AppDump
//
//  「App 解密」页的第二种解密方式：FairPlay（不需要内核漏洞）。
//  选一个加密 IPA → 解包 → 用 mremap_encrypted(cryptid 2) 让 fairplayd
//  就地解密 → 重新打包 → 校验产物。
//
//  与内核砸壳并列，用户在前面用 A/B 选择。
//

import SwiftUI
import UniformTypeIdentifiers

final class FPCancelToken {
    private let lock = NSLock()
    private var flag = false

    var cancelled: Bool {
        lock.lock()
        defer { lock.unlock() }
        return flag
    }

    func cancel() {
        lock.lock()
        flag = true
        lock.unlock()
    }
}

struct FPSourceIPA: Identifiable {
    let id = UUID()
    let name: String
    let path: String
    let size: Int64
    let date: Date
}

struct FairPlayView: View {
    @State private var ipas: [FPSourceIPA] = []
    @State private var running: String? = nil
    @State private var phase = ""
    @State private var fraction: Double = 0
    @State private var detail = ""
    @State private var lines: [String] = []
    @State private var errormsg: String? = nil
    @State private var resultText: String? = nil
    @State private var importing = false
    @State private var showEnv = false
    @State private var envLines: [String] = []
    @State private var token = FPCancelToken()
    @State private var confirming: FPSourceIPA? = nil

    @AppStorage("fpAllowBundleStage") private var allowBundleStage: Bool = true

    private var documents: String {
        NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true).first ?? ""
    }

    private var busy: Bool { running != nil }

    var body: some View {
        List {
            if let errormsg {
                Section {
                    PlainAlert(title: "解密失败", icon: "exclamationmark.triangle.fill",
                               text: errormsg, color: .red)
                }
            }

            if busy || resultText != nil {
                Section {
                    if busy {
                        VStack(alignment: .leading, spacing: 8) {
                            HStack(spacing: 8) {
                                ProgressView()
                                Text(phase.isEmpty ? "准备中…" : phase)
                                    .font(.subheadline.weight(.medium))
                            }
                            ProgressView(value: min(max(fraction, 0), 1))
                            Text(detail)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(2)
                            Button(role: .destructive) {
                                token.cancel()
                            } label: {
                                Text("取消")
                            }
                            .font(.footnote)
                        }
                        .padding(.vertical, 2)
                    }
                    if let resultText {
                        Text(resultText)
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                    if !lines.isEmpty {
                        // 只显示尾部，完整日志在「日志」页
                        ForEach(Array(lines.suffix(10).enumerated()), id: \.offset) { _, line in
                            Text(line)
                                .font(.caption2.monospaced())
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                        }
                    }
                } header: {
                    HeaderLabel(text: "FairPlay 解密", icon: "lock.open")
                }
            }

            Section {
                Toggle(isOn: $allowBundleStage) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("允许写入 App 包内暂存")
                            .font(.subheadline)
                        Text("没有 App Group 权限时，fairplayd 只认 App 包内的路径。")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
            } header: {
                HeaderLabel(text: "暂存位置", icon: "folder.badge.gearshape")
            } footer: {
                Text("优先用签名授权的 App Group 容器；没有时按上面的开关退到 App 包内（运行结束自动删除）。两者都不可用时才会落到 Documents，fairplayd 通常直接拒绝。")
            }

            Section {
                Button {
                    envLines = FPStage.describe()
                    showEnv = true
                } label: {
                    HStack(spacing: 10) {
                        Image(systemName: "stethoscope").foregroundStyle(.blue)
                        Text("检查运行环境")
                        Spacer()
                        Image(systemName: "chevron.right")
                            .font(.caption)
                            .foregroundStyle(.secondary)
                    }
                }
            } header: {
                HeaderLabel(text: "环境", icon: "wrench.and.screwdriver")
            }

            Section {
                Button {
                    importing = true
                } label: {
                    HStack(spacing: 10) {
                        Image(systemName: "square.and.arrow.down").foregroundStyle(.blue)
                        Text("导入加密 IPA")
                        Spacer()
                    }
                }
                .disabled(busy)

                if ipas.isEmpty {
                    Text("Documents 里还没有 .ipa 文件。用「导入加密 IPA」选一个从 App Store 下载的安装包。")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(ipas) { ipa in
                        Button {
                            confirming = ipa
                        } label: {
                            HStack(spacing: 12) {
                                Image(systemName: "shippingbox")
                                    .foregroundStyle(.secondary)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(ipa.name)
                                        .font(.subheadline)
                                        .lineLimit(1)
                                    Text("\(fpSizeText(ipa.size)) · \(fpDate(ipa.date))")
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                                if running == ipa.path {
                                    ProgressView()
                                } else {
                                    Image(systemName: "play.circle.fill")
                                        .foregroundStyle(busy ? Color.secondary : Color.accentColor)
                                }
                            }
                        }
                        .disabled(busy)
                    }
                }
            } header: {
                HStack {
                    HeaderLabel(text: "来源 IPA \(ipas.count)", icon: "tray.full")
                    Spacer()
                    Button("刷新") { loadIPAs() }
                        .font(.caption)
                }
            } footer: {
                Text("用哪个 Apple 账号下载的，就得让那个账号在系统「App Store」登录过一次，否则 fairplayd 没有解密授权。产物写入 Documents/Decrypted，可在「IPA」页导出。")
            }
        }
        .listStyle(.insetGrouped)
        .scrollContentBackground(.hidden)
        .onAppear {
            FPStage.cleanupStaleWork()
            loadIPAs()
        }
        .fileImporter(isPresented: $importing,
                      allowedContentTypes: [UTType(filenameExtension: "ipa") ?? .data],
                      allowsMultipleSelection: false) { result in
            handleImport(result)
        }
        .sheet(isPresented: $showEnv) {
            NavigationStack {
                List {
                    Section {
                        ForEach(envLines, id: \.self) { line in
                            Text(line)
                                .font(.caption.monospaced())
                                .foregroundStyle(.secondary)
                        }
                    } header: {
                        HeaderLabel(text: "环境自检", icon: "stethoscope")
                    }
                    Section {
                        Text("解密走 mremap_encrypted(cryptid 2)：内核把映射交给 FairPlayIOKit，由 fairplayd 按 SC_Info 里的授权解密，全程不需要内核漏洞。失败只会返回 errno，不会重启。")
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                    }
                }
                .navigationTitle("运行环境")
                .navigationBarTitleDisplayMode(.inline)
                .toolbar {
                    ToolbarItem(placement: .navigationBarTrailing) {
                        Button("完成") { showEnv = false }
                    }
                }
            }
            .presentationDetents([.medium, .large])
        }
        .confirmationDialog(
            confirming.map { "用 FairPlay 解密 \($0.name)？" } ?? "",
            isPresented: Binding(get: { confirming != nil }, set: { if !$0 { confirming = nil } }),
            titleVisibility: .visible
        ) {
            if let ipa = confirming {
                Button("开始解密") { start(ipa) }
                Button("取消", role: .cancel) {}
            }
        }
    }

    // MARK: - 数据

    private func fpDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.dateFormat = "M/d/yy HH:mm"
        return formatter.string(from: date)
    }

    private func loadIPAs() {
        DispatchQueue.global(qos: .userInitiated).async {
            let manager = FileManager.default
            let root = FPStage.documents.path
            var results: [FPSourceIPA] = []
            if let files = try? manager.contentsOfDirectory(atPath: root) {
                for file in files where file.lowercased().hasSuffix(".ipa") {
                    let full = root + "/" + file
                    let attrs = try? manager.attributesOfItem(atPath: full)
                    let size = (attrs?[.size] as? NSNumber)?.int64Value ?? 0
                    let date = (attrs?[.modificationDate] as? Date) ?? Date()
                    results.append(FPSourceIPA(name: file, path: full, size: size, date: date))
                }
            }
            results.sort { $0.date > $1.date }
            DispatchQueue.main.async { ipas = results }
        }
    }

    private func handleImport(_ result: Result<[URL], Error>) {
        switch result {
        case .success(let urls):
            guard let source = urls.first else { return }
            let target = documents + "/" + source.lastPathComponent
            let scoped = source.startAccessingSecurityScopedResource()
            defer { if scoped { source.stopAccessingSecurityScopedResource() } }
            do {
                if FileManager.default.fileExists(atPath: target) {
                    try FileManager.default.removeItem(atPath: target)
                }
                try FileManager.default.copyItem(at: source, to: URL(fileURLWithPath: target))
                AppDumpmgr.shared.logmsg("(fairplay) 导入 \(source.lastPathComponent)")
                loadIPAs()
            } catch {
                errormsg = "导入失败：\(error.localizedDescription)"
            }
        case .failure(let error):
            errormsg = "导入失败：\(error.localizedDescription)"
        }
    }

    // MARK: - 执行

    private func start(_ ipa: FPSourceIPA) {
        guard running == nil else { return }
        errormsg = nil
        resultText = nil
        lines.removeAll()
        phase = "准备中"
        fraction = 0
        detail = ""
        running = ipa.path

        let token = FPCancelToken()
        self.token = token
        let allowBundle = allowBundleStage

        AppDumpmgr.shared.logmsg("(fairplay) 开始解密 \(ipa.name)，暂存开关=\(allowBundle ? "允许" : "禁用")")

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let outcome = try FPDecryptor.decrypt(
                    ipa: URL(fileURLWithPath: ipa.path),
                    allowBundleStaging: allowBundle,
                    isCancelled: { token.cancelled },
                    progress: { phase, fraction, detail in
                        DispatchQueue.main.async {
                            self.phase = phase
                            self.fraction = fraction
                            self.detail = detail
                        }
                    },
                    log: { line in
                        DispatchQueue.main.async {
                            self.lines.append(line)
                            if self.lines.count > 300 {
                                self.lines.removeFirst(self.lines.count - 300)
                            }
                        }
                        AppDumpmgr.shared.logmsg("(fairplay) \(line)")
                    })
                DispatchQueue.main.async {
                    self.running = nil
                    let seconds = String(format: "%.0f", outcome.elapsed)
                    self.resultText = "\(outcome.clean ? "解密完成" : "部分完成")：解密 \(outcome.decrypted) / 明文 \(outcome.plain) / 失败 \(outcome.failed)，"
                        + "Mach-O \(outcome.machO) 个，耗时 \(seconds) 秒。\n"
                        + "校验：\(outcome.verifySummary)\n"
                        + "产物：\(outcome.output.lastPathComponent)"
                    if !outcome.clean {
                        self.errormsg = outcome.failed > 0
                            ? "有 \(outcome.failed) 个文件没解开，产物带 PARTIAL 标记。"
                            : "产物校验未通过，请检查日志。"
                    }
                }
            } catch {
                DispatchQueue.main.async {
                    self.running = nil
                    if let fpError = error as? FPError, case .cancelled = fpError {
                        self.resultText = "已取消。"
                    } else {
                        self.errormsg = error.localizedDescription
                    }
                    AppDumpmgr.shared.logmsg("(fairplay) 失败：\(error.localizedDescription)")
                }
            }
        }
    }
}