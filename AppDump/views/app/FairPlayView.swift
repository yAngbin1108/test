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

struct FPSourceIPA: Identifiable {
    let id = UUID()
    let name: String
    let path: String
    let size: Int64
    let date: Date
}

struct FairPlayView: View {
    /// 由 DecryptView 传入（它已经加载好已安装应用列表）
    let installedApps: [DecryptApp]

    @ObservedObject private var mgr = AppDumpmgr.shared
    /// 运行中的任务属于这个单例，不随视图销毁（离开页面也不会丢进度/结果）。
    @ObservedObject private var job = FairPlayJob.shared
    @State private var ipas: [FPSourceIPA] = []
    @State private var importing = false
    @State private var showEnv = false
    @State private var envLines: [String] = []
    @State private var query = ""
    @State private var confirming: FPSourceIPA? = nil
    @State private var installedPending: DecryptApp? = nil
    /// 只有「导入 IPA」这种视图内动作的错误
    @State private var localerror: String? = nil

    @AppStorage("fpAllowBundleStage") private var allowBundleStage: Bool = true
    /// 解不开的扩展是否从产物里剔除。默认关闭：删包是不可逆动作，要用户自己开。
    @AppStorage("fpDropFailedExtensions") private var dropFailedExtensions: Bool = false

    private var documents: String {
        NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true).first ?? ""
    }

    private var busy: Bool { job.busy }

    private var trimmedQuery: String {
        query.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    private var filteredApps: [DecryptApp] {
        let q = trimmedQuery.lowercased()
        guard !q.isEmpty else { return installedApps }
        return installedApps.filter {
            $0.name.lowercased().contains(q) || $0.bundleID.lowercased().contains(q)
        }
    }

    private var filteredIPAs: [FPSourceIPA] {
        let q = trimmedQuery.lowercased()
        guard !q.isEmpty else { return ipas }
        return ipas.filter { $0.name.lowercased().contains(q) }
    }

    var body: some View {
        List {
            Section {
                HStack(spacing: 8) {
                    Image(systemName: "magnifyingglass")
                        .font(.body)
                        .foregroundStyle(.secondary)
                    TextField("搜索应用或 IPA", text: $query)
                        .font(.body)
                        .textInputAutocapitalization(.never)
                        .autocorrectionDisabled()
                    if !query.isEmpty {
                        Button {
                            query = ""
                        } label: {
                            Image(systemName: "xmark.circle.fill")
                                .foregroundStyle(Color.secondary.opacity(0.6))
                        }
                        .buttonStyle(.plain)
                    }
                    Button {
                        loadIPAs()
                    } label: {
                        Image(systemName: "arrow.clockwise")
                            .font(.body.weight(.semibold))
                            .foregroundStyle(.blue)
                    }
                    .disabled(busy)
                }
            }

            if let message = job.errormsg ?? localerror {
                Section {
                    PlainAlert(title: "解密失败", icon: "exclamationmark.triangle.fill",
                               text: message, color: .red)
                }
            }

            if busy || job.resultText != nil {
                Section {
                    if busy {
                        VStack(alignment: .leading, spacing: 8) {
                            HStack(spacing: 8) {
                                ProgressView()
                                Text(job.phase.isEmpty ? "准备中…" : job.phase)
                                    .font(.subheadline.weight(.medium))
                            }
                            ProgressView(value: min(max(job.fraction, 0), 1))
                            Text(job.detail)
                                .font(.caption)
                                .foregroundStyle(.secondary)
                                .lineLimit(2)
                            Button(role: .destructive) {
                                job.cancel()
                            } label: {
                                Text(job.cancelling ? "正在取消…" : "取消")
                            }
                            .font(.footnote)
                            .disabled(job.cancelling)

                            if job.stalled {
                                Text("后台线程卡在内核调用里，取消不会生效——只能放弃这次任务。")
                                    .font(.caption2)
                                    .foregroundStyle(.orange)
                                    .fixedSize(horizontal: false, vertical: true)
                                Button(role: .destructive) {
                                    job.forceAbandon()
                                } label: {
                                    Text("强制结束任务")
                                }
                                .font(.footnote)
                            }
                        }
                        .padding(.vertical, 2)
                    }
                    if let resultText = job.resultText {
                        Text(resultText)
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                        HStack(spacing: 12) {
                            if let path = job.outputPath {
                                Button {
                                    presentShareSheet(with: URL(fileURLWithPath: path))
                                } label: {
                                    Label("分享", systemImage: "square.and.arrow.up")
                                        .font(.footnote)
                                }
                            }
                            Button(role: .destructive) {
                                job.clearResult()
                            } label: {
                                Text("清除结果")
                                    .font(.footnote)
                            }
                        }
                    }
                    if !job.lines.isEmpty {
                        // 只显示尾部，完整日志在「日志」页
                        ForEach(Array(job.lines.suffix(10).enumerated()), id: \.offset) { _, line in
                            Text(line)
                                .font(.caption2.monospaced())
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                        }
                    }
                } header: {
                    HeaderLabel(text: "FairPlay 解密", icon: "lock.open")
                } footer: {
                    if busy {
                        Text("任务在后台独立运行，离开本页也不会中断；回来还能看到进度和结果。")
                    }
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
                Toggle(isOn: $dropFailedExtensions) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("剔除解不开的扩展")
                            .font(.subheadline)
                        Text("把整包都解不开的 .appex（分享面板、小组件等）从产物里整包删掉。")
                            .font(.caption2)
                            .foregroundStyle(.secondary)
                    }
                }
            } header: {
                HeaderLabel(text: "产物处理", icon: "scissors")
            } footer: {
                Text("被改过壳的包常有扩展解不开（位置没按 16 KB 对齐，内核直接拒绝），产物就会被标成 PARTIAL。打开这个开关后，那些扩展整包移除，产物是干净的、能装能用，只是少了这些扩展本身。主程序和框架不受影响；关掉时保留原样。")
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
                if filteredApps.isEmpty {
                    Text(trimmedQuery.isEmpty
                         ? "尚未读取到已安装应用。若「内核」页还没初始化，请先去初始化系统；也可以直接用下面的 IPA。"
                         : "没有匹配的应用。")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(filteredApps) { app in
                        Button {
                            installedPending = app
                        } label: {
                            HStack(spacing: 12) {
                                Image(systemName: app.isEncrypted == .unencrypted
                                      ? "lock.open" : "lock.doc")
                                    .foregroundStyle(.secondary)
                                VStack(alignment: .leading, spacing: 2) {
                                    Text(app.name)
                                        .font(.subheadline)
                                        .lineLimit(1)
                                    Text(app.isEncrypted == .unencrypted ? "已解密，可直接提取" : "加密 · 直砸不用 IPA")
                                        .font(.caption2)
                                        .foregroundStyle(.secondary)
                                }
                                Spacer()
                                if job.runningBundle == app.bundlePath {
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
                    HeaderLabel(text: "已安装应用 \(filteredApps.count)", icon: "square.grid.2x2")
                    Spacer()
                }
            } footer: {
                Text("直接把手机上已安装的包拷到暂存目录解密：磁盘上是密文，但安装目录里本来就有 SC_Info 授权，所以不需要 IPA，也不需要让应用先跑起来。需要先在「内核」页初始化系统以读取应用目录。")
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

                if filteredIPAs.isEmpty {
                    Text(trimmedQuery.isEmpty
                         ? "Documents 里还没有 .ipa 文件。用「导入加密 IPA」选一个从 App Store 下载的安装包。"
                         : "没有匹配的 IPA。")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                } else {
                    ForEach(filteredIPAs) { ipa in
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
                                if job.runningIPA == ipa.path {
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
                    HeaderLabel(text: "来源 IPA \(filteredIPAs.count)", icon: "tray.full")
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
            // 有任务在跑时绝不能清理：fpwork-* 可能正是它的暂存目录。
            if !job.busy { FPStage.cleanupStaleWork() }
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
            installedPending.map { "用 FairPlay 直砸 \($0.name)？" } ?? "",
            isPresented: Binding(get: { installedPending != nil }, set: { if !$0 { installedPending = nil } }),
            titleVisibility: .visible
        ) {
            if let app = installedPending {
                Button("开始解密") {
                    job.startInstalled(app, allowBundleStaging: allowBundleStage,
                                       dropFailedExtensions: dropFailedExtensions)
                }
                Button("取消", role: .cancel) {}
            }
        }
        .confirmationDialog(
            confirming.map { "用 FairPlay 解密 \($0.name)？" } ?? "",
            isPresented: Binding(get: { confirming != nil }, set: { if !$0 { confirming = nil } }),
            titleVisibility: .visible
        ) {
            if let ipa = confirming {
                Button("开始解密") {
                    job.startIPA(path: ipa.path, allowBundleStaging: allowBundleStage,
                                 dropFailedExtensions: dropFailedExtensions)
                }
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
                localerror = "导入失败：\(error.localizedDescription)"
            }
        case .failure(let error):
            localerror = "导入失败：\(error.localizedDescription)"
        }
    }

}
// MARK: - 应用包拷贝

enum FairPlayCopy {
    /// 沙箱逃逸可用时用 FileManager 直拷（任意大小），否则退回内核 VFS 逐文件读。
    static func run(from source: String, to destination: String,
                    isCancelled: () -> Bool = { false }) -> Int {
        let manager = FileManager.default
        if AppDumpmgr.shared.sbxready {
            guard let walker = manager.enumerator(atPath: source) else { return 0 }
            var count = 0
            for case let sub as String in walker {
                // 拷贝是整个流程里最久的一步，必须能中途取消。
                if count % 64 == 0, isCancelled() {
                    AppDumpmgr.shared.logmsg("(fairplay) 拷贝中已取消（\(count) 个文件）")
                    return count
                }
                let src = (source as NSString).appendingPathComponent(sub)
                let dst = (destination as NSString).appendingPathComponent(sub)
                var isDir: ObjCBool = false
                guard manager.fileExists(atPath: src, isDirectory: &isDir) else { continue }
                if isDir.boolValue {
                    try? manager.createDirectory(atPath: dst, withIntermediateDirectories: true)
                } else {
                    try? manager.createDirectory(atPath: (dst as NSString).deletingLastPathComponent,
                                                 withIntermediateDirectories: true)
                    if (try? manager.copyItem(atPath: src, toPath: dst)) != nil { count += 1 }
                }
            }
            return count
        }
        let copied = vfsfs.copytree(from: source, to: destination)
        AppDumpmgr.shared.logmsg("(fairplay) vfs 拷贝 \(copied.files) 个文件，失败 \(copied.failed)")
        return copied.files
    }
}
