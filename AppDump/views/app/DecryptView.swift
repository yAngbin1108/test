//
//  DecryptView.swift
//  AppDump
//
//  Created by neonmodder123 on 23.05.26.
//

import SwiftUI
import UIKit

struct DecryptApp: Identifiable {
    let id = UUID()
    let name: String
    let bundleID: String
    let bundlePath: String
    let executable: String
    let icon: UIImage?
    var isEncrypted: DecryptStatus = .unknown
}

enum DecryptStatus {
    case encrypted, unencrypted, unknown
}

/// 文件管理器弹窗的目标目录
struct BrowseTarget: Identifiable {
    let id = UUID()
    let path: String
}

/// 已导出 IPA 的来源
enum IPASource: String {
    case decrypted = "已砸壳"
    case extracted = "已提取"
}

/// 已砸壳 / 已提取的 IPA 文件
struct OutputIPA: Identifiable {
    let id = UUID()
    let baseName: String      // 不含 .ipa 的文件名
    let fileName: String      // 完整文件名（含 .ipa）
    let path: String          // 完整路径
    let size: Int64
    let date: Date
    let source: IPASource
    /// 深分析结果（后台补上，没有时列表只显示文件名 / 大小 / 时间）
    var analysis: ipaanalysis? = nil
}

/// 顶部模式：应用列表 / 导出 IPA
enum DecryptMode {
    case apps, ipas
}

/// 解密引擎：A = 内核砸壳（需要漏洞链），B = FairPlay（需要原始加密 IPA）
enum DecryptEngine: String {
    case kernel = "kernel"
    case fairplay = "fairplay"
}

struct DecryptView: View {
    @ObservedObject private var mgr = AppDumpmgr.shared
    // A 引擎的进度单独放一个单例：C 回调是函数指针，拿不到视图的 @State
    @ObservedObject private var kjob = DecryptProgress.shared
    @State private var query = ""
    @State private var apps: [DecryptApp] = []
    @State private var decryptingbid: String? = nil
    @State private var extractingbid: String? = nil
    @State private var errormsg: String? = nil
    @State private var pendingdecrypt: DecryptApp? = nil
    @State private var loadingapps: Bool = false

    // 解密引擎（持久化，和「降级方式」一样的 A/B 选择）
    @AppStorage("decryptEngine") private var engineRaw: String = "kernel"

    // IPA 管理
    @State private var mode: DecryptMode = .apps
    @State private var ipas: [OutputIPA] = []
    /// 已分析过的包：路径 -> 结果。扫描刷新列表时沿用，避免每次重进都重算。
    @State private var ipaAnalysis: [String: ipaanalysis] = [:]
    /// 正在分析中的包路径，列表显示「分析中…」
    @State private var ipaAnalyzing: Set<String> = []
    /// 正在查看分析的包
    @State private var ipaDetail: OutputIPA? = nil
    /// 滑动删除 / 清空 的二次确认
    @State private var ipaPendingDelete: OutputIPA? = nil
    /// IPA 模式筛选：tried 过「全部 / 可安装 / 未解密 / 结构异常」
    @AppStorage("decrypt.ipafilter") private var ipaFilterRaw: Int = 0
    @State private var loadingipas: Bool = false
    @State private var ipaEditing: Bool = false
    @State private var selectedipas: Set<UUID> = []
    @State private var actionapp: DecryptApp? = nil
    @State private var browsertarget: BrowseTarget? = nil

    private let documentspath = NSSearchPathForDirectoriesInDomains(.documentDirectory, .userDomainMask, true).first ?? ""

    private var busy: Bool { decryptingbid != nil || extractingbid != nil }

    private var filteredapps: [DecryptApp] {
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { return apps }
        let q = trimmed.lowercased()
        return apps.filter { $0.name.lowercased().contains(q) || $0.bundleID.lowercased().contains(q) }
    }

    /// IPA 列表筛选：搜索词 + 状态筛选（全部 / 可直接安装 / 未解密 / 结构异常）
    private var filteredipas: [OutputIPA] {
        var list = ipas
        switch ipaFilterRaw {
        case 1: list = list.filter { $0.analysis?.installable == true }
        case 2: list = list.filter { $0.analysis?.encrypted == true }
        case 3: list = list.filter { a in
            guard let a = a.analysis else { return false }
            return !a.integrity.isOK
        }
        default: break
        }
        let trimmed = query.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty { return list }
        let q = trimmed.lowercased()
        return list.filter { ipa in
            if ipa.baseName.lowercased().contains(q) { return true }
            if ipa.fileName.lowercased().contains(q) { return true }
            if let a = ipa.analysis {
                if (a.appName ?? "").lowercased().contains(q) { return true }
                if (a.bundleID ?? "").lowercased().contains(q) { return true }
            }
            return false
        }
    }

    /// 已生成过 IPA 的应用名集合（用于提示“避免重复砸壳/提取”）
    private var doneIPANames: Set<String> {
        Set(ipas.map { $0.baseName.lowercased() })
    }

    private var totalipaSize: Int64 {
        ipas.reduce(0) { $0 + $1.size }
    }

    var body: some View {
        NavigationStack {
            ZStack {
                AppTheme.background

                ScrollViewReader { proxy in
                    Group {
                        if mode == .apps {
                            if engine == .fairplay {
                                // B：FairPlay —— 不需要漏洞链，失败只会返回 errno
                                FairPlayView(installedApps: apps)
                                    .safeAreaInset(edge: .top, spacing: 0) { pinnedHeader }
                            } else {
                            // 注意：section 必须直接写在 List 里（不能藏在 some View
                            // 计算属性后面），否则 List 的 section 检测失效、全部合并
                            // 成一个隐式 section，sectiongap/索引条都会失灵。
                            List {
                                if filteredapps.isEmpty {
                                    Section {
                                        Text(query.isEmpty ? "正在加载..." : "无匹配结果。")
                                            .foregroundColor(.secondary)
                                            .frame(maxWidth: .infinity, alignment: .leading)
                                    } header: {
                                        HeaderLabel(text: "已安装应用", icon: "app.badge")
                                    }
                                } else {
                                    ForEach(azgrouped(filteredapps, name: { $0.name })) { group in
                                        Section {
                                            ForEach(group.items) { app in
                                                AppRow(
                                                    app: app,
                                                    isdecrypting: decryptingbid == app.bundleID,
                                                    isextracting: extractingbid == app.bundleID,
                                                    isdone: doneIPANames.contains(ipaBaseName(for: app).lowercased()),
                                                    ondecrypt: { startDecrypt(app) },
                                                    onextract: { startExtract(app) },
                                                    ontap: { actionapp = app }
                                                )
                                                .listRowSeparator(.hidden)
                                            }
                                        } header: {
                                            Text(group.letter)
                                                .font(.footnote.weight(.semibold))
                                                .foregroundStyle(.secondary)
                                        }
                                        .id(group.letter)   // 供索引条 scrollTo 精确跳字母分组
                                    }
                                }
                            }
                            .listStyle(.insetGrouped)
                            .scrollContentBackground(.hidden)
                            .sectiongap(0)   // 字母分组压紧
                            // 关键：状态卡 / 错误卡 / 搜索框 / 模式切换 全部放进
                            // safeAreaInset 固定区。List 内容会自动避让，滚动时从
                            // 卡片下方滑过，彻底解决大标题与条目互相遮挡的问题。
                            .safeAreaInset(edge: .top, spacing: 0) { pinnedHeader }
                            // A-Z 索引条只覆盖 List 区域
                            .overlay(alignment: .trailing) {
                                if !filteredapps.isEmpty {
                                    azindexbar(letters: azgrouped(filteredapps, name: { $0.name }).map { $0.letter }) { letter in
                                        proxy.scrollTo(letter, anchor: .top)
                                    }
                                }
                            }
                            }
                        } else {
                            // IPA 管理：改用 ScrollView + 显式卡片布局。
                            // 汇总卡 / 列表卡 / 删除条 三块之间用写死的 14pt 间距，
                            // 不再依赖 listSectionSpacing（真机上不可靠）。
                            ScrollView {
                                LazyVStack(spacing: 14) {
                                    if filteredipas.isEmpty {
                                        Text(query.isEmpty ? "暂无已砸壳 / 已提取的 IPA。" : "无匹配结果。")
                                            .font(.subheadline)
                                            .foregroundStyle(.secondary)
                                            .frame(maxWidth: .infinity)
                                            .padding(.vertical, 28)
                                            .glassCard()
                                    } else {
                                        ipaSummaryCard
                                        ipaRowsCard
                                        if ipaEditing {
                                            ipaActionBarCard
                                        }
                                    }
                                }
                                .padding(.horizontal, 16)
                                .padding(.top, 12)
                                .padding(.bottom, 28)
                            }
                            .safeAreaInset(edge: .top, spacing: 0) { pinnedHeader }
                        }
                    }
                    .toolbar {
                        if mode == .ipas {
                            ToolbarItem(placement: .navigationBarTrailing) {
                                Button(action: {
                                    ipaEditing.toggle()
                                    if !ipaEditing { selectedipas.removeAll() }
                                }) {
                                    Text(ipaEditing ? "完成" : "管理")
                                }
                            }
                        }
                    }
                }
                .navigationTitle("App 解密")
                .toolbarBackground(.hidden, for: .navigationBar)
            }
        }
        .onAppear {
            set_log_callback { msg in
                guard let msg = msg else { return }
                let s = String(cString: msg)
                DispatchQueue.main.async {
                    AppDumpmgr.shared.logmsg("(decrypt) \(s)")
                }
            }
            set_progress_callback { p in
                // C 侧已按 1% 节流，这里再做时间合并 + 主线程更新
                DecryptProgress.shared.ingestPages(Double(p))
            }
            if fsready { loadApps() }
            loadIPAs()
        }
        .onReceive(NotificationCenter.default.publisher(for: .appDumpIPAStoreDidChange)) { _ in
            // 任何路径（A 内核 / B FairPlay / 提取）写出新 IPA 都即时刷新
            loadIPAs()
        }
        .onChange(of: ipaEditing) { editing in
            if editing { selectedipas.removeAll() }
        }
        .sheet(item: $ipaDetail) { ipa in
            NavigationStack {
                ipaanalysisView(ipa: ipa,
                                onShare: { shareIPA(ipa) },
                                onDelete: {
                                    ipaDetail = nil
                                    ipaPendingDelete = ipa
                                })
            }
        }
        .confirmationDialog(
            ipaPendingDelete.map { "删除 \($0.fileName)？" } ?? "",
            isPresented: Binding(
                get: { ipaPendingDelete != nil },
                set: { if !$0 { ipaPendingDelete = nil } }
            ),
            titleVisibility: .visible
        ) {
            if let ipa = ipaPendingDelete {
                Button("删除", role: .destructive) { deleteIPA(ipa) }
            }
            Button("取消", role: .cancel) { ipaPendingDelete = nil }
        } message: {
            if let ipa = ipaPendingDelete {
                Text("\(ByteCountFormatter.string(fromByteCount: ipa.size, countStyle: .file)) · 删除后无法恢复。")
            }
        }
        .onReceive(NotificationCenter.default.publisher(for: UIApplication.didBecomeActiveNotification)) { _ in
            if let app = pendingdecrypt {
                pendingdecrypt = nil
                let pid = find_process_pid(app.executable)
                if pid > 0 {
                    doDecrypt(app, pid: pid)
                } else {
                    errormsg = "App is not running, try again."
                    decryptingbid = nil
                }
            }
        }
        .onChange(of: mgr.sbxready) { ready in
            if ready { loadApps() } else { apps.removeAll() }
        }
        // 点应用行 → 目录/砸壳/写权限 操作面板
        .confirmationDialog(
            actionapp.map { "\($0.name)  ·  \($0.bundleID)" } ?? "",
            isPresented: Binding(
                get: { actionapp != nil },
                set: { if !$0 { actionapp = nil } }
            ),
            titleVisibility: .visible
        ) {
            if let app = actionapp {
                Button("主程序目录 (.app)") { opencontainer(.bundle, app) }
                Button("Group 目录") { opencontainer(.group, app) }
                Button("数据目录") { opencontainer(.data, app) }
                if app.isEncrypted == .encrypted {
                    Button("砸壳") { startDecrypt(app) }
                } else if app.isEncrypted == .unencrypted {
                    Button("提取") { startExtract(app) }
                }
                Button("取消", role: .cancel) {}
            }
        }
        .sheet(item: $browsertarget) { target in
            SantanderView(startPath: target.path)
                .presentationDragIndicator(.visible)
        }
    }

    // MARK: - 目录跳转 / 修权限

    private enum ContainerKind { case bundle, data, group }

    private func opencontainer(_ kind: ContainerKind, _ app: DecryptApp) {
        errormsg = nil
        DispatchQueue.global(qos: .userInitiated).async {
            var path: String? = nil
            switch kind {
            case .bundle:
                path = app.bundlePath
            case .data:
                path = vfsfs.datacontainerPath(for: app.bundleID)
            case .group:
                path = vfsfs.groupcontainerPath(for: app.bundleID)
            }
            DispatchQueue.main.async {
                guard let path = path else {
                    switch kind {
                    case .group:
                        errormsg = "未找到 Group 容器：该应用可能没有配置 App Group，或容器目录当前不可读。"
                    case .data:
                        errormsg = "未找到数据容器：已尝试 /var/containers/Data 与 /var/mobile/Containers/Data 等路径均不可读，请确认「初始化系统」已完成。"
                    case .bundle:
                        errormsg = "无效的应用包路径。"
                    }
                    AppDumpmgr.shared.logmsg("(browse) \(browseKindName(kind)) 解析失败 bid=\(app.bundleID)")
                    return
                }
                browsertarget = BrowseTarget(path: path)
            }
        }
    }

    private func browseKindName(_ kind: ContainerKind) -> String {
        switch kind {
        case .bundle: return "主程序目录"
        case .group:  return "Group 目录"
        case .data:   return "数据目录"
        }
    }


    private var fsready: Bool { mgr.vfsready || mgr.sbxready }

    // MARK: - 固定头部（状态卡 / 错误卡 / 搜索框 / 模式切换）

    private var pinnedHeader: some View {
        VStack(spacing: 10) {
            if engine == .kernel && !fsready {
                statusCard
            }
            if engine == .kernel, decryptingbid != nil || extractingbid != nil {
                decryptProgressCard
            }
            if let error = errormsg {
                errorCard(error)
            }
            if engine == .kernel { searchCard }
            enginePicker
            modePicker
        }
        .padding(.horizontal, 16)
        .padding(.top, 8)
        .padding(.bottom, 20)
        .background(Color(uiColor: .systemGroupedBackground))
    }

    // MARK: - IPA 管理卡片（ScrollView 布局，间距写死，不依赖 section 间距）

    private var ipaSummaryCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                VStack(alignment: .leading, spacing: 2) {
                    Text("共 \(filteredipas.count) 个 IPA")
                        .font(.subheadline.weight(.medium))
                    Text("占用 \(byteString(totalipaSize))")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                }
                Spacer()
                if ipaEditing {
                    Button("全选") {
                        selectedipas = Set(filteredipas.map { $0.id })
                    }
                    .font(.footnote)
                    Button("清空全部", role: .destructive) {
                        confirmClearAll()
                    }
                    .font(.footnote)
                    .foregroundStyle(.red)
                }
            }

            // 状态统计：只在分析完成的包之间统计
            let done = ipas.compactMap { $0.analysis }
            if !done.isEmpty {
                HStack(spacing: 14) {
                    ipaStat("可安装", done.filter { $0.installable }.count, .green)
                    ipaStat("未解密", done.filter { $0.encrypted }.count, .red)
                    ipaStat("异常", done.filter { !$0.integrity.isOK }.count, .orange)
                    Spacer()
                }
            }

            HStack(spacing: 6) {
                Menu {
                    Button { ipaFilterRaw = 0 } label: { filterLabel("全部", 0) }
                    Button { ipaFilterRaw = 1 } label: { filterLabel("可直接安装", 1) }
                    Button { ipaFilterRaw = 2 } label: { filterLabel("未解密", 2) }
                    Button { ipaFilterRaw = 3 } label: { filterLabel("结构异常", 3) }
                } label: {
                    Label(ipaFilterRaw == 0 ? "全部" : ["全部", "可直接安装", "未解密", "结构异常"][min(ipaFilterRaw, 3)],
                          systemImage: "line.3.horizontal.decrease.circle")
                        .font(.footnote)
                }
                Spacer()
                Button {
                    analyzeAllIPAs(force: true)
                } label: {
                    Label("重新分析", systemImage: "sparkle.magnifyingglass")
                        .font(.footnote)
                }
            }
        }
        .padding(14)
        .glassCard()
    }

    private func ipaStat(_ title: String, _ n: Int, _ color: Color) -> some View {
        HStack(spacing: 4) {
            Circle().fill(color).frame(width: 6, height: 6)
            Text("\(title) \(n)")
                .font(.caption2)
                .foregroundStyle(.secondary)
        }
    }

    @ViewBuilder
    private func filterLabel(_ title: String, _ value: Int) -> some View {
        if ipaFilterRaw == value {
            Label(title, systemImage: "checkmark")
        } else {
            Text(title)
        }
    }

    private var ipaRowsCard: some View {
        // 每行自己是一张卡片：滑动露出的动作色块被行自己的圆角裁掉，
        // 不会在整块大卡片的角上漏出红 / 绿边。
        VStack(spacing: 10) {
            ForEach(filteredipas) { ipa in
                IPARow(
                    ipa: ipa,
                    analysis: ipaAnalysis[ipa.path],
                    analyzing: ipaAnalyzing.contains(ipa.path),
                    editing: ipaEditing,
                    selected: selectedipas.contains(ipa.id),
                    onToggle: {
                        if selectedipas.contains(ipa.id) {
                            selectedipas.remove(ipa.id)
                        } else {
                            selectedipas.insert(ipa.id)
                        }
                    },
                    onShare: { shareIPA(ipa) },
                    onAnalyze: { openAnalysis(for: ipa) }
                )
            }
        }
    }

    private var ipaActionBarCard: some View {
        HStack {
            Text("已选 \(selectedipas.count) 项")
                .font(.subheadline)
            Spacer()
            Button("删除所选", role: .destructive) {
                deleteSelectedIPAs()
            }
            .font(.subheadline.weight(.medium))
            .disabled(selectedipas.isEmpty)
        }
        .padding(14)
        .glassCard()
    }

    // MARK: - 顶部卡片

    @ViewBuilder
    private var statusCard: some View {
        if !mgr.dsready {
            StatusCard(icon: "bolt.slash.fill", tint: .orange,
                       title: "漏洞利用未运行",
                       message: "请先前往「内核」页，点击“运行漏洞利用”。")
        } else if mgr.vfsrunning || mgr.sbxrunning {
            StatusCard(spinner: true, tint: .blue,
                       title: "正在初始化…",
                       message: "正在建立系统访问，请稍候几秒。")
        } else if (mgr.vfsattempted && mgr.vfsfailed) || (mgr.sbxattempted && mgr.sbxfailed) {
            StatusCard(icon: "xmark.octagon.fill", tint: .red,
                       title: "系统初始化失败",
                       message: "请前往「内核」页，再次点击“初始化系统”。")
        } else {
            StatusCard(icon: "play.circle.fill", tint: .blue,
                       title: "待初始化",
                       message: "请前往「内核」页，点击“初始化系统”。")
        }
    }

    /// 砸壳进行中的实时进度（拷贝 / 逐页解密 / 打包三段合一）
    private var decryptProgressCard: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Text(kjob.stage.isEmpty ? "砸壳中…" : kjob.stage)
                    .font(.footnote.weight(.medium))
                    .lineLimit(1)
                Spacer(minLength: 8)
                Text("\(Int((min(max(kjob.fraction, 0), 1) * 100).rounded()))%")
                    .font(.footnote.monospacedDigit())
                    .foregroundStyle(.secondary)
            }
            ProgressView(value: min(max(kjob.fraction, 0), 1))
                .tint(.blue)
        }
        .padding(12)
        .glassCard()
    }

    private func errorCard(_ msg: String) -> some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "exclamationmark.triangle.fill")
                .font(.body.weight(.semibold))
                .foregroundStyle(.red)
                .padding(.top, 1)
            Text(msg)
                .font(.footnote)
                .foregroundStyle(.white.opacity(0.92))
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 0)
        }
        .padding(12)
        .background(
            RoundedRectangle(cornerRadius: AppTheme.cornerRadius, style: .continuous)
                .fill(Color.red.opacity(0.12))
        )
        .overlay(
            RoundedRectangle(cornerRadius: AppTheme.cornerRadius, style: .continuous)
                .strokeBorder(Color.red.opacity(0.3), lineWidth: 0.5)
        )
    }

    private var searchCard: some View {
        HStack(spacing: 8) {
            Image(systemName: "magnifyingglass")
                .font(.body)
                .foregroundStyle(.secondary)
            TextField(mode == .apps ? "搜索应用" : "搜索 IPA", text: $query)
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
            Button(action: {
                if mode == .apps { loadApps() } else { loadIPAs() }
            }) {
                Image(systemName: "arrow.clockwise")
                    .font(.body.weight(.semibold))
                    .foregroundStyle(.blue)
            }
            .disabled((mode == .apps && !fsready) || busy)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 11)
        .glassCard()
    }

    private var engine: DecryptEngine {
        DecryptEngine(rawValue: engineRaw) ?? .kernel
    }

    private var enginePicker: some View {
        Picker("", selection: Binding(
            get: { engine },
            set: { newValue in
                engineRaw = newValue.rawValue
                errormsg = nil
                query = ""
            }
        )) {
            Text("A · 内核砸壳").tag(DecryptEngine.kernel)
            Text("B · FairPlay").tag(DecryptEngine.fairplay)
        }
        .pickerStyle(.segmented)
        .labelsHidden()
    }

    private var modePicker: some View {
        Picker("", selection: $mode) {
            Text("应用").tag(DecryptMode.apps)
            Text("IPA").tag(DecryptMode.ipas)
        }
        .pickerStyle(.segmented)
        .onChange(of: mode) { _ in
            query = ""
            selectedipas.removeAll()
            ipaEditing = false
            // 切到 IPA 页就重新扫盘：B 版（FairPlay）产物是后台任务写的，
            // 以前不切视图就不会刷新，看起来像「刚砸好的应用没出现」。
            if mode == .ipas { loadIPAs() }
        }
    }

    // MARK: - IPA 逻辑

    private func ipaBaseName(for app: DecryptApp) -> String {
        app.name
            .replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "\t", with: "")
    }

    func loadIPAs() {
        guard !loadingipas else { return }
        loadingipas = true
        DispatchQueue.global(qos: .userInitiated).async {
            let fm = FileManager.default
            var results: [OutputIPA] = []
            let sources: [(String, IPASource)] = [
                (documentspath + "/Decrypted", .decrypted),
                (documentspath + "/Extracted", .extracted)
            ]
            for (dir, source) in sources {
                guard let files = try? fm.contentsOfDirectory(atPath: dir) else { continue }
                for f in files where f.hasSuffix(".ipa") {
                    let full = dir + "/" + f
                    let attrs = try? fm.attributesOfItem(atPath: full)
                    let size = (attrs?[.size] as? Int64) ?? 0
                    let date = (attrs?[.modificationDate] as? Date) ?? Date()
                    results.append(OutputIPA(
                        baseName: (f as NSString).deletingPathExtension,
                        fileName: f, path: full, size: size, date: date, source: source
                    ))
                }
            }
            results.sort { $0.date > $1.date }
            DispatchQueue.main.async {
                // 沿用已经分析过的结果（文件没变就不重算）
                for i in results.indices {
                    if let cached = ipaAnalysis[results[i].path] { results[i].analysis = cached }
                }
                // 文件被外部删掉 / 改名时清掉对应缓存
                let live = Set(results.map { $0.path })
                ipaAnalysis = ipaAnalysis.filter { live.contains($0.key) }
                ipas = results
                loadingipas = false
                analyzeAllIPAs(force: false)
            }
        }
    }

    // MARK: - IPA 分析

    /// 逐个在后台分析（串行，避免同时开多个 zip 句柄和 512KB 缓冲）。
    /// force = false 时跳过已经有结果的包。
    private func analyzeAllIPAs(force: Bool) {
        let pending = ipas.filter { !ipaAnalyzing.contains($0.path) && (force || ipaAnalysis[$0.path] == nil) }
        guard !pending.isEmpty else { return }
        ipaAnalyzing.formUnion(pending.map { $0.path })
        DispatchQueue.global(qos: .utility).async {
            for ipa in pending {
                let result = ipaanalyzer.analyze(path: ipa.path)
                DispatchQueue.main.async {
                    ipaAnalysis[ipa.path] = result
                    ipaAnalyzing.remove(ipa.path)
                    if let idx = ipas.firstIndex(where: { $0.path == ipa.path }) {
                        ipas[idx].analysis = result
                    }
                }
            }
        }
    }

    /// 点「分析」：有缓存直接展示，没有就先算再展示。
    private func openAnalysis(for ipa: OutputIPA) {
        if let a = ipaAnalysis[ipa.path] {
            var copy = ipa
            copy.analysis = a
            ipaDetail = copy
            return
        }
        ipaAnalyzing.insert(ipa.path)
        DispatchQueue.global(qos: .userInitiated).async {
            let result = ipaanalyzer.analyze(path: ipa.path)
            DispatchQueue.main.async {
                ipaAnalysis[ipa.path] = result
                ipaAnalyzing.remove(ipa.path)
                if let idx = ipas.firstIndex(where: { $0.path == ipa.path }) {
                    ipas[idx].analysis = result
                }
                var copy = ipa
                copy.analysis = result
                ipaDetail = copy
            }
        }
    }

    /// 单个删除（滑动菜单用）。同名 .plist / .app 目录一起清。
    private func deleteIPA(_ ipa: OutputIPA) {
        let fm = FileManager.default
        let stem = (ipa.path as NSString).deletingPathExtension
        var removed = false
        for p in [ipa.path, stem + ".plist", stem] where fm.fileExists(atPath: p) {
            do {
                try fm.removeItem(atPath: p)
                removed = true
            } catch {
                // 属主不对的文件：先改成可写再试一次
                chmod(p, 0o700)
                if (try? fm.removeItem(atPath: p)) != nil { removed = true }
                else { AppDumpmgr.shared.logmsg("(ipa) delete failed \(p): \(error.localizedDescription)") }
            }
        }
        if !removed {
            errormsg = "删除失败：\(ipa.fileName)"
        } else {
            AppDumpmgr.shared.logmsg("(ipa) deleted \(ipa.fileName)")
            ipaAnalysis.removeValue(forKey: ipa.path)
            ipas.removeAll { $0.path == ipa.path }
            selectedipas.remove(ipa.id)
        }
        ipaPendingDelete = nil
    }

    private func deleteSelectedIPAs() {
        let toDelete = ipas.filter { selectedipas.contains($0.id) }
        guard !toDelete.isEmpty else { return }
        let fm = FileManager.default
        var failed = 0
        for ipa in toDelete {
            do {
                try fm.removeItem(atPath: ipa.path)
            } catch {
                failed += 1
                AppDumpmgr.shared.logmsg("(ipa) delete failed \(ipa.fileName): \(error.localizedDescription)")
            }
        }
        selectedipas.removeAll()
        if failed > 0 {
            errormsg = "有 \(failed) 个 IPA 删除失败。"
        }
        loadIPAs()
    }

    private func confirmClearAll() {
        Alertinator.shared.alert(
            title: "清空全部 IPA？",
            body: "将删除所有已砸壳 / 已提取的 IPA（共 \(ipas.count) 个，占用 \(byteString(totalipaSize))）。此操作不可撤销。",
            actionLabel: "清空",
            action: {
                let fm = FileManager.default
                for dir in [documentspath + "/Decrypted", documentspath + "/Extracted"] {
                    if let files = try? fm.contentsOfDirectory(atPath: dir) {
                        for f in files where f.hasSuffix(".ipa") {
                            try? fm.removeItem(atPath: dir + "/" + f)
                        }
                    }
                }
                selectedipas.removeAll()
                AppDumpmgr.shared.logmsg("(ipa) cleared all")
                loadIPAs()
            }
        )
    }

    private func shareIPA(_ ipa: OutputIPA) {
        presentShareSheet(with: URL(fileURLWithPath: ipa.path))
    }

    private func byteString(_ bytes: Int64) -> String {
        let formatter = ByteCountFormatter()
        formatter.allowedUnits = [.useKB, .useMB, .useGB]
        formatter.countStyle = .file
        return formatter.string(fromByteCount: bytes)
    }

    func loadApps() {
        guard fsready else { return }
        guard !loadingapps else { return }   // 防止重复触发（onAppear + sbxready 变化会各来一次）
        // FairPlay 任务运行时不要重扫 144 个应用：vfs 会给每个图标刷十几行日志，
        // 主线程被日志和重排拖死，取消按钮就点不动了。
        guard !FairPlayJob.shared.busy else {
            AppDumpmgr.shared.logmsg("(decrypt) 跳过应用列表刷新：FairPlay 任务进行中")
            return
        }
        loadingapps = true
        DispatchQueue.global(qos: .userInitiated).async {
            // 沙箱逃逸失败时走 VFS：内核级列目录 + 读 Info.plist / Mach-O，不过沙箱
            if !mgr.sbxready {
                var vfsresults: [DecryptApp] = []
                for b in vfsfs.listappbundles() {
                    var status: DecryptStatus = .unknown
                    if let head = mgr.vfsread(path: b.path + "/" + b.executable, maxSize: 256 * 1024) {
                        let cid = vfsfs.cryptid(head)
                        if cid > 0 { status = .encrypted }
                        else if cid == 0 { status = .unencrypted }
                    }
                    vfsresults.append(DecryptApp(name: b.name, bundleID: b.bundleid, bundlePath: b.path,
                                                 executable: b.executable,
                                                 icon: b.icon ?? UIImage(named: "unknown"),
                                                 isEncrypted: status))
                }
                vfsresults.sort { $0.name.lowercased() < $1.name.lowercased() }
                AppDumpmgr.shared.logmsg("(decrypt) VFS app list: \(vfsresults.count)")
                DispatchQueue.main.async {
                    apps = vfsresults
                    loadingapps = false
                }
                return
            }

            var results: [DecryptApp] = []
            let bundleFolder = "/private/var/containers/Bundle/Application"

            guard let bundles = try? FileManager.default.contentsOfDirectory(atPath: bundleFolder) else {
                AppDumpmgr.shared.logmsg("(decrypt) cannot list \(bundleFolder)")
                DispatchQueue.main.async {
                    apps.removeAll()
                    loadingapps = false
                }
                return
            }

            for bundle in bundles {
                let appPath = bundleFolder + "/" + bundle
                guard let contents = try? FileManager.default.contentsOfDirectory(atPath: appPath) else { continue }
                for item in contents {
                    guard item.hasSuffix(".app") else { continue }
                    let fullAppPath = appPath + "/" + item
                    let infoPath = fullAppPath + "/Info.plist"
                    guard let info = NSDictionary(contentsOfFile: infoPath) else { continue }

                    let executable = info["CFBundleExecutable"] as? String ?? ""
                    if executable.isEmpty { continue }
                    let bundleid = info["CFBundleIdentifier"] as? String ?? ""
                    let name = (info["CFBundleDisplayName"] as? String) ??
                               (info["CFBundleName"] as? String) ??
                               (item as NSString).deletingPathExtension

                    // 图标统一走 vfsfs 的加载器（POSIX/VFS 双通道 + 文件名兜底 + Assets.car），
                    // 这里原来只认 CFBundlePrimaryIcon 的 @2x/.png 三个候选，自签包很容易一个都不中。
                    let icon = vfsfs.iconforapp(appdir: fullAppPath, info: info)

                    let encResult = is_encrypted(fullAppPath, executable)
                    let status: DecryptStatus
                    if encResult > 0 { status = .encrypted }
                    else if encResult == 0 { status = .unencrypted }
                    else { status = .unknown }

                    results.append(DecryptApp(
                        name: name, bundleID: bundleid, bundlePath: fullAppPath,
                        executable: executable,
                        icon: icon ?? UIImage(named: "unknown"),
                        isEncrypted: status
                    ))
                    break
                }
            }

            results.sort { $0.name.lowercased() < $1.name.lowercased() }
            AppDumpmgr.shared.logmsg("(decrypt) app list: \(results.count)")
            DispatchQueue.main.async {
                apps = results
                loadingapps = false
            }
        }
    }

    private func bundledSize(_ app: DecryptApp) -> Int64 {
        var total: Int64 = 0
        let appurl = URL(fileURLWithPath: app.bundlePath)
        if let enumerator = FileManager.default.enumerator(at: appurl, includingPropertiesForKeys: [.fileSizeKey]) {
            for case let furi as URL in enumerator {
                if let fs = (try? furi.resourceValues(forKeys: [.fileSizeKey]))?.fileSize {
                    total += Int64(fs)
                }
            }
        }
        return total
    }

    /// 可用空间（优先取 volumeAvailableCapacityForImportantUsage，回落 systemFreeSize）
    private func ipaBaseNameForLog(_ path: String) -> String {
        (path as NSString).lastPathComponent
    }

    private func freeDiskBytes() -> Int64 {
        let url = URL(fileURLWithPath: documentspath)
        if let v = try? url.resourceValues(forKeys: [.volumeAvailableCapacityForImportantUsageKey]),
           let n = v.volumeAvailableCapacityForImportantUsage, n > 0 {
            return Int64(n)
        }
        if let a = try? FileManager.default.attributesOfFileSystem(forPath: documentspath),
           let n = a[.systemFreeSize] as? NSNumber {
            return n.int64Value
        }
        return 0
    }

    /// 砸壳/提取至少要「原包拷贝 + 打包产物」两份空间，再留 512MB 余量。
    /// 空间不够时提前报错，而不是写到一半被系统打断/闪退。
    /// 体积由调用方在后台算好传进来 —— 以前这里自己调 bundledSize()，
    /// 主线程上递归枚举 GB 级目录，点一下应用就冻好几秒。
    private func checkDiskSpace(bytes: Int64) -> String? {
        let need = bytes * 2 + 512 * 1024 * 1024
        let free = freeDiskBytes()
        guard free > 0 else { return nil }
        if free < need {
            return "可用空间不足：需要约 \(byteString(need))（原包拷贝 + 打包），当前仅剩 \(byteString(free))。请先清理 Documents 里的旧 IPA。"
        }
        return nil
    }

    func startDecrypt(_ app: DecryptApp) {
        guard decryptingbid == nil && pendingdecrypt == nil else { return }
        guard mgr.dsready else { errormsg = "Darksword 未就绪，请先运行漏洞利用。"; return }
        guard fsready else { errormsg = "沙箱未逃逸且 VFS 未就绪。"; return }

        // 体积枚举放后台：大 App 递归 stat 整个 bundle 要好几秒，不能占主线程
        DispatchQueue.global(qos: .userInitiated).async {
            let size = bundledSize(app)
            DispatchQueue.main.async {
                guard decryptingbid == nil && pendingdecrypt == nil else { return }
                if size > 200 * 1024 * 1024 {
                    Alertinator.shared.alert(
                        title: "大型应用",
                        body: "该应用体积 \(byteString(size))，砸壳可能需要较长时间，请保持屏幕常亮。",
                        actionLabel: "继续",
                        action: { self.runDecrypt(app, sourceBytes: size) }
                    )
                } else {
                    self.runDecrypt(app, sourceBytes: size)
                }
            }
        }
    }

    // self-signed / sideloaded apps are not FairPlay-encrypted, so there is nothing
    // to decrypt: the bundle just gets copied out and zipped back into an ipa.
    // no kernel work and no target process needed, the sandbox escape is enough.
    func startExtract(_ app: DecryptApp) {
        guard !busy && pendingdecrypt == nil else { return }
        guard fsready else { errormsg = "沙箱未逃逸且 VFS 未就绪。"; return }

        DispatchQueue.global(qos: .userInitiated).async {
            let size = bundledSize(app)
            DispatchQueue.main.async {
                guard !busy && pendingdecrypt == nil else { return }
                if size > 200 * 1024 * 1024 {
                    Alertinator.shared.alert(
                        title: "大型应用",
                        body: "该应用体积 \(byteString(size))，提取可能需要较长时间，请保持屏幕常亮。",
                        actionLabel: "继续",
                        action: { self.runExtract(app, sourceBytes: size) }
                    )
                } else {
                    self.runExtract(app, sourceBytes: size)
                }
            }
        }
    }

    func runExtract(_ app: DecryptApp, sourceBytes: Int64 = 0) {
        errormsg = nil
        extractingbid = app.bundleID
        DecryptProgress.shared.begin(sourceBytes: sourceBytes)

        let appName = (app.bundlePath as NSString).lastPathComponent
        let ipaName = app.name
            .replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "\t", with: "")
            .appending(".ipa")
        let outDir = documentspath + "/Extracted"
        let workDir = outDir + "/.tmp_" + app.bundleID
        let destAppPath = workDir + "/" + appName
        let payloadDir = workDir + "/Payload"
        let payloadAppPath = payloadDir + "/" + appName
        let ipaPath = outDir + "/" + ipaName

        AppDumpmgr.shared.logmsg("(extract) \(app.bundleID) is not encrypted, copying bundle...")

        // 整个拷贝/打包期间持有后台断言，锁屏或切后台不会把任务挂起
        let assertion = BackgroundAssertion("AppDumpExtract")

        DispatchQueue.global(qos: .userInitiated).async {
            defer { assertion.end() }
            let fm = FileManager.default

            try? fm.removeItem(atPath: workDir)
            try? fm.createDirectory(atPath: payloadDir, withIntermediateDirectories: true)
            // 关键修复：destAppPath 必须先建好。enumerator 的返回顺序是
            // readdir 顺序（不保证父目录在前），若主二进制排在前面、而
            // workDir/<App>.app 还不存在，copyItem 会静默失败 →
            // "main binary missing after copy"（部分 App 提取失败的真因）
            try? fm.createDirectory(atPath: destAppPath, withIntermediateDirectories: true)

            // 沙箱逃逸不可用时用 VFS 递归拷贝（读走内核，写走本 App 沙箱）
            if !mgr.sbxready {
                let cr = vfsfs.copytree(from: app.bundlePath, to: destAppPath)
                AppDumpmgr.shared.logmsg("(copy) vfs: \(cr.files) files / \(cr.bytes) bytes, failed \(cr.failed)")
                DecryptProgress.shared.endCopy()
            } else {
            guard let enumerator = fm.enumerator(atPath: app.bundlePath) else {
                DispatchQueue.main.async {
                    extractingbid = nil
                    errormsg = "无法枚举应用包以拷贝"
                    AppDumpmgr.shared.logmsg("(extract) cannot enumerate \(app.bundlePath)")
                }
                return
            }

            var copiedBytes: Int64 = 0
            for case let subpath as String in enumerator {
                let src = (app.bundlePath as NSString).appendingPathComponent(subpath)
                let dst = (destAppPath as NSString).appendingPathComponent(subpath)
                var isDir: ObjCBool = false
                guard fm.fileExists(atPath: src, isDirectory: &isDir) else { continue }
                if isDir.boolValue {
                    try? fm.createDirectory(atPath: dst, withIntermediateDirectories: true)
                } else {
                    do {
                        try fm.copyItem(atPath: src, toPath: dst)
                    } catch {
                        // 个别文件被系统拒绝时跳过并记录，不能让整个提取失败
                        AppDumpmgr.shared.logmsg("(extract) copy skipped \(subpath): \(error.localizedDescription)")
                    }
                    let sz = ((try? fm.attributesOfItem(atPath: dst))?[.size] as? NSNumber)?.int64Value ?? 0
                    copiedBytes += sz
                    DecryptProgress.shared.updateCopy(done: copiedBytes, total: sourceBytes)
                }
            }
            DecryptProgress.shared.endCopy()
            }

            guard fm.fileExists(atPath: destAppPath + "/" + app.executable) else {
                DispatchQueue.main.async {
                    extractingbid = nil
                    errormsg = "拷贝不完整，无法提取。"
                    AppDumpmgr.shared.logmsg("(extract) main binary missing after copy")
                }
                return
            }

            // 去除设备限制：打包前改写 MinimumOSVersion / 设备能力要求
            if UserDefaults.standard.bool(forKey: "stripInstallLimits") {
                let minimum = UserDefaults.standard.string(forKey: "minimumOSOverride") ?? installrestrict.defaultminimum
                let res = installrestrict.apply(toAppAt: destAppPath, minimum: minimum)
                let tag = res.ok ? "ok" : "failed"
                AppDumpmgr.shared.logmsg("(restrict) \(tag): \(res.message)")
            }

            do {
                try fm.moveItem(atPath: destAppPath, toPath: payloadAppPath)
            } catch {
                DispatchQueue.main.async {
                    extractingbid = nil
                    errormsg = "移动应用包失败：\(error.localizedDescription)"
                    AppDumpmgr.shared.logmsg("(extract) move failed: \(error.localizedDescription)")
                }
                return
            }

            DecryptProgress.shared.setStage("打包 ipa…")
            do {
                try createZipArchive(
                    fromDirectory: URL(fileURLWithPath: workDir, isDirectory: true),
                    to: URL(fileURLWithPath: ipaPath),
                    progress: { f in DecryptProgress.shared.updatePack(f) }
                )
            } catch {
                DecryptProgress.shared.abort()
                DispatchQueue.main.async {
                    extractingbid = nil
                    errormsg = "生成 ipa 失败：\(error.localizedDescription)"
                    AppDumpmgr.shared.logmsg("(extract) zip failed: \(error.localizedDescription)")
                }
                return
            }

            try? fm.removeItem(atPath: workDir)
            DecryptProgress.shared.finish()

            DispatchQueue.main.async {
                extractingbid = nil
                AppDumpmgr.shared.logmsg("(extract) ipa saved to \(ipaPath)")
                loadIPAs()   // 刷新 IPA 列表
                NotificationCenter.default.post(name: .appDumpIPAStoreDidChange, object: nil)
                // 超大 IPA 不要自动弹分享面板：UIActivityViewController 会为
                // 3GB+ 的归档建预览/拷贝一份，内存瞬间翻倍，直接闪退。
                let outAttrs = (try? FileManager.default.attributesOfItem(atPath: ipaPath)) ?? [:]
                let outSize = (outAttrs[.size] as? NSNumber)?.int64Value ?? 0
                if outSize > 1_536 * 1024 * 1024 {
                    AppDumpmgr.shared.logmsg("\(ipaBaseNameForLog(ipaPath)) 体积 \(byteString(outSize))，已跳过自动分享；请在「IPA」页手动导出。")
                } else {
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                        presentShareSheet(with: URL(fileURLWithPath: ipaPath))
                    }
                }
            }
        }
    }

    func runDecrypt(_ app: DecryptApp, sourceBytes: Int64 = 0) {
        errormsg = nil
        decryptingbid = app.bundleID
        DecryptProgress.shared.begin(sourceBytes: sourceBytes)

        let pid = find_process_pid(app.executable)
        if pid > 0 {
            doDecrypt(app, pid: pid, sourceBytes: sourceBytes)
        } else {
            pendingdecrypt = app

            var bgTask: UIBackgroundTaskIdentifier = .invalid
            bgTask = UIApplication.shared.beginBackgroundTask(withName: "AutoResumeDecrypt") {
                UIApplication.shared.endBackgroundTask(bgTask)
            }

            let ret = launch_app(app.bundleID)
            guard ret == 0 else {
                UIApplication.shared.endBackgroundTask(bgTask)
                pendingdecrypt = nil
                decryptingbid = nil
                errormsg = "无法启动应用，请手动打开。"
                return
            }

            DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + 2.5) {
                launch_app(Bundle.main.bundleIdentifier!)
                usleep(500000)

                if self.pendingdecrypt != nil {
                    self.pendingdecrypt = nil
                    let foundPid = find_process_pid(app.executable)
                    if foundPid > 0 {
                        DispatchQueue.main.async {
                            self.doDecrypt(app, pid: foundPid, sourceBytes: sourceBytes)
                        }
                    } else {
                        DispatchQueue.main.async {
                            self.decryptingbid = nil
                            self.errormsg = "启动后未找到进程，请手动尝试。"
                        }
                    }
                }

                DispatchQueue.main.async {
                    UIApplication.shared.endBackgroundTask(bgTask)
                }
            }
        }
    }

    func doDecrypt(_ app: DecryptApp, pid: pid_t, sourceBytes: Int64 = 0) {
        let appName = (app.bundlePath as NSString).lastPathComponent
        let ipaName = app.name
            .replacingOccurrences(of: " ", with: "")
            .replacingOccurrences(of: "\t", with: "")
            .appending(".ipa")
        let workDir = documentspath + "/Decrypted/.tmp_" + app.bundleID
        let destAppPath = workDir + "/" + appName
        let payloadDir = workDir + "/Payload"
        let payloadAppPath = payloadDir + "/" + appName
        let ipaPath = documentspath + "/Decrypted/" + ipaName

        AppDumpmgr.shared.logmsg("(decrypt) decrypting \(app.bundleID)...")

        // 整段任务（拷贝 → 逐页解密 → 打包）都要有后台断言，否则锁屏即挂起
        let assertion = BackgroundAssertion("AppDumpKernelDecrypt")

        DispatchQueue.global(qos: .userInitiated).async {
            defer { assertion.end() }
            let fm = FileManager.default

            // 体积优先用调用方算好的；没传（例如从 didBecomeActive 直接续跑）就在这里补算，
            // 反正这段已经在后台队列上了
            let sourceTotal = sourceBytes > 0 ? sourceBytes : bundledSize(app)
            DecryptProgress.shared.begin(sourceBytes: sourceTotal)

            if let spaceErr = checkDiskSpace(bytes: sourceTotal) {
                DispatchQueue.main.async {
                    decryptingbid = nil
                    errormsg = spaceErr
                    AppDumpmgr.shared.logmsg("(decrypt) aborted: \(spaceErr)")
                }
                return
            }

            try? fm.removeItem(atPath: workDir)
            try? fm.createDirectory(atPath: payloadDir, withIntermediateDirectories: true)
            // 同 runExtract：先建好 destAppPath，避免拷贝顺序导致主二进制丢失
            try? fm.createDirectory(atPath: destAppPath, withIntermediateDirectories: true)
            AppDumpmgr.shared.logmsg("(copy) start → \(destAppPath)")

            // 沙箱逃逸不可用时用 VFS 递归拷贝（读走内核，写走本 App 沙箱）
            if !mgr.sbxready {
                let cr = vfsfs.copytree(from: app.bundlePath, to: destAppPath)
                AppDumpmgr.shared.logmsg("(copy) vfs: \(cr.files) files / \(cr.bytes) bytes, failed \(cr.failed)")
                DecryptProgress.shared.endCopy()
            } else {
            guard let enumerator = fm.enumerator(atPath: app.bundlePath) else {
                DispatchQueue.main.async {
                    decryptingbid = nil
                    errormsg = "无法枚举应用包以拷贝"
                    AppDumpmgr.shared.logmsg("(decrypt) cannot enumerate \(app.bundlePath)")
                }
                return
            }

            var copiedBytes: Int64 = 0
            for case let subpath as String in enumerator {
                let src = (app.bundlePath as NSString).appendingPathComponent(subpath)
                let dst = (destAppPath as NSString).appendingPathComponent(subpath)
                var isDir: ObjCBool = false
                guard fm.fileExists(atPath: src, isDirectory: &isDir) else { continue }
                if isDir.boolValue {
                    try? fm.createDirectory(atPath: dst, withIntermediateDirectories: true)
                } else {
                    do {
                        try fm.copyItem(atPath: src, toPath: dst)
                    } catch {
                        // 个别文件被系统拒绝时跳过并记录，不能让整个砸壳失败
                        AppDumpmgr.shared.logmsg("(decrypt) copy skipped \(subpath): \(error.localizedDescription)")
                    }
                    let sz = ((try? fm.attributesOfItem(atPath: dst))?[.size] as? NSNumber)?.int64Value ?? 0
                    copiedBytes += sz
                    DecryptProgress.shared.updateCopy(done: copiedBytes, total: sourceTotal)
                }
            }
            DecryptProgress.shared.endCopy()
            }

            AppDumpmgr.shared.logmsg("(copy) done")

            let mainBinary = destAppPath + "/" + app.executable
            // 主程序占 0.30→0.62，其余附属 Mach-O 均分 0.62→0.88
            DecryptProgress.shared.beginBinary("解密主二进制…",
                                              base: DecryptProgress.copyEnd,
                                              span: 0.32)
            let mainRet = decrypt_binary_pid((app.bundlePath + "/" + app.executable), pid, mainBinary)
            guard mainRet == 0 else {
                DecryptProgress.shared.abort()
                DispatchQueue.main.async {
                    decryptingbid = nil
                    errormsg = "主二进制解密失败"
                    AppDumpmgr.shared.logmsg("(decrypt) main binary decrypt failed")
                }
                return
            }

            // ── 解密 bundle 内其余全部加密 Mach-O ──────────────────────────
            // 递归扫整个 bundle，覆盖 Frameworks/*.framework、
            // PlugIns/*.appex 以及散落的 .dylib，而不只是 Frameworks 一层。
            // 扩展（.appex）跑在自己的进程里，宿主 pid 匹配不上它的 LC_UUID，
            // 所以用 decrypt_binary_search：先试宿主 pid，失败再遍历所有进程。
            let mainBinURL = URL(fileURLWithPath: mainBinary)
            // 先把候选列出来，才知道每份二进制该占进度条的多少；以前是边走边解，
            // 进度只能给个含糊的百分比
            var subs: [String] = []
            for rel in (fm.subpaths(atPath: destAppPath) ?? []) {
                let full = (destAppPath as NSString).appendingPathComponent(rel)
                var isDir: ObjCBool = false
                guard fm.fileExists(atPath: full, isDirectory: &isDir), !isDir.boolValue else { continue }
                if full == mainBinURL.path { continue }

                let ext = (rel as NSString).pathExtension.lowercased()
                let candidate = ext == "dylib"
                    || (full as NSString).pathExtension.isEmpty   // framework / appex 主二进制
                    || rel.contains(".framework/")
                    || rel.contains(".appex/")
                if !candidate { continue }
                if is_encrypted_path(full) <= 0 { continue }
                subs.append(full)
            }

            var subDecrypted = 0, subFailed = 0
            let subBase = 0.62
            let subSpan = DecryptProgress.pagesEnd - subBase
            for (idx, full) in subs.enumerated() {
                let rel = String(full.dropFirst(destAppPath.count + 1))
                // 每份二进制分到自己的小格；C 回调的 0…1 只映射到这一格，
                // 且整体只增不减，所以不会出现"解下一个文件时进度倒退"
                DecryptProgress.shared.beginBinary(
                    "解密 \(rel)（\(idx + 1)/\(subs.count)）",
                    base: subBase + subSpan * Double(idx) / Double(max(subs.count, 1)),
                    span: subSpan / Double(max(subs.count, 1))
                )

                if decrypt_binary_search(full, pid, full) != 0 {
                    // 空闲的 .appex 没有进程在跑，读不到解密页
                    subFailed += 1
                    AppDumpmgr.shared.logmsg("(decrypt) \(rel) 未在运行，无法脱壳（可先启动该扩展）")
                } else {
                    subDecrypted += 1
                    AppDumpmgr.shared.logmsg("(decrypt) \(rel) 解密成功")
                }
            }
            AppDumpmgr.shared.logmsg("(decrypt) 附属 Mach-O：成功 \(subDecrypted)，跳过 \(subFailed)")

            // 去除设备限制：打包前改写 MinimumOSVersion / 设备能力要求
            if UserDefaults.standard.bool(forKey: "stripInstallLimits") {
                let minimum = UserDefaults.standard.string(forKey: "minimumOSOverride") ?? installrestrict.defaultminimum
                let res = installrestrict.apply(toAppAt: destAppPath, minimum: minimum)
                let tag = res.ok ? "ok" : "failed"
                AppDumpmgr.shared.logmsg("(restrict) \(tag): \(res.message)")
            }

            AppDumpmgr.shared.logmsg("(decrypt) all Mach-O done, packaging ipa...")

            do {
                try fm.moveItem(atPath: destAppPath, toPath: payloadAppPath)
            } catch {
                DispatchQueue.main.async {
                    decryptingbid = nil
                    errormsg = "移动应用包失败：\(error.localizedDescription)"
                    AppDumpmgr.shared.logmsg("(decrypt) move failed: \(error.localizedDescription)")
                }
                return
            }

            DecryptProgress.shared.setStage("打包 ipa…")
            do {
                try createZipArchive(
                    fromDirectory: URL(fileURLWithPath: workDir, isDirectory: true),
                    to: URL(fileURLWithPath: ipaPath),
                    progress: { f in DecryptProgress.shared.updatePack(f) }
                )
            } catch {
                DecryptProgress.shared.abort()
                DispatchQueue.main.async {
                    decryptingbid = nil
                    errormsg = "生成 ipa 失败：\(error.localizedDescription)"
                    AppDumpmgr.shared.logmsg("(decrypt) zip failed: \(error.localizedDescription)")
                }
                return
            }

            try? fm.removeItem(atPath: workDir)
            DecryptProgress.shared.finish()

            DispatchQueue.main.async {
                decryptingbid = nil
                AppDumpmgr.shared.logmsg("(decrypt) ipa saved to \(ipaPath)")
                loadIPAs()   // 刷新 IPA 列表
                NotificationCenter.default.post(name: .appDumpIPAStoreDidChange, object: nil)
                // 超大 IPA 不要自动弹分享面板：UIActivityViewController 会为
                // 3GB+ 的归档建预览/拷贝一份，内存瞬间翻倍，直接闪退。
                let outAttrs = (try? FileManager.default.attributesOfItem(atPath: ipaPath)) ?? [:]
                let outSize = (outAttrs[.size] as? NSNumber)?.int64Value ?? 0
                if outSize > 1_536 * 1024 * 1024 {
                    AppDumpmgr.shared.logmsg("\(ipaBaseNameForLog(ipaPath)) 体积 \(byteString(outSize))，已跳过自动分享；请在「IPA」页手动导出。")
                } else {
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                        presentShareSheet(with: URL(fileURLWithPath: ipaPath))
                    }
                }
            }
        }
    }
}

// MARK: - 状态卡

private struct StatusCard: View {
    var icon: String = ""
    var spinner: Bool = false
    let tint: Color
    let title: String
    let message: String

    var body: some View {
        HStack(spacing: 12) {
            ZStack {
                if spinner {
                    ProgressView()
                        .tint(tint)
                } else {
                    Image(systemName: icon)
                        .font(.title3.weight(.semibold))
                        .foregroundStyle(tint)
                }
            }
            .frame(width: 28, height: 28)

            VStack(alignment: .leading, spacing: 2) {
                Text(title)
                    .font(.subheadline.weight(.semibold))
                Text(message)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
        .padding(14)
        .glassCard()
    }
}

// MARK: - 应用行

struct AppRow: View {
    let app: DecryptApp
    let isdecrypting: Bool
    let isextracting: Bool
    var isdone: Bool = false
    let ondecrypt: () -> Void
    let onextract: () -> Void
    var ontap: (() -> Void)? = nil

    var body: some View {
        HStack(spacing: 12) {
            appIcon

            VStack(alignment: .leading, spacing: 3) {
                Text(app.name)
                    .font(.body.weight(.medium))
                    .lineLimit(1)
                Text(app.bundleID)
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                statusBadge
            }

            Spacer(minLength: 8)

            actionButton
        }
        .padding(.vertical, 4)
        .opacity(isdecrypting || isextracting ? 0.6 : 1.0)
        .contentShape(Rectangle())
        .onTapGesture { ontap?() }
    }

    @ViewBuilder
    private var appIcon: some View {
        if let icon = app.icon {
            Image(uiImage: icon)
                .resizable()
                .scaledToFit()
                .frame(width: 44, height: 44)
                .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))
        } else {
            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(Color.white.opacity(0.06))
                .frame(width: 44, height: 44)
                .overlay(
                    Image(systemName: "app.dashed")
                        .foregroundStyle(.secondary)
                )
        }
    }

    private var statusBadge: some View {
        let text: String
        let color: Color
        switch app.isEncrypted {
        case .encrypted:
            text = "已加密"; color = .orange
        case .unencrypted:
            text = "未加密"; color = .green
        case .unknown:
            text = "不适用"; color = .gray
        }
        return HStack(spacing: 6) {
            Text(text)
                .font(.caption2.weight(.medium))
                .padding(.horizontal, 7)
                .padding(.vertical, 2)
                .background(Capsule().fill(color.opacity(0.15)))
                .foregroundStyle(color)
            // 已生成过 IPA：提示避免重复操作
            if isdone {
                Text("已生成")
                    .font(.caption2.weight(.medium))
                    .padding(.horizontal, 7)
                    .padding(.vertical, 2)
                    .background(Capsule().fill(Color.blue.opacity(0.15)))
                    .foregroundStyle(.blue)
            }
        }
    }

    @ViewBuilder
    private var actionButton: some View {
        switch app.isEncrypted {
        case .encrypted:
            pillButton(label: "砸壳", systemImage: "lock.open.fill", tint: .blue,
                       busy: isdecrypting, action: ondecrypt)
        case .unknown:
            pillButton(label: "砸壳", systemImage: "lock.fill", tint: .gray,
                       busy: isdecrypting, action: ondecrypt)
                .disabled(true)
                .opacity(0.5)
        case .unencrypted:
            pillButton(label: "提取", systemImage: "square.and.arrow.up.fill", tint: .green,
                       busy: isextracting, action: onextract)
        }
    }

    private func pillButton(label: String, systemImage: String, tint: Color,
                            busy: Bool, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 5) {
                if busy {
                    ProgressView()
                        .controlSize(.mini)
                        .tint(.white)
                } else {
                    Image(systemName: systemImage)
                        .font(.caption2.weight(.bold))
                    Text(label)
                        .font(.footnote.weight(.semibold))
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 8)
            .background(Capsule().fill(tint))
            .foregroundStyle(.white)
        }
        .buttonStyle(.plain)
        .disabled(busy)
    }
}

// MARK: - IPA 行

struct IPARow: View {
    let ipa: OutputIPA
    let analysis: ipaanalysis?
    let analyzing: Bool
    let editing: Bool
    let selected: Bool
    let onToggle: () -> Void
    let onShare: () -> Void
    let onAnalyze: () -> Void

    private let rowHeight: CGFloat = 68
    private let corner: CGFloat = 12

    var body: some View {
        content
            .frame(height: rowHeight)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(AppTheme.cardFill)
            .overlay(alignment: .leading) { selectionBorder }
            .clipShape(RoundedRectangle(cornerRadius: corner, style: .continuous))
            .contentShape(Rectangle())
            .onTapGesture {
                // 点整行：编辑时勾选，否则打开分析
                if editing { onToggle() } else { onAnalyze() }
            }
    }

    // MARK: - 内容

    private var content: some View {
        HStack(spacing: 12) {
            if editing {
                Button(action: onToggle) {
                    Image(systemName: selected ? "checkmark.circle.fill" : "circle")
                        .font(.title3)
                        .foregroundStyle(selected ? Color.blue : Color.secondary)
                }
                .buttonStyle(.plain)
            }

            RoundedRectangle(cornerRadius: 10, style: .continuous)
                .fill(Color.primary.opacity(0.06))
                .frame(width: 44, height: 44)
                .overlay(
                    Image(systemName: iconName)
                        .font(.title3)
                        .foregroundStyle(iconColor)
                )

            VStack(alignment: .leading, spacing: 3) {
                Text(analysis?.appName ?? ipa.baseName)
                    .font(.body.weight(.medium))
                    .lineLimit(1)
                HStack(spacing: 4) {
                    Text(titleLine)
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                    if let status {
                        Text(status.text)
                            .font(.caption2.weight(.medium))
                            .foregroundStyle(status.color)
                    }
                }
                Text(ByteCountFormatter.string(fromByteCount: ipa.size, countStyle: .file))
                    .font(.caption2)
                    .foregroundStyle(.tertiary)
            }

            Spacer(minLength: 8)

            if !editing {
                Button(action: onShare) {
                    Image(systemName: "square.and.arrow.up")
                        .font(.body.weight(.semibold))
                        .foregroundStyle(.blue)
                        .padding(6)
                        .contentShape(Rectangle())
                }
                .buttonStyle(.plain)
            }
        }
        .padding(.horizontal, 12)
    }

    @ViewBuilder
    private var selectionBorder: some View {
        if editing && selected {
            RoundedRectangle(cornerRadius: corner, style: .continuous)
                .strokeBorder(Color.blue, lineWidth: 2)
        }
    }

    private var titleLine: String {
        if analyzing { return "分析中…" }
        var parts: [String] = [ipa.source.rawValue]
        if let a = analysis {
            if let v = a.version, !v.isEmpty { parts.append("v" + v) }
            if !a.variant.isEmpty { parts.append(a.variant) }
        } else {
            parts.append(ipa.date.formatted(date: .abbreviated, time: .shortened))
        }
        if let a = analysis, let bid = a.bundleID, !bid.isEmpty { parts.append(bid) }
        return parts.joined(separator: " · ")
    }

    private var iconName: String {
        guard let a = analysis else {
            return ipa.source == .decrypted ? "lock.open.fill" : "square.and.arrow.up.fill"
        }
        if !a.integrity.isOK { return "exclamationmark.triangle.fill" }
        if a.encrypted { return "lock.fill" }
        return a.installable ? "checkmark.seal.fill" : "shippingbox.fill"
    }

    private var iconColor: Color {
        guard let a = analysis else { return ipa.source == .decrypted ? .blue : .green }
        if !a.integrity.isOK { return .orange }
        if a.encrypted { return .red }
        return .green
    }

    private var status: (text: String, color: Color)? {
        guard let a = analysis else { return analyzing ? ("分析中", .secondary) : nil }
        if !a.integrity.isOK { return ("结构异常", .orange) }
        if a.encrypted { return ("未解密", .red) }
        return a.installable ? ("可安装", .green) : nil
    }

}

// MARK: - IPA 分析详情

struct ipaanalysisView: View {
    let ipa: OutputIPA
    let onShare: () -> Void
    let onDelete: () -> Void

    @Environment(\.dismiss) private var dismiss

    var body: some View {
        List {
            Section {
                if let a = ipa.analysis {
                    kv("应用", a.appName ?? "—")
                    kv("Bundle ID", a.bundleID ?? "—")
                    kv("版本", a.version ?? "—")
                    kv("最低系统", a.minimumOS.map { "iOS \($0)" } ?? "—")
                } else {
                    HStack(spacing: 8) {
                        ProgressView()
                        Text("正在分析…").foregroundStyle(.secondary)
                    }
                }
            } header: {
                Text("概览")
            }

            if let a = ipa.analysis {
                Section {
                    HStack {
                        Text("结构完整性")
                        Spacer()
                        Text(a.integrity.text)
                            .foregroundStyle(a.integrity.isOK ? Color.secondary : Color.orange)
                    }
                    HStack {
                        Text("签名")
                        Spacer()
                        Text(a.signed ? "有 _CodeSignature" : "缺失")
                            .foregroundStyle(a.signed ? Color.secondary : Color.orange)
                    }
                    HStack {
                        Text("加密")
                        Spacer()
                        Text(a.encrypted ? "仍有密文（不能直接用）"
                             : (a.binaries.isEmpty ? "未检测" : "已解密"))
                            .foregroundStyle(a.encrypted ? Color.red : Color.green)
                    }
                    kv("架构", a.archs.isEmpty ? "—" : a.archs.joined(separator: ", "))
                    kv("条目", "\(a.entryCount) 个，解压后 \(ByteCountFormatter.string(fromByteCount: Int64(a.uncompressedTotal), countStyle: .file))")
                    if let e = a.extensionSummary { kv("扩展", e) }
                    if a.hasWatchApp { kv("Watch", "包含") }
                } header: {
                    Text("分析结论")
                }

                if !a.binaries.isEmpty {
                    Section {
                        ForEach(a.binaries) { b in
                            VStack(alignment: .leading, spacing: 2) {
                                Text(b.name)
                                    .font(.subheadline.weight(.medium))
                                Text("\(b.archs.joined(separator: ", ")) · \(ByteCountFormatter.string(fromByteCount: Int64(b.size), countStyle: .file)) · \(b.encrypted ? "cryptid≠0" : "明文")")
                                    .font(.caption)
                                    .foregroundStyle(b.encrypted ? Color.red : Color.green)
                            }
                            .padding(.vertical, 2)
                        }
                    } header: {
                        Text("包内二进制")
                    } footer: {
                        Text("cryptid≠0 表示该二进制仍带非零的 LC_ENCRYPTION_INFO，安装后会闪退，需要重新砸壳。")
                    }
                }

                if !a.notes.isEmpty {
                    Section("提示") {
                        ForEach(a.notes, id: \.self) { n in
                            Text(n).font(.footnote).foregroundStyle(.secondary)
                        }
                    }
                }
            }

            Section {
                kv("文件", ipa.fileName)
                kv("大小", ByteCountFormatter.string(fromByteCount: ipa.size, countStyle: .file))
                kv("修改", ipa.date.formatted(date: .abbreviated, time: .shortened))
                kv("来源", ipa.source.rawValue)
            } header: {
                Text("文件")
            } footer: {
                Text((ipa.path as NSString).deletingLastPathComponent)
                    .font(.caption2)
                    .textSelection(.enabled)
            }

            Section {
                Button {
                    onShare()
                } label: {
                    Label("分享 IPA + 分析报告", systemImage: "square.and.arrow.up")
                }
                Button(role: .destructive) {
                    dismiss()
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.35) { onDelete() }
                } label: {
                    Label("删除", systemImage: "trash")
                }
            }
        }
        .navigationTitle("IPA 分析")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button("完成") { dismiss() }
            }
        }
    }

    @ViewBuilder
    private func kv(_ k: String, _ v: String) -> some View {
        HStack(alignment: .top) {
            Text(k).foregroundStyle(.secondary)
            Spacer(minLength: 12)
            Text(v)
                .multilineTextAlignment(.trailing)
                .textSelection(.enabled)
        }
    }
}
