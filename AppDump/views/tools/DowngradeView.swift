//
//  DowngradeView.swift
//  AppDump
//
//  应用降级：列出本机已安装应用 → 查看历史版本 → 通过 StoreKit 私有接口下载旧版本。
//  交互参照 RetroApp：应用行显示 名称 / bundleID / 版本(构建)，右侧标注来源，
//  点击后以 sheet 弹出「选择版本」列表。
//

import SwiftUI

struct DowngradeView: View {
    @ObservedObject private var mgr = AppDumpmgr.shared

    struct rowitem: Identifiable {
        let id = UUID()
        let bundleid: String
        let name: String
        let localversion: String        // 本机安装版本
        let localbuild: String          // CFBundleVersion
        let icon: UIImage?
        let store: storeapp?            // App Store 匹配结果，nil = 签名/侧载
        var issigned: Bool { store == nil }
    }

    @State private var rows: [rowitem] = []
    @State private var query = ""
    @State private var filter: RowFilter = .all
    @State private var loading = false
    @State private var progress = ""
    @State private var errormsg: String? = nil
    @AppStorage(downgrademgr.modeKey) private var dgMode: Int = 1
    @State private var expanded: String? = nil
    @State private var failure: downgradefailure? = nil
    @State private var sourcenames: String = ""
    @State private var versionnote: String = ""
    @State private var showsources: Bool = false
    @State private var inlinevers: [storeversion] = []
    @State private var loadingvers = false


    enum RowFilter: String, CaseIterable {
        case all = "全部"
        case store = "App Store"
        case signed = "签名"
    }

    private var shown: [rowitem] {
        var list = rows
        switch filter {
        case .all: break
        case .store: list = list.filter { !$0.issigned }
        case .signed: list = list.filter { $0.issigned }
        }
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if !q.isEmpty {
            list = list.filter {
                $0.name.lowercased().contains(q) || $0.bundleid.lowercased().contains(q)
            }
        }
        return list
    }

    var body: some View {
        List {
            if let failure {
                Section {
                    VStack(alignment: .leading, spacing: 6) {
                        HStack(spacing: 8) {
                            Image(systemName: failure.kind.symbol)
                                .foregroundStyle(.orange)
                            Text(failure.title)
                                .font(.subheadline.weight(.semibold))
                        }
                        Text(failure.reason)
                            .font(.footnote)
                            .foregroundStyle(.secondary)
                        Text(failure.advice)
                            .font(.footnote)
                            .foregroundStyle(.blue)
                    }
                    .padding(.vertical, 2)

                    Button("知道了") { self.failure = nil }
                        .font(.footnote)
                } header: {
                    HeaderLabel(text: "为什么失败", icon: "questionmark.circle")
                }
            }

            if let errormsg {
                Section {
                    PlainAlert(title: "提示", icon: "exclamationmark.triangle.fill",
                               text: errormsg, color: .red)
                }
            }

            Section {
                NavigationLink {
                    VersionSourcesView()
                } label: {
                    HStack(spacing: 10) {
                        Image(systemName: "point.3.connected.trianglepath.dotted")
                            .foregroundStyle(.blue)
                        VStack(alignment: .leading, spacing: 2) {
                            Text("版本来源")
                                .font(.subheadline)
                            Text(sourcenames.isEmpty ? "正在读取…" : sourcenames)
                                .font(.caption2)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                        }
                        Spacer()
                    }
                }
            }

            Section {
                HStack(spacing: 8) {
                    Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                    TextField("搜索名称或 Bundle ID", text: $query)
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
                }
                VStack(alignment: .leading, spacing: 6) {
                    Text("降级方式").font(.footnote.weight(.semibold))
                    Picker("", selection: $dgMode) {
                        Text("本进程").tag(0 as Int)
                        Text("注入 SpringBoard").tag(1 as Int)
                    }
                    .pickerStyle(.segmented)
                    .labelsHidden()
                }
                .padding(.vertical, 2)

                Picker("", selection: $filter) {
                    ForEach(RowFilter.allCases, id: \.self) { f in
                        Text(f.rawValue).tag(f)
                    }
                }
                .pickerStyle(.segmented)
            } header: {
                HStack {
                    HeaderLabel(text: "已安装应用 \(shown.count)", icon: "square.grid.2x2")
                    Spacer()
                }
            } footer: {
                Text("只有「App Store」来源的应用可以降级；侧载签名应用没有 App Store 下载记录。")
            }

            if loading {
                Section {
                    HStack(spacing: 8) {
                        ProgressView()
                        Text(progress.isEmpty ? "正在读取已安装应用…" : progress)
                            .foregroundStyle(.secondary)
                    }
                }
            } else if rows.isEmpty {
                Section {
                    Text(mgr.sbxready || mgr.vfsready
                         ? "未读取到已安装应用。若刚初始化系统，请点右上角刷新。"
                         : "请先在「内核」页运行漏洞利用并初始化系统。")
                        .foregroundStyle(.secondary)
                }
            } else {
                Section {
                    ForEach(shown) { item in
                        // 之前用 Button + .buttonStyle(.plain) 嵌套在 List 行里，
                        // 点击能触发 action（日志有记录）但 sheet 不弹出 ——
                        // List 行手势与 Button 冲突，状态更新被吞掉。
                        // 改成 contentShape + onTapGesture，点击区域明确、不冲突。
                        rowview(item)
                            .contentShape(Rectangle())
                            .onTapGesture {
                                AppDumpmgr.shared.logmsg("(downgrade) 点击 \(item.name) store=\(item.store == nil ? "nil" : "track=\(item.store!.trackid)")")
                                if let st = item.store, st.trackid != 0 {
                                    // 内联展开：不依赖 sheet / fullScreenCover。
                                    // 之前两种 modal 都试过，在本页（NavigationLink push
                                    // 进来的 List）里状态更新了也不呈现，改为页内展开。
                                    if expanded == item.bundleid {
                                        expanded = nil
                                    } else {
                                        expanded = item.bundleid
                                        loadversions(for: st.trackid)
                                    }
                                } else {
                                    errormsg = "「\(item.name)」是侧载签名应用，App Store 没有它的下载记录，无法降级。"
                                }
                            }

                        if expanded == item.bundleid {
                            inlineversions(item)
                        }
                    }
                }
            }
        }
        .themedBackground()
        .navigationTitle("应用降级")
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button(action: reload) {
                    Image(systemName: "arrow.clockwise")
                }
                .disabled(loading)
            }
        }
        .onAppear {
            refreshsourcenames()
            if rows.isEmpty { reload() }
        }
        .sheet(isPresented: $showsources) {
            NavigationStack {
                VersionSourcesView()
                    .toolbar {
                        ToolbarItem(placement: .navigationBarTrailing) {
                            Button("完成") { showsources = false }
                        }
                    }
            }
        }
        // 沙盒逃逸完成时自动重载：用户常在初始化系统之前就点进本页，
        // 那时读不到目录（日志显示 sbx=false 时 FileManager 被拒）。
        .onChange(of: mgr.sbxready) { ready in
            if ready && rows.isEmpty {
                reload()
            }
        }
        // 版本列表改为页内内联展开（见 inlineversions），不再使用任何 modal。
    }

    @ViewBuilder
    private func rowview(_ item: rowitem) -> some View {
        HStack(spacing: 12) {
            Group {
                if let icon = item.icon {
                    Image(uiImage: icon).resizable().scaledToFit()
                } else {
                    RoundedRectangle(cornerRadius: 10, style: .continuous)
                        .fill(Color.white.opacity(0.06))
                        .overlay(Image(systemName: "app.dashed").foregroundStyle(.secondary))
                }
            }
            .frame(width: 44, height: 44)
            .clipShape(RoundedRectangle(cornerRadius: 10, style: .continuous))

            VStack(alignment: .leading, spacing: 3) {
                Text(item.name).font(.body.weight(.medium)).lineLimit(1)
                Text(item.bundleid).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                Text(versionline(item)).font(.caption2).foregroundStyle(.tertiary).lineLimit(1)
            }

            Spacer(minLength: 6)

            if item.issigned {
                Text("签名")
                    .font(.caption2.weight(.semibold))
                    .padding(.horizontal, 8).padding(.vertical, 3)
                    .background(Capsule().fill(Color.orange.opacity(0.18)))
                    .foregroundStyle(.orange)
            } else {
                HStack(spacing: 3) {
                    Image(systemName: "bag.fill").font(.caption2)
                    Text("App Store").font(.caption2.weight(.semibold))
                }
                .padding(.horizontal, 8).padding(.vertical, 3)
                .background(Capsule().fill(Color.blue.opacity(0.18)))
                .foregroundStyle(.blue)
            }

            Image(systemName: "chevron.right")
                .font(.caption).foregroundStyle(.tertiary)
        }
        .contentShape(Rectangle())
    }

    private func refreshsourcenames() {
        let enabled = versionsources.shared.enabled
        sourcenames = enabled.isEmpty
            ? "没有启用的来源"
            : "已启用 " + enabled.map(\.name).joined(separator: "、")
    }

    /// 版本行第二行：日期 · 大小 · 版本 ID · 来源
    private func versionmeta(_ v: storeversion) -> String {
        var parts: [String] = []
        if !v.releasedate.isEmpty { parts.append(v.releasedate) }
        if let size = v.size, !size.isEmpty { parts.append(size) }
        parts.append("ID \(v.versionid)")
        if !v.source.isEmpty { parts.append(v.source) }
        return parts.joined(separator: " · ")
    }

    private func versionline(_ item: rowitem) -> String {
        if item.localbuild.isEmpty { return item.localversion }
        return "\(item.localversion) (\(item.localbuild))"
    }

    // MARK: - 数据

    private func reload() {
        // 读取应用列表需要沙盒逃逸（或内核 VFS）。仅 vfsready 时 VFS 对
        // /private/var/containers/... 常因 namecache 缺失而失败，
        // 所以这里优先要求 sbxready，并在未就绪时给出明确指引。
        guard mgr.sbxready else {
            errormsg = mgr.vfsready
                ? "沙盒尚未逃逸，无法读取其它应用的目录。请到「内核」页点「初始化系统」等待沙盒逃逸成功后再刷新。"
                : "请先在「内核」页运行漏洞利用并初始化系统。"
            return
        }
        loading = true
        errormsg = nil
        rows = []
        progress = "正在读取已安装应用…"

        DispatchQueue.global(qos: .userInitiated).async {
            let bundles = vfsfs.listappbundles()
            progress = "正在匹配 App Store 信息 0/\(bundles.count)"

            // 批量解析（一次最多 80 个 bundleId）
            let ids = bundles.map { $0.bundleid }
            let map = downgrademgr.shared.resolvebundles(ids) { done, total in
                DispatchQueue.main.async { progress = "正在匹配 App Store 信息 \(done)/\(total)" }
            }

            var out: [rowitem] = []
            for b in bundles where !b.bundleid.isEmpty {
                let localver = localversionof(b.path) 
                out.append(rowitem(
                    bundleid: b.bundleid,
                    name: b.name,
                    localversion: localver.version,
                    localbuild: localver.build,
                    icon: b.icon,
                    store: map[b.bundleid]
                ))
            }
            out.sort { $0.name.lowercased() < $1.name.lowercased() }

            DispatchQueue.main.async {
                loading = false
                rows = out
                if out.isEmpty {
                    errormsg = "未能读取已安装应用列表。"
                }
            }
        }
    }

    /// 读 bundle 内的 Info.plist 拿本地版本号
    private func localversionof(_ bundlepath: String) -> (version: String, build: String) {
        let plist = bundlepath + "/Info.plist"
        var dict: NSDictionary? = nil
        if AppDumpmgr.shared.vfsready,
           let d = AppDumpmgr.shared.vfsread(path: plist, maxSize: 2 * 1024 * 1024),
           let p = try? PropertyListSerialization.propertyList(from: d, options: [], format: nil) as? NSDictionary {
            dict = p
        } else if let p = NSDictionary(contentsOfFile: plist) {
            dict = p
        }
        let v = dict?["CFBundleShortVersionString"] as? String ?? "-"
        let b = dict?["CFBundleVersion"] as? String ?? ""
        return (v, b)
    }

    /// 加载某应用的版本列表（内联展开用）
    private func loadversions(for tid: Int64) {
        inlinevers = []
        loadingvers = true
        AppDumpmgr.shared.logmsg("(downgrade) 内联加载版本 tid=\(tid)")
        versionnote = ""
        failure = nil
        DispatchQueue.global(qos: .userInitiated).async {
            let list = downgrademgr.shared.history(trackid: tid)
            let note = downgrademgr.shared.lastversionnote
            DispatchQueue.main.async {
                inlinevers = list
                versionnote = note
                loadingvers = false
                if list.isEmpty {
                    failure = downgrademgr.classifyempty(note: note)
                }
                AppDumpmgr.shared.logmsg("(downgrade) 内联版本数=\(list.count)")
            }
        }
    }

    /// 内联展开的版本列表（不使用 sheet / cover）
    @ViewBuilder
    private func inlineversions(_ item: rowitem) -> some View {
        if loadingvers {
            HStack(spacing: 8) {
                ProgressView()
                Text("正在获取历史版本…").font(.footnote).foregroundStyle(.secondary)
            }
            .padding(.vertical, 6)
        } else if inlinevers.isEmpty {
            VStack(alignment: .leading, spacing: 4) {
                Text("没有拿到历史版本")
                    .font(.footnote.weight(.semibold))
                if !versionnote.isEmpty {
                    Text(versionnote)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                }
                Button("打开版本来源") { showsources = true }
                    .font(.caption)
            }
            .padding(.vertical, 6)
        } else {
            VStack(alignment: .leading, spacing: 0) {
                HStack {
                    Text("选择版本（\(inlinevers.count)）")
                        .font(.footnote.weight(.semibold))
                    Spacer()
                    Button("收起") { expanded = nil }
                        .font(.footnote)
                }
                .padding(.bottom, 6)

                if !versionnote.isEmpty {
                    Text(versionnote)
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .padding(.bottom, 4)
                }

                ForEach(inlinevers) { v in
                    Button {
                        downgrade(item, v)
                    } label: {
                        HStack(alignment: .top, spacing: 8) {
                            VStack(alignment: .leading, spacing: 2) {
                                Text(v.displayline)
                                    .font(.callout.weight(.semibold))
                                    .foregroundStyle(.blue)
                                Text(versionmeta(v))
                                    .font(.caption2).foregroundStyle(.secondary)
                            }
                            Spacer()
                            Image(systemName: "arrow.down.circle")
                                .foregroundStyle(.blue)
                        }
                        .padding(.vertical, 6)
                        .contentShape(Rectangle())
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.leading, 58)
        }
    }

    private func downgrade(_ item: rowitem, _ v: storeversion) {
        guard let store = item.store else { return }
        showconfirm(item, v, store)
    }

    private func showconfirm(_ item: rowitem, _ v: storeversion, _ store: storeapp) {
        Alertinator.shared.alert(
            title: "降级 \(item.name) 到 \(v.displayline)？",
            body: "将向 App Store 提交下载历史版本 \(v.displayline) 的请求。\n\n前提：当前 Apple ID 此前下载过该应用；苹果可能随时限制此机制。",
            actionLabel: "开始降级",
            action: {
                downgrademgr.shared.downgrade(trackid: store.trackid, version: v) { result in
                    switch result {
                    case .success:
                        AppDumpmgr.shared.logmsg("(downgrade) 降级请求已提交：\(item.name) -> \(v.displayline)")
                    case .failure(let e):
                        AppDumpmgr.shared.logmsg("(downgrade) 降级失败：\(e.reason)")
                        failure = e
                    }
                }
            }
        )
    }
}
