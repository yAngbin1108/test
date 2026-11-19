//
//  BlockUpdatesView.swift
//  AppDump
//
//  阻止 App Store 自动更新：列出已安装应用，勾选后标记为「不更新」，
//  也可随时恢复。视觉沿用 AppDump 玻璃卡片风格。
//

import SwiftUI

struct BlockUpdatesView: View {
    @ObservedObject private var mgr = AppDumpmgr.shared

    struct item: Identifiable {
        let id = UUID()
        let bundleid: String
        let name: String
        let version: String
        let icon: UIImage?
    }

    @State private var items: [item] = []
    @State private var selected: Set<String> = []
    @State private var query = ""
    @State private var loading = false
    @State private var busy = false
    @State private var msg: String? = nil
    @State private var errormsg: String? = nil
    @State private var blocked: Set<String> = []

    private var shown: [item] {
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if q.isEmpty { return items }
        return items.filter { $0.name.lowercased().contains(q) || $0.bundleid.lowercased().contains(q) }
    }

    var body: some View {
        List {
            if let errormsg {
                Section {
                    PlainAlert(title: "提示", icon: "exclamationmark.triangle.fill",
                               text: errormsg, color: .red)
                }
            }
            if let msg {
                Section {
                    PlainAlert(title: "结果", icon: "checkmark.seal.fill",
                               text: msg, color: .green)
                }
            }

            Section {
                HStack(spacing: 8) {
                    Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                    TextField("搜索应用", text: $query)
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
                HStack {
                    Button(selected.count == shown.count && !shown.isEmpty ? "取消全选" : "全选") {
                        if selected.count == shown.count {
                            selected.removeAll()
                        } else {
                            selected = Set(shown.map { $0.bundleid })
                        }
                    }
                    .disabled(shown.isEmpty)
                    Spacer()
                    Text("已选 \(selected.count)")
                        .font(.footnote).foregroundStyle(.secondary)
                }
                HStack {
                    Button {
                        apply(block: true)
                    } label: {
                        Label("阻止更新", systemImage: "hand.raised.fill")
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(selected.isEmpty || busy)

                    Button {
                        apply(block: false)
                    } label: {
                        Label("恢复更新", systemImage: "arrow.clockwise")
                    }
                    .buttonStyle(.bordered)
                    .disabled(selected.isEmpty || busy)
                }
            } footer: {
                Text("原理：在应用目录下建立 com.apple.mobileinstallation.placeholder 并设为不可访问，安装服务会跳过该应用的更新。\n\n首次操作需要唤醒 installd —— 若提示等待，请到 App Store 点任意 App 的「获取」，回来重试即可。")
            }

            if loading {
                Section {
                    HStack(spacing: 8) {
                        ProgressView()
                        Text("正在读取已安装应用…").foregroundStyle(.secondary)
                    }
                }
            } else if items.isEmpty {
                Section {
                    Text("未读取到已安装应用。请先在「内核」页初始化系统。")
                        .foregroundStyle(.secondary)
                }
            } else {
                Section {
                    ForEach(shown) { it in
                        Button {
                            toggle(it.bundleid)
                        } label: {
                            HStack(spacing: 12) {
                                Image(systemName: selected.contains(it.bundleid)
                                      ? "checkmark.circle.fill" : "circle")
                                    .font(.title3)
                                    .foregroundStyle(selected.contains(it.bundleid)
                                                     ? Color.blue : Color.secondary)

                                Group {
                                    if let ic = it.icon {
                                        Image(uiImage: ic).resizable().scaledToFit()
                                    } else {
                                        RoundedRectangle(cornerRadius: 10, style: .continuous)
                                            .fill(Color.white.opacity(0.06))
                                            .overlay(Image(systemName: "app.dashed")
                                                .foregroundStyle(.secondary))
                                    }
                                }
                                .frame(width: 40, height: 40)
                                .clipShape(RoundedRectangle(cornerRadius: 9, style: .continuous))

                                VStack(alignment: .leading, spacing: 2) {
                                    Text(it.name).font(.body.weight(.medium)).lineLimit(1)
                                    Text(it.bundleid).font(.caption)
                                        .foregroundStyle(.secondary).lineLimit(1)
                                }
                                Spacer(minLength: 6)
                                if blocked.contains(it.bundleid) {
                                    Text("已阻止")
                                        .font(.caption2.weight(.semibold))
                                        .padding(.horizontal, 7).padding(.vertical, 2)
                                        .background(Capsule().fill(Color.orange.opacity(0.18)))
                                        .foregroundStyle(.orange)
                                }
                            }
                            .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                    }
                } header: {
                    HeaderLabel(text: "已安装 \(shown.count)", icon: "square.grid.2x2")
                }
            }
        }
        .themedBackground()
        .navigationTitle("阻止更新")
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button(action: load) { Image(systemName: "arrow.clockwise") }
                    .disabled(loading || busy)
            }
        }
        .onAppear {
            blocked = Set(blockupdates.blockedList())
            if items.isEmpty { load() }
        }
        .onChange(of: mgr.sbxready) { ready in
            if ready && items.isEmpty { load() }
        }
    }

    private func toggle(_ bid: String) {
        if selected.contains(bid) { selected.remove(bid) } else { selected.insert(bid) }
    }

    private func load() {
        guard mgr.sbxready || mgr.vfsready else {
            errormsg = "请先在「内核」页初始化系统。"
            return
        }
        loading = true
        errormsg = nil
        msg = nil

        DispatchQueue.global(qos: .userInitiated).async {
            let bundles = vfsfs.listappbundles()
            var out: [item] = []
            for b in bundles where !b.bundleid.isEmpty {
                out.append(item(bundleid: b.bundleid, name: b.name,
                                version: "", icon: b.icon))
            }
            out.sort { $0.name.lowercased() < $1.name.lowercased() }
            DispatchQueue.main.async {
                loading = false
                items = out
                if out.isEmpty { errormsg = "未读取到已安装应用列表。" }
            }
        }
    }

    private func apply(block: Bool) {
        busy = true
        errormsg = nil
        msg = nil
        let targets = Array(selected)

        DispatchQueue.global(qos: .userInitiated).async {
            let r = block ? blockupdates.block(targets) : blockupdates.unblock(targets)
            DispatchQueue.main.async {
                busy = false
                msg = r.message
                blocked = Set(blockupdates.blockedList())
                if !r.failed.isEmpty && r.ok.isEmpty {
                    errormsg = "全部失败，请确认已初始化系统并拥有写入权限。"
                }
            }
        }
    }
}
