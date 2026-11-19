//
//  PathTabs.swift
//  AppDump
//
//  路径标签（多标签文件浏览器）+ 底部状态栏
//  参考 Blade 的文件管理器：底部一排可横向滚动的路径标签，
//  左侧显示剪贴板状态，中间显示当前目录条目数，当前标签高亮。
//

import SwiftUI
import Combine

// MARK: - 模型

struct santandertab: Identifiable, Codable, Equatable {
    var id: UUID = UUID()
    var path: String = "/"
    /// 当前标签里已经压栈的子目录（保存路径，切回来时恢复）
    var stack: [String] = []
    /// 用户自定义标题；为空时显示路径最后一段
    var customtitle: String? = nil

    var title: String {
        if let customtitle, !customtitle.isEmpty { return customtitle }
        if path == "/" { return "/" }
        let last = (path as NSString).lastPathComponent
        return last.isEmpty ? "/" : last
    }

    var subtitle: String { path }
}

private struct santandertabsnapshot: Codable {
    var tabs: [santandertab]
    var active: UUID
}

// MARK: - 存储（持久化到 UserDefaults）

final class santandertabstore: ObservableObject {
    static let shared = santandertabstore()

    @Published private(set) var tabs: [santandertab] = []
    @Published private(set) var activeid: UUID = UUID()

    private let storekey = "fmPathTabs.v2"

    init() {
        if let data = UserDefaults.standard.data(forKey: storekey),
           let snap = try? JSONDecoder().decode(santandertabsnapshot.self, from: data),
           !snap.tabs.isEmpty {
            tabs = snap.tabs
            activeid = snap.tabs.contains(where: { $0.id == snap.active }) ? snap.active : snap.tabs[0].id
        } else {
            let tab = santandertab(path: "/")
            tabs = [tab]
            activeid = tab.id
        }
    }

    var active: santandertab {
        tabs.first(where: { $0.id == activeid }) ?? tabs[0]
    }

    func tab(_ id: UUID) -> santandertab? {
        tabs.first(where: { $0.id == id })
    }

    func select(_ id: UUID) {
        guard tabs.contains(where: { $0.id == id }), id != activeid else { return }
        activeid = id
        persist()
    }

    /// 新增标签；同路径已存在时直接切过去。
    @discardableResult
    func add(path: String, title: String? = nil) -> santandertab {
        let clean = path.isEmpty ? "/" : path
        if let existing = tabs.first(where: { $0.path == clean }) {
            activeid = existing.id
            persist()
            return existing
        }
        var tab = santandertab(path: clean)
        if let title, !title.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            tab.customtitle = title
        }
        tabs.append(tab)
        activeid = tab.id
        persist()
        return tab
    }

    func close(_ id: UUID) {
        guard tabs.count > 1 else { return }
        guard let idx = tabs.firstIndex(where: { $0.id == id }) else { return }
        tabs.remove(at: idx)
        if activeid == id {
            let next = min(idx, tabs.count - 1)
            activeid = tabs[next].id
        }
        persist()
    }

    func rename(_ id: UUID, title: String) {
        guard let idx = tabs.firstIndex(where: { $0.id == id }) else { return }
        let trimmed = title.trimmingCharacters(in: .whitespacesAndNewlines)
        tabs[idx].customtitle = trimmed.isEmpty ? nil : trimmed
        persist()
    }

    /// 导航时回写当前标签的路径/栈。
    func update(path: String, stack: [String], for id: UUID) {
        guard let idx = tabs.firstIndex(where: { $0.id == id }) else { return }
        let clean = path.isEmpty ? "/" : path
        if tabs[idx].path == clean && tabs[idx].stack == stack { return }
        tabs[idx].path = clean
        tabs[idx].stack = stack
        persist()
    }

    private func persist() {
        let snap = santandertabsnapshot(tabs: tabs, active: activeid)
        if let data = try? JSONEncoder().encode(snap) {
            UserDefaults.standard.set(data, forKey: storekey)
        }
    }
}

// MARK: - 底部状态栏 / 标签栏

struct santandertabbar: View {
    @ObservedObject var nav: santandernav
    @ObservedObject var store: santandertabstore = .shared
    @ObservedObject var clip: santanderclip = .shared

    var body: some View {
        VStack(spacing: 0) {
            Divider().opacity(0.35)

            HStack(spacing: 10) {
                HStack(spacing: 4) {
                    Image(systemName: clip.item == nil ? "doc.on.clipboard" : "doc.on.clipboard.fill")
                    Text(clip.item?.name ?? "剪贴板为空")
                        .lineLimit(1)
                        .truncationMode(.middle)
                }
                .font(.caption)
                .foregroundStyle(.secondary)

                Text("\(nav.itemcount) 项")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .fixedSize()

                ScrollViewReader { proxy in
                    ScrollView(.horizontal, showsIndicators: false) {
                        HStack(spacing: 6) {
                            ForEach(store.tabs) { tab in
                                chip(tab)
                                    .id(tab.id)
                            }
                        }
                        .padding(.vertical, 2)
                    }
                    .onChange(of: store.activeid) { id in
                        withAnimation(.easeInOut(duration: 0.2)) {
                            proxy.scrollTo(id, anchor: .center)
                        }
                    }
                }
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
        }
        .background(.ultraThinMaterial)
    }

    private func chip(_ tab: santandertab) -> some View {
        let active = tab.id == store.activeid
        return Button {
            store.select(tab.id)
        } label: {
            Text(tab.title)
                .font(.caption.weight(active ? .semibold : .regular))
                .lineLimit(1)
                .truncationMode(.middle)
                .frame(maxWidth: 140)
                .padding(.horizontal, 10)
                .padding(.vertical, 5)
                .background(
                    Capsule(style: .continuous)
                        .fill(active ? Color.accentColor.opacity(0.28) : Color(uiColor: .tertiarySystemFill))
                )
                .foregroundStyle(active ? Color.accentColor : Color.secondary)
        }
        .buttonStyle(.plain)
        .contextMenu {
            Button {
                UIPasteboard.general.string = tab.path
            } label: {
                Label("复制路径", systemImage: "doc.on.doc")
            }

            Button {
                nav.requestrenametab = tab.id
            } label: {
                Label("重命名标签", systemImage: "pencil")
            }

            Button(role: .destructive) {
                store.close(tab.id)
            } label: {
                Label("关闭标签", systemImage: "xmark")
            }
            .disabled(store.tabs.count <= 1)
        }
    }
}