//
//  SantanderView.swift
//  symlin2k
//
//  Created by ruter on 15.02.26.
//

import SwiftUI
import Combine

struct SantanderView: View {
    let startpath: String

    @AppStorage("selectedmethod") private var selectedmethod: method = .hybrid
    @ObservedObject private var mgr = AppDumpmgr.shared
    
    @State private var showsecret: Bool = false

    init(startPath: String = "/") {
        self.startpath = startPath.isEmpty ? "/" : startPath
    }

    private var readsbx: Bool {
        selectedmethod != .vfs
    }

    private var writevfs: Bool {
        selectedmethod != .sbx
    }

    private var ready: Bool {
        switch selectedmethod {
        case .sbx:
            return mgr.sbxready
        case .vfs:
            return mgr.vfsready
        case .hybrid:
            return mgr.sbxready && mgr.vfsready
        }
    }

    var body: some View {
        Group {
            if ready {
                santanderroot(startpath: startpath, readsbx: readsbx, writevfs: writevfs)
            } else {
                NavigationStack {
                    VStack {
                        Image(systemName: "externaldrive.trianglebadge.exclamationmark")
                            .imageScale(.large)
                        Text("文件管理器未就绪！")
                        Text("请返回主页，点击“运行漏洞利用”，然后点击“初始化系统”。")
                            .multilineTextAlignment(.center)
                            .font(.subheadline)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
        .background(AppTheme.background)
    }
}

struct santandertabhandle: Identifiable {
    let id: UUID
}

private struct santanderroot: View {
    let startpath: String
    let readsbx: Bool
    let writevfs: Bool

    @StateObject private var nav: santandernav
    @ObservedObject private var tabstore = santandertabstore.shared

    @State private var renametab: santandertabhandle?
    @State private var renametext = ""

    init(startpath: String, readsbx: Bool, writevfs: Bool) {
        self.startpath = startpath
        self.readsbx = readsbx
        self.writevfs = writevfs
        _nav = StateObject(wrappedValue: santandernav())
    }

    var body: some View {
        NavigationStack(path: $nav.stack) {
            santanderdirview(item: nav.root, readsbx: readsbx, writevfs: writevfs)
                .environmentObject(nav)
                .id(nav.root.path)
                .navigationDestination(for: santanderitem.self) { item in
                    if item.isdir {
                        santanderdirview(item: item, readsbx: readsbx, writevfs: writevfs)
                            .environmentObject(nav)
                            .id(item.path)
                    } else {
                        santanderfileview(item: item, readsbx: readsbx, writevfs: writevfs)
                            .environmentObject(nav)
                            .id(item.path)
                    }
                }
        }
        .safeAreaInset(edge: .bottom, spacing: 0) {
            santandertabbar(nav: nav)
        }
        .onAppear {
            nav.bootstrap(startpath)
        }
        .onChange(of: tabstore.activeid) { id in
            nav.activate(id)
        }
        .onChange(of: nav.requestrenametab) { id in
            guard let id, let tab = tabstore.tab(id) else { return }
            renametext = tab.title
            renametab = santandertabhandle(id: id)
        }
        .sheet(item: $renametab) { handle in
            santandernamesheet(
                title: "重命名标签",
                itemname: tabstore.tab(handle.id)?.subtitle ?? "",
                placeholder: renametext,
                actiontitle: "保存"
            ) { name in
                tabstore.rename(handle.id, title: name)
            }
            .onDisappear {
                nav.requestrenametab = nil
            }
        }
    }
}

final class santandernav: ObservableObject {
    @Published var root: santanderitem
    @Published var stack: [santanderitem] = []
    /// 当前目录条目数（底部状态栏用）
    @Published var itemcount: Int = 0
    /// 底部标签“重命名”请求
    @Published var requestrenametab: UUID?

    private let store: santandertabstore
    private var activeid: UUID
    private var bootstrapped = false

    init() {
        let store = santandertabstore.shared
        self.store = store
        let tab = store.active
        self.activeid = tab.id
        self.root = santanderitem(path: tab.path, isdir: true)
        self.stack = tab.stack.map { santanderitem(path: $0, isdir: true) }
    }

    /// 从「应用 → 主程序目录/数据目录/Group 目录」进来时新开一个标签
    func bootstrap(_ startpath: String) {
        guard !bootstrapped else { return }
        bootstrapped = true
        guard startpath != "/", !startpath.isEmpty else { return }
        let tab = store.add(path: startpath)
        activeid = tab.id
        root = santanderitem(path: tab.path, isdir: true)
        stack = tab.stack.map { santanderitem(path: $0, isdir: true) }
        itemcount = 0
    }

    /// 当前所在目录（栈顶或根）
    var currentpath: String {
        stack.last?.path ?? root.path
    }

    func push(_ item: santanderitem) {
        stack.append(item)
        save()
    }

    func go(_ item: santanderitem) {
        root = item
        stack.removeAll()
        itemcount = 0
        save()
    }

    @discardableResult
    func up() -> Bool {
        if !stack.isEmpty {
            stack.removeLast()
            save()
            return true
        }
        let path = root.path
        guard path != "/" else { return false }
        var parent = (path as NSString).deletingLastPathComponent
        if parent.isEmpty { parent = "/" }
        root = santanderitem(path: parent, isdir: true)
        itemcount = 0
        save()
        return true
    }

    /// 切换到某个标签
    func activate(_ id: UUID) {
        guard id != activeid, let tab = store.tab(id) else { return }
        activeid = id
        root = santanderitem(path: tab.path, isdir: true)
        stack = tab.stack.map { santanderitem(path: $0, isdir: true) }
        itemcount = 0
    }

    /// 新建标签并切过去
    func newtab(path: String, title: String? = nil) {
        let tab = store.add(path: path, title: title)
        activeid = tab.id
        root = santanderitem(path: tab.path, isdir: true)
        stack = tab.stack.map { santanderitem(path: $0, isdir: true) }
        itemcount = 0
    }

    /// 标签标题随当前目录自动更新
    private func save() {
        store.update(path: currentpath, stack: stack.map { $0.path }, for: activeid)
    }
}

extension UIViewController {
    func topMostViewController() -> UIViewController {
        if let presented = presentedViewController {
            return presented.topMostViewController()
        }
        return self
    }
}