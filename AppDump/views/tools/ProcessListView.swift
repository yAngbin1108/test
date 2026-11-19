//
//  ProcessListView.swift
//  AppDump
//
//  进程管理：遍历内核 allproc/kernproc 链表列出全部进程，可按名称 / PID 过滤，
//  对单个进程可以修改内存（h5gg 风格搜索/改值/锁定）或结束进程。
//
//  底层走 kexploit 的 proclist() / free_proclist() / killprocbypid()。
//  proclist 会读内核内存，必须在后台线程调用，并且要和砸壳、内存扫描共用
//  同一把内核锁。
//

import SwiftUI
import UIKit

struct ProcInfo: Identifiable {
    let id = UUID()
    let pid: UInt32
    let uid: UInt32
    let kaddr: UInt64
    let name: String
}

struct ProcessListView: View {
    @ObservedObject private var mgr = AppDumpmgr.shared

    @State private var procs: [ProcInfo] = []
    @State private var loading = false
    @State private var query = ""
    @State private var errormsg: String? = nil
    @State private var editing: ProcInfo? = nil

    /// 结束进程的冷却时间：连续对同一个刚退出的 proc 写坏 sp 容易踩到
    /// 已回收的 proc/thread，进而破坏内核内存。
    @State private var lastKill: Date = .distantPast

    private var filtered: [ProcInfo] {
        let q = query.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        if q.isEmpty { return procs }
        return procs.filter { $0.name.lowercased().contains(q) || String($0.pid) == q }
    }

    var body: some View {
        List {
            if let errormsg {
                Section {
                    PlainAlert(title: "错误", icon: "exclamationmark.triangle.fill",
                               text: errormsg, color: .red)
                }
            }

            Section {
                HStack(spacing: 8) {
                    Image(systemName: "magnifyingglass")
                        .foregroundStyle(.secondary)
                    TextField("搜索进程名 / PID", text: $query)
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
            }

            if loading && procs.isEmpty {
                Section {
                    HStack(spacing: 8) {
                        ProgressView()
                        Text("正在读取内核进程链表…").foregroundStyle(.secondary)
                    }
                }
            } else if filtered.isEmpty {
                Section {
                    Text(procs.isEmpty ? "未读到进程。" : "无匹配进程。")
                        .foregroundStyle(.secondary)
                }
            } else {
                Section {
                    ForEach(filtered) { p in
                        row(p)
                    }
                } header: {
                    HeaderLabel(text: "进程 \(filtered.count)", icon: "list.bullet.rectangle")
                }
            }
        }
        .themedBackground()
        .navigationTitle("进程管理")
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button {
                    load()
                } label: {
                    Image(systemName: "arrow.clockwise")
                }
                .disabled(loading)
            }
        }
        .onAppear {
            if procs.isEmpty { load() }
        }
        .sheet(item: $editing) { p in
            MemoryEditorView(pid: pid_t(p.pid), name: p.name)
        }
    }

    // MARK: - row

    @ViewBuilder
    private func row(_ p: ProcInfo) -> some View {
        HStack(spacing: 12) {
            VStack(alignment: .leading, spacing: 2) {
                Text(p.name)
                    .font(.body.weight(.medium))
                    .foregroundStyle(.primary)
                Text("PID \(p.pid) · UID \(p.uid) · \(String(format: "0x%llx", p.kaddr))")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .lineLimit(1)
                    .minimumScaleFactor(0.8)
            }
            Spacer(minLength: 8)

            Menu {
                Button {
                    editing = p
                } label: {
                    Label("修改内存", systemImage: "memorychip")
                }
                Button(role: .destructive) {
                    confirmKill(p)
                } label: {
                    Label("结束进程", systemImage: "xmark.circle")
                }
                Divider()
                Button {
                    UIPasteboard.general.string = String(p.pid)
                    toast("已复制 PID: \(p.pid)")
                } label: {
                    Label("复制 PID", systemImage: "doc.on.doc")
                }
                Button {
                    UIPasteboard.general.string = String(p.uid)
                    toast("已复制 UID: \(p.uid)")
                } label: {
                    Label("复制 UID", systemImage: "doc.on.doc")
                }
            } label: {
                Image(systemName: "ellipsis.circle")
                    .font(.title3)
                    .foregroundStyle(.secondary)
                    .frame(width: 32, height: 32)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
        }
        .contentShape(Rectangle())
    }

    // MARK: - 读取

    private func load() {
        guard mgr.dsready else {
            errormsg = "内核读写未就绪，请先运行漏洞利用。"
            return
        }
        errormsg = nil
        loading = true

        DispatchQueue.global(qos: .userInitiated).async {
            var count: Int32 = 0
            var items: [ProcInfo] = []

            // 遍历 allproc 读内核内存，必须和砸壳 / 内存扫描 / sbx 重放串行。
            AppDumpKernelLockAcquire()
            let list = proclist(nil, &count)
            globallogger.log("(proc) proclist 返回 list=\(list != nil ? "非空" : "NULL") count=\(count)")

            if let list = list, count > 0 {
                items.reserveCapacity(Int(count))
                for i in 0..<Int(count) {
                    var e = list[i]
                    let name: String = withUnsafeBytes(of: &e.name) { raw in
                        guard let base = raw.baseAddress else { return "" }
                        return String(cString: base.assumingMemoryBound(to: CChar.self))
                    }
                    items.append(ProcInfo(pid: e.pid, uid: e.uid, kaddr: e.kaddr,
                                          name: name.isEmpty ? "(未知)" : name))
                }
                free_proclist(list)
            }
            AppDumpKernelLockRelease()

            items.sort { $0.name.lowercased() < $1.name.lowercased() }

            DispatchQueue.main.async {
                procs = items
                loading = false
                if items.isEmpty {
                    errormsg = "未能枚举进程（内核链表读取失败）。"
                }
            }
        }
    }

    // MARK: - 结束进程

    private func confirmKill(_ p: ProcInfo) {
        if p.pid == 0 {
            toast("不能结束内核进程 (PID 0)")
            return
        }
        if p.pid == UInt32(getpid()) {
            toast("不能结束自身进程")
            return
        }
        if Date().timeIntervalSince(lastKill) < 1.5 {
            toast("操作过于频繁，请稍候再试")
            return
        }

        Alertinator.shared.alert(
            title: "结束 \(p.name)？",
            body: "PID \(p.pid)\n\n系统守护进程被结束后会被 launchd 自动重新拉起，反复结束可能导致内核不稳定。",
            actionLabel: "结束",
            action: {
                lastKill = Date()
                AppDumpKernelLockAcquire()
                let rc = killprocbypid(pid_t(p.pid))
                AppDumpKernelLockRelease()
                AppDumpmgr.shared.logmsg("(proc) kill \(p.name) pid=\(p.pid) rc=\(rc)")
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) {
                    load()
                }
            }
        )
    }

    private func toast(_ message: String) {
        Alertinator.shared.alert(title: message, body: "", showCancel: false, actionLabel: "好", action: {})
    }
}