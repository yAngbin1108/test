//
//  decryptprogress.swift
//  AppDump
//
//  内核砸壳 / 提取的进度汇聚 + 后台保活。
//
//  C 侧的 set_progress_callback 只是一个函数指针，捕获不了视图；而 SwiftUI 的
//  @Published 必须在主线程改。回调来自后台解密线程，如果直接在主线程上一次一
//  条地派发，几千页就是几千次主队列往返，界面反而更卡。所以这里统一做三件事：
//
//   1. 串行化：C 的回调线程只写锁里的数字，真正改 @Published 一律跳主线程；
//   2. 节流：C 侧已经按 1% 上报，这里再按时间合并（≥80ms），主队列不会被淹；
//   3. 分段 + 单调：拷贝 / 逐页解密 / 打包三段各有自己的区间；每解一个附属
//      Mach-O，C 的进度都会从 0 重来，若直接覆盖，进度条就会往回跳。
//

import Foundation
import UIKit
import Combine

final class DecryptProgress: ObservableObject {
    static let shared = DecryptProgress()

    /// 三段区间的分界：拷贝 0→0.30，逐页解密 0.30→0.88，打包 0.88→1.00
    static let copyEnd = 0.30
    static let pagesEnd = 0.88

    @Published private(set) var fraction: Double = 0
    @Published private(set) var stage: String = ""

    /// 应用原始体积。startDecrypt 已在后台算过一次，这里存下来给磁盘空间检查
    /// 复用——原来 checkDiskSpace 会在主线程再枚举一遍 GB 级目录。
    private(set) var sourceBytes: Int64 = 0

    private let lock = NSLock()
    private var pageBase: Double = 0
    private var pageSpan: Double = 0
    private var lastPagesTime: CFAbsoluteTime = 0
    private var lastCopyTime: CFAbsoluteTime = 0
    private var lastPackTime: CFAbsoluteTime = 0

    private init() {}

    // MARK: - 生命周期

    /// 任务开始：进度归零（不能用 max()，否则上一次的残留不会清掉）
    func begin(sourceBytes: Int64) {
        self.sourceBytes = sourceBytes
        lock.lock()
        pageBase = 0
        pageSpan = 0
        lastPagesTime = 0
        lastCopyTime = 0
        lastPackTime = 0
        lock.unlock()
        DispatchQueue.main.async {
            self.fraction = 0
            self.stage = "准备中…"
        }
    }

    func setStage(_ text: String) {
        DispatchQueue.main.async { self.stage = text }
    }

    func finish() {
        DispatchQueue.main.async {
            self.fraction = 1
            self.stage = "完成"
        }
    }

    /// 失败/取消：只清阶段文字，进度条留给下一次 begin() 归零
    func abort() {
        DispatchQueue.main.async { self.stage = "" }
    }

    // MARK: - 拷贝阶段（0 → copyEnd）

    func updateCopy(done: Int64, total: Int64) {
        guard total > 0 else { return }
        guard due(&lastCopyTime) else { return }
        let frac = min(max(Double(done) / Double(total), 0), 1)
        raise(to: frac * DecryptProgress.copyEnd, stage: "拷贝应用包…")
    }

    /// 拷贝结束（或走 VFS / 无进度来源时直接跳到分界点）
    func endCopy() {
        raise(to: DecryptProgress.copyEnd, stage: "拷贝完成")
    }

    // MARK: - 逐页解密（copyEnd → pagesEnd）

    /// 标记「接下来 C 的 0…1 属于哪一个二进制」。
    /// base/span 是这一份二进制在整条进度条上占的区间。
    func beginBinary(_ label: String, base: Double, span: Double) {
        lock.lock()
        pageBase = base
        pageSpan = span
        lock.unlock()
        DispatchQueue.main.async { self.stage = label }
    }

    /// 由 C 回调（后台线程）调用，p 是「当前这份二进制」的 0…1
    func ingestPages(_ p: Double) {
        lock.lock()
        let base = pageBase
        let span = pageSpan
        let clamped = min(max(p, 0), 1)
        let value = base + clamped * span
        let force = clamped >= 1
        lock.unlock()
        guard force || due(&lastPagesTime) else { return }
        raise(to: value, stage: nil)
    }

    // MARK: - 打包阶段（pagesEnd → 1）

    func updatePack(_ frac: Double) {
        guard due(&lastPackTime) || frac >= 1 else { return }
        let clamped = min(max(frac, 0), 1)
        let value = DecryptProgress.pagesEnd
            + clamped * (1.0 - DecryptProgress.pagesEnd)
        raise(to: min(value, 0.999), stage: "打包 ipa…")
    }

    // MARK: - 内部

    /// 主线程上把进度推到 value —— 只增不减。
    /// stage 为 nil 表示保留当前阶段文字（逐页回调太密集，不必每次都改）。
    private func raise(to value: Double, stage text: String?) {
        DispatchQueue.main.async {
            let v = min(max(value, 0), 1)
            if v > self.fraction { self.fraction = v }
            if let t = text { self.stage = t }
        }
    }

    private func due(_ last: inout CFAbsoluteTime) -> Bool {
        let now = CFAbsoluteTimeGetCurrent()
        guard now - last >= 0.08 else { return false }
        last = now
        return true
    }
}

/// 整段任务期间持有一次后台断言，结束时释放。
///
/// 以前长任务唯一持有的断言是「拉起目标 App 后 2.5 秒重开自己」那一个，
/// 真正耗时的拷贝 / 解密 / 打包阶段没有任何断言：一锁屏或切到别的 App，
/// 进程被挂起，用户看到的就是「砸到一半停住」。
final class BackgroundAssertion {
    private var token: UIBackgroundTaskIdentifier = .invalid

    init(_ name: String) {
        token = UIApplication.shared.beginBackgroundTask(withName: name) { [weak self] in
            self?.end()
        }
        if token == .invalid {
            AppDumpmgr.shared.logmsg("(task) 后台断言申请失败：\(name)")
        }
    }

    func end() {
        guard token != .invalid else { return }
        UIApplication.shared.endBackgroundTask(token)
        token = .invalid
    }

    deinit { end() }
}