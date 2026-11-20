//
//  fairplayjob.swift
//  AppDump
//
//  FairPlay（B 版）解密任务的宿主。
//
//  以前「运行中」的全部状态（running / phase / fraction / lines / result）
//  都是 FairPlayView 的 @State：一旦离开「App 解密」页（切到 IPA 标签页、
//  切回 A 版引擎、退出页面），视图被销毁，进度写进已释放的 State，
//  于是界面看起来「不继续了」、结果永远不出来、也不会弹分享面板。
//
//  现在改成单例 ObservableObject：任务和状态活在视图之外，页面只是渲染器。
//  完成时还会：
//    · post .appDumpIPAStoreDidChange  → DecryptView 立即刷新 IPA 列表
//    · 自动弹分享面板（和 A 版内核砸壳一致，>1.5 GB 跳过）
//

import Foundation
import SwiftUI
import UIKit
import Combine

extension Notification.Name {
    /// 有新的 IPA 写进 Documents/Decrypted 时广播，IPA 页据此即时刷新。
    static let appDumpIPAStoreDidChange = Notification.Name("AppDumpIPAStoreDidChange")
}

/// 取消标志：任务线程只读，UI 线程只写。
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

final class FairPlayJob: ObservableObject {
    static let shared = FairPlayJob()

    /// 正在解密的来源（已安装应用 = bundlePath，导入的 IPA = path）
    @Published private(set) var runningBundle: String? = nil
    @Published private(set) var runningIPA: String? = nil

    @Published private(set) var phase: String = ""
    @Published private(set) var fraction: Double = 0
    @Published private(set) var detail: String = ""
    @Published private(set) var lines: [String] = []
    @Published private(set) var errormsg: String? = nil
    @Published private(set) var resultText: String? = nil
    @Published private(set) var outputPath: String? = nil
    @Published private(set) var startedAt: Date? = nil

    private var token: FPCancelToken?
    private var bgTask: UIBackgroundTaskIdentifier = .invalid
    private var keepaliveWasOff = false

    private init() {}

    var busy: Bool { runningBundle != nil || runningIPA != nil }

    /// 任务结束后清掉结果卡片（用户手动关掉 / 开始新任务时）。
    func clearResult() {
        errormsg = nil
        resultText = nil
        outputPath = nil
        lines.removeAll()
        phase = ""
        fraction = 0
        detail = ""
    }

    func cancel() {
        token?.cancel()
    }

    // MARK: - 开始

    func startInstalled(_ app: DecryptApp, allowBundleStaging: Bool) {
        guard !busy else { return }
        prepareRun(bundle: app.bundlePath, ipa: nil)
        AppDumpmgr.shared.logmsg("(fairplay) 直砸已安装应用 \(app.bundleID)")

        let token = FPCancelToken()
        self.token = token
        let bundlePath = app.bundlePath
        let appName = app.name

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let outcome = try FPDecryptor.decryptInstalledApp(
                    bundlePath: bundlePath,
                    appName: appName,
                    allowBundleStaging: allowBundleStaging,
                    isCancelled: { token.cancelled },
                    progress: { phase, fraction, detail in
                        DispatchQueue.main.async { self.applyProgress(phase, fraction, detail) }
                    },
                    copyBundle: { destination in
                        FairPlayCopy.run(from: bundlePath, to: destination.path)
                    },
                    log: { line in self.append(line) })
                DispatchQueue.main.async { self.finish(outcome: outcome) }
            } catch {
                DispatchQueue.main.async { self.fail(error) }
            }
        }
    }

    func startIPA(path: String, allowBundleStaging: Bool) {
        guard !busy else { return }
        prepareRun(bundle: nil, ipa: path)
        AppDumpmgr.shared.logmsg("(fairplay) 开始解密 \((path as NSString).lastPathComponent)，暂存开关=\(allowBundleStaging ? "允许" : "禁用")")

        let token = FPCancelToken()
        self.token = token

        DispatchQueue.global(qos: .userInitiated).async {
            do {
                let outcome = try FPDecryptor.decrypt(
                    ipa: URL(fileURLWithPath: path),
                    allowBundleStaging: allowBundleStaging,
                    isCancelled: { token.cancelled },
                    progress: { phase, fraction, detail in
                        DispatchQueue.main.async { self.applyProgress(phase, fraction, detail) }
                    },
                    log: { line in self.append(line) })
                DispatchQueue.main.async { self.finish(outcome: outcome) }
            } catch {
                DispatchQueue.main.async { self.fail(error) }
            }
        }
    }

    // MARK: - 内部

    private func prepareRun(bundle: String?, ipa: String?) {
        clearResult()
        runningBundle = bundle
        runningIPA = ipa
        phase = "准备中"
        startedAt = Date()
        beginBackground()
        beginKeepalive()
    }

    private func applyProgress(_ phase: String, _ fraction: Double, _ detail: String) {
        self.phase = phase
        self.fraction = min(max(fraction, 0), 1)
        self.detail = detail
    }

    private func append(_ line: String) {
        DispatchQueue.main.async {
            self.lines.append(line)
            if self.lines.count > 300 {
                self.lines.removeFirst(self.lines.count - 300)
            }
        }
        AppDumpmgr.shared.logmsg("(fairplay) \(line)")
    }

    private func finish(outcome: FPDecryptor.Outcome) {
        runningBundle = nil
        runningIPA = nil
        endBackground()
        endKeepalive()
        phase = "完成"
        fraction = 1

        outputPath = outcome.output.path
        let seconds = String(format: "%.0f", outcome.elapsed)
        resultText = "\(outcome.clean ? "解密完成" : "部分完成")：解密 \(outcome.decrypted) / 明文 \(outcome.plain) / 失败 \(outcome.failed)，"
            + "Mach-O \(outcome.machO) 个，耗时 \(seconds) 秒。\n"
            + "校验：\(outcome.verifySummary)\n"
            + "产物：\(outcome.output.lastPathComponent)"
        if !outcome.clean {
            errormsg = outcome.failed > 0
                ? "有 \(outcome.failed) 个文件没解开，产物带 PARTIAL 标记。"
                : "产物校验未通过，请检查日志。"
        } else {
            errormsg = nil
        }
        AppDumpmgr.shared.logmsg("(fairplay) 完成：\(outcome.output.lastPathComponent)（\(outcome.clean ? "干净" : "部分")）")

        NotificationCenter.default.post(name: .appDumpIPAStoreDidChange, object: nil)
        presentIfReasonablySized(outcome.output)
    }

    private func fail(_ error: Error) {
        runningBundle = nil
        runningIPA = nil
        endBackground()
        endKeepalive()
        phase = "结束"
        if let fpError = error as? FPError, case .cancelled = fpError {
            resultText = "已取消。"
            errormsg = nil
        } else {
            errormsg = error.localizedDescription
            resultText = nil
        }
        AppDumpmgr.shared.logmsg("(fairplay) 失败：\(error.localizedDescription)")
        NotificationCenter.default.post(name: .appDumpIPAStoreDidChange, object: nil)
    }

    /// 和 A 版一致：小体积产物直接弹分享面板；超大归档交给 IPA 页手动导出，
    /// 否则 UIActivityViewController 会为 3 GB+ 的文件建预览、内存翻倍闪退。
    private func presentIfReasonablySized(_ url: URL) {
        let attrs = (try? FileManager.default.attributesOfItem(atPath: url.path)) ?? [:]
        let size = (attrs[.size] as? NSNumber)?.int64Value ?? 0
        guard size > 0 else { return }
        if size > 1_536 * 1024 * 1024 {
            AppDumpmgr.shared.logmsg("\(url.lastPathComponent) 体积 \(fpSizeText(size))，已跳过自动分享；请在「IPA」页手动导出。")
            return
        }
        DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
            Task { @MainActor in presentShareSheet(with: url) }
        }
    }

    // MARK: - 保活

    /// 让 iOS 在用户短暂切走时别立刻挂起进程（FairPlay 是纯 IO，慢）。
    private func beginBackground() {
        endBackground()
        bgTask = UIApplication.shared.beginBackgroundTask(withName: "FairPlayDecrypt") {
            UIApplication.shared.endBackgroundTask(self.bgTask)
            self.bgTask = .invalid
        }
    }

    private func endBackground() {
        guard bgTask != .invalid else { return }
        UIApplication.shared.endBackgroundTask(bgTask)
        bgTask = .invalid
    }

    /// FairPlay 是纯 IO，耗时可到几分钟；用户切到别的 App 时 iOS 会挂起进程。
    /// 复用设置页那个静音保活（Info.plist 已声明 audio 后台模式），任务结束再还原。
    private func beginKeepalive() {
        guard !kaenabled else { keepaliveWasOff = false; return }
        toggleka()
        keepaliveWasOff = kaenabled
    }

    private func endKeepalive() {
        guard keepaliveWasOff else { return }
        keepaliveWasOff = false
        if kaenabled { toggleka() }
    }
}