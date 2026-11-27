//
//  downgrademgr.swift
//  AppDump
//
//  App Store 历史版本降级（App Downgrade 实现）。
//
//  链路：
//   1. itunes.apple.com/lookup?bundleId=...&limit=1&media=software&country=XX
//      逐个国家代码尝试，直到拿到 trackId（不同地区上架的 App 不同）
//   2. apis.bilin.eu.org/history/<trackId> 取全部历史版本
//   3. StoreKitUI 私有对象：
//        SKUIItemOffer  --KVC setValue:forKey:@"_versionIdentifier"
//        SKUIItem       --持有 offer
//        SKUIItemStateCenter → _newPurchasesWithItems:
//        → _performPurchases:hasBundlePurchase:withClientContext:completionBlock:
//

import Foundation
import StoreKit
import Darwin
import UIKit

// MARK: - 数据模型

struct storeapp: Identifiable, Hashable {
    let trackid: Int64
    let name: String
    let bundleid: String
    let appiconurl: String?
    let sellername: String?
    let version: String?
    let country: String
    /// iTunes lookup 返回的原始 item 字典。
    /// SKUIItem 必须用 initWithLookupDictionary: 从它构造 —— 裸 alloc/init
    /// 得到的是无效对象，后续调用会直接闪退。
    var lookupitem: [String: Any]? = nil

    var id: Int64 { trackid }
    static func == (l: storeapp, r: storeapp) -> Bool { l.trackid == r.trackid }
    func hash(into h: inout Hasher) { h.combine(trackid) }
}

struct storeversion: Identifiable, Hashable, Codable {
    let versionid: String
    /// 已净化的版本号；第三方接口有时把 externalVersionId 直接塞进版本字段，
    /// 那种情况这里留空，由界面显示"未知版本"，不要把 32 位数字当版本号展示。
    let version: String
    let build: String?
    let releasedate: String
    let size: String?
    /// 来自哪个版本源，便于排查"为什么少了一个版本"
    let source: String

    var id: String { versionid }

    var displayversion: String { version.isEmpty ? "未知版本" : version }

    /// 展示行：版本 (构建) 或者只有版本
    var displayline: String {
        guard let build = build, !build.isEmpty, build != version else { return displayversion }
        return "\(displayversion) (\(build))"
    }

    var released: Date? { storeversion.parsedate(releasedate) }

    static func parsedate(_ raw: String) -> Date? {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        if let n = Double(trimmed), n > 1_000_000_000 { return Date(timeIntervalSince1970: n) }
        let formats = ["yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd'T'HH:mm:ssZ", "yyyy-MM-dd", "yyyy/MM/dd"]
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        for fmt in formats {
            f.dateFormat = fmt
            if let d = f.date(from: trimmed) { return d }
        }
        let iso = ISO8601DateFormatter()
        return iso.date(from: trimmed)
    }

    /// 版本号净化：纯数字且长度 >= 7 视为外部版本 ID，不是版本号。
    static func sanitize(_ raw: String?, id: String) -> String {
        let text = (raw ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return "" }
        if text == id { return "" }
        if text.allSatisfy({ $0.isNumber }), text.count >= 7 { return "" }
        return text
    }
}

// MARK: - 失败分类

/// 把"哪一步错了"和"下一步该做什么"分开存，界面就不用再猜字符串。
enum downgradekind: String {
    case notfound       // 查不到这个 App
    case noversions     // 有 App 但没有历史版本数据
    case sideloaded     // 侧载签名应用，商店没有记录
    case notpurchased   // 当前账号没买过 / 没领取过
    case storekit       // StoreKit 私有接口不可用
    case kernel         // 需要内核读写 / 注入，但没就绪
    case timeout        // 超时
    case network        // 网络/接口问题
    case cancelled
    case other

    var symbol: String {
        switch self {
        case .network, .timeout: return "wifi.exclamationmark"
        case .kernel: return "bolt.slash"
        case .notpurchased: return "person.crop.circle.badge.exclamationmark"
        case .sideloaded: return "signature"
        case .cancelled: return "xmark.circle"
        default: return "exclamationmark.triangle.fill"
        }
    }
}

struct downgradefailure: Identifiable, Error {
    let id = UUID()
    let kind: downgradekind
    let title: String
    let reason: String
    let advice: String

    var text: String { "\(reason)\n\n\(advice)" }
}

// MARK: - 版本来源（可配置，多源并发合并）

struct versionSource: Identifiable, Codable, Equatable {
    var id: UUID = UUID()
    var name: String
    /// 含 {id} / {appId} 占位符的 HTTPS 模板
    var template: String
    var enabled: Bool = true
    /// 返回 JSON 里装版本数组的键；留空表示根就是数组
    var containerKey: String = "data"

    static let placeholders = ["{id}", "{appId}", "{appid}", "{APPID}"]

    var hasplaceholder: Bool { Self.placeholders.contains { template.contains($0) } }

    func url(for trackid: Int64) -> URL? {
        guard hasplaceholder else { return nil }
        var filled = template.trimmingCharacters(in: .whitespacesAndNewlines)
        for token in Self.placeholders {
            filled = filled.replacingOccurrences(of: token, with: String(trackid))
        }
        guard let url = URL(string: filled), url.scheme == "https", url.host != nil else { return nil }
        return url
    }

    static let defaults: [versionSource] = [
        versionSource(name: "bilin", template: "https://apis.bilin.eu.org/history/{id}", containerKey: "data"),
        versionSource(name: "iosdump", template: "https://iosdump.apdoilaan.work/history/{id}", containerKey: "data"),
    ]

    /// 参与缓存键，源改了就要重新抓。
    var signature: String { "\(name)|\(template)|\(containerKey)|\(enabled)" }
}

/// 版本来源的持久化（UserDefaults，JSON）。
final class versionsources {
    static let shared = versionsources()

    private let key = "downgrade.versionSources"
    private let lock = NSLock()
    private var stored: [versionSource]

    private init() {
        if let data = UserDefaults.standard.data(forKey: key),
           let list = try? JSONDecoder().decode([versionSource].self, from: data),
           !list.isEmpty {
            stored = list
        } else {
            stored = versionSource.defaults
            if let data = try? JSONEncoder().encode(stored) {
                UserDefaults.standard.set(data, forKey: key)
            }
        }
    }

    var all: [versionSource] {
        lock.lock()
        defer { lock.unlock() }
        return stored
    }

    var enabled: [versionSource] { all.filter(\.enabled) }

    func replace(_ list: [versionSource]) {
        lock.lock()
        stored = list.isEmpty ? versionSource.defaults : list
        lock.unlock()
        if let data = try? JSONEncoder().encode(stored) {
            UserDefaults.standard.set(data, forKey: key)
        }
    }

    func restoredefaults() { replace(versionSource.defaults) }
}

enum downgradeerror: LocalizedError {
    case notFound(String)
    case noVersions
    case storeKitUnavailable(String)
    case failed(String)
    /// C 层的原始返回码，用于结构化分类
    case coded(Int32)

    var errorDescription: String? {
        switch self {
        case .notFound(let q): return "未找到应用：\(q)"
        case .noVersions: return "没有可用的历史版本"
        case .storeKitUnavailable(let w): return "StoreKit 私有接口不可用（\(w)）"
        case .failed(let m): return "降级失败：\(m)"
        case .coded(let rc): return downgrademgr.describe(rc: rc)
        }
    }
}

// MARK: - StoreKitUI 降级执行

final class storekitbridge {
    static let shared = storekitbridge()
    private init() {}

    /// 支持的国家代码：逐个试查 trackId。
    /// 一个 App 只在部分区上架，用单一地区查不到时换区就能查到。
    // 顺序很重要：只在中国区上架的应用（例如 123云盘）必须靠前，
    // 否则前面的区逐个超时后，查到这里时请求已被系统节流。
    /// trackId -> storeapp，供降级时取 lookupitem
    var pendinglookup: [Int64: storeapp] = [:]


    static let countryCodes = ["CN", "US", "HK", "TW", "JP", "SG", "GB", "KR", "CA", "AU", "DE", "FR"]

    /// 执行降级。
    static func purchase(trackid: Int64,
                         versionid: String,
                         completion: @escaping (Result<Void, downgradeerror>) -> Void) {
        DispatchQueue.global(qos: .userInitiated).async {
            let r = performSync(trackid: trackid, versionid: versionid)
            DispatchQueue.main.async { completion(r) }
        }
    }

    /// 显式加载 StoreKitUI 私有框架。
    ///
    /// SKUIClientContext / SKUIItem / SKUIItemOffer 都定义在这个框架里，
    /// 不 dlopen 的话 NSClassFromString 永远返回 nil（表现为提示
    /// "StoreKit 私有接口不可用 (SKUIClientContext)"）。
    /// 先 dlopen 再取类。
    private static var storekituiLoaded = false

    @discardableResult
    private static func loadstorekitui() -> Bool {
        if storekituiLoaded { return true }
        let paths = [
            "/System/Library/PrivateFrameworks/StoreKitUI.framework/StoreKitUI",
            "/System/Library/PrivateFrameworks/StoreKitUI.framework/StoreKitUI",
        ]
        for p in paths {
            if dlopen(p, RTLD_NOW) != nil {
                storekituiLoaded = true
                AppDumpmgr.shared.logmsg("(downgrade) StoreKitUI 已加载")
                return true
            }
        }
        AppDumpmgr.shared.logmsg("(downgrade) StoreKitUI 加载失败：\(String(cString: dlerror()))")
        return false
    }

    private static func performSync(trackid: Int64, versionid: String) -> Result<Void, downgradeerror> {
        // 实现放在 kcdowngrade.m：Swift 的 do-catch 捕获不到 ObjC 的
        // NSException，私有 API 一旦抛异常就会让 App 直接崩溃。
        AppDumpmgr.shared.logmsg("(downgrade) 开始降级 track=\(trackid) ver=\(versionid)")

        guard ds_is_ready() else {
            return .failure(.storeKitUnavailable("内核读写未就绪，请先运行漏洞利用"))
        }

        // 取该 trackId 对应的 iTunes lookup 原始条目，序列化后交给注入代码当
        // SKUIItem 的 lookup 字典。缺了它，item 里的 itemIdentifier / bundleId 都是 0，
        // 商店收到购买请求后既不报错也不下载。
        let app = storekitbridge.shared.pendinglookup[trackid]
        var lookupjson = ""
        if let item = app?.lookupitem,
           let data = try? JSONSerialization.data(withJSONObject: item),
           let text = String(data: data, encoding: .utf8) {
            lookupjson = text
            AppDumpmgr.shared.logmsg("(downgrade) lookup 条目已就绪（\(data.count) 字节）")
        } else {
            AppDumpmgr.shared.logmsg("(downgrade) 警告：缺少 lookup 条目，改用兜底字典")
        }

        // 只有注入 SpringBoard 一条路（本进程模式已移除）。
        AppDumpmgr.shared.logmsg("(downgrade) 使用模式 B（注入 SpringBoard）")

        let rc = kcd_perform_downgrade_withlookup(trackid, versionid, lookupjson)
        if rc == 0 {
            AppDumpmgr.shared.logmsg("(downgrade) 购买请求已提交，请回到桌面查看下载")
            return .success(())
        }
        return .failure(.coded(rc))
    }

    /// KVC 写入，失败不抛异常（字段名随系统版本变化）
    @discardableResult
    private static func setKVCSafe(_ obj: AnyObject, key: String, value: Any) -> Bool {
        guard obj.responds(to: NSSelectorFromString("setValue:forKey:")) else { return false }
        do {
            try (obj as? NSObject)?.setValue(value, forKey: key)
            return true
        } catch {
            return false
        }
    }

    /// 调 _newPurchasesWithItems: 生成 SKPayment 数组
    private static func buildPurchases(items: [AnyObject], context: AnyObject) -> [AnyObject]? {
        guard let centerClass = NSClassFromString("SKUIItemStateCenter") else { return nil }

        // 优先单例
        var center: AnyObject? = nil
        for selName in ["defaultCenter", "sharedCenter"] {
            let sel = NSSelectorFromString(selName)
            if (centerClass as AnyObject).responds(to: sel),
               let c = (centerClass as AnyObject).perform(sel)?.takeUnretainedValue() {
                center = c
                break
            }
        }
        if center == nil {
            center = (centerClass as AnyObject).perform(NSSelectorFromString("new"))?
                        .takeUnretainedValue()
        }
        guard let center = center else { return nil }

        let sel = NSSelectorFromString("_newPurchasesWithItems:")
        guard center.responds(to: sel), let cls = object_getClass(center) else { return nil }
        let imp = class_getMethodImplementation(cls, sel)
        typealias Fn = @convention(c) (AnyObject, Selector, AnyObject) -> AnyObject?
        let fn = unsafeBitCast(imp, to: Fn.self)
        let result = fn(center, sel, items as NSArray)
        return result as? [AnyObject]
    }

    /// 调 _performPurchases:hasBundlePurchase:withClientContext:completionBlock:
    private static func dispatch(queue: SKPaymentQueue,
                                 purchases: [AnyObject],
                                 context: AnyObject) -> Result<Void, downgradeerror> {
        let sel = NSSelectorFromString("_performPurchases:hasBundlePurchase:withClientContext:completionBlock:")
        guard queue.responds(to: sel), let cls = object_getClass(queue) else {
            return .failure(.storeKitUnavailable("_performPurchases"))
        }
        let imp = class_getMethodImplementation(cls, sel)

        let sem = DispatchSemaphore(value: 0)
        var outcome: Result<Void, downgradeerror>? = nil

        let blk: @convention(block) (Int, NSError?) -> Void = { status, err in
            if status == 0 {
                outcome = .success(())
            } else {
                outcome = .failure(.failed(err?.localizedDescription ?? "状态码 \(status)"))
            }
            sem.signal()
        }

        typealias Fn4 = @convention(c) (AnyObject, Selector, AnyObject, Bool, AnyObject?,
                                        @escaping @convention(block) (Int, NSError?) -> Void) -> Void
        let fn = unsafeBitCast(imp, to: Fn4.self)
        fn(queue, sel, purchases as NSArray, false, context, blk)

        if sem.wait(timeout: .now() + 30) == .timedOut {
            return .failure(.failed("App Store 无响应（30 秒超时）"))
        }
        return outcome ?? .failure(.failed("回调无结果"))
    }
}

// MARK: - 管理器

final class downgrademgr {
    static let shared = downgrademgr()

    /// 最近一次版本抓取的说明（多少源有数据、哪些失败），给界面直接显示。
    private(set) var lastversionnote: String = ""

    /// bundleId → App Store 匹配结果缓存。界面重新进入/刷新时只查新增的，
    /// 不再对 144 个应用重复打 iTunes 接口（那正是被限流的根源）。
    private var lookupcache: [String: (app: storeapp, at: Date)] = [:]
    private let lookuplock = NSLock()
    private let lookupttl: TimeInterval = 10 * 60

    private func cachedapp(_ bundleid: String) -> storeapp? {
        lookuplock.lock()
        defer { lookuplock.unlock() }
        guard let entry = lookupcache[bundleid],
              Date().timeIntervalSince(entry.at) < lookupttl else { return nil }
        return entry.app
    }

    private func cacheapp(_ app: storeapp, for bundleid: String) {
        lookuplock.lock()
        lookupcache[bundleid] = (app, Date())
        lookuplock.unlock()
    }

    /// 空 trackId 代表"确认查不到"，同样缓存，避免反复请求侧载应用。
    private func cachenil(_ bundleid: String) {
        let placeholder = storeapp(trackid: 0, name: bundleid, bundleid: bundleid,
                                   appiconurl: nil, sellername: nil, version: nil, country: "")
        cacheapp(placeholder, for: bundleid)
    }

    /// C 层返回码 → 结构化失败。rc 语义见 storekitbridge.describe。
    static func classify(rc: Int32) -> downgradefailure {
        switch Int(rc) {
        case 2:
            return downgradefailure(kind: .noversions, title: "版本号无效",
                                    reason: "选中的版本 ID 没能通过校验。",
                                    advice: "换一个版本再试；如果版本来源里出现「未知版本」，先到「版本来源」里换一个能给出正确版本号的源。")
        case 20:
            let why = kcd_last_attach_error() ?? ""
            let kernelReady = ds_is_ready()
            return downgradefailure(kind: .kernel, title: "无法附着 SpringBoard",
                                    reason: why.isEmpty
                                        ? "模式 B 需要把代码注入 SpringBoard 才能复用商店的购买流程。"
                                        : "模式 B 需要把代码注入 SpringBoard，这次注入失败：\(why)",
                                    advice: kernelReady
                                        ? "内核读写是就绪的，问题出在注入这一环（上面那句具体原因）。先重试一次；如果每次原因都一样，说明这套系统（\(ProcessInfo.processInfo.operatingSystemVersionString)）上的注入方式不适配，换版本得等适配。"
                                        : "到「内核」页运行漏洞利用并初始化系统，然后重试。")
        case 21, 22, 23:
            return downgradefailure(kind: .storekit, title: "SpringBoard 里加载 StoreKitUI 失败",
                                    reason: "目标进程里没能取到 SKUIClientContext / SKUIItem 这些私有类。",
                                    advice: "重试一次；仍失败说明该系统的 StoreKitUI 结构变了，只能等适配。")
        case 24, 25, 26:
            return downgradefailure(kind: .storekit, title: "构造购买请求失败",
                                    reason: "SKUIItemOffer / SKUIItemStateCenter 没能构造出可用的请求对象。",
                                    advice: "重试一次，或换一个更早的版本号试试（个别版本 ID 已被苹果下架）。")
        case 27:
            return downgradefailure(kind: .kernel, title: "内核读写未就绪",
                                    reason: "模式 B 需要内核读写才能把参数写进目标进程。",
                                    advice: "到「内核」页初始化系统后重试。")
        case 98:
            return downgradefailure(kind: .timeout, title: "注入执行超时",
                                    reason: "目标进程长时间没有返回。",
                                    advice: "重试；必要时先杀掉 SpringBoard 让系统自己重启（会自动恢复），再初始化系统后重试。")
        case 99:
            return downgradefailure(kind: .other, title: "执行过程抛出异常",
                                    reason: "注入的代码在目标进程里异常退出。",
                                    advice: "重试一次；日志里有完整堆栈。")
        default:
            return downgradefailure(kind: .other, title: "降级失败",
                                    reason: "错误码 \(rc)（注入 SpringBoard）。",
                                    advice: "查看日志里的完整输出。")
        }
    }

    /// 拿不到版本列表时的分类提示。
    static func classifyempty(note: String) -> downgradefailure {
        if note.contains("没有启用的版本来源") {
            return downgradefailure(kind: .network, title: "没有可用的版本来源",
                                    reason: "所有版本来源都被关掉了。",
                                    advice: "打开「版本来源」，至少启用一个；也可以点「恢复默认」。")
        }
        return downgradefailure(kind: .network, title: "拿不到历史版本",
                                reason: note.isEmpty ? "所有版本来源都没有返回数据。" : note,
                                advice: "检查网络后重试；如果只是某个来源失败，可以到「版本来源」里换一个能用的接口。")
    }

    private init() {}


    /// 把 C 层返回码翻译成可读信息。
    static func describe(rc: Int32) -> String {
        switch Int(rc) {
        case 2:  return "版本号无效"
        case 20: return "无法附着 SpringBoard，请先在「内核」页运行漏洞利用并初始化系统。"
        case 21, 22: return "SpringBoard 内加载 StoreKitUI 失败"
        case 23: return "SpringBoard 内缺少 SKUI 类"
        case 24: return "SKUIItemOffer / SKUIItem 构造失败"
        case 25: return "SKUIItemStateCenter 不可用"
        case 26: return "购买项构造失败"
        case 27: return "内核读写未就绪，请先运行漏洞利用"
        case 98: return "注入执行超时"
        case 99: return "执行过程抛出异常（详见日志）"
        default: return "失败（错误码 \(rc)，注入 SpringBoard）"
        }
    }

    private func log(_ m: String) { AppDumpmgr.shared.logmsg("(downgrade) \(m)") }

    // MARK: 网络

    private func anyjson(_ url: URL, timeout: TimeInterval = 20) -> Any? {
        var req = URLRequest(url: url)
        req.timeoutInterval = timeout
        req.setValue("AppDump/1.0", forHTTPHeaderField: "User-Agent")
        req.cachePolicy = .reloadIgnoringLocalCacheData

        let sem = DispatchSemaphore(value: 0)
        var result: Any? = nil
        URLSession.shared.dataTask(with: req) { data, _, err in
            defer { sem.signal() }
            guard let data = data, err == nil, !data.isEmpty,
                  let obj = try? JSONSerialization.jsonObject(with: data)
            else { return }
            result = obj
        }.resume()
        _ = sem.wait(timeout: .now() + timeout + 5)
        return result
    }

    private func fetchjson(_ url: URL, timeout: TimeInterval = 20) -> [String: Any]? {
        anyjson(url, timeout: timeout) as? [String: Any]
    }

    // MARK: 1. 批量解析已安装应用的 App Store 信息

    /// 对每个 bundleId 依次尝试多个国家代码，命中即停。
    /// - Parameter progress: (已完成, 总数)
    func resolvebundles(_ bundleids: [String],
                        progress: @escaping (Int, Int) -> Void = { _, _ in }) -> [String: storeapp] {
        var out: [String: storeapp] = [:]
        let allids = bundleids.filter { !$0.isEmpty }
        var missing: [String] = []
        var cached = 0
        for bid in allids {
            if let app = cachedapp(bid) {
                cached += 1
                if app.trackid != 0 {
                    out[bid] = app
                    storekitbridge.shared.pendinglookup[app.trackid] = app
                }
            } else {
                missing.append(bid)
            }
        }
        if cached > 0 {
            log("匹配缓存命中 \(cached)/\(allids.count)，需要查询 \(missing.count) 个")
        }
        let list = missing
        var done = 0

        // 并发查询（限 6 路）：138 个应用串行逐个查会耗时数分钟，
        // 期间很容易被系统限流，导致排在后面的应用（如只在中国区上架的）
        // 全部查询失败、被误判为侧载应用。
        let lock = NSLock()
        let sem = DispatchSemaphore(value: 6)
        let group = DispatchGroup()

        for bid in list {
            sem.wait()
            group.enter()
            DispatchQueue.global(qos: .userInitiated).async {
                defer { group.leave(); sem.signal() }
                let app = self.lookupTrackId(bundleid: bid)
                if let app {
                    self.cacheapp(app, for: bid)
                } else {
                    // 侧载应用查不到商店记录，也要缓存"查不到"，否则每次刷新都白查一遍
                    self.cachenil(bid)
                }
                lock.lock()
                if let app {
                    out[bid] = app
                    storekitbridge.shared.pendinglookup[app.trackid] = app
                }
                done += 1
                let d = done
                lock.unlock()
                progress(d, list.count)
            }
        }
        group.wait()
        log("解析完成：\(out.count)/\(allids.count)（本次查询 \(list.count) 个）")
        return out
    }

    /// 用国家列表逐个查 trackId
    func lookupTrackId(bundleid: String) -> storeapp? {
        for cc in storekitbridge.countryCodes {
            let enc = bundleid.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? bundleid
            let urlstr = "https://itunes.apple.com/lookup?bundleId=\(enc)&limit=1&media=software&country=\(cc)"
            // 超时压到 6 秒：单个国家查不到就没必要等太久，
            // 138 个应用 × 多国逐个等 12 秒会拖到几分钟并被系统限流。
            guard let url = URL(string: urlstr), let json = fetchjson(url, timeout: 6) else { continue }
            if let app = parseapp(json, country: cc) {
                return app
            }
        }
        return nil
    }

    private func parseapp(_ json: [String: Any], country: String) -> storeapp? {
        guard let arr = json["results"] as? [[String: Any]], let item = arr.first,
              let tid = item["trackId"] as? NSNumber,
              let bid = item["bundleId"] as? String else { return nil }
        return storeapp(
            trackid: tid.int64Value,
            name: item["trackName"] as? String ?? bid,
            bundleid: bid,
            appiconurl: item["artworkUrl100"] as? String,
            sellername: item["sellerName"] as? String,
            version: item["version"] as? String,
            country: country,
            lookupitem: item
        )
    }

    // MARK: 2. 历史版本

    /// 多源并发抓历史版本：每个启用的源各发一次请求，**全部返回后**再合并去重。
    /// 先到先得会让列表取决于网络时序，还会漏掉只有某个源才收录的版本。
    func history(trackid: Int64) -> [storeversion] {
        let result = fetchversions(trackid: trackid)
        lastversionnote = result.note
        log(result.note)
        return result.versions
    }

    private struct cacheentry: Codable {
        let savedAt: Date
        let complete: Bool
        let versions: [storeversion]
    }

    private struct fetchresult {
        let versions: [storeversion]
        let note: String
        let complete: Bool
    }

    private var cacheurl: URL? {
        guard let dir = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first else { return nil }
        return dir.appendingPathComponent("downgrade-versions.json")
    }

    private func loadcache() -> [String: cacheentry] {
        guard let url = cacheurl, let data = try? Data(contentsOf: url),
              let map = try? JSONDecoder().decode([String: cacheentry].self, from: data) else { return [:] }
        return map
    }

    private func savecache(_ map: [String: cacheentry]) {
        guard let url = cacheurl, let data = try? JSONEncoder().encode(map) else { return }
        try? data.write(to: url, options: .atomic)
    }

    private func fetchversions(trackid: Int64) -> fetchresult {
        let sources = versionsources.shared.enabled
        guard !sources.isEmpty else {
            return fetchresult(versions: [], note: "没有启用的版本来源，请到「版本来源」里至少开启一个。", complete: false)
        }

        let signature = sources.map(\.signature).joined(separator: ";")
        let cachekey = "\(trackid)|\(signature)"
        var cache = loadcache()
        if let entry = cache[cachekey] {
            let ttl: TimeInterval = entry.complete ? 24 * 3600 : 10 * 60
            if Date().timeIntervalSince(entry.savedAt) < ttl {
                return fetchresult(versions: entry.versions,
                                   note: "历史版本 \(entry.versions.count) 个（缓存，来源 \(sources.count) 个）",
                                   complete: entry.complete)
            }
        }

        let lock = NSLock()
        var collected: [(String, [storeversion])] = []
        let group = DispatchGroup()
        let sem = DispatchSemaphore(value: 4)

        for source in sources {
            guard let url = source.url(for: trackid) else {
                log("来源 \(source.name) 模板无效：\(source.template)")
                continue
            }
            group.enter()
            sem.wait()
            DispatchQueue.global(qos: .utility).async {
                defer { sem.signal(); group.leave() }
                let list = self.parsesource(source, url: url, trackid: trackid)
                lock.lock()
                collected.append((source.name, list))
                lock.unlock()
            }
        }
        // 单个源卡死也不能拖住整页
        _ = group.wait(timeout: .now() + 45)

        lock.lock()
        let results = collected
        lock.unlock()

        var merged: [String: storeversion] = [:]
        for (_, list) in results {
            for item in list where merged[item.versionid] == nil {
                merged[item.versionid] = item
            }
        }
        let failed = results.filter { $0.1.isEmpty }.map { $0.0 }
        let complete = failed.isEmpty && results.count == sources.count

        var versions = Array(merged.values)
        versions.sort { lhs, rhs in
            switch (lhs.released, rhs.released) {
            case let (l?, r?): return l == r ? lhs.versionid > rhs.versionid : l > r
            case (_?, nil): return true
            case (nil, _?): return false
            case (nil, nil): return lhs.versionid > rhs.versionid
            }
        }

        if !versions.isEmpty {
            cache[cachekey] = cacheentry(savedAt: Date(), complete: complete, versions: versions)
            savecache(cache)
        } else if let old = cache[cachekey], !old.versions.isEmpty {
            // 这次所有来源都失败，但之前抓到过：宁可给过期数据 + 说明，
            // 也不要把列表清空（清空后界面看起来像"降级没生效"）。
            let mins = Int(Date().timeIntervalSince(old.savedAt) / 60)
            return fetchresult(versions: old.versions,
                               note: "历史版本 \(old.versions.count) 个（离线缓存，\(mins) 分钟前）",
                               complete: old.complete)
        }

        var note = "历史版本 \(versions.count) 个（\(results.count - failed.count)/\(sources.count) 个来源有数据）"
        if !failed.isEmpty {
            note += "，失败：\(failed.joined(separator: "、"))"
        }
        return fetchresult(versions: versions, note: note, complete: complete)
    }

    /// 不同接口字段名不一样，逐个兼容；拿不到 versionid 的条目直接丢。
    private func parsesource(_ source: versionSource, url: URL, trackid: Int64) -> [storeversion] {
        guard let json = anyjson(url) else {
            log("来源 \(source.name) 请求失败")
            return []
        }
        var items: [[String: Any]] = []
        if source.containerKey.isEmpty, let array = json as? [[String: Any]] {
            items = array
        } else if let dict = json as? [String: Any] {
            if let array = dict[source.containerKey] as? [[String: Any]] {
                items = array
            } else if let array = dict["data"] as? [[String: Any]] {
                items = array
            } else if let array = dict["versions"] as? [[String: Any]] {
                items = array
            } else if let nested = dict["result"] as? [String: Any],
                      let array = nested["data"] as? [[String: Any]] {
                items = array
            }
        } else if let array = json as? [[String: Any]] {
            items = array
        }

        var out: [storeversion] = []
        for item in items {
            let vid = field(item, ["external_identifier", "externalVersionId", "external_version_id",
                                   "version_id", "versionId", "id"])
            guard !vid.isEmpty, vid.allSatisfy({ $0.isNumber }) else { continue }

            let rawVersion = field(item, ["bundle_version", "bundleShortVersionString",
                                          "short_version", "version"])
            let rawBuild = field(item, ["build", "bundleVersion", "bundle_version_string"])
            let version = storeversion.sanitize(rawVersion, id: vid)
            var build = storeversion.sanitize(rawBuild, id: vid)
            if build == version { build = "" }

            var sizeText: String? = nil
            if let n = item["size"] as? NSNumber ?? item["fileSize"] as? NSNumber {
                sizeText = ByteCountFormatter.string(fromByteCount: n.int64Value, countStyle: .file)
            }

            out.append(storeversion(
                versionid: vid,
                version: version,
                build: build.isEmpty ? nil : build,
                releasedate: field(item, ["created_at", "createdAt", "date", "releaseDate",
                                          "released", "uploaded_at", "timestamp"]),
                size: sizeText,
                source: source.name
            ))
        }
        log("来源 \(source.name) 返回 \(out.count) 个版本（原始条目 \(items.count)）")
        return out
    }

    private func field(_ item: [String: Any], _ keys: [String]) -> String {
        for key in keys {
            if let text = item[key] as? String {
                let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
                if !trimmed.isEmpty { return trimmed }
            }
            if let number = item[key] as? NSNumber { return number.stringValue }
        }
        return ""
    }

    // MARK: 3. 执行降级

    func downgrade(trackid: Int64, version: storeversion,
                   completion: @escaping (Result<Void, downgradefailure>) -> Void) {
        log("[DOWNGRADE] Requesting downgrade (Track: \(trackid), Version: \(version.versionid) / \(version.displayline))")
        storekitbridge.purchase(trackid: trackid, versionid: version.versionid) { r in
            switch r {
            case .success:
                self.log("降级请求已提交")
                completion(.success(()))
            case .failure(let e):
                let failure = Self.classify(error: e)
                self.log("降级失败[\(failure.kind.rawValue)]：\(failure.reason)")
                completion(.failure(failure))
            }
        }
    }

    /// 老错误类型 → 结构化失败
    static func classify(error: Error) -> downgradefailure {
        guard let e = error as? downgradeerror else {
            return downgradefailure(kind: .other, title: "降级失败",
                                    reason: error.localizedDescription,
                                    advice: "查看日志里的完整输出。")
        }
        switch e {
        case .coded(let rc):
            return classify(rc: rc)
        case .storeKitUnavailable(let message):
            let kernelRelated = message.contains("内核") || message.contains("漏洞")
            return downgradefailure(kind: kernelRelated ? .kernel : .storekit,
                                    title: kernelRelated ? "内核读写未就绪" : "StoreKit 私有接口不可用",
                                    reason: message,
                                    advice: kernelRelated
                                        ? "到「内核」页运行漏洞利用并初始化系统后重试。"
                                        : "该系统的 StoreKitUI 结构与预期不一致，重试一次；仍失败只能等适配。")
        case .noVersions:
            return downgradefailure(kind: .noversions, title: "没有可用的历史版本",
                                    reason: "这个应用一个历史版本都没查到。",
                                    advice: "到「版本来源」里换一个可用的接口，或稍后再试。")
        case .notFound(let query):
            return downgradefailure(kind: .notfound, title: "没找到这个应用",
                                    reason: "App Store 查不到「\(query)」。",
                                    advice: "确认它确实上架过 App Store；侧载签名的应用没有商店记录，无法降级。")
        case .failed(let message):
            return downgradefailure(kind: .other, title: "降级失败",
                                    reason: message,
                                    advice: "查看日志里的完整输出。")
        }
    }
}
