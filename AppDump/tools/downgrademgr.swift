//
//  downgrademgr.swift
//  AppDump
//
//  App Store 历史版本降级（复刻 Cyanide 的 App Downgrade 实现）。
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

struct storeversion: Identifiable, Hashable {
    let versionid: String
    let version: String
    let releasedate: String
    let size: String?

    var id: String { versionid }
}

enum downgradeerror: LocalizedError {
    case notFound(String)
    case noVersions
    case storeKitUnavailable(String)
    case failed(String)

    var errorDescription: String? {
        switch self {
        case .notFound(let q): return "未找到应用：\(q)"
        case .noVersions: return "没有可用的历史版本"
        case .storeKitUnavailable(let w): return "StoreKit 私有接口不可用（\(w)）"
        case .failed(let m): return "降级失败：\(m)"
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
    /// Cyanide 也是先 dlopen 再取类。
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

        // 取该 trackId 对应的 lookup 原始字典（SKUIItem 构造所需）
        let app = storekitbridge.shared.pendinglookup[trackid]
        // ObjC 的 NSDictionary* 会被 Swift 桥接成 [AnyHashable: Any]?
        let dict: [AnyHashable: Any]? = app?.lookupitem
        if dict == nil {
            AppDumpmgr.shared.logmsg("(downgrade) 警告：缺少 lookup 字典，SKUIItem 可能构造失败")
        }

        let mode = downgrademgr.currentMode
        let bundleid = app?.bundleid ?? ""
        AppDumpmgr.shared.logmsg("(downgrade) 使用\(mode == 0 ? "模式 A（本进程）" : "模式 B（注入 SpringBoard）")")

        let rc = kcd_perform_downgrade_mode(trackid, versionid, bundleid, Int32(mode))
        if rc == 0 {
            AppDumpmgr.shared.logmsg("(downgrade) 购买请求已提交，请回到桌面查看下载")
            return .success(())
        }
        return .failure(.failed(downgrademgr.describe(rc: rc, mode: mode)))
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

    /// 降级实现方式。两条路径完全独立，不会混合执行。
    ///   0 = 本进程（AppRetro 做法，不需要漏洞利用）
    ///   1 = 注入 SpringBoard（Cyanide 做法，需要内核读写就绪）
    static let modeKey = "AppDump.downgradeMode"

    static var currentMode: Int {
        get { UserDefaults.standard.object(forKey: modeKey) == nil
                ? 1                                   // 默认沿用已验证的注入模式
                : UserDefaults.standard.integer(forKey: modeKey) }
        set { UserDefaults.standard.set(newValue, forKey: modeKey) }
    }

    private init() {}


    /// 把 C 层返回码翻译成可读信息。10~1x 属模式 A，20~2x 属模式 B。
    static func describe(rc: Int32, mode: Int) -> String {
        switch Int(rc) {
        case 2:  return "版本号无效"
        case 10: return "模式 A 失败：AppStoreDaemon 与本进程 StoreKitUI 都没成功。可改用模式 B（需先运行漏洞利用）。"
        case 20: return "无法附着 SpringBoard，请先在「内核」页运行漏洞利用并初始化系统，或改用模式 A。"
        case 21, 22: return "SpringBoard 内加载 StoreKitUI 失败"
        case 23: return "SpringBoard 内缺少 SKUI 类"
        case 24: return "SKUIItemOffer / SKUIItem 构造失败"
        case 25: return "SKUIItemStateCenter 不可用"
        case 26: return "购买项构造失败"
        case 27: return "内核读写未就绪，请先运行漏洞利用，或改用模式 A"
        case 98: return "注入执行超时"
        case 99: return "执行过程抛出异常（详见日志）"
        default: return "失败（错误码 \(rc)，模式 \(mode == 0 ? "A" : "B")）"
        }
    }

    private func log(_ m: String) { AppDumpmgr.shared.logmsg("(downgrade) \(m)") }

    // MARK: 网络

    private func fetchjson(_ url: URL, timeout: TimeInterval = 20) -> [String: Any]? {
        var req = URLRequest(url: url)
        req.timeoutInterval = timeout
        req.setValue("AppDump/1.0", forHTTPHeaderField: "User-Agent")

        let sem = DispatchSemaphore(value: 0)
        var result: [String: Any]? = nil
        URLSession.shared.dataTask(with: req) { data, _, err in
            defer { sem.signal() }
            guard let data = data, err == nil,
                  let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
            else { return }
            result = obj
        }.resume()
        _ = sem.wait(timeout: .now() + timeout + 5)
        return result
    }

    // MARK: 1. 批量解析已安装应用的 App Store 信息

    /// 对每个 bundleId 依次尝试多个国家代码，命中即停。
    /// - Parameter progress: (已完成, 总数)
    func resolvebundles(_ bundleids: [String],
                        progress: @escaping (Int, Int) -> Void = { _, _ in }) -> [String: storeapp] {
        var out: [String: storeapp] = [:]
        let list = bundleids.filter { !$0.isEmpty }
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
        log("解析完成：\(out.count)/\(list.count)")
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

    /// apis.bilin.eu.org/history/<trackId>
    /// 返回结构：{"code":200,"total":N,"data":[
    ///   {"bundle_version":"34.4.441103001","external_identifier":894485282,
    ///    "size":273574912,"created_at":"2026-11-06 01:40:09"}]}
    func history(trackid: Int64) -> [storeversion] {
        let urlstr = "https://apis.bilin.eu.org/history/\(trackid)"
        guard let url = URL(string: urlstr) else { return [] }
        guard let json = fetchjson(url, timeout: 30) else {
            log("history 请求失败：\(urlstr)")
            return []
        }
        guard let list = json["data"] as? [[String: Any]] else {
            log("history 无 data 字段 code=\(json["code"] ?? "-")")
            return []
        }

        var out: [storeversion] = []
        for item in list {
            var vid = ""
            if let n = item["external_identifier"] as? NSNumber {
                vid = n.stringValue
            } else if let s = item["external_identifier"] as? String {
                vid = s
            }
            guard !vid.isEmpty else { continue }

            let ver = (item["bundle_version"] as? String) ?? vid
            var sizeStr: String? = nil
            if let n = item["size"] as? NSNumber {
                sizeStr = ByteCountFormatter.string(fromByteCount: n.int64Value, countStyle: .file)
            }
            out.append(storeversion(
                versionid: vid,
                version: ver,
                releasedate: (item["created_at"] as? String) ?? "",
                size: sizeStr
            ))
        }

        var seen = Set<String>()
        out = out.filter { seen.insert($0.versionid).inserted }
        out.sort { $0.releasedate > $1.releasedate }
        log("track=\(trackid) 历史版本 \(out.count) 个")
        return out
    }

    // MARK: 3. 执行降级

    func downgrade(trackid: Int64, version: storeversion,
                   completion: @escaping (Result<Void, downgradeerror>) -> Void) {
        log("[DOWNGRADE] Requesting downgrade (Track: \(trackid), Version: \(version.versionid))")
        storekitbridge.purchase(trackid: trackid, versionid: version.versionid) { r in
            switch r {
            case .success: self.log("降级请求已提交")
            case .failure(let e): self.log("降级失败：\(e.localizedDescription)")
            }
            completion(r)
        }
    }
}
