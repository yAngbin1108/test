//
//  writeperm.swift
//  AppDump
//
//  写权限（与 blade 最新版一模一样的机制）
//  ==========================================
//
//  第一层：沙盒策略探针 + 重放逃逸（SandboxKeeper）
//  ------------------------------------------------
//  沙盒逃逸改的是「内核里这份进程的 sandbox policy」，这个修改是易失的：内核
//  在重新推导策略（特权路径写、IPC 事件、凭据重算）时会把它覆盖回磁盘上的
//  profile，写权限就悄悄没了。而内核读写原语本身是持久的（挂在进程的内核
//  socket 结构上）。
//
//  所以 blade 的做法是：
//    * 用**特权路径**上的探针判断写权限是否还在
//      （/private/var/mobile/Library/Preferences/.sbxkit_alive，create+write+unlink。
//       不能放自己的容器里 —— 那里本来就可写，证明不了任何事）；
//    * 丢了只**重放策略那一次内存写**（sbx_escape），绝不重跑漏洞链；
//    * 后台每 7 秒自动查一次（可关）；连续失败 5 次就停手，避免在坏状态上
//      反复写内核；
//    * 每次文件操作前先 restoreIfLost()，失败就重放一次再走。
//
//  第二层：容器属主（内核里改写 apfs_fsnode）
//  ------------------------------------------
//  沙盒逃逸只解除 MAC(sandbox) 限制；/var/containers/... 下的文件还要过普通
//  UNIX 属主/权限检查，.app 包里的文件所有者通常不是本进程的 uid，于是即使
//  已有完整读写沙盒扩展，open(O_WRONLY) 仍然 EACCES。
//
//  blade 的做法（与 FilzaJailedDS 一致）：沿 vnode -> v_data -> apfs_fsnode 在
//  内核里把 uid/gid 改成 501:501，再把 owner 读写位补上（mode|0600）。
//  apfs_fsnode 在普通可写 zone，内核写原语够得到。
//
//  这一层只作用于 /var 下（字面路径与 realpath 都要过白名单），越界直接拒绝，
//  免得把系统其它位置的文件属主改坏。
//
//  限制：这只让文件可写，不会让改过的可执行文件可加载 —— 改 .app 里的 Mach-O
//  会破坏签名，AMFI 会拒绝。改数据文件/资源/plist 是安全的。
//

import Combine
import Foundation
import UIKit
import Darwin

// MARK: - 沙盒写权限探针与修复（blade: SKSandboxKeeper）

final class SandboxKeeper: ObservableObject {
    static let shared = SandboxKeeper()

    /// 特权路径。绝不能用自己的容器：那里始终可写，探针没有意义。
    ///
    /// 两个探针：单一探针可能误判 —— 某些 entitlement / 容器规则会让
    /// /var/mobile/Library/Preferences 在沙盒没逃逸时也能写，于是保活以为一切正常。
    /// 两条路径都在 mobile 自己的可写区域里（属主 mobile），所以任何失败都只可能
    /// 是 MAC（sandbox）拒绝，正是我们要检测的东西。任一路径失败即视为权限丢失。
    static let probeDir   = "/private/var/mobile/Library/Preferences"
    static let probeFile  = "/private/var/mobile/Library/Preferences/.sbxkit_alive"
    static let probeDir2  = "/private/var/mobile/Library"
    static let probeFile2 = "/private/var/mobile/Library/.sbxkit_alive2"

    // ——— 状态（只由 publishState 在主线程写） ———
    @Published private(set) var running = false
    @Published private(set) var repairCount = 0          // 重放成功次数
    @Published private(set) var repairAttempts = 0       // 重放尝试次数
    @Published private(set) var consecutiveFailures = 0  // 连续失败（到 5 停自动修复）
    @Published private(set) var lastProbeErrno: Int32 = 0
    @Published private(set) var lastProbeOK = false
    @Published private(set) var lastEvent: String?
    /// 自动修复开关（blade: autoRepair）。关掉后后台 tick 只报告，不写内核。
    @Published var autoRepair = true

    /// 探测间隔，blade 默认 7 秒，夹在 [3, 60]
    var interval: TimeInterval = 7.0

    private var timer: DispatchSourceTimer?
    private let queue = DispatchQueue(label: "appdump.keeper", qos: .utility)

    /// 探针 errno 的共享槽（探针可能从任意队列进来）
    private static let probeLock = NSLock()
    private static var probeErrnoValue: Int32 = 0

    private init() {}

    // ─────────────────────────────────────────────────────────────
    // MARK: 探针
    // ─────────────────────────────────────────────────────────────

    /// 一次探针：create + write 6 字节 + unlink。
    /// 只 open 不够 —— 读权限可以在写权限已经没了的时候还留着，
    /// 而那正是要检测的失效形态。
    @discardableResult
    static func probe() -> Bool {
        if !probeOne(probeFile) { return false }
        if !probeOne(probeFile2) { return false }
        setProbeErrno(0)
        return true
    }

    /// 单条探针：create + write + unlink。
    ///
    /// ★ 必须先 unlink 再 open ★（照搬 FilzaJailedDS / Blade）
    /// open(O_CREAT) 碰到已存在的文件时，需要的是**文件本身**的写权限，而不只是
    /// 目录的；而这里只在成功时才 unlink。上一次跑到一半死掉、或文件被别的属主
    /// 占住，之后每次探针都会失败，逃逸本身却是好的 —— 表现为「永远修不好」。
    private static func probeOne(_ path: String) -> Bool {
        unlink(path)

        errno = 0
        let fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0o600)
        if fd < 0 {
            setProbeErrno(errno)
            return false
        }
        var e: Int32 = 0
        let marker = Array("alive\n".utf8)          // 6 字节
        let n = marker.withUnsafeBytes { write(fd, $0.baseAddress, marker.count) }
        if n != marker.count { e = errno } else { e = 0 }
        close(fd)
        unlink(path)
        if n != marker.count {
            setProbeErrno(e)
            return false
        }
        return true
    }

    /// 当前是否真的有特权写权限（只读检查，不写内核）
    static func hasPrivilegedWriteAccess() -> Bool { probe() }

    /// 上次探针失败的 errno（blade: writeAccessProbeErrno）
    static var writeAccessProbeErrno: Int32 {
        probeLock.lock(); defer { probeLock.unlock() }
        return probeErrnoValue
    }

    private static func setProbeErrno(_ e: Int32) {
        probeLock.lock(); probeErrnoValue = e; probeLock.unlock()
    }

    // ─────────────────────────────────────────────────────────────
    // MARK: 修复
    // ─────────────────────────────────────────────────────────────

    /// 探针通过就 true；否则重放一次逃逸再看。
    /// 文件操作失败前调用：策略是易失的，一分钟前还能 unlink 的路径现在可能
    /// 就 EPERM 了，而文件本身什么都没变。
    @discardableResult
    func ensureWriteAccess() -> Bool {
        if SandboxKeeper.hasPrivilegedWriteAccess() { return true }
        return tick()
    }

    /// 后台一次：探针 → 丢了就重放 sbx_escape。返回调用后写权限是否在。
    @discardableResult
    func tick() -> Bool {
        guard ds_is_ready() else { return false }

        let lost = !SandboxKeeper.probe()
        let e = SandboxKeeper.writeAccessProbeErrno

        if !lost {
            publishState(probeOK: true, errno: 0)
            if reportedLost { reportedLost = false }
            return true
        }

        publishState(probeOK: false, errno: e)

        if !reportedLost {
            reportedLost = true
            emit("keeper: write access lost (probe errno=\(e) \(SandboxKeeper.strerror(e)))")
        }

        guard autoRepair else {
            emit("keeper: write access lost; auto-repair is OFF — tap repair to attempt it")
            return false
        }

        // 连续失败到上限就停手：在坏状态上无止境地写内核只会更糟。
        if failures >= 5 {
            autoRepair = false
            emit("keeper: write access lost, and \(failures) automatic repairs failed in a row — stopping auto-repair (避免在坏状态上反复写内核)")
            return false
        }

        attempts += 1
        publishState(attempts: attempts)
        let rc = SandboxKeeper.reapplyEscape()
        if rc != 0 {
            failures += 1
            publishState(failures: failures)
            emit("keeper: sbx_escape rc=\(rc); retry next tick")
            return false
        }

        repairs += 1
        let ok = SandboxKeeper.probe()
        let e2 = ok ? 0 : SandboxKeeper.writeAccessProbeErrno
        if ok { failures = 0 }
        reportedLost = !ok
        publishState(repairs: repairs, failures: failures, probeOK: ok, errno: e2)
        emit("keeper: re-apply ok, probe=\(ok ? "pass" : "fail"), repair #\(repairs)")
        return ok
    }

    /// 手动「修复写权限」（blade: repair 菜单 / -[MainViewController repairWriteAccess]）。
    /// 与后台 tick 的区别：不受 autoRepair 与失败上限限制，并把原因写清楚。
    @discardableResult
    func repairNow() -> Bool {
        guard ds_is_ready() else {
            emit("repair: ds_is_ready=0 — exploit not running")
            return false
        }

        let before = SandboxKeeper.probe()
        attempts += 1
        let rc = SandboxKeeper.reapplyEscape()
        let after = SandboxKeeper.probe()

        if rc != 0 {
            failures += 1
            emit("repair: sbx_escape rc=\(rc); write access not restored")
        } else {
            repairs += 1
            if after {
                failures = 0
                autoRepair = true
                reportedLost = false
            } else {
                failures += 1
                let e = SandboxKeeper.writeAccessProbeErrno
                emit("repair: probe=fail errno=\(e) (\(SandboxKeeper.strerror(e))), repair #\(repairs) — sbx_escape 返回 0 但策略没生效")
            }
        }

        publishState(repairs: repairs, attempts: attempts,
                     failures: failures,
                     probeOK: after,
                     errno: after ? 0 : SandboxKeeper.writeAccessProbeErrno)
        emit("repair: probe before=\(before ? 1 : 0) after=\(after ? 1 : 0)")
        return after
    }

    /// 文件操作后发现写权限被内核冲掉时调用（blade: restoreIfLost:）。
    /// 返回 true 表示可以重试该操作。
    @discardableResult
    func restoreIfLost(_ label: String) -> Bool {
        guard ds_is_ready() else { return false }
        if SandboxKeeper.hasPrivilegedWriteAccess() { return true }

        let e = SandboxKeeper.writeAccessProbeErrno
        let ok = repairNow()
        emit("keeper: \(label) 之后写权限被内核冲掉(probe errno=\(e) \(SandboxKeeper.strerror(e)))，自动重放逃逸: \(ok ? "已恢复" : "失败")")
        return ok
    }

    /// 只做一次内核写：重放沙盒策略（blade: sbx_escape(proc)）。
    /// sbx_escape() 每次都从内核重新读 proc → proc_ro → ucred → cr_label →
    /// sandbox → ext_set，内核重建过的结构也能接住，不会用到缓存。
    /// 它读写内核内存，必须和其它原语用户（砸壳、扫描、属主遍历）互斥。
    private static func reapplyEscape() -> Int32 {
        var proc = ds_get_our_proc()
        if proc == 0 { proc = ourproc() }
        if proc == 0 { return -1 }
        AppDumpKernelLockAcquire()
        let rc = sbx_escape(proc)
        AppDumpKernelLockRelease()
        return rc
    }

    static func strerror(_ e: Int32) -> String {
        guard let c = Darwin.strerror(e) else { return "errno \(e)" }
        return String(cString: c)
    }

    // ─────────────────────────────────────────────────────────────
    // MARK: 状态与生命周期
    // ─────────────────────────────────────────────────────────────

    private var repairs = 0
    private var attempts = 0
    private var failures = 0
    private var reportedLost = false

    private func publishState(repairs: Int? = nil, attempts: Int? = nil,
                              failures: Int? = nil, probeOK: Bool? = nil,
                              errno: Int32? = nil) {
        let apply = {
            if let v = repairs { self.repairCount = v }
            if let v = attempts { self.repairAttempts = v }
            if let v = failures { self.consecutiveFailures = v }
            if let v = probeOK { self.lastProbeOK = v }
            if let v = errno { self.lastProbeErrno = v }
        }
        if Thread.isMainThread { apply() } else { DispatchQueue.main.async(execute: apply) }
    }

    func start() {
        guard !running else { return }

        // ★ 不再因为「原语没就绪」就放弃启动 ★
        // 旧代码这里是 guard ds_is_ready() else { return }，是致命的：如果启动时
        // exploit 还没跑完（或者第一次逃逸失败），保活就永远不会被装上，之后
        // 权限一掉就再也没人修。现在定时器无条件装上，tick 内部自己判。
        if !ds_is_ready() {
            emit("started anyway (kernel primitive not up yet — tick will retry)")
        }

        var iv = interval
        if iv < 3 { iv = 3 }
        if iv > 60 { iv = 60 }

        let t = DispatchSource.makeTimerSource(queue: queue)
        t.schedule(deadline: .now() + iv, repeating: iv, leeway: .seconds(1))
        t.setEventHandler { [weak self] in self?.tick() }
        t.resume()
        timer = t
        running = true
        emit("started (every \(Int(iv))s)")

        // ★ 回前台立刻补一次 ★
        // 进程被挂起时 dispatch timer 不会走，用户切回来那段时间权限是掉的，
        // 等下一个 7 秒 tick 才恢复，表现就是「权限掉了不会自己恢复」。
        let nc = NotificationCenter.default
        observers.append(nc.addObserver(forName: UIApplication.willEnterForegroundNotification,
                                        object: nil, queue: nil) { [weak self] _ in
            self?.recoverNow()
        })
        observers.append(nc.addObserver(forName: UIApplication.didBecomeActiveNotification,
                                        object: nil, queue: nil) { [weak self] _ in
            self?.recoverNow()
        })
    }

    func stop() {
        guard running else { return }
        timer?.cancel()
        timer = nil
        for o in observers { NotificationCenter.default.removeObserver(o) }
        observers.removeAll()
        running = false
        emit("stopped")
    }

    /// 立刻异步补一次检测/修补（回前台 / 首次启动 / 遇到权限错误时调）。
    func recoverNow() {
        queue.async { [weak self] in _ = self?.tick() }
    }

    private var observers: [NSObjectProtocol] = []

    /// 一条消息两个出口：日志和界面显示同一句话，否则事后对不上。
    private func emit(_ msg: String) {
        AppDumpmgr.shared.logmsg("[keeper] \(msg)")
        if Thread.isMainThread {
            self.lastEvent = msg
        } else {
            DispatchQueue.main.async { self.lastEvent = msg }
        }
    }
}

// MARK: - 落盘之后

extension SandboxKeeper {
    /// 每次真实落盘（写/删/改名/复制）之后调。
    ///
    /// 逃逸改的是内存里的 sandbox 扩展表，内核每处理一次真实落盘就会按磁盘上的
    /// profile 重推，把我们改的那份换回去 —— 也就是说「写一个文件权限必掉」是常态，
    /// 不是偶发。只靠 7 秒轮询意味着每次写完都有几秒到几十秒的空窗，用户在这段
    /// 时间里点什么都 EPERM。所以在每个落盘 API 之后立刻探一次、丢了就重放；
    /// 探针通过时是零内核写（两个 create+write+unlink）。
    static func afterDiskWrite(_ label: String) {
        guard ds_is_ready() else { return }
        _ = SandboxKeeper.shared.restoreIfLost(label)
    }
}

// MARK: - 容器属主（blade: SKKernelTakeOwnership / apfs own_tree）

enum WritePerm {
    static let targetUID: uid_t = 501
    static let targetGID: gid_t = 501

    private static let maxEntries = 200_000
    private static let maxDepth = 48

    private static let fixSeenLock = NSLock()
    private static var fixSeen = Set<String>()
    private static let chownedAppsLock = NSLock()
    private static var chownedApps = Set<String>()
    private static let chownQueue = DispatchQueue(label: "appdump.chown", qos: .utility)

    /// 内核改属主只允许在 /var 下（字面值与 realpath 都要过白名单）。
    static func allowsModify(_ path: String) -> Bool {
        let prefixes = ["/var", "/private/var"]
        func ok(_ s: String) -> Bool {
            for p in prefixes where s == p || s.hasPrefix(p + "/") { return true }
            return false
        }
        guard ok(path) else { return false }
        // 软链接可以指到任何地方：realpath 之后必须仍在 /var 下
        if let rp = realpath(path, nil) {
            defer { free(rp) }
            return ok(String(cString: rp))
        }
        return true
    }

    /// 单个路径：内核里把属主改成 501:501 并补上 owner 读写位。
    /// 已经是 501 且 owner 可写就直接返回（常见快路径）。
    @discardableResult
    static func kernelTakeOwnership(_ path: String, uid: uid_t = targetUID, gid: gid_t = targetGID) -> Bool {
        guard ds_is_ready(), !path.isEmpty else { return false }
        guard allowsModify(path) else {
            AppDumpmgr.shared.logmsg("[fm] 拒绝内核改属主（路径不在 /var 下）: \(path)")
            return false
        }

        var st = stat()
        guard stat(path, &st) == 0 else { return false }
        let olduid = st.st_uid
        let oldmode = st.st_mode

        if olduid == uid && st.st_gid == gid && (oldmode & S_IWUSR) != 0 { return true }

        AppDumpKernelLockAcquire()
        let rcOwn = path.withCString { apfs_own($0, uid, gid) }
        var rcMod: Int32 = 0
        if rcOwn == 0 && uid == targetUID && gid == targetGID {
            // 只改权限位：apfs_mod 会保留类型位
            let want = mode_t(truncatingIfNeeded: UInt32(oldmode) | UInt32(S_IRUSR) | UInt32(S_IWUSR))
            rcMod = path.withCString { apfs_mod($0, want) }
        }
        AppDumpKernelLockRelease()

        var st2 = stat()
        let ok = stat(path, &st2) == 0 && st2.st_uid == uid && st2.st_gid == gid

        AppDumpmgr.shared.logmsg(String(
            format: "[fm] 内核取得写权限 %@: %@ (uid %u->%u mode %04o->%04o)",
            ok ? "成功" : "失败", path,
            UInt32(olduid), UInt32(uid),
            UInt32(oldmode & 0o7777), UInt32(st2.st_mode & 0o7777)))
        if rcOwn != 0 {
            AppDumpmgr.shared.logmsg("[fm] apfs_own 返回 \(rcOwn): \(path)")
        }
        return ok
    }

    /// 属主修复应该作用在哪个根上：
    ///   /var/containers/Bundle/Application/<UUID>/Foo.app[/...] -> 该 .app
    ///   /var/mobile/Containers/Data/Application/<UUID>[/...]    -> 该数据容器
    ///   /var/mobile/Containers/Shared/AppGroup/<UUID>[/...]     -> 该 group 容器
    static func ownershipRoot(for path: String) -> String? {
        guard !path.isEmpty else { return nil }
        let comps = (path as NSString).pathComponents

        if path.hasPrefix("/var/containers/Bundle/Application/") ||
           path.hasPrefix("/private/var/containers/Bundle/Application/") {
            for (i, c) in comps.enumerated() where c.hasSuffix(".app") {
                return NSString.path(withComponents: Array(comps.prefix(i + 1)))
            }
            return nil
        }

        let containers = [
            "/var/mobile/Containers/Data/Application/",
            "/var/mobile/Containers/Shared/AppGroup/",
        ]
        for p in containers
        where path.hasPrefix(p) || path.hasPrefix("/private" + p) {
            if comps.count >= 8 {
                return NSString.path(withComponents: Array(comps.prefix(7)))
            }
            return nil
        }
        return nil
    }

    // ─────────────────────────────────────────────────────────────
    // MARK: 递归改属主（blade: apfs own_tree）
    // ─────────────────────────────────────────────────────────────

    struct WalkResult {
        var entries = 0     // 成功改成目标属主的项数
        var skipped = 0     // lstat 失败
        var failed = 0      // apfs_own 失败
        var opendirFail = 0
    }

    /// 递归把 root 的属主在内核里改掉。
    /// 跳过 _CodeSignature 与 SC_Info：改属主没有意义，动内容会破坏签名/FairPlay。
    @discardableResult
    static func chownTree(_ root: String, uid: uid_t = targetUID, gid: gid_t = targetGID) -> WalkResult {
        var r = WalkResult()
        walk(root, depth: 0, uid: uid, gid: gid, r: &r)
        AppDumpmgr.shared.logmsg("(apfs) own_tree \(root): \(r.entries) entries (skip lstat=\(r.skipped) chown=\(r.failed) opendir=\(r.opendirFail))")
        return r
    }

    private static func shouldSkip(_ name: String) -> Bool {
        name == "_CodeSignature" || name == "SC_Info"
    }

    private static func walk(_ path: String, depth: Int, uid: uid_t, gid: gid_t, r: inout WalkResult) {
        if depth > maxDepth || r.entries + r.failed > maxEntries { return }

        // lstat：不跟随软链接，行为与 blade 的 C 走查一致
        var st = stat()
        guard lstat(path, &st) == 0 else { r.skipped += 1; return }

        if st.st_uid != uid || st.st_gid != gid {
            AppDumpKernelLockAcquire()
            let rc = path.withCString { apfs_own($0, uid, gid) }
            AppDumpKernelLockRelease()
            if rc == 0 { r.entries += 1 } else { r.failed += 1 }
        } else {
            r.entries += 1
        }

        guard (st.st_mode & S_IFMT) == S_IFDIR else { return }

        guard let d = opendir(path) else { r.opendirFail += 1; return }
        defer { closedir(d) }
        while let ent = readdir(d) {
            let name = withUnsafeBytes(of: ent.pointee.d_name) { raw -> String in
                String(cString: raw.baseAddress!.assumingMemoryBound(to: CChar.self))
            }
            if name == "." || name == ".." { continue }
            if shouldSkip(name) { continue }
            walk(path + "/" + name, depth: depth + 1, uid: uid, gid: gid, r: &r)
            if r.entries + r.failed > maxEntries { return }
        }
    }

    // ─────────────────────────────────────────────────────────────
    // MARK: 文件操作入口
    // ─────────────────────────────────────────────────────────────

    /// 写之前保证有权限：容器里先把属主改成 mobile（父目录不是我们的才做），
    /// 再确认沙盒策略还在（不在就重放）。blade: SKEnsureWriteAccess。
    @discardableResult
    static func ensureWriteAccess(_ path: String) -> Bool {
        if let root = ownershipRoot(for: path), ds_is_ready() {
            // create/delete/rename 由**父目录**的属主决定，不是目标文件本身。
            // 只看目标文件会漏掉「刚建的、已经属于我们」的情况，然后 unlink
            // 依旧 EACCES。
            let dir = (path as NSString).deletingLastPathComponent
            var st = stat()
            let parentOurs = !dir.isEmpty && stat(dir, &st) == 0 && st.st_uid == targetUID
            if !parentOurs {
                AppDumpmgr.shared.logmsg("[fm] 写操作需要属主修复，父目录=\(dir)")
                _ = chownTree(root)
            }
        }
        return SandboxKeeper.shared.ensureWriteAccess()
    }

    /// 后台整树修一次（每个根每次启动只跑一次）。blade: SKOwnershipFixAsync
    static func fixAsync(_ path: String) {
        guard let root = ownershipRoot(for: path), ds_is_ready() else { return }

        fixSeenLock.lock()
        let already = fixSeen.contains(root)
        if !already { fixSeen.insert(root) }
        fixSeenLock.unlock()
        guard !already else { return }

        AppDumpmgr.shared.logmsg("后台整树取得写权限: \(root)")
        DispatchQueue.global(qos: .utility).async {
            _ = chownTree(root)
        }
    }

    /// 应用包/数据容器一次性取得写权限（blade: SKEnsureAppChowned，去重 + 串行队列）
    static func ensureAppChowned(_ appPath: String) {
        guard let root = ownershipRoot(for: appPath) else { return }
        chownQueue.async {
            chownedAppsLock.lock()
            let already = chownedApps.contains(root)
            if !already { chownedApps.insert(root) }
            chownedAppsLock.unlock()
            guard !already else { return }
            _ = chownTree(root)
        }
    }
}
