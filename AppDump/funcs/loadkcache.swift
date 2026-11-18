//
//  loadkcache.swift
//  AppDump
//
//  内核缓存的"用缓存优先"入口。
//
//  你的设备上 SBX 是红的，所以走 /private/preboot 的 fetchkcache() 那套会失败。
//  但内核缓存其实之前已经被旧版软件取到 Documents/kernelcache 里了 ——
//  dlkcache() 本来就是"文件存在就用缓存、不存在才下载"。
//
//  这里把它包一层：只要 Documents/kernelcache 在，就直接用它，
//  完全不碰 preboot、也不下载；只有文件真的没了才尝试别的路。
//

import Foundation

/// 优先使用已缓存的内核缓存（Documents/kernelcache）。
/// - Returns: 是否能解析出 offset（决定 mgr.hasOffsets）。
func loadkernelcache() -> Bool {
    let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first
    let kc = docs?.appendingPathComponent("kernelcache").path

    if let kc, FileManager.default.fileExists(atPath: kc) {
        globallogger.log("(kc) cached kernelcache present, using it (no preboot / no download)")
        return dlkcache()          // 内部走 "using cached kernelcache" -> resolvekernoffsets
    }

    // 没有缓存才尝试 preboot 拉取；拉不到再让 dlkcache 兜底下载
    globallogger.log("(kc) no cached kernelcache, trying preboot fetch then fallback")
    _ = fetchkcache()
    return dlkcache()
}
