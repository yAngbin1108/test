//
//  Logger.swift
//  mowiwewgewawt
//  bacon why would you do that
//  teehee :3
//  yeah yeah teehee all you want 
//
//  I love that you just straight skidded this from jessi lmfao
//  skidding is my specialty.
//
//

import Foundation
import Darwin
import Combine
import SwiftUI

let globallogger = Logger()

class Logger: ObservableObject {
    @Published var logs: [String] = []

    private var lastmessage: String?
    private var repeatCount = 0
    private var lastwasdivider = false
    private var pendingdivider = false
    private var stdoutpipe: Pipe?
    private var panding = ""
    private var ogstdout: Int32 = -1
    private var ogstderr: Int32 = -1
    private var logfileurl: URL?
    private var logfilehandle: FileHandle?
    private let nobullshitkey = "loggernobullshit"
    private let ignoredlogsubstrings = [
        "Faulty glyph",
        "outline detected - replacing with a space/null glyph",
        "Gesture:",
        "tcp_output [",
        "Error Domain=",
        "com.apple.UIKit.dragInitiation",
        "OSLOG",
        "_UISystemGestureGateGestureRecognizer",
        "NSError",
        "UITouch",
        "com.apple",
        "gestureRecognizers",
        "graph: {(",
        "UILongPressGestureRecognizer",
        "UIScrollViewPanGestureRecognizer",
        "UIScrollViewDelayedTouchesBeganGestureRecognizer",
        "_UISwipeActionPanGestureRecognizer",
        "_UISecondaryClickDriverGestureRecognizer",
        "SwiftUI.UIHostingViewDebugLayer",
        "ValueType:",
        "EventType:",
        "AttributeDataLength:",
        "AttributeData:",
        "SenderID:",
        "Timestamp:",
        "TransducerType:",
        "TransducerIndex:",
        "GenerationCount:",
        "WillUpdateMask:",
        "DidUpdateMask:",
        "Pressure:",
        "AuxiliaryPressure:",
        "TiltX:",
        "TiltY:",
        "MajorRadius:",
        "MinorRadius:",
        "Accuracy:",
        "Quality:",
        "Density:",
        "Irregularity:",
        "Range:",
        "Touch:",
        "Events:",
        "ChildEvents:",
        "DisplayIntegrated:",
        "BuiltIn:",
        "EventMask:",
        "ButtonMask:",
        "Flags:",
        "Identity:",
        "Twist:",
        "X:",
        "Y:",
        "Z:",
        "Total Latency:",
        "Timestamp type:",
        "AppDump[",
        "};",
        "NSLayoutConstraint",
        "   \"",
    ]

    init() {
        setuplogfile()
    }

    // 每条日志都在主线程「追加到最后一个条目 + 触发 @Published」，
    // 一个 3 万行的 vfs 刷屏就会把主线程钉死（字符串每次复制、界面每次重排），
    // 表现就是「卡住不动，点取消也没反应」。这里改成批量合并 + 有界裁剪，
    // 文件写入也放到串行后台队列，不再每行 fsync。
    private var uipending: [String] = []
    private var uiflushscheduled = false
    private let filequeue = DispatchQueue(label: "appdump.log.file", qos: .utility)
    private var filepending: [String] = []
    private var fileflushscheduled = false
    private let maxlogentries = 2500
    private let maxentrychars = 16000

    func log(_ message: String) {
        emit(message)
        enqueuefile(message)
        DispatchQueue.main.async {
            self.uipending.append(message)
            if self.uipending.count >= 200 {
                self.flushui()
            } else if !self.uiflushscheduled {
                self.uiflushscheduled = true
                DispatchQueue.main.asyncAfter(deadline: .now() + 0.2) { self.flushui() }
            }
        }
    }

    /// 主线程：把攒下的日志一次性塞进 UI 列表。
    private func flushui() {
        uiflushscheduled = false
        guard !uipending.isEmpty else { return }
        let batch = uipending
        uipending.removeAll(keepingCapacity: true)
        for message in batch { appendui(message) }
        trim()
    }

    private func appendui(_ message: String) {
        let dividersEnabled = !UserDefaults.standard.bool(forKey: self.nobullshitkey)
        if dividersEnabled && self.pendingdivider {
            self.divider()
            self.pendingdivider = false
        } else if !dividersEnabled {
            self.pendingdivider = false
            self.lastwasdivider = false
        }

        if message == self.lastmessage {
            self.repeatCount += 1
            if let lastIndex = self.logs.indices.last {
                self.logs[lastIndex] = "\(message) (\(self.repeatCount + 1)x)"
            }
        } else {
            self.repeatCount = 0
            if dividersEnabled {
                if self.lastwasdivider || self.logs.isEmpty {
                    self.logs.append(message)
                } else {
                    self.logs[self.logs.count - 1] += "\n" + message
                }
            } else {
                self.logs.append(message)
            }
            self.lastmessage = message
        }

        self.lastwasdivider = false
    }

    /// 日志列表有界：条目数、单条目长度都要封顶，否则越滚越慢。
    private func trim() {
        if logs.count > maxlogentries {
            logs.removeFirst(logs.count - maxlogentries)
        }
        if let last = logs.last, last.count > maxentrychars {
            logs[logs.count - 1] = String(last.suffix(maxentrychars))
        }
    }

    private func enqueuefile(_ message: String) {
        filequeue.async {
            self.filepending.append(message)
            if self.filepending.count >= 200 {
                self.flushfile()
            } else if !self.fileflushscheduled {
                self.fileflushscheduled = true
                self.filequeue.asyncAfter(deadline: .now() + 0.5) {
                    self.fileflushscheduled = false
                    self.flushfile()
                }
            }
        }
    }

    private func flushfile() {
        guard !filepending.isEmpty else { return }
        let batch = filepending
        filepending.removeAll(keepingCapacity: true)
        appendtofile(batch)
    }

    func divider() {
        if UserDefaults.standard.bool(forKey: nobullshitkey) { return }
        DispatchQueue.main.async {
            self.lastwasdivider = true
            self.lastmessage = nil
            self.repeatCount = 0
        }
    }
    
    func enclosedlog(_ message: String) {
        if UserDefaults.standard.bool(forKey: nobullshitkey) {
            log(message)
            return
        }
        DispatchQueue.main.async {
            if !self.lastwasdivider && !self.logs.isEmpty {
                self.divider()
            }
            
            if self.lastwasdivider || self.logs.isEmpty {
                self.logs.append(message)
            } else {
                self.logs[self.logs.count - 1] += "\n" + message
            }
            
            self.lastwasdivider = false
            self.pendingdivider = true
        }
    }
    
    func flushdivider() {
        if UserDefaults.standard.bool(forKey: nobullshitkey) { return }
        DispatchQueue.main.async {
            if self.pendingdivider {
                self.divider()
                self.pendingdivider = false
            }
        }
    }

    func clear() {
        DispatchQueue.main.async {
            self.logs.removeAll()
            self.lastwasdivider = false
            self.pendingdivider = false
            self.lastmessage = nil
            self.repeatCount = 0
        }
        if let url = logfileurl {
            try? logfilehandle?.close()
            try? "".write(to: url, atomically: true, encoding: .utf8)
            logfilehandle = try? FileHandle(forWritingTo: url)
        }
    }

    func capture() {
        if stdoutpipe != nil { return }
        reopenlogfileondemand()

        let pipe = Pipe()
        stdoutpipe = pipe

        ogstdout = dup(STDOUT_FILENO)
        ogstderr = dup(STDERR_FILENO)

        setvbuf(stdout, nil, _IOLBF, 0)
        setvbuf(stderr, nil, _IOLBF, 0)

        dup2(pipe.fileHandleForWriting.fileDescriptor, STDOUT_FILENO)
        dup2(pipe.fileHandleForWriting.fileDescriptor, STDERR_FILENO)

        pipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            let data = handle.availableData
            if data.isEmpty { return }
            guard let chunk = String(data: data, encoding: .utf8), !chunk.isEmpty else { return }
            self?.appendraw(chunk)
        }
    }

    func stopcapture() {
        guard let pipe = stdoutpipe else { return }
        pipe.fileHandleForReading.readabilityHandler = nil

        if ogstdout != -1 {
            dup2(ogstdout, STDOUT_FILENO)
            close(ogstdout)
            ogstdout = -1
        }
        if ogstderr != -1 {
            dup2(ogstderr, STDERR_FILENO)
            close(ogstderr)
            ogstderr = -1
        }

        try? pipe.fileHandleForWriting.close()
        try? pipe.fileHandleForReading.close()
        stdoutpipe = nil

        if let handle = logfilehandle {
            try? handle.synchronize()
            try? handle.close()
            logfilehandle = nil
        }
    }

    private func appendraw(_ chunk: String) {
        var text = panding + chunk
        var lines = text.components(separatedBy: "\n")
        panding = lines.removeLast()
        if !lines.isEmpty {
            let filtered = lines.filter { !shouldignore($0) }
            DispatchQueue.main.async {
                self.logs.append(contentsOf: filtered)
            }
            appendtofile(filtered)
            for line in filtered {
                emit(line)
            }
        }
    }

    private func emit(_ message: String) {
        if shouldignore(message) { return }
        guard ogstdout != -1 else { return }
        let line = message + "\n"
        line.withCString { ptr in
            _ = Darwin.write(ogstdout, ptr, strlen(ptr))
        }
    }

    private func shouldignore(_ message: String) -> Bool {
        let trimmed = message.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            return true
        }
        if isgarbageline(trimmed) {
            return true
        }
        for fragment in ignoredlogsubstrings {
            if message.contains(fragment) {
                return true
            }
        }
        return false
    }

    private func isgarbageline(_ line: String) -> Bool {
        let allowed = CharacterSet(charactersIn: "0123456789-+|*.:(){}[]/\\_ \t")
        if line.unicodeScalars.allSatisfy({ allowed.contains($0) }) {
            return true
        }
        if line == ")}" || line == ")}," || line == ")}))" {
            return true
        }
        return false
    }

    private func setuplogfile() {
        let docs = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask)[0]
        let url = docs.appendingPathComponent("AppDump.log")
        logfileurl = url
        
        if FileManager.default.fileExists(atPath: url.path) {
            try? FileManager.default.removeItem(at: url)
        }
        
        FileManager.default.createFile(atPath: url.path, contents: nil, attributes: [
            FileAttributeKey.protectionKey: FileProtectionType.none
        ])
        
        logfilehandle = try? FileHandle(forWritingTo: url)
        try? logfilehandle?.seekToEnd()
        
        let formatter = DateFormatter()
        formatter.dateFormat = "yyyy-MM-dd HH:mm:ss"
        let separator = "AppDump started: \(formatter.string(from: Date()))"
        self.logs = [separator]
        self.lastwasdivider = true
        
        if let data = (separator + "\n").data(using: .utf8) {
            try? logfilehandle?.write(contentsOf: data)
            try? logfilehandle?.synchronize()
        }
    }

    private func reopenlogfileondemand() {
        if logfilehandle != nil { return }
        guard let url = logfileurl else { return }
        if !FileManager.default.fileExists(atPath: url.path) {
            FileManager.default.createFile(atPath: url.path, contents: nil, attributes: [
                FileAttributeKey.protectionKey: FileProtectionType.none
            ])
        }
        logfilehandle = try? FileHandle(forWritingTo: url)
        try? logfilehandle?.seekToEnd()
    }

    private func appendtofile(_ lines: [String]) {
        guard let handle = logfilehandle else { return }
        let filtered = lines.filter { !shouldignore($0) }
        guard !filtered.isEmpty else { return }
        let text = filtered.joined(separator: "\n") + "\n"
        if let data = text.data(using: .utf8) {
            try? handle.write(contentsOf: data)
            try? handle.synchronize()
        }
    }
}
