//
//  MemoryEditorView.swift
//  AppDump
//
//  用 SwiftUI 包住 ObjC 的内存编辑器（SKMemoryEditorViewController），
//  从进程管理的「修改内存」进入。编辑器自带「转到地址 / 清空」导航项，
//  这里不额外加按钮，直接下滑关闭 sheet。
//

import SwiftUI
import UIKit

struct MemoryEditorView: UIViewControllerRepresentable {
    let pid: pid_t
    let name: String

    func makeUIViewController(context: Context) -> UINavigationController {
        let editor = SKMemoryEditorViewController(pid: pid, processName: name)
        return UINavigationController(rootViewController: editor)
    }

    func updateUIViewController(_ uiViewController: UINavigationController, context: Context) {}
}