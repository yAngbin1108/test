//
//  ProcessListView.swift
//  AppDump
//
//  进程管理入口：用 SwiftUI 包住移植过来的 Objective-C 进程列表
//  （ProcessListViewController），列表里可以查看/结束进程，以及对选中
//  进程做内存搜索、修改、锁定（MemoryEditor）。
//

import SwiftUI
import UIKit

struct ProcessListView: UIViewControllerRepresentable {
    func makeUIViewController(context: Context) -> UINavigationController {
        let root = ProcessListViewController()
        let nav = UINavigationController(rootViewController: root)
        nav.navigationBar.prefersLargeTitles = false
        return nav
    }

    func updateUIViewController(_ uiViewController: UINavigationController, context: Context) {}
}