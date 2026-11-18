//
//  Theme.swift
//  AppDump
//
//  极简主题：纯色背景 + 纯色卡片。
//
//  这里刻意**不使用** `.ultraThinMaterial` 之类的实时毛玻璃，也不用渐变：
//  实时模糊在列表频繁刷新（砸壳进度、日志流）时会不断重建 backdrop，
//  在内存已经很紧张的大包砸壳过程中是额外的负担。纯色填充零成本。
//

import SwiftUI
import UIKit

enum AppTheme {
    /// 卡片圆角
    static let cornerRadius: CGFloat = 14

    /// 卡片填充（跟随系统亮/暗）
    static var cardFill: Color {
        Color(uiColor: .secondarySystemGroupedBackground)
    }

    /// 页面背景（跟随系统亮/暗，纯色，无渐变）
    static var background: some View {
        Color(uiColor: .systemGroupedBackground)
            .ignoresSafeArea()
    }
}

extension View {
    /// 卡片：纯色底 + 一条细边，不用材质模糊
    func glassCard(cornerRadius: CGFloat = AppTheme.cornerRadius) -> some View {
        self
            .background(
                RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                    .fill(AppTheme.cardFill)
            )
            .overlay(
                RoundedRectangle(cornerRadius: cornerRadius, style: .continuous)
                    .strokeBorder(Color.primary.opacity(0.06), lineWidth: 0.5)
            )
    }

    /// List 透明化 + 纯色背景
    func themedBackground() -> some View {
        self
            .scrollContentBackground(.hidden)
            .background(AppTheme.background)
    }
}
