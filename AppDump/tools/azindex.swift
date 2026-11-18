//
//  azindex.swift
//  AppDump
//
//  列表 A-Z（包括特殊符号）快捷操作
//
//  AppsDump3 does this with a UITableView (its binary carries
//  -sectionIndexTitlesForTableView: and -tableView:sectionForSectionIndexTitle:atIndex:).
//  This project is SwiftUI, so the same thing is built from a List plus a
//  right-hand letter strip that drives ScrollViewReader.
//
//  Bucketing goes through UILocalizedIndexedCollation so that Chinese names
//  land under their pinyin initial instead of all piling up under "#";
//  everything the collation cannot place (digits, symbols, emoji) ends up in
//  the trailing "#" section.
//

import SwiftUI
import UIKit

/// UILocalizedIndexedCollation needs an ObjC object + selector to read the string.
final class azkey: NSObject {
    @objc let title: String
    init(_ t: String) {
        title = t
        super.init()
    }
}

enum azsort {
    static let collation = UILocalizedIndexedCollation.current()

    static var titles: [String] { collation.sectionTitles }

    static func index(of name: String) -> Int {
        let t = titles
        guard !t.isEmpty else { return 0 }
        let raw = collation.section(for: azkey(name), collationStringSelector: #selector(getter: azkey.title))
        if raw >= 0 && raw < t.count { return raw }
        return fallbackindex(of: name)
    }

    static func fallbackindex(of name: String) -> Int {
        let t = titles
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let first = trimmed.first else { return max(t.count - 1, 0) }
        let up = String(first).uppercased()
        if up >= "A", up <= "Z", let i = t.firstIndex(of: up) { return i }
        return max(t.count - 1, 0)   // "#" is always the last section title
    }

    static func letter(of name: String) -> String {
        let t = titles
        let i = index(of: name)
        if i >= 0 && i < t.count { return t[i] }
        return "#"
    }
}

struct azgroup<T: Identifiable>: Identifiable {
    let letter: String
    let items: [T]
    var id: String { letter }
}

/// Group + sort `items` into letter buckets, in collation order.
func azgrouped<T: Identifiable>(_ items: [T], name: (T) -> String) -> [azgroup<T>] {
    var buckets: [String: [T]] = [:]
    for it in items {
        buckets[azsort.letter(of: name(it)), default: []].append(it)
    }
    var out: [azgroup<T>] = []
    for letter in azsort.titles {
        if let v = buckets[letter], !v.isEmpty {
            out.append(azgroup(letter: letter, items: v))
            buckets.removeValue(forKey: letter)
        }
    }
    for letter in buckets.keys.sorted() {
        if let v = buckets[letter], !v.isEmpty {
            out.append(azgroup(letter: letter, items: v))
        }
    }
    return out
}

/// 苹果通讯录式字母索引条：按住字母条上下拖动即可滑动列表。
///
/// 关键点（之前"长按没反应"就是这里）：
///   1. 手势用 `.highPriorityGesture`，否则会被外层 List 的滚动手势抢走；
///   2. 用 `DragGesture(minimumDistance: 0)`：手指按下立即响应，
///      按住不放再上下滑，就会连续跳到对应字母（和系统通讯录一致）；
///   3. 命中高亮只换背景色，字体大小 / 行高 / 位置全不变 —— 字母不会偏移；
///   4. 字母之间留 4pt 空隙。
struct azindexbar: View {
    let letters: [String]
    let onjump: (String) -> Void

    @State private var activeIndex: Int?

    private let rowheight: CGFloat = 14
    private let rowspacing: CGFloat = 4

    var body: some View {
        VStack(spacing: rowspacing) {
            ForEach(letters.indices, id: \.self) { i in
                Text(letters[i])
                    .font(.system(size: 11, weight: .semibold))
                    .foregroundColor(activeIndex == i ? Color.white : Color.secondary)
                    .frame(width: 24, height: rowheight)
                    .background(
                        RoundedRectangle(cornerRadius: 7)
                            .fill(activeIndex == i ? Color.accentColor : Color.clear)
                    )
            }
        }
        .contentShape(Rectangle())
        .highPriorityGesture(
            DragGesture(minimumDistance: 0, coordinateSpace: .local)
                .onChanged { value in
                    guard let idx = indexfor(y: value.location.y) else { return }
                    if activeIndex != idx {
                        activeIndex = idx
                        onjump(letters[idx])
                    }
                }
                .onEnded { _ in activeIndex = nil }
        )
        .padding(.vertical, 5)
        .padding(.horizontal, 3)
        .background(Color(uiColor: .secondarySystemGroupedBackground), in: RoundedRectangle(cornerRadius: 9, style: .continuous))
        .overlay(
            RoundedRectangle(cornerRadius: 9, style: .continuous)
                .strokeBorder(Color.white.opacity(0.08), lineWidth: 0.5)
        )
        .padding(.trailing, 4)
    }

    private func indexfor(y: CGFloat) -> Int? {
        guard !letters.isEmpty else { return nil }
        let cell = rowheight + rowspacing
        let raw = Int(y / cell)
        return min(max(raw, 0), letters.count - 1)
    }
}

/// iOS 17+ 才有的 `listSectionSpacing`，这里做个兼容包装：
/// 用来压紧 insetGrouped 列表里「每个字母分组之间」的大空隙，
/// 让列表回到紧凑观感，同时保留按首字母分组的样式。
extension View {
    @ViewBuilder
    func compactsectionlist() -> some View {
        if #available(iOS 17.0, *) {
            self.listSectionSpacing(0)
        } else {
            self
        }
    }

    /// 可指定 section 间距的兼容包装（IPA 管理页需要分组之间的空隙）
    @ViewBuilder
    func sectiongap(_ spacing: CGFloat) -> some View {
        if #available(iOS 17.0, *) {
            self.listSectionSpacing(spacing)
        } else {
            self
        }
    }
}

/// 带字母索引条的列表：长按字母条并上下拖动即可滑动到对应字母分组。
struct azlist<Item: Identifiable, Row: View>: View {
    let items: [Item]
    let title: (Item) -> String
    let row: (Item) -> Row

    init(items: [Item],
         title: @escaping (Item) -> String,
         @ViewBuilder row: @escaping (Item) -> Row) {
        self.items = items
        self.title = title
        self.row = row
    }

    var body: some View {
        let groups = azgrouped(items, name: title)
        ScrollViewReader { proxy in
            ZStack(alignment: .trailing) {
                List {
                    ForEach(groups) { group in
                        Section {
                            ForEach(group.items) { item in
                                row(item)
                            }
                        } header: {
                            Text(group.letter)
                        }
                        .id(group.letter)
                    }
                }
                if groups.count > 1 {
                    azindexbar(letters: groups.map { $0.letter }) { letter in
                        proxy.scrollTo(letter, anchor: .top)   // 不加动画，拖动才跟手
                    }
                }
            }
        }
    }
}
