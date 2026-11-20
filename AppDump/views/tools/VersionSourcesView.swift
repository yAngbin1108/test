//
//  VersionSourcesView.swift
//  AppDump
//
//  降级用的历史版本来源。每个来源是一个 HTTPS 模板，用 {id} / {appId}
//  代表 App Store 的数字 trackId。多个来源并发查询后合并去重：
//  某一个接口挂了，列表只会少几条，不会整页空白。
//

import SwiftUI

struct VersionSourcesView: View {
    @Environment(\.dismiss) private var dismiss
    @State private var sources: [versionSource] = versionsources.shared.all

    var body: some View {
        List {
            Section {
                ForEach($sources) { $source in
                    row($source)
                }
                .onDelete { indexSet in
                    sources.remove(atOffsets: indexSet)
                    persist()
                }

                Button {
                    sources.append(versionSource(name: "新来源",
                                                 template: "https://example.com/history/{id}",
                                                 enabled: false,
                                                 containerKey: "data"))
                    persist()
                } label: {
                    HStack(spacing: 10) {
                        Image(systemName: "plus.circle.fill").foregroundStyle(.blue)
                        Text("添加来源")
                    }
                }

                Button("恢复默认来源") {
                    versionsources.shared.restoredefaults()
                    sources = versionsources.shared.all
                }
                .foregroundStyle(.orange)
            } header: {
                HeaderLabel(text: "版本来源 \(sources.count)", icon: "point.3.connected.trianglepath.dotted")
            } footer: {
                Text("请求会并发发出，全部返回后再合并去重，所以某个来源失败只会少几条记录。模板必须是 https，并用 {id} 或 {appId} 代表 App Store 的数字 ID。")
            }

            Section {
                Text("返回格式：JSON。默认从 data 数组里读，每条需要有 external_identifier（版本 ID），可选 bundle_version（版本号）、build、created_at（日期）、size（字节）。容器键留空表示根就是数组。")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
            } header: {
                HeaderLabel(text: "格式说明", icon: "doc.text.magnifyingglass")
            }
        }
        .navigationTitle("版本来源")
        .navigationBarTitleDisplayMode(.inline)
        .toolbar {
            ToolbarItem(placement: .navigationBarTrailing) {
                Button("完成") {
                    persist()
                    dismiss()
                }
            }
        }
        .onDisappear { persist() }
    }

    @ViewBuilder
    private func row(_ source: Binding<versionSource>) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack(spacing: 8) {
                Toggle("", isOn: source.enabled)
                    .labelsHidden()
                    .onChange(of: source.wrappedValue.enabled) { _ in persist() }
                TextField("名称", text: source.name)
                    .font(.subheadline.weight(.medium))
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .onSubmit { persist() }
                if !source.wrappedValue.hasplaceholder {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.caption)
                        .foregroundStyle(.orange)
                }
            }

            TextField("https://…/history/{id}", text: source.template)
                .font(.caption.monospaced())
                .textInputAutocapitalization(.never)
                .autocorrectionDisabled()
                .keyboardType(.URL)
                .onSubmit { persist() }

            HStack(spacing: 8) {
                Text("容器键")
                    .font(.caption2)
                    .foregroundStyle(.secondary)
                TextField("data", text: source.containerKey)
                    .font(.caption.monospaced())
                    .textInputAutocapitalization(.never)
                    .autocorrectionDisabled()
                    .onSubmit { persist() }
                Spacer()
                Text(source.wrappedValue.url(for: 0) == nil ? "模板无效" : "模板可用")
                    .font(.caption2)
                    .foregroundStyle(source.wrappedValue.url(for: 0) == nil ? .red : .green)
            }
        }
        .padding(.vertical, 4)
    }

    private func persist() {
        sources = sources.map { item in
            var copy = item
            if copy.name.trimmingCharacters(in: .whitespaces).isEmpty { copy.name = "未命名来源" }
            return copy
        }
        versionsources.shared.replace(sources)
    }
}