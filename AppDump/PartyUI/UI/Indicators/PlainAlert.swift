//
//  PlainAlert.swift
//  PartyUI
//
//  Created by lunginspector on 4/21/26.
//

import SwiftUI

public struct PlainAlert: View {
    var title: String
    var icon: String
    var text: String
    var color: Color
    
    public init(title: String = "", icon: String = "", text: String, color: Color = Color.accentColor) {
        self.title = title
        self.icon = icon
        self.text = text
        self.color = color
    }
    
    public var body: some View {
        HStack(alignment: .top, spacing: 12) {
            if !icon.isEmpty {
                Image(systemName: icon)
                    .font(.body.weight(.semibold))
                    .foregroundStyle(color)
                    .frame(width: 22)
                    .padding(.top, 2)
            }
            VStack(alignment: .leading, spacing: 3) {
                if !title.isEmpty {
                    Text(title)
                        .font(.subheadline.weight(.semibold))
                }
                Text(text)
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 0)
        }
    }
}
