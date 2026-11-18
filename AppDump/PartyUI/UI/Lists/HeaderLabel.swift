//
//  HeaderLabel.swift
//  PartyUI
//
//  Created by lunginspector on 3/3/26.
//

import SwiftUI

public struct HeaderLabel: View {
    var text: String
    var icon: String
    
    public init(text: String, icon: String) {
        self.text = text
        self.icon = icon
    }
    
    public var body: some View {
        HStack(spacing: 6) {
            Image(systemName: icon)
                .font(.footnote.weight(.semibold))
                .frame(width: 18, alignment: .center)
            Text(text)
                .font(.footnote.weight(.semibold))
                .kerning(0.4)
                .textCase(.uppercase)
        }
        .foregroundStyle(.secondary)
        .padding(.leading, 4)
    }
}
