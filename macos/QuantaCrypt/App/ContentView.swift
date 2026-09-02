import SwiftUI

struct ContentView: View {
    @Environment(AppState.self) private var state

    var body: some View {
        @Bindable var state = state
        NavigationSplitView {
            SidebarView(selection: $state.section)
        } detail: {
            detail
                .navigationTitle(current.title)
        }
        .toolbar {
            ToolbarItem(placement: .status) {
                // Reads the status inside its own body: dependencies read in
                // a toolbar builder closure are not reliably tracked, so the
                // item would stay on its first value.
                HelperStatusView()
            }
        }
    }

    private var current: AppSection { state.section ?? .encrypt }

    @ViewBuilder
    private var detail: some View {
        switch current {
        case .encrypt: EncryptView(model: state.encrypt)
        case .decrypt: DecryptView(model: state.decrypt)
        case .volumes: VolumesView(model: state.volumes)
        }
    }
}

struct SidebarView: View {
    @Binding var selection: AppSection?
    @Environment(AppState.self) private var state

    var body: some View {
        List(selection: $selection) {
            Section {
                ForEach(AppSection.allCases) { section in
                    NavigationLink(value: section) {
                        Label(section.title, systemImage: section.systemImage)
                    }
                }
            }
            if !state.recents.isEmpty {
                Section("Recent") {
                    ForEach(state.recents.decrypted, id: \.self) { path in
                        recentRow(path, systemImage: "doc.badge.ellipsis", kind: .decrypted)
                    }
                    ForEach(state.recents.mounted, id: \.self) { path in
                        recentRow(path, systemImage: "externaldrive.badge.checkmark", kind: .mounted)
                    }
                }
            }
        }
        .listStyle(.sidebar)
        .navigationSplitViewColumnWidth(min: 180, ideal: 210, max: 280)
    }

    private func recentRow(_ path: String, systemImage: String, kind: RecentStore.Kind) -> some View {
        Button {
            state.open(URL(fileURLWithPath: path))
        } label: {
            Label {
                Text(Format.fileName(path))
                    .lineLimit(1)
                    .truncationMode(.middle)
            } icon: {
                Image(systemName: systemImage)
            }
        }
        .buttonStyle(.plain)
        .help(Format.tildePath(path))
        .contextMenu {
            Button("Show in Finder") { Finder.reveal(path) }
            Button("Remove from Recent") { state.recents.remove(path, kind: kind) }
        }
    }
}

struct HelperStatusView: View {
    @Environment(AppState.self) private var state
    private var status: HelperStatus { state.helperStatus }

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: "circle.fill")
                .font(.system(size: 8))
                .foregroundStyle(color)
            Text(text)
                .font(.callout)
                .foregroundStyle(.secondary)
        }
        .help(help)
        .accessibilityElement(children: .combine)
    }

    private var color: Color {
        switch status {
        case .starting: return .orange
        case .ready: return .green
        case .failed: return .red
        }
    }

    private var text: String {
        switch status {
        case .starting: return "Starting helper…"
        case .ready(let info): return "Core \(info.version)"
        case .failed: return "Helper unavailable"
        }
    }

    private var help: String {
        switch status {
        case .starting: return "The encryption helper is starting."
        case .ready(let info): return "qc-core \(info.version), file format \(info.formatVersion)"
        case .failed(let error): return error.message
        }
    }
}
