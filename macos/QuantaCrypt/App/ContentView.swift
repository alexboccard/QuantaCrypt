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
        .safeAreaInset(edge: .bottom) {
            VStack(spacing: 0) {
                if let warning = state.integrityWarning {
                    IntegrityWarningBar(text: warning)
                }
                if let note = state.openNote {
                    OpenNoteBar(note: note)
                }
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
    @State private var hoveredRecent: String?

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

    /// These are actions, not navigation destinations, so they stay buttons
    /// rather than joining the list's selection — arrowing onto a row must
    /// not open a file. They get an explicit hover highlight (a `.plain`
    /// button in a sidebar has none, which made them read as dead text), and
    /// File ▸ Open Recent carries the same list for keyboard users.
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
            .frame(maxWidth: .infinity, alignment: .leading)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .listRowBackground(
            RoundedRectangle(cornerRadius: 6)
                .fill(hoveredRecent == path ? Color.secondary.opacity(0.15) : Color.clear)
        )
        .onHover { inside in
            if inside { hoveredRecent = path } else if hoveredRecent == path { hoveredRecent = nil }
        }
        .help(Format.tildePath(path))
        .accessibilityHint("Opens \(Format.tildePath(path))")
        .contextMenu {
            Button("Show in Finder") { Finder.reveal(path) }
            Button("Remove from Recent") { state.recents.remove(path, kind: kind) }
        }
    }
}

/// One-line banner for a document that could not be opened because the
/// section it belongs to was busy.
///
/// Two shapes: while the job runs it says to wait; once the job is done it
/// offers the document again. Previously it said "finish the current job"
/// forever, about a job that had already finished, and the document was
/// dropped.
struct OpenNoteBar: View {
    @Environment(AppState.self) private var state
    let note: AppState.OpenNote

    private var stillBusy: Bool { state.isBusy(note.section) }

    var body: some View {
        HStack(spacing: 10) {
            Label(stillBusy ? note.text : "Ready to open \(Format.fileName(note.url.path)).",
                  systemImage: stillBusy ? "hourglass" : "checkmark.circle")
                .font(.callout)
                .lineLimit(2)
                .truncationMode(.middle)
            Spacer()
            if stillBusy {
                if state.section != note.section {
                    Button("Show \(note.section.title)") { state.section = note.section }
                        .controlSize(.small)
                }
            } else {
                Button("Open \(Format.fileName(note.url.path))") { state.open(note.url) }
                    .controlSize(.small)
            }
            Button("Dismiss") { state.openNote = nil }
                .controlSize(.small)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
        .background(.bar)
        .accessibilityElement(children: .contain)
    }
}

/// The app's own signature — nested helper included — failed to verify at
/// launch. A strip, not a modal: an unsigned development build trips it on
/// every launch, and the user who can act on it needs the words, not a
/// door in their way.
struct IntegrityWarningBar: View {
    @Environment(AppState.self) private var state
    let text: String

    var body: some View {
        HStack(spacing: 10) {
            Label(text, systemImage: "exclamationmark.shield")
                .font(.callout)
                .foregroundStyle(.orange)
                .lineLimit(3)
                .fixedSize(horizontal: false, vertical: true)
            Spacer()
            Button("Dismiss") { state.integrityWarning = nil }
                .controlSize(.small)
        }
        .padding(.horizontal, 14)
        .padding(.vertical, 8)
        .background(.bar)
        .accessibilityElement(children: .contain)
    }
}

/// Health of the encryption helper.
///
/// Quiet when everything works — an 8pt dot and a subsystem version number
/// spent the best square inches of the toolbar telling the user something
/// they could neither read nor act on. Loud, named and actionable when it
/// breaks, which is the only time it matters. State is carried by the symbol
/// and the words; colour is redundant.
struct HelperStatusView: View {
    @Environment(AppState.self) private var state
    private var status: HelperStatus { state.helperStatus }

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: symbol)
                .imageScale(.small)
                .foregroundStyle(tint)
            Text(text)
                .font(.callout)
                .foregroundStyle(isFailed ? .primary : .secondary)
            if isFailed {
                Button("Try again") { state.restartHelper() }
                    .controlSize(.small)
            }
        }
        .help(help)
        .accessibilityElement(children: .contain)
        .accessibilityLabel(text)
    }

    private var isFailed: Bool {
        if case .failed = status { return true }
        return false
    }

    private var symbol: String {
        switch status {
        case .starting: return "clock"
        case .ready: return "checkmark.circle"
        case .failed: return "exclamationmark.triangle.fill"
        }
    }

    private var tint: Color {
        isFailed ? .red : .secondary
    }

    private var text: String {
        switch status {
        case .starting: return "Starting…"
        case .ready: return "Ready"
        case .failed: return "Can't encrypt: helper unavailable"
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
