import SwiftUI

@main
struct QuantaCryptApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate

    var body: some Scene {
        // `Window`, not `WindowGroup`: every window would be bound to the one
        // AppState the delegate owns, so opening a document from Finder used
        // to spawn a mirror of the window you already had.
        Window("QuantaCrypt", id: "main") {
            ContentView()
                .environment(delegate.state)
                .frame(minWidth: 720, minHeight: 520)
        }
        .defaultSize(width: 900, height: 620)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("Open…") { delegate.state.openDocument() }
                    .keyboardShortcut("o")
                // The sidebar's Recent rows are mouse-only by nature; this is
                // where a keyboard user looks for them anyway.
                OpenRecentMenu(state: delegate.state)
                Divider()
                // Shift-modified throughout: bare ⌘M is Window ▸ Minimize and
                // ⌘D/⌘E are taken by system text and dialog conventions.
                Button("Encrypt File…") { delegate.state.encryptFile() }
                    .keyboardShortcut("e", modifiers: [.command, .shift])
                Button("Decrypt…") { delegate.state.decryptFile() }
                    .keyboardShortcut("d", modifiers: [.command, .shift])
                Button("Mount Volume…") { delegate.state.mountVolume() }
                    .keyboardShortcut("m", modifiers: [.command, .shift])
            }
            SidebarCommands()
            CommandGroup(replacing: .help) {
                Button("QuantaCrypt Help") { NSWorkspace.shared.open(AppState.readmeURL) }
            }
        }

        Settings {
            SettingsView()
                .environment(delegate.state)
        }
    }
}

/// File ▸ Open Recent. Reads `state` inside its own body so the menu tracks
/// the store instead of freezing on the list that existed at launch.
private struct OpenRecentMenu: View {
    @Bindable var state: AppState

    var body: some View {
        Menu("Open Recent") {
            ForEach(state.recents.decrypted, id: \.self) { path in
                Button(Format.fileName(path)) { state.open(URL(fileURLWithPath: path)) }
            }
            ForEach(state.recents.mounted, id: \.self) { path in
                Button(Format.fileName(path)) { state.open(URL(fileURLWithPath: path)) }
            }
            Divider()
            // The sidebar row's other two actions live in a context menu,
            // which a keyboard or VoiceOver user cannot open. Same actions,
            // reachable the way every other command in the app is.
            Menu("Show in Finder") {
                recentButtons { path, _ in Finder.reveal(path) }
            }
            Menu("Remove from Recent") {
                recentButtons { path, kind in state.recents.remove(path, kind: kind) }
            }
            Button("Clear Menu") { state.recents.clear() }
                .disabled(state.recents.isEmpty)
        }
        .disabled(state.recents.isEmpty)
    }

    @ViewBuilder
    private func recentButtons(_ action: @escaping (String, RecentStore.Kind) -> Void) -> some View {
        ForEach(state.recents.decrypted, id: \.self) { path in
            Button(Format.fileName(path)) { action(path, .decrypted) }
        }
        ForEach(state.recents.mounted, id: \.self) { path in
            Button(Format.fileName(path)) { action(path, .mounted) }
        }
    }
}
