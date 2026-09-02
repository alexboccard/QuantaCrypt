import SwiftUI

@main
struct QuantaCryptApp: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate

    var body: some Scene {
        WindowGroup {
            ContentView()
                .environment(delegate.state)
                .frame(minWidth: 720, minHeight: 520)
        }
        .defaultSize(width: 900, height: 620)
        .commands {
            CommandGroup(replacing: .newItem) {
                Button("Open…") { delegate.state.openDocument() }
                    .keyboardShortcut("o")
                Divider()
                Button("Encrypt File…") { delegate.state.encryptFile() }
                    .keyboardShortcut("e")
                Button("Decrypt…") { delegate.state.decryptFile() }
                    .keyboardShortcut("d")
                Button("Mount Volume…") { delegate.state.mountVolume() }
                    .keyboardShortcut("m")
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
