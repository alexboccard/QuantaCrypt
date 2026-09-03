import SwiftUI

struct SettingsView: View {
    @Environment(AppState.self) private var state
    @AppStorage(HelperLocator.overrideDefaultsKey) private var helperPath = ""
    @AppStorage("defaultOutputFolder") private var outputFolder = ""
    @State private var clearedRecent = false

    var body: some View {
        Form {
            Section("Encryption helper") {
                LabeledContent("Helper path") {
                    HStack {
                        TextField("Automatic", text: $helperPath)
                            .textFieldStyle(.roundedBorder)
                            .frame(minWidth: 260)
                        Button("Choose…") {
                            if let url = Panels.chooseFile(types: [.unixExecutable, .executable, .item],
                                                           message: "Choose the qc-core helper.") {
                                helperPath = url.path
                            }
                        }
                    }
                }
                LabeledContent("In use") {
                    Text(resolvedDescription)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .lineLimit(2)
                        .truncationMode(.middle)
                }
                Button("Restart helper") { state.restartHelper() }
                Text("Leave the path empty to use the helper bundled with QuantaCrypt. Restart the helper after changing it.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }

            Section("Output") {
                LabeledContent("Default output folder") {
                    HStack {
                        Text(outputFolder.isEmpty ? "Same folder as the original" : Format.tildePath(outputFolder))
                            .foregroundStyle(outputFolder.isEmpty ? .secondary : .primary)
                            .lineLimit(1)
                            .truncationMode(.middle)
                        Button("Choose…") {
                            if let url = Panels.chooseFolder(message: "Choose where encrypted and decrypted files go by default.") {
                                outputFolder = url.path
                            }
                        }
                        if !outputFolder.isEmpty {
                            Button("Use original folder") { outputFolder = "" }
                        }
                    }
                }
            }

            Section("Recent files") {
                HStack {
                    Button("Clear recent files") {
                        state.recents.clear()
                        clearedRecent = true
                    }
                    .disabled(state.recents.isEmpty)
                    if clearedRecent && state.recents.isEmpty {
                        Text("Cleared").foregroundStyle(.secondary)
                    }
                }
            }
        }
        .formStyle(.grouped)
        // minWidth, not width: at accessibility text sizes a fixed 560 clips
        // the path row instead of letting the window grow.
        .frame(minWidth: 560)
        .fixedSize(horizontal: false, vertical: true)
    }

    private var resolvedDescription: String {
        let resolution = HelperLocator.resolve(override: helperPath)
        if let launch = resolution.launch {
            let args = launch.arguments.isEmpty ? "" : " " + launch.arguments.joined(separator: " ")
            return "\(launch.displayPath)\(args) (\(launch.origin))"
        }
        return "Not found — searched \(resolution.searched.count) locations."
    }
}
