import SwiftUI

struct SettingsView: View {
    @Environment(AppState.self) private var state
    @AppStorage(HelperLocator.overrideDefaultsKey) private var helperPath = ""
    @AppStorage("defaultOutputFolder") private var outputFolder = ""
    @State private var clearedRecent = false
    /// Bumped when the user approves a helper. Approvals live in a static
    /// store, so nothing else would tell this view to re-resolve.
    @State private var approvals = 0
    /// Resolved off the main actor: every candidate — the bundled helper
    /// included — is code-signature-checked, which is ~100 ms for the real
    /// helper, and the path field re-renders this form on every keystroke.
    @State private var resolution = HelperLocator.Resolution(launch: nil, searched: [])

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
                // Everything typed into QuantaCrypt — passwords, shares — is
                // written to this binary's stdin. When it is not the bundled
                // one, that has to be stated where the user cannot miss it;
                // the grey caption that used to sit here read as reassurance.
                if let refusal = resolution.refusal {
                    WarningStrip(text: refusal.reason)
                    if refusal.approvable {
                        Button("Use \(Format.fileName(refusal.path)) anyway") {
                            HelperLocator.approve(refusal.path)
                            approvals += 1
                            state.restartHelper()
                        }
                    }
                } else if let launch = resolution.launch, launch.origin != "bundle" {
                    WarningStrip(text: "QuantaCrypt is using a helper from outside its own app bundle (\(launch.origin)). Everything you type — passwords and shares — is sent to it. Clear the path above to go back to the bundled helper.")
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
        // Re-runs (and cancels the previous run) whenever the id changes.
        .task(id: "\(approvals)|\(helperPath)") {
            let override = helperPath
            let resolved = await Task.detached(priority: .userInitiated) {
                HelperLocator.resolve(override: override)
            }.value
            guard !Task.isCancelled else { return }
            resolution = resolved
        }
    }

    private var resolvedDescription: String {
        if let launch = resolution.launch {
            let args = launch.arguments.isEmpty ? "" : " " + launch.arguments.joined(separator: " ")
            return "\(launch.displayPath)\(args) (\(launch.origin))"
        }
        return "Not found after searching \(resolution.searched.count) locations."
    }
}
