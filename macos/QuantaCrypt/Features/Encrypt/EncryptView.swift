import SwiftUI

struct EncryptView: View {
    @Bindable var model: EncryptModel

    var body: some View {
        Form {
            sourceSection
            protectionSection
            outputSection
            activitySection
        }
        .formStyle(.grouped)
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button("Encrypt file", systemImage: "lock", action: model.encrypt)
                    .buttonStyle(.borderedProminent)
                    .keyboardShortcut(.return, modifiers: .command)
                    .disabled(!model.canRun)
                    .help(model.validationMessage ?? "Encrypt with the chosen protection (⌘↩)")
            }
        }
        .sheet(item: $model.sharesToShow) { presentation in
            SharesSheet(shares: presentation.shares, context: presentation.context)
        }
        .confirmationDialog("Replace the existing file?", isPresented: $model.confirmReplace, titleVisibility: .visible) {
            Button("Replace file", role: .destructive, action: model.encryptReplacingExisting)
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("\(model.outputPath.map(Format.fileName) ?? "The file") already exists and will be overwritten.")
        }
    }

    private var sourceSection: some View {
        Section("File") {
            if let path = model.sourcePath {
                PathRow(path: path, detail: model.sourceDetail,
                        systemImage: model.sourceIsFolder ? "folder" : "doc",
                        changeTitle: "Change…", onChange: model.chooseSource)
            } else {
                DropZone(title: "Drop a file or folder here",
                         subtitle: "Folders are zipped first, then encrypted as one file.",
                         systemImage: "arrow.down.doc",
                         chooseTitle: "Choose file or folder…",
                         onChoose: model.chooseSource,
                         accepts: { _ in true },
                         onDrop: { model.setSource($0.path) })
            }
        }
    }

    private var protectionSection: some View {
        Section("Protection") {
            Picker("Protect with", selection: $model.mode) {
                ForEach(ProtectionMode.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            .labelsHidden()
            switch model.mode {
            case .password:
                NewPasswordFields(password: $model.password, confirmation: $model.confirmation,
                                  onSubmit: model.encrypt)
            case .splitKey:
                SplitKeyFields(threshold: $model.threshold, total: $model.total)
            }
        }
    }

    private var outputSection: some View {
        Section("Save to") {
            if let output = model.outputPath {
                PathRow(path: output, detail: nil, systemImage: "doc.badge.plus",
                        changeTitle: "Change…", onChange: model.chooseOutput)
            } else {
                Text("Choose a file first.")
                    .foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder
    private var activitySection: some View {
        if model.isRunning || model.error != nil || model.status != nil || model.result != nil {
            Section {
                if model.isRunning {
                    ProgressPanel(progress: model.progress, onCancel: model.cancel)
                }
                if let error = model.error {
                    ErrorPanel(error: error)
                }
                if let status = model.status {
                    StatusNote(text: status)
                }
                if let result = model.result {
                    resultCard(result)
                }
            }
        }
    }

    private func resultCard(_ result: EncryptResult) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Encrypted \(result.filename)")
                        .font(.headline)
                    Text("\(Format.bytes(result.size)) · \(Format.tildePath(result.output))")
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .lineLimit(2)
                        .truncationMode(.middle)
                }
            } icon: {
                Image(systemName: "checkmark.circle.fill")
                    .foregroundStyle(.green)
            }
            if result.mode == "shamir", let k = result.threshold, let n = result.total {
                Text("Any \(k) of the \(n) shares unlock it. Test decrypting with \(k) shares before you hand them out.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Button("Show in Finder") { Finder.reveal(result.output) }
                if result.mode == "shamir", let shares = result.shares, let k = result.threshold, let n = result.total {
                    Button("Show shares again") {
                        model.sharesToShow = SharesPresentation(
                            shares: shares,
                            context: ShareFiles.Context(stem: Format.stem(result.output),
                                                        protectedName: result.filename, k: k, n: n))
                    }
                }
                Button("Encrypt another file", action: model.reset)
            }
        }
        .padding(.vertical, 4)
    }
}
