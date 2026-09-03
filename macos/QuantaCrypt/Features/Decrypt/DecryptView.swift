import SwiftUI

struct DecryptView: View {
    @Bindable var model: DecryptModel

    var body: some View {
        Form {
            fileSection
            if model.info != nil {
                unlockSection
                outputSection
                actionSection
            }
            activitySection
        }
        .formStyle(.grouped)
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                Button("Decrypt file", systemImage: "lock.open", action: model.decrypt)
                    // Not `.borderedProminent`: macOS 26 renders a disabled
                    // prominent toolbar button at full saturation, so it reads
                    // as live. The prominent copy is the inline one, which
                    // dims correctly.
                    .labelStyle(.titleAndIcon)
                    .keyboardShortcut(.return, modifiers: .command)
                    .disabled(!model.canRun)
                    .help(model.validationMessage ?? "Restore the original file (⌘↩)")
            }
        }
        .onChange(of: outcome) { _, new in
            if let new { AccessibilityNotification.Announcement(new).post() }
        }
    }

    private var outcome: String? {
        if let error = model.error { return error.message }
        if let note = model.verifiedNote { return note }
        if let result = model.result { return "Decrypted \(result.filename)." }
        return nil
    }

    @ViewBuilder
    private var actionSection: some View {
        if !model.isRunning {
            Section {
                PrimaryActionRow(title: "Decrypt file", systemImage: "lock.open",
                                 isEnabled: model.canRun, blockedReason: model.validationMessage,
                                 action: model.decrypt)
            }
        }
    }

    private var fileSection: some View {
        Section("Encrypted file") {
            if let path = model.filePath {
                PathRow(path: path, detail: fileDetail, systemImage: "doc.badge.ellipsis",
                        changeTitle: "Change…", changeLabel: "Change the encrypted file",
                        onChange: model.chooseFile)
                if model.verifyPrompt && model.info != nil {
                    StatusNote(text: "Enter the password you just used, then Verify only. Nothing is written.",
                               systemImage: "checkmark.shield")
                }
                if model.inspecting {
                    HStack(spacing: 8) {
                        ProgressView().controlSize(.small)
                        Text("Reading the file…")
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                    .accessibilityElement(children: .combine)
                }
                if let error = model.inspectError {
                    ErrorPanel(error: error)
                    Button("Try again", action: model.retryInspect)
                }
            } else {
                DropZone(title: "Drop an encrypted file here",
                         subtitle: "Files end in .qcx. Anything else is ignored.",
                         systemImage: "arrow.down.doc",
                         chooseTitle: "Choose encrypted file…",
                         onChoose: model.chooseFile,
                         accepts: DecryptModel.accepts,
                         onDrop: { model.load(path: $0.path) })
            }
        }
    }

    private var fileDetail: String? {
        guard let info = model.info else { return nil }
        return "\(Format.bytes(info.size)) · \(info.protectionSummary)"
    }

    @ViewBuilder
    private var unlockSection: some View {
        Section("Unlock") {
            if let info = model.info, info.isSplitKey {
                ShareEntryFields(shares: $model.shares, required: info.threshold, total: info.total,
                                 onLoadFiles: model.loadSharesFromFiles)
            } else {
                SecureField("Password", text: $model.password)
                    .textContentType(.password)
                    .onSubmit(model.decrypt)
            }
            HStack {
                Button("Verify only", action: model.verify)
                    .disabled(!model.canRun)
                Text("Checks that the password or shares are right without writing anything.")
                    .font(.callout)
                    .foregroundStyle(.secondary)
            }
        }
    }

    private var outputSection: some View {
        Section("Save to") {
            PathRow(path: model.outputDir, detail: Format.tildePath(model.outputDir), systemImage: "folder",
                    changeTitle: "Change…", changeLabel: "Change where the decrypted file goes",
                    onChange: model.chooseOutputDir)
        }
    }

    @ViewBuilder
    private var activitySection: some View {
        if model.isRunning || model.error != nil || model.status != nil || model.result != nil || model.verifiedNote != nil {
            Section {
                if model.isRunning {
                    ProgressPanel(progress: model.progress, isCancelling: model.isCancelling,
                                  onCancel: model.cancel)
                }
                if let error = model.error {
                    ErrorPanel(error: error, note: model.errorNote)
                }
                if let status = model.status {
                    StatusNote(text: status)
                }
                if let note = model.verifiedNote {
                    HStack {
                        Label(note, systemImage: "checkmark.seal")
                            .foregroundStyle(.green)
                        Button("Decrypt file now", action: model.decrypt)
                            .disabled(!model.canRun)
                    }
                }
                if let result = model.result {
                    resultCard(result)
                }
            }
        }
    }

    private func resultCard(_ result: DecryptResult) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Label {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Decrypted \(result.filename)")
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
            if result.renamed {
                Text("A file named \(result.filename) already existed there, so this one was saved as \(Format.fileName(result.output)).")
                    .font(.callout)
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Button("Open file") { Finder.open(result.output) }
                Button("Show in Finder") { Finder.reveal(result.output) }
                Button("Decrypt another file", action: model.reset)
            }
        }
        .padding(.vertical, 4)
    }
}
