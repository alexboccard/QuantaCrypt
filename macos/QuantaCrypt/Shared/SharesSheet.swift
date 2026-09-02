import SwiftUI

/// The split-key hand-off: every share with its code and phrase, per-share
/// copy, save-to-files, and the leave-guard when nothing was saved yet.
struct SharesSheet: View {
    let shares: [Share]
    let context: ShareFiles.Context
    var onDismiss: () -> Void = {}

    @Environment(\.dismiss) private var dismiss
    @State private var saved = false
    @State private var savedNote: String?
    @State private var savedLocation: String?
    @State private var saveError: String?
    @State private var showLeaveGuard = false
    @State private var copiedIndex: Int?

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            VStack(alignment: .leading, spacing: 6) {
                Text("Give each person one share")
                    .font(.title2.weight(.semibold))
                Text("Any \(context.k) of these \(context.n) shares unlock \(context.protectedName). Saving to files is what protects you — the clipboard clears in 60 s.")
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(20)

            Divider()

            ScrollView {
                VStack(alignment: .leading, spacing: 14) {
                    ForEach(shares) { share in
                        shareCard(share)
                    }
                }
                .padding(20)
            }

            Divider()

            VStack(alignment: .leading, spacing: 8) {
                if let saveError {
                    Label(saveError, systemImage: "exclamationmark.triangle.fill")
                        .foregroundStyle(.red)
                        .font(.callout)
                }
                if let savedNote {
                    HStack {
                        Label(savedNote, systemImage: "checkmark.circle.fill")
                            .foregroundStyle(.green)
                            .font(.callout)
                        if let savedLocation {
                            Button("Show in Finder") { Finder.reveal(savedLocation) }
                                .controlSize(.small)
                        }
                    }
                }
                HStack {
                    Button("Save share files…", action: saveIndividual)
                    Button("Save combined file…", action: saveCombined)
                    Spacer()
                    Button("Close", action: close)
                        .keyboardShortcut(.cancelAction)
                    Button("I've saved the shares", action: close)
                        .keyboardShortcut(.defaultAction)
                        .buttonStyle(.borderedProminent)
                        .disabled(!saved)
                }
            }
            .padding(20)
        }
        .frame(minWidth: 560, idealWidth: 620, minHeight: 420, idealHeight: 560)
        .interactiveDismissDisabled(!saved)
        .confirmationDialog("Save the shares first", isPresented: $showLeaveGuard, titleVisibility: .visible) {
            Button("Discard shares", role: .destructive) {
                dismiss()
                onDismiss()
            }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("Without them, \(context.protectedName) can never be opened again. Leave and discard the shares?")
        }
    }

    private func shareCard(_ share: Share) -> some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 8) {
                Text(share.code)
                    .font(.callout.monospaced())
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                if let mnemonic = share.mnemonic {
                    Text(mnemonic)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                }
                HStack {
                    Button(copiedIndex == share.index ? "Copied" : "Copy share \(share.index)") {
                        Clipboard.copy(share.code)
                        copiedIndex = share.index
                    }
                    .controlSize(.small)
                    if let mnemonic = share.mnemonic {
                        Button("Copy phrase \(share.index)") {
                            Clipboard.copy(mnemonic)
                            copiedIndex = nil
                        }
                        .controlSize(.small)
                    }
                }
            }
            .frame(maxWidth: .infinity, alignment: .leading)
        } label: {
            Text("Share \(share.index) of \(context.n)")
        }
    }

    private func close() {
        if saved {
            dismiss()
            onDismiss()
        } else {
            showLeaveGuard = true
        }
    }

    private func saveIndividual() {
        guard let folder = Panels.chooseFolder(message: "Choose a folder for the \(context.n) share files.",
                                               prompt: "Save Shares") else { return }
        do {
            let written = try ShareFiles.writeIndividual(shares, context: context, into: folder)
            saved = true
            saveError = nil
            savedNote = "Saved \(written.count) share files to \(Format.tildePath(folder.path))"
            savedLocation = written.first?.path ?? folder.path
        } catch {
            saveError = "Could not write the share files: \(error.localizedDescription) Try a different folder."
        }
    }

    private func saveCombined() {
        guard let url = Panels.save(suggestedName: "\(context.stem).shares.txt", type: .plainText,
                                    message: "Save all \(context.n) shares in one file.") else { return }
        do {
            try ShareFiles.writeCombined(shares, context: context, to: url)
            saved = true
            saveError = nil
            savedNote = "Saved all shares to \(Format.tildePath(url.path))"
            savedLocation = url.path
        } catch {
            saveError = "Could not write the shares file: \(error.localizedDescription) Try a different location."
        }
    }
}
