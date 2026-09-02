import SwiftUI

/// Progress for the running helper request, with a Cancel button.
struct ProgressPanel: View {
    let progress: CoreProgress?
    let onCancel: () -> Void

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 6) {
                Text(progress?.label ?? "Starting…")
                    .font(.body)
                if let pct = progress?.pct {
                    ProgressView(value: min(max(pct, 0), 1))
                } else {
                    ProgressView()
                        .progressViewStyle(.linear)
                }
            }
            Button("Cancel", action: onCancel)
                .keyboardShortcut(.cancelAction)
        }
        .padding(.vertical, 4)
        .accessibilityElement(children: .combine)
    }
}

/// Error from the helper shown inline: cause + next step, details on demand.
struct ErrorPanel: View {
    let error: CoreError
    var note: String? = nil

    @State private var showDetails = false

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Label {
                VStack(alignment: .leading, spacing: 4) {
                    Text(error.message)
                        .fixedSize(horizontal: false, vertical: true)
                        .textSelection(.enabled)
                    if let note {
                        Text(note)
                            .font(.callout)
                            .foregroundStyle(.secondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            } icon: {
                Image(systemName: "exclamationmark.triangle.fill")
                    .foregroundStyle(.red)
            }
            if !error.detail.isEmpty {
                DisclosureGroup("Details", isExpanded: $showDetails) {
                    Text(error.detail)
                        .font(.callout.monospaced())
                        .foregroundStyle(.secondary)
                        .textSelection(.enabled)
                        .fixedSize(horizontal: false, vertical: true)
                        .padding(.top, 2)
                }
                .font(.callout)
            }
        }
        .padding(.vertical, 4)
    }
}

/// Neutral one-line status ("Cancelled — nothing was written.").
struct StatusNote: View {
    let text: String
    var systemImage: String = "info.circle"

    var body: some View {
        Label(text, systemImage: systemImage)
            .foregroundStyle(.secondary)
            .font(.callout)
    }
}

/// Amber strip for a condition the user should know before continuing.
struct WarningStrip: View {
    let text: String

    var body: some View {
        Label(text, systemImage: "exclamationmark.triangle")
            .foregroundStyle(.orange)
            .font(.callout)
            .fixedSize(horizontal: false, vertical: true)
    }
}
