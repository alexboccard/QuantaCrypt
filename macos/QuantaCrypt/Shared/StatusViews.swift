import SwiftUI

/// Progress for the running helper request, with a Cancel button.
///
/// Cancelling is not instant — the helper has up to `cancelGrace` to answer —
/// so the panel says so and stops the percentage from climbing under a user
/// who already asked it to stop.
struct ProgressPanel: View {
    let progress: CoreProgress?
    var isCancelling: Bool = false
    let onCancel: () -> Void

    var body: some View {
        HStack(alignment: .center, spacing: 12) {
            VStack(alignment: .leading, spacing: 6) {
                Text(label)
                    .font(.body)
                if let pct = progress?.pct, !isCancelling {
                    ProgressView(value: min(max(pct, 0), 1))
                        .accessibilityLabel(label)
                } else {
                    ProgressView()
                        .progressViewStyle(.linear)
                        .accessibilityLabel(label)
                }
            }
            Button("Cancel", action: onCancel)
                .keyboardShortcut(.cancelAction)
                .disabled(isCancelling)
        }
        .padding(.vertical, 4)
        // Deliberately not `.combine`: that swallows Cancel, the only way to
        // abort a running job.
        .accessibilityElement(children: .contain)
    }

    private var label: String {
        isCancelling ? "Cancelling…" : (progress?.label ?? "Starting…")
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

/// The one thing still missing before the primary action can run.
///
/// Lives in the form, not only in the toolbar button's `.help`: a tooltip is
/// invisible to a keyboard or VoiceOver user, and macOS suppresses it on the
/// disabled state the button spends most of its life in.
struct NextStepNote: View {
    let text: String

    var body: some View {
        Label(text, systemImage: "arrow.right.circle")
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }
}

/// The screen's primary action, repeated where the eye ends up — at the
/// bottom of the form. The toolbar item is a shortcut to it, not the only
/// route to it: macOS 26 draws toolbar buttons icon-only, and a disabled
/// prominent one is indistinguishable from an enabled one.
struct PrimaryActionRow: View {
    let title: String
    let systemImage: String
    let isEnabled: Bool
    let blockedReason: String?
    let action: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            Button(title, systemImage: systemImage, action: action)
                .buttonStyle(.borderedProminent)
                .disabled(!isEnabled)
            if let blockedReason, !isEnabled {
                NextStepNote(text: blockedReason)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
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
