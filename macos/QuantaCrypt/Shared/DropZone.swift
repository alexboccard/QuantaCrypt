import SwiftUI
import UniformTypeIdentifiers

/// Dashed drop target that also offers the equivalent open panel.
struct DropZone: View {
    let title: String
    let subtitle: String
    let systemImage: String
    let chooseTitle: String
    let onChoose: () -> Void
    let accepts: (URL) -> Bool
    let onDrop: (URL) -> Void

    @State private var isTargeted = false

    var body: some View {
        VStack(spacing: 10) {
            Image(systemName: systemImage)
                .font(.largeTitle)
                .foregroundStyle(.secondary)
                .accessibilityHidden(true)
            Text(title)
                .font(.headline)
            Text(subtitle)
                .font(.callout)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.center)
            Button(chooseTitle, action: onChoose)
                .padding(.top, 4)
                .accessibilityHint("You can also drag a file onto this area.")
        }
        .frame(maxWidth: .infinity)
        .padding(24)
        .background(isTargeted ? Color.accentColor.opacity(0.12) : Color.clear,
                    in: RoundedRectangle(cornerRadius: 10))
        .overlay {
            RoundedRectangle(cornerRadius: 10)
                .strokeBorder(style: StrokeStyle(lineWidth: 1, dash: [6, 4]))
                .foregroundStyle(isTargeted ? Color.accentColor : Color.secondary)
        }
        .contentShape(RoundedRectangle(cornerRadius: 10))
        .dropDestination(for: URL.self) { urls, _ in
            guard let url = urls.first(where: accepts) else { return false }
            onDrop(url)
            return true
        } isTargeted: { isTargeted = $0 }
        // `.contain`, never `.combine`: combining swallows the Choose button,
        // which is the only control that starts the task on this screen.
        .accessibilityElement(children: .contain)
        .accessibilityLabel(title)
    }
}

/// A picked file or folder, with a swap button.
struct PathRow: View {
    let path: String
    let detail: String?
    let systemImage: String
    let changeTitle: String
    /// Distinct VoiceOver name — several rows on one screen all say "Change…".
    var changeLabel: String? = nil
    let onChange: () -> Void

    var body: some View {
        HStack(alignment: .firstTextBaseline) {
            Label {
                VStack(alignment: .leading, spacing: 2) {
                    Text(Format.fileName(path))
                        .font(.body.weight(.medium))
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Text(detail ?? Format.tildePath(Format.directory(path)))
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                        .textSelection(.enabled)
                }
            } icon: {
                Image(systemName: systemImage)
                    .foregroundStyle(.secondary)
            }
            Spacer()
            Button(changeTitle, action: onChange)
                .accessibilityLabel(changeLabel ?? changeTitle)
        }
    }
}
