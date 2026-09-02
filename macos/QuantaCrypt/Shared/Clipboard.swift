import AppKit

/// Pasteboard writes that expire: secrets should not sit in the clipboard.
@MainActor
enum Clipboard {
    static let clearDelay: Duration = .seconds(60)

    static func copy(_ text: String, expiring: Bool = true) {
        let pasteboard = NSPasteboard.general
        pasteboard.clearContents()
        pasteboard.setString(text, forType: .string)
        guard expiring else { return }
        let change = pasteboard.changeCount
        Task {
            try? await Task.sleep(for: clearDelay)
            // Only clear if the user has not copied something else meanwhile.
            if NSPasteboard.general.changeCount == change {
                NSPasteboard.general.clearContents()
            }
        }
    }
}
