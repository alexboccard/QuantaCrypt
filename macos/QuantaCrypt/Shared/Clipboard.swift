import AppKit

/// Pasteboard writes that expire: secrets should not sit in the clipboard.
@MainActor
enum Clipboard {
    static let clearDelay: Duration = .seconds(60)

    /// The marker Maccy, Paste, Alfred, Raycast and LaunchBar look for before
    /// deciding whether to record a copy. Without it a share code lands in a
    /// plaintext, searchable clipboard-history database that outlives the app,
    /// the file and the volume — somewhere QuantaCrypt can never clear it.
    static let concealedType = NSPasteboard.PasteboardType("org.nspasteboard.ConcealedType")

    /// `expiring` marks key material: it is what gets the concealed marker and
    /// the 60-second clear. Ordinary text (the Homebrew command) is copied as
    /// plain text so clipboard managers keep it, which is what the user wants.
    static func copy(_ text: String, expiring: Bool = true, to pasteboard: NSPasteboard = .general) {
        pasteboard.clearContents()
        guard expiring else {
            pasteboard.setString(text, forType: .string)
            return
        }
        let item = NSPasteboardItem()
        item.setString(text, forType: .string)
        item.setString("", forType: concealedType)
        pasteboard.writeObjects([item])
        let change = pasteboard.changeCount
        // Best effort only: this timer dies with the process, so quitting
        // inside the window leaves the share on the pasteboard. The concealed
        // marker above is the part that does not depend on us still running.
        let name = pasteboard.name
        Task {
            try? await Task.sleep(for: clearDelay)
            let pasteboard = NSPasteboard(name: name)
            // Only clear if the user has not copied something else meanwhile.
            if pasteboard.changeCount == change { pasteboard.clearContents() }
        }
    }
}
