import Foundation

/// Writes and reads the `<stem>.share-N-of-M.txt` files the Tk encryptor
/// produces, so both UIs stay interchangeable.
enum ShareFiles {
    static var privateAttributes: [FileAttributeKey: Any] { [.posixPermissions: 0o600] }

    struct Context: Sendable {
        let stem: String
        let protectedName: String
        let k: Int
        let n: Int
    }

    static func fileName(stem: String, index: Int, total: Int) -> String {
        "\(stem).share-\(index)-of-\(total).txt"
    }

    /// One private file per share. Returns the paths written; throws on the
    /// first failure after removing nothing (partial sets are still useful).
    @discardableResult
    static func writeIndividual(_ shares: [Share], context: Context, into directory: URL,
                                fileManager: FileManager = .default) throws -> [URL] {
        var written: [URL] = []
        for share in shares {
            let url = directory.appending(path: fileName(stem: context.stem, index: share.index, total: context.n))
            try write(individualText(share, context: context), to: url, fileManager: fileManager)
            written.append(url)
        }
        return written
    }

    static func writeCombined(_ shares: [Share], context: Context, to url: URL,
                              fileManager: FileManager = .default) throws {
        try write(combinedText(shares, context: context), to: url, fileManager: fileManager)
    }

    static func individualText(_ share: Share, context: Context) -> String {
        let rule = String(repeating: "=", count: 60)
        var text = """
        QuantaCrypt Share \(share.index) of \(context.n)
        \(rule)
        Encrypted file:    \(context.protectedName)
        Threshold:         Any \(context.k) of \(context.n) shares are needed to decrypt
        \(rule)

        This file contains one of the \(context.n) keys to \(context.protectedName). \
        Either format below works — use whichever is easier.

        KEEP THIS FILE PRIVATE. Do not share it with other shareholders.

        ── QCSHARE- code (for copy-paste) ──────────────────────
        \(share.code)


        """
        if let mnemonic = share.mnemonic {
            text += """
            ── 50-word mnemonic (for offline backup) ───────────────
            \(mnemonic)


            """
        }
        text += """
        ── How to decrypt ───────────────────────────────────────
        1. Collect \(context.k) share files from \(context.k) of the \(context.n) shareholders.
        2. Open QuantaCrypt, choose Decrypt, and pick the encrypted file.
        3. Load the share files, or paste each QCSHARE- code (or the 50 words).
        4. Click Decrypt file.

        """
        return text
    }

    static func combinedText(_ shares: [Share], context: Context) -> String {
        let rule = String(repeating: "=", count: 60)
        var text = "QuantaCrypt Key Shares\nThreshold: \(context.k) of \(context.n)\nFile:      \(context.protectedName)\n\(rule)\n\n"
        for share in shares {
            text += "Share \(share.index) — QCSHARE- code:\n\(share.code)\n\n"
            if let mnemonic = share.mnemonic {
                text += "Share \(share.index) — 50-word mnemonic:\n\(mnemonic)\n\n"
            }
            text += String(repeating: "-", count: 60) + "\n\n"
        }
        return text
    }

    /// Extract every share (code or 50-word phrase) from a text file's
    /// contents. Codes win when present; phrases are the fallback so a file
    /// containing only the mnemonic still loads.
    static func parse(_ contents: String) -> [String] {
        let lines = contents.components(separatedBy: .newlines).map {
            $0.trimmingCharacters(in: .whitespaces)
        }
        let codes = lines.filter { $0.uppercased().hasPrefix("QCSHARE-") }
        if !codes.isEmpty { return codes }

        // Mnemonic: 50 lowercase words, possibly wrapped across lines.
        var phrases: [String] = []
        var buffer: [String] = []
        func flush() {
            if buffer.count == 50 { phrases.append(buffer.joined(separator: " ")) }
            buffer.removeAll()
        }
        for line in lines {
            let words = line.split(separator: " ").map(String.init)
            let isWordLine = !words.isEmpty && words.allSatisfy { w in
                w.count >= 3 && w.unicodeScalars.allSatisfy { CharacterSet.lowercaseLetters.contains($0) }
            }
            if isWordLine {
                buffer.append(contentsOf: words)
                if buffer.count >= 50 { flush() }
            } else {
                flush()
            }
        }
        flush()
        if phrases.isEmpty {
            let all = contents.split(whereSeparator: { $0.isWhitespace }).map(String.init)
            if all.count == 50 { phrases.append(all.joined(separator: " ")) }
        }
        return phrases
    }

    private static func write(_ text: String, to url: URL, fileManager: FileManager) throws {
        guard fileManager.createFile(atPath: url.path, contents: Data(text.utf8), attributes: privateAttributes) else {
            throw CocoaError(.fileWriteUnknown, userInfo: [NSFilePathErrorKey: url.path])
        }
    }
}
