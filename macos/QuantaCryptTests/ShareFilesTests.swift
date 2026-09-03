import XCTest
@testable import QuantaCrypt

final class ShareFilesTests: XCTestCase {
    private let shares = [
        Share(index: 1, code: "QCSHARE-AAAA", mnemonic: Array(repeating: "apple", count: 50).joined(separator: " ")),
        Share(index: 2, code: "QCSHARE-BBBB", mnemonic: nil),
        Share(index: 3, code: "QCSHARE-CCCC", mnemonic: nil),
    ]
    private let context = ShareFiles.Context(stem: "report.pdf", protectedName: "report.pdf.qcx", k: 2, n: 3, kind: .qcxFile)
    private let volumeContext = ShareFiles.Context(stem: "Vault", protectedName: "Vault.qcv", k: 2, n: 3, kind: .qcvVolume)

    private func makeTempDir() throws -> URL {
        let dir = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        return dir
    }

    func testIndividualFilesAreNamedAndPrivate() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let outcome = try ShareFiles.writeIndividual(shares, context: context, into: dir)
        XCTAssertNil(outcome.renamedStem)
        XCTAssertEqual(outcome.files.map(\.lastPathComponent),
                       ["report.pdf.share-1-of-3.txt", "report.pdf.share-2-of-3.txt", "report.pdf.share-3-of-3.txt"])
        for url in outcome.files {
            let perms = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? Int
            XCTAssertEqual(perms, 0o600)
        }
        let text = try String(contentsOf: outcome.files[0], encoding: .utf8)
        XCTAssertTrue(text.contains("QCSHARE-AAAA"))
        XCTAssertTrue(text.contains("Any 2 of 3 shares"))
        XCTAssertTrue(text.contains("Encrypted file:"))
        XCTAssertTrue(text.contains("choose Decrypt"))
        XCTAssertEqual(ShareFiles.parse(text), ["QCSHARE-AAAA"])
    }

    func testIndividualFilesNeverOverwriteAnEarlierRun() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }

        let first = try ShareFiles.writeIndividual(shares, context: context, into: dir)
        let firstText = try String(contentsOf: first.files[1], encoding: .utf8)

        // Only one of the three names is taken: the whole second run must move.
        try FileManager.default.removeItem(at: first.files[0])
        try FileManager.default.removeItem(at: first.files[2])
        let newShares = shares.map { Share(index: $0.index, code: "QCSHARE-NEW\($0.index)", mnemonic: nil) }
        let second = try ShareFiles.writeIndividual(newShares, context: context, into: dir)
        XCTAssertEqual(second.renamedStem, "report.pdf_2")
        XCTAssertEqual(second.files.map(\.lastPathComponent),
                       ["report.pdf_2.share-1-of-3.txt", "report.pdf_2.share-2-of-3.txt", "report.pdf_2.share-3-of-3.txt"])
        XCTAssertEqual(try String(contentsOf: first.files[1], encoding: .utf8), firstText, "earlier run untouched")
        XCTAssertTrue(try String(contentsOf: second.files[0], encoding: .utf8).contains("QCSHARE-NEW1"))
        // No stray file from the aborted first attempt of the second run.
        XCTAssertFalse(FileManager.default.fileExists(atPath: first.files[0].path))

        let third = try ShareFiles.writeIndividual(newShares, context: context, into: dir)
        XCTAssertEqual(third.renamedStem, "report.pdf_3")
        let perms = try FileManager.default.attributesOfItem(atPath: third.files[0].path)[.posixPermissions] as? Int
        XCTAssertEqual(perms, 0o600)
    }

    func testCombinedFileRoundTrips() throws {
        let url = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString + ".txt")
        defer { try? FileManager.default.removeItem(at: url) }
        let outcome = try ShareFiles.writeCombined(shares, context: context, to: url)
        XCTAssertEqual(outcome.files, [url])
        XCTAssertNil(outcome.renamedStem)
        let perms = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? Int
        XCTAssertEqual(perms, 0o600)
        let text = try String(contentsOf: url, encoding: .utf8)
        XCTAssertEqual(ShareFiles.parse(text), ["QCSHARE-AAAA", "QCSHARE-BBBB", "QCSHARE-CCCC"])
    }

    func testCombinedFileNeverOverwrites() throws {
        let dir = try makeTempDir()
        defer { try? FileManager.default.removeItem(at: dir) }
        let url = dir.appending(path: "report.pdf.shares.txt")
        try Data("earlier run".utf8).write(to: url)

        let outcome = try ShareFiles.writeCombined(shares, context: context, to: url)
        XCTAssertEqual(outcome.files.map(\.lastPathComponent), ["report.pdf_2.shares.txt"])
        XCTAssertEqual(outcome.renamedStem, "report.pdf_2.shares.txt")
        XCTAssertEqual(try String(contentsOf: url, encoding: .utf8), "earlier run")

        let other = dir.appending(path: "keys.txt")
        try Data("x".utf8).write(to: other)
        let second = try ShareFiles.writeCombined(shares, context: context, to: other)
        XCTAssertEqual(second.files.map(\.lastPathComponent), ["keys_2.txt"])
    }

    func testVolumeSharesCarryVolumeInstructions() {
        let text = ShareFiles.individualText(shares[0], context: volumeContext)
        XCTAssertTrue(text.contains("Encrypted volume: Vault.qcv"))
        XCTAssertTrue(text.contains("choose Volumes"))
        XCTAssertTrue(text.contains("Choose Split key"))
        XCTAssertTrue(text.contains("Click Mount volume"))
        XCTAssertFalse(text.contains("choose Decrypt"))
        XCTAssertFalse(text.contains("Click Decrypt file"))
        XCTAssertEqual(ShareFiles.parse(text), ["QCSHARE-AAAA"])

        let combined = ShareFiles.combinedText(shares, context: volumeContext)
        XCTAssertTrue(combined.contains("Volume:    Vault.qcv"))
        XCTAssertTrue(combined.contains("Volumes"))
        XCTAssertFalse(combined.contains("Decrypt"))
        XCTAssertEqual(ShareFiles.parse(combined), ["QCSHARE-AAAA", "QCSHARE-BBBB", "QCSHARE-CCCC"])
    }

    func testSavedNoteMentionsRename() {
        let files = [URL(fileURLWithPath: "/tmp/x/report.pdf_2.share-1-of-3.txt")]
        let renamed = ShareFiles.Outcome(files: files, renamedStem: "report.pdf_2")
        let note = SharesSheet.savedNote(for: renamed, count: 1, location: "/tmp/x")
        XCTAssertTrue(note.contains("already existed"))
        XCTAssertTrue(note.contains("report.pdf_2.share-1-of-3.txt"))
        let plain = SharesSheet.savedNote(for: ShareFiles.Outcome(files: files, renamedStem: nil), count: 1, location: "/tmp/x")
        XCTAssertFalse(plain.contains("already existed"))
    }

    func testMnemonicOnlyFileParses() {
        let words = (0..<50).map { "word\($0 % 7 + 3)" }.map { String($0.filter { $0.isLetter }) }
        let text = "Some header\n" + words.prefix(25).joined(separator: " ") + "\n" + words.suffix(25).joined(separator: " ") + "\n"
        let parsed = ShareFiles.parse(text)
        XCTAssertEqual(parsed.count, 1)
        XCTAssertEqual(parsed.first?.split(separator: " ").count, 50)
    }

    func testPasswordStrengthOrdering() {
        XCTAssertEqual(PasswordStrength.estimate("").level, .empty)
        XCTAssertEqual(PasswordStrength.estimate("abc").level, .weak)
        XCTAssertEqual(PasswordStrength.estimate("password123").level, .weak)
        XCTAssertLessThan(PasswordStrength.estimate("aaaaaaaaaaaa").level, PasswordStrength.estimate("correct horse battery staple").level)
        XCTAssertEqual(PasswordStrength.estimate("Tr0ub4dor&3-Jump-Over-Lazy-Dogs!").level, .strong)
    }
}
