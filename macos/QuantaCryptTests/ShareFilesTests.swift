import XCTest
@testable import QuantaCrypt

final class ShareFilesTests: XCTestCase {
    private let shares = [
        Share(index: 1, code: "QCSHARE-AAAA", mnemonic: Array(repeating: "apple", count: 50).joined(separator: " ")),
        Share(index: 2, code: "QCSHARE-BBBB", mnemonic: nil),
        Share(index: 3, code: "QCSHARE-CCCC", mnemonic: nil),
    ]
    private let context = ShareFiles.Context(stem: "report.pdf", protectedName: "report.pdf.qcx", k: 2, n: 3)

    func testIndividualFilesAreNamedAndPrivate() throws {
        let dir = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let written = try ShareFiles.writeIndividual(shares, context: context, into: dir)
        XCTAssertEqual(written.map(\.lastPathComponent),
                       ["report.pdf.share-1-of-3.txt", "report.pdf.share-2-of-3.txt", "report.pdf.share-3-of-3.txt"])
        for url in written {
            let perms = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? Int
            XCTAssertEqual(perms, 0o600)
        }
        let text = try String(contentsOf: written[0], encoding: .utf8)
        XCTAssertTrue(text.contains("QCSHARE-AAAA"))
        XCTAssertTrue(text.contains("Any 2 of 3 shares"))
        XCTAssertEqual(ShareFiles.parse(text), ["QCSHARE-AAAA"])
    }

    func testCombinedFileRoundTrips() throws {
        let url = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString + ".txt")
        defer { try? FileManager.default.removeItem(at: url) }
        try ShareFiles.writeCombined(shares, context: context, to: url)
        let text = try String(contentsOf: url, encoding: .utf8)
        XCTAssertEqual(ShareFiles.parse(text), ["QCSHARE-AAAA", "QCSHARE-BBBB", "QCSHARE-CCCC"])
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
