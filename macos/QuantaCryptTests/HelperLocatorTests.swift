import XCTest
@testable import QuantaCrypt

/// The helper receives every password and every Shamir share on its stdin, so
/// which binary is chosen is a security decision, not a convenience.
final class HelperLocatorTests: XCTestCase {
    private var scratch: URL!
    /// A stand-in app bundle with a helper where `build.py` puts one.
    private var appBundle: Bundle!
    private var bundledHelper: URL!

    override func setUpWithError() throws {
        scratch = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        let helpers = scratch.appending(path: "QuantaCrypt.app/Contents/Helpers/qc-core.app/Contents/MacOS")
        try FileManager.default.createDirectory(at: helpers, withIntermediateDirectories: true)
        bundledHelper = helpers.appending(path: "qc-core")
        try write(executable: bundledHelper)
        appBundle = try XCTUnwrap(Bundle(path: scratch.appending(path: "QuantaCrypt.app").path))
    }

    override func tearDownWithError() throws {
        try? FileManager.default.removeItem(at: scratch)
    }

    private func write(executable url: URL) throws {
        try "#!/bin/sh\nexit 0\n".write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
    }

    private func outsideHelper(_ name: String = "qc-core") throws -> URL {
        let url = scratch.appending(path: name)
        try write(executable: url)
        return url
    }

    /// Stand-in for a real code hash: only its equality matters here.
    private static let pinnedHash = Data([0xC0, 0xDE, 0xF0, 0x0D])

    private func resolve(override: String?,
                         environment: [String: String] = [:],
                         signature: @escaping @Sendable (URL) -> HelperLocator.SignatureStatus
                             = { _ in .satisfiesPin(cdHash: HelperLocatorTests.pinnedHash) },
                         approved: @escaping @Sendable (String, Data) -> Bool = { _, _ in false })
    -> HelperLocator.Resolution {
        HelperLocator.resolve(override: override, environment: environment, bundle: appBundle,
                              signature: signature, approved: approved)
    }

    /// A real, ad-hoc-signed helper: `scripts/build.py --helper` signs with
    /// `--sign -` too, so this is the production shape of an override.
    private func signHelper(_ url: URL, contents: String) throws {
        try contents.write(to: url, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
        let codesign = Process()
        codesign.executableURL = URL(fileURLWithPath: "/usr/bin/codesign")
        codesign.arguments = ["--force", "--sign", "-", "--identifier", "qc-core", url.path]
        codesign.standardOutput = FileHandle.nullDevice
        codesign.standardError = FileHandle.nullDevice
        try codesign.run()
        codesign.waitUntilExit()
        if codesign.terminationStatus != 0 {
            throw XCTSkip("codesign is unavailable, so the pin cannot be exercised end to end")
        }
    }

    // MARK: Resolution order

    func testBundledHelperIsUsedWhenNothingOverridesIt() {
        let resolution = resolve(override: nil)
        XCTAssertEqual(resolution.launch?.executable.path, bundledHelper.path)
        XCTAssertEqual(resolution.launch?.origin, "bundle")
        XCTAssertNil(resolution.refusal)
    }

    func testBundledHelperBeatsTheEnvironment() throws {
        let env = try outsideHelper("env-helper")
        let resolution = resolve(override: nil, environment: ["QC_CORE_PATH": env.path])
        XCTAssertEqual(resolution.launch?.executable.path, bundledHelper.path,
                       "the bundle must win over an environment variable")
    }

    func testAnOverrideThatDoesNotExistFallsThroughWithoutRefusing() {
        let resolution = resolve(override: scratch.appending(path: "missing").path)
        XCTAssertEqual(resolution.launch?.origin, "bundle")
        XCTAssertNil(resolution.refusal, "a path that isn't there was never a candidate")
        XCTAssertTrue(resolution.searched.contains { $0.contains("Settings override") })
    }

    // MARK: The override is the attack surface

    func testAnOverrideOutsideTheBundleIsRefusedUntilApproved() throws {
        let planted = try outsideHelper("planted")
        let refused = resolve(override: planted.path)
        XCTAssertEqual(refused.launch?.executable.path, bundledHelper.path,
                       "a planted preference must not receive passwords and shares")
        XCTAssertEqual(refused.refusal?.path, planted.standardizedFileURL.path)
        XCTAssertEqual(refused.refusal?.approvable, true)

        let approved = resolve(override: planted.path,
                               approved: { path, hash in
                                   path == planted.standardizedFileURL.path && hash == Self.pinnedHash
                               })
        XCTAssertEqual(approved.launch?.executable.path, planted.path)
        XCTAssertEqual(approved.launch?.origin, "settings")
        XCTAssertNil(approved.refusal)
    }

    func testAnUnsignedOverrideIsRefusedEvenWhenApproved() throws {
        let planted = try outsideHelper("unsigned")
        let resolution = resolve(override: planted.path,
                                 signature: { _ in .unsigned("no signature") },
                                 approved: { _, _ in true })
        XCTAssertEqual(resolution.launch?.executable.path, bundledHelper.path)
        XCTAssertEqual(resolution.refusal?.approvable, false,
                       "nothing the user can click makes an unsigned binary safe")
    }

    func testAnOverridePointingIntoTheAppBundleNeedsNoApproval() {
        let resolution = resolve(override: bundledHelper.path, signature: { _ in .unsigned("not reached") })
        XCTAssertEqual(resolution.launch?.executable.path, bundledHelper.path)
        XCTAssertEqual(resolution.launch?.origin, "settings")
        XCTAssertNil(resolution.refusal, "the app's own signature already covers its payload")
    }

    /// A binary that is signed, but not as *this* helper, cannot be approved
    /// at all. Treating "signed by someone else" exactly like "signed as
    /// qc-core" is what made the requirement pin decorative: the check ran and
    /// its answer changed no branch.
    func testASignedButUnpinnedOverrideCannotBeApproved() throws {
        let planted = try outsideHelper("someone-elses")
        let resolution = resolve(override: planted.path,
                                 signature: { _ in .signedButUnpinned("it is signed by someone else") },
                                 approved: { _, _ in true })
        XCTAssertEqual(resolution.launch?.executable.path, bundledHelper.path)
        XCTAssertEqual(resolution.refusal?.approvable, false,
                       "the override is for a qc-core, not for any signed binary")
        XCTAssertTrue(resolution.refusal?.reason.contains("not as QuantaCrypt's qc-core helper") == true)
    }

    func testAnApprovedLaunchCarriesTheHashItWasApprovedAt() throws {
        let planted = try outsideHelper("pinned")
        let resolution = resolve(override: planted.path, approved: { _, _ in true })
        XCTAssertEqual(resolution.launch?.approvedCDHash, Self.pinnedHash,
                       "ProcessTransport re-measures this immediately before exec")
    }

    /// The approval names the bytes, not the path: swapping the file for a
    /// differently signed one used to inherit the click, and every password
    /// and share typed afterwards would have gone to the replacement.
    func testAnApprovalDoesNotSurviveTheFileBeingReplaced() throws {
        let planted = scratch.appending(path: "swappable")
        try signHelper(planted, contents: "#!/bin/sh\nexit 0\n")
        guard case .satisfiesPin(let first) = HelperLocator.signatureStatus(of: planted) else {
            throw XCTSkip("ad-hoc signing did not take on this machine")
        }
        XCTAssertTrue(HelperLocator.approve(planted.path))
        XCTAssertTrue(HelperLocator.isApproved(planted.standardizedFileURL.path, cdHash: first))
        XCTAssertFalse(HelperLocator.isApproved(scratch.appending(path: "other").path, cdHash: first))

        let allowed = HelperLocator.resolve(override: planted.path, environment: [:], bundle: appBundle)
        XCTAssertEqual(allowed.launch?.origin, "settings")
        XCTAssertEqual(allowed.launch?.approvedCDHash, first)

        try signHelper(planted, contents: "#!/bin/sh\nexec /usr/bin/true\n")
        guard case .satisfiesPin(let second) = HelperLocator.signatureStatus(of: planted), second != first else {
            return XCTFail("re-signing different bytes must change the code hash")
        }
        XCTAssertFalse(HelperLocator.isApproved(planted.standardizedFileURL.path, cdHash: second))
        let refused = HelperLocator.resolve(override: planted.path, environment: [:], bundle: appBundle)
        XCTAssertEqual(refused.launch?.executable.path, bundledHelper.path,
                       "the replacement must not inherit the approval")
        XCTAssertEqual(refused.refusal?.approvable, true)
    }

    /// Nothing is recorded for a file that cannot be pinned, so a click on a
    /// stale refusal cannot grant more than it showed.
    func testApprovingAnUnpinnableFileRecordsNothing() throws {
        let script = try outsideHelper("not-signed")
        XCTAssertFalse(HelperLocator.approve(script.path))
        XCTAssertFalse(HelperLocator.isApproved(script.standardizedFileURL.path, cdHash: Self.pinnedHash))
    }

    // MARK: The signature check must not be vacuous

    func testTheRequirementRejectsBinariesSignedBySomeoneElse() {
        // Also asserts the requirement string still compiles: a compile
        // failure has its own `.signedButUnpinned` detail, and now that only
        // pinned binaries are approvable it would lock out every override.
        XCTAssertEqual(HelperLocator.signatureStatus(of: URL(fileURLWithPath: "/bin/ls")),
                       .signedButUnpinned("it is signed by someone else"))
    }

    func testAPinnedBinaryReportsANonEmptyCodeHash() throws {
        let helper = scratch.appending(path: "qc-core-copy")
        try signHelper(helper, contents: "#!/bin/sh\nexit 0\n")
        guard case .satisfiesPin(let hash) = HelperLocator.signatureStatus(of: helper) else {
            return XCTFail("an ad-hoc signature under our identifier must satisfy the pin")
        }
        XCTAssertFalse(hash.isEmpty, "an approval with nothing to compare is an approval of the path")
    }

    func testAnUnsignedFileIsReportedAsUnsigned() throws {
        let script = try outsideHelper("script.sh")
        guard case .unsigned = HelperLocator.signatureStatus(of: script) else {
            return XCTFail("a shell script has no code signature to check")
        }
    }
}
