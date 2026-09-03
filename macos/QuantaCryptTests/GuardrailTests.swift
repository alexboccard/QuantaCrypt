import XCTest
@testable import QuantaCrypt

/// The guards added by the 2026-09 UI audit: the ones whose absence lost data
/// or sent the user somewhere useless. See docs/design/ui-audit-native-2026-09.md.
@MainActor
final class GuardrailTests: XCTestCase {

    // MARK: Already-encrypted sources (N-07)

    func testQuantaCryptContainersAreNotEncryptionSources() {
        XCTAssertEqual(EncryptModel.alreadyEncrypted("/tmp/notes.txt.qcx"), .decrypt)
        XCTAssertEqual(EncryptModel.alreadyEncrypted("/tmp/Vault.qcv"), .volumes)
        // Case is the file system's business, not the user's.
        XCTAssertEqual(EncryptModel.alreadyEncrypted("/tmp/Notes.QCX"), .decrypt)
        XCTAssertNil(EncryptModel.alreadyEncrypted("/tmp/notes.txt"))
        XCTAssertNil(EncryptModel.alreadyEncrypted("/tmp/archive.qcxx"))
        XCTAssertNil(EncryptModel.alreadyEncrypted("/tmp/folder"))
    }

    func testSettingAnEncryptedSourceIsRefusedAndExplained() {
        let model = EncryptModel(core: CoreClient(transportFactory: { FakeTransport() }))
        XCTAssertFalse(model.setSource("/tmp/notes.txt.qcx"))
        XCTAssertNil(model.sourcePath, "a refused source must not become the file to encrypt")
        XCTAssertEqual(model.wrongSection?.section, .decrypt)
        XCTAssertEqual(model.wrongSection?.path, "/tmp/notes.txt.qcx")
    }

    func testAPlainSourceClearsTheRefusal() {
        let model = EncryptModel(core: CoreClient(transportFactory: { FakeTransport() }))
        XCTAssertFalse(model.setSource("/tmp/notes.txt.qcx"))
        XCTAssertTrue(model.setSource("/tmp/notes.txt"))
        XCTAssertNil(model.wrongSection)
        XCTAssertEqual(model.sourcePath, "/tmp/notes.txt")
    }

    // MARK: Quit guard (N-01)

    func testQuitIsBlockedWhileSharesAreUnsaved() {
        let state = AppState(core: CoreClient(transportFactory: { FakeTransport() }),
                             recents: RecentStore(defaults: Self.scratchDefaults()))
        XCTAssertNil(state.quitBlocker, "an idle app must quit without ceremony")

        state.encrypt.sharesToShow = Self.presentation(named: "secrets.qcx")
        XCTAssertEqual(state.quitBlocker, .unsavedShares("secrets.qcx"))

        // Writing them somewhere durable is what lifts the guard — the sheet
        // being open is not, and neither is copying to the clipboard.
        state.encrypt.sharesSaved = true
        XCTAssertNil(state.quitBlocker)
    }

    func testShowingANewShareSetReArmsTheGuard() {
        let state = AppState(core: CoreClient(transportFactory: { FakeTransport() }),
                             recents: RecentStore(defaults: Self.scratchDefaults()))
        state.encrypt.sharesToShow = Self.presentation(named: "first.qcx")
        state.encrypt.sharesSaved = true
        state.encrypt.sharesToShow = Self.presentation(named: "second.qcx")
        XCTAssertEqual(state.quitBlocker, .unsavedShares("second.qcx"),
                       "a second share set must not inherit the first one's saved flag")
    }

    func testVolumeSharesBlockQuitToo() {
        let state = AppState(core: CoreClient(transportFactory: { FakeTransport() }),
                             recents: RecentStore(defaults: Self.scratchDefaults()))
        state.volumes.sharesToShow = Self.presentation(named: "Vault.qcv")
        XCTAssertEqual(state.quitBlocker, .unsavedShares("Vault.qcv"))
    }

    func testQuitBlockerCopyNamesWhatIsLost() {
        let blocker = AppState.QuitBlocker.unsavedShares("Vault.qcv")
        XCTAssertTrue(blocker.informativeText.contains("Vault.qcv"))
        XCTAssertTrue(blocker.informativeText.contains("never be opened again"))
        XCTAssertEqual(blocker.quitTitle, "Quit and discard shares")
    }

    // MARK: Decrypt input hygiene (E-10)

    func testLoadingAnotherFileClearsTheSharesTypedForTheLastOne() {
        let state = AppState(core: CoreClient(transportFactory: { FakeTransport() }),
                             recents: RecentStore(defaults: Self.scratchDefaults()))
        let decrypt = state.decrypt
        decrypt.shares = ["QCSHARE-one", "QCSHARE-two"]
        decrypt.password = "hunter2"
        XCTAssertTrue(decrypt.load(path: "/tmp/other.qcx"))
        XCTAssertEqual(decrypt.shares, [], "one file's shares must not stand in for another's")
        XCTAssertEqual(decrypt.password, "")
    }

    // MARK: Mount support tri-state (E-05)

    func testUncheckedMountSupportIsNotReportedAsMissing() {
        let model = VolumesModel(core: CoreClient(transportFactory: { FakeTransport() }),
                                 recents: RecentStore(defaults: Self.scratchDefaults()))
        XCTAssertEqual(model.mountSupport, .unknown)
        model.mountPath = "/tmp/Vault.qcv"
        model.mountPoint = "/tmp/mnt"
        model.mountPassword = "hunter2hunter2"
        // "Install disk mounting support" is the wrong advice for a check
        // that has not finished; so is it for a helper that is down.
        XCTAssertEqual(model.mountBlockedMessage,
                       "Checking whether this Mac can open volumes as drives…")
        model.fuseError = CoreError(code: .helperUnavailable, message: "no helper", detail: "")
        XCTAssertEqual(model.mountBlockedMessage,
                       "Couldn't check whether this Mac can mount volumes — the helper isn't responding.")
    }

    // MARK: One job at a time (A-02)

    func testCreateAndMountBlockEachOther() {
        let model = VolumesModel(core: CoreClient(transportFactory: { FakeTransport() }),
                                 recents: RecentStore(defaults: Self.scratchDefaults()))
        model.mountRunning = true
        XCTAssertEqual(model.createValidationMessage, "Wait for the volume that is opening to finish.")
        XCTAssertFalse(model.canCreate)
        model.mountRunning = false
        model.createRunning = true
        XCTAssertEqual(model.mountValidationMessage, "Wait for the volume being created to finish.")
        XCTAssertFalse(model.canMount)
    }

    // MARK: Mount failure copy (E-04)

    func testFuseStartupFailureGetsACauseAndANextStep() {
        let raw = CoreError(code: .io, message: "FUSE mount failed: [Errno 1] Operation not permitted",
                            detail: "")
        let shown = VolumesModel.friendlyMountError(raw, credential: .password, path: "/tmp/Vault.qcv")
        XCTAssertFalse(shown.message.contains("Errno"), "the raw interpolation is not a user message")
        XCTAssertTrue(shown.message.contains("Privacy & Security"))
        XCTAssertTrue(shown.detail.contains("Errno 1"), "the raw text belongs in the details")
    }

    func testUnrelatedIOErrorsKeepTheHelperMessage() {
        let raw = CoreError(code: .io, message: "The volume file is unreadable.", detail: "")
        let shown = VolumesModel.friendlyMountError(raw, credential: .password, path: "/tmp/Vault.qcv")
        XCTAssertEqual(shown.message, "The volume file is unreadable.")
    }

    // MARK: Wire errors (E-11)

    func testAMessagelessHelperErrorStillSaysWhatToDo() {
        let error = CoreError.fromWire(code: "internal", message: nil, detail: nil)
        XCTAssertFalse(error.message.contains("Something went wrong"))
        XCTAssertTrue(error.message.contains("Try again"))
    }

    // MARK: Stale mounted list (E-06)

    func testMountedListIsOnlyStaleAfterARunOfFailures() async {
        let model = VolumesModel(core: CoreClient(transportFactory: { FailingTransport() }),
                                 recents: RecentStore(defaults: Self.scratchDefaults()))
        XCTAssertFalse(model.listIsStale)
        await model.refreshMounted()
        XCTAssertFalse(model.listIsStale, "one missed poll is noise, not a stale list")
        await model.refreshMounted()
        XCTAssertTrue(model.listIsStale)
    }

    // MARK: Helpers

    private static func presentation(named name: String) -> SharesPresentation {
        SharesPresentation(shares: [],
                           context: ShareFiles.Context(stem: "stem", protectedName: name,
                                                       k: 2, n: 3, kind: .qcxFile))
    }

    private static func scratchDefaults() -> UserDefaults {
        UserDefaults(suiteName: "QuantaCryptTests.\(UUID().uuidString)")!
    }
}

/// A transport that refuses to start, for the poll-failure path.
private struct FailingTransport: CoreTransport {
    struct Boom: Error {}
    func start() async throws -> AsyncThrowingStream<String, any Error> { throw Boom() }
    func send(_ line: String) async throws { throw Boom() }
    func closeInput() async {}
    func terminate(timeout: Duration) async {}
}
