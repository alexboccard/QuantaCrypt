import Foundation
import Observation
import UniformTypeIdentifiers

@MainActor
@Observable
final class DecryptModel {
    static let noRecoveryNote = "There is no way to recover this file without the password."

    static let inspectTimeout: Duration = .seconds(20)
    static let inspectTimedOut = CoreError(
        code: .helperUnavailable,
        message: "The encryption helper didn't answer. Try again. If it keeps happening, restart the helper in Settings.",
        detail: "inspect timed out after 20s")

    /// Re-run the inspection for the file already on screen.
    func retryInspect() {
        guard let path = filePath else { return }
        load(path: path)
    }

    private let core: CoreClient
    private let recents: RecentStore

    var filePath: String?
    var info: InspectInfo?
    var inspecting = false
    var inspectError: CoreError?

    var password = ""
    var shares: [ShareEntry] = []
    var outputDir: String = Paths.defaultOutputFolder ?? Paths.homeDirectory
    private var outputChosenByUser = false

    var progress: CoreProgress?
    var isRunning = false
    var isCancelling = false
    var isVerifying = false
    var error: CoreError?
    var errorNote: String?
    var status: String?
    var result: DecryptResult?
    var verifiedNote: String?
    /// Set when the user arrives from "Check it opens" on the encrypt result,
    /// so Decrypt can say why it is showing them this file.
    var verifyPrompt = false
    /// Called with the file's path when Verify proves the credential. The
    /// encrypt model listens so it can drop the shares it kept for "Show
    /// shares again" once they are known to work.
    var onVerified: ((String) -> Void)?
    private var wrongPasswordCount = 0
    private var task: Task<Void, Never>?

    init(core: CoreClient, recents: RecentStore) {
        self.core = core
        self.recents = recents
    }

    // MARK: File

    func chooseFile() {
        guard let url = Panels.chooseFile(types: [.qcx], message: "Choose an encrypted .qcx file.") else { return }
        load(path: url.path)
    }

    static func accepts(_ url: URL) -> Bool {
        url.pathExtension.lowercased() == "qcx"
    }

    /// Load `path` for inspection. Returns false — with the reason in
    /// `status` — while a decrypt is running.
    @discardableResult
    func load(path: String) -> Bool {
        guard !isRunning else {
            status = EncryptModel.busyMessage(for: path)
            return false
        }
        filePath = path
        info = nil
        inspectError = nil
        result = nil
        error = nil
        errorNote = nil
        status = nil
        verifiedNote = nil
        verifyPrompt = false
        wrongPasswordCount = 0
        password = ""
        // Shares too, not just the password: leftovers from the previous
        // file used to sit in the fields looking valid, and the failure then
        // advised swapping a share that was never wrong.
        shares = []
        if !outputChosenByUser { outputDir = Paths.defaultOutputFolder ?? Format.directory(path) }
        inspecting = true
        Task { [core] in
            do {
                // A helper that launches but never answers is the worst
                // failure this client has; without a bound the user gets a
                // spinner on an otherwise empty screen and no way out.
                let info: InspectInfo = try await withTimeout(Self.inspectTimeout) {
                    try await core.perform(.inspect(path: path))
                }
                guard filePath == path else { return }
                self.info = info
                let needed = info.threshold ?? 2
                if info.isSplitKey, shares.count < needed {
                    shares = (0..<needed).map { _ in ShareEntry() }
                } else if !info.isSplitKey {
                    shares = []
                }
            } catch let error as CoreError {
                if filePath == path { inspectError = error }
            } catch is TimeoutError {
                if filePath == path { inspectError = Self.inspectTimedOut }
            } catch {
                if filePath == path {
                    inspectError = CoreError(code: .internal, message: error.localizedDescription, detail: "\(error)")
                }
            }
            if filePath == path { inspecting = false }
        }
        return true
    }

    func chooseOutputDir() {
        guard let url = Panels.chooseFolder(message: "Choose where the decrypted file goes.",
                                            directory: URL(fileURLWithPath: outputDir)) else { return }
        outputDir = url.path
        outputChosenByUser = true
    }

    func loadSharesFromFiles() {
        let urls = Panels.chooseFiles(types: ShareFiles.fileTypes, message: "Choose one or more share files.")
        guard !urls.isEmpty else { return }
        let (loaded, problems) = ShareFiles.load(urls)
        guard !loaded.isEmpty else {
            status = problems.first ?? "No shares were found in \(urls.count == 1 ? "that file" : "those files")."
            return
        }
        status = problems.first
        shares = ShareValidation.merge(loaded, into: shares, threshold: info?.threshold, total: info?.total)
    }

    // MARK: Validation

    var validationMessage: String? {
        guard filePath != nil else { return "Choose an encrypted file." }
        guard let info else { return inspectError == nil ? "Reading the file…" : "This file can't be read." }
        if info.isSplitKey {
            return ShareValidation.message(entries: shares, threshold: info.threshold)
        }
        if password.isEmpty { return "Enter the password." }
        return nil
    }

    var canRun: Bool { !isRunning && validationMessage == nil }

    // MARK: Run

    func decrypt() { start(verifyOnly: false) }
    func verify() { start(verifyOnly: true) }

    private func start(verifyOnly: Bool) {
        guard canRun, let path = filePath, let info else { return }
        let credential: CoreRequest.Credential = info.isSplitKey
            ? .shares(ShareValidation.prepared(shares))
            : .password(password)
        isRunning = true
        isCancelling = false
        isVerifying = verifyOnly
        progress = nil
        error = nil
        errorNote = nil
        status = nil
        result = nil
        verifiedNote = nil
        let outputDir = self.outputDir
        task = Task { [core] in
            do {
                let raw = try await core.perform(
                    .decrypt(path: path, outputDir: verifyOnly ? nil : outputDir,
                             credential: credential, verifyOnly: verifyOnly)
                ) { p in
                    Task { @MainActor [weak self] in self?.progress = p }
                }
                if verifyOnly {
                    finishVerify(path: path)
                } else {
                    finish(try raw.decoded(as: DecryptResult.self), path: path)
                }
            } catch let error as CoreError {
                fail(error, info: info)
            } catch {
                fail(CoreError(code: .protocolError, message: "The helper answered in an unexpected format.",
                               detail: "\(error)"), info: info)
            }
        }
    }

    private func finishVerify(path: String) {
        isRunning = false
        isCancelling = false
        progress = nil
        verifiedNote = info?.isSplitKey == true
            ? "These shares unlock the file. Nothing was written."
            : "The password is correct. Nothing was written."
        onVerified?(path)
    }

    private func finish(_ result: DecryptResult, path: String) {
        isRunning = false
        isCancelling = false
        progress = nil
        self.result = result
        password = ""
        // Shares are key material — k points on the polynomial that rebuilds
        // the master key. The password next to them has always been cleared
        // here; leaving the shares live in an @Observable model, rendered in
        // plain TextFields, outlasts the operation they were typed for.
        shares = shares.map { _ in ShareEntry() }
        recents.add(path, kind: .decrypted)
    }

    private func fail(_ error: CoreError, info: InspectInfo) {
        isRunning = false
        isCancelling = false
        progress = nil
        if error.isCancellation {
            status = error.message
            return
        }
        if error.code == .wrongCredentials, !info.isSplitKey { wrongPasswordCount += 1 }
        let shown = Self.userFacingError(error, info: info, wrongPasswordCount: wrongPasswordCount)
        self.error = shown.error
        errorNote = shown.note
    }

    /// The error to show for a failed decrypt. Only `wrong_credentials` is
    /// rewritten (Caps Lock hint, "which share?" advice, the no-recovery note
    /// after `wrongPasswordCount` misses); every other code — `format` for a
    /// damaged payload, `invalid_input` for an unreadable share — keeps the
    /// helper's own message, which is written for the user.
    static func userFacingError(_ error: CoreError, info: InspectInfo,
                                wrongPasswordCount: Int) -> (error: CoreError, note: String?) {
        guard error.code == .wrongCredentials else { return (error, nil) }
        if info.isSplitKey {
            let k = info.threshold.map(String.init) ?? "the required"
            let n = info.total.map(String.init) ?? "its"
            return (CoreError(
                code: error.code,
                message: "These shares don't unlock this file. Any \(k) of the \(n) shares will work, so try swapping in a different share. QuantaCrypt can't tell which one is wrong.",
                detail: error.detail), nil)
        }
        return (CoreError(code: error.code,
                          message: "The password is incorrect. Check Caps Lock and try again.",
                          detail: error.detail),
                wrongPasswordCount >= 3 ? noRecoveryNote : nil)
    }

    func cancel() {
        guard isRunning else { return }
        isCancelling = true
        task?.cancel()
    }

    func reset() {
        guard !isRunning else { return }
        filePath = nil
        info = nil
        inspectError = nil
        password = ""
        shares = []
        result = nil
        error = nil
        errorNote = nil
        status = nil
        verifiedNote = nil
        wrongPasswordCount = 0
    }
}
