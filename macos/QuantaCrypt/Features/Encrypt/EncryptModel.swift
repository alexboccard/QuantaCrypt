import Foundation
import Observation

enum ProtectionMode: String, CaseIterable, Identifiable {
    case password = "Password"
    case splitKey = "Split key"
    var id: String { rawValue }
}

/// Shares to hand over after a split-key encrypt or volume create.
struct SharesPresentation: Identifiable {
    let id = UUID()
    let shares: [Share]
    let context: ShareFiles.Context
}

@MainActor
@Observable
final class EncryptModel {
    private let core: CoreClient

    var sourcePath: String?
    var sourceIsFolder = false
    var sourceDetail: String?
    var mode: ProtectionMode = .password
    var password = ""
    var confirmation = ""
    var threshold = 2
    var total = 3
    var outputPath: String?
    private var outputChosenByUser = false

    var progress: CoreProgress?
    var isRunning = false
    var isCancelling = false
    var error: CoreError?
    var status: String?
    var result: EncryptResult?
    var sharesToShow: SharesPresentation? {
        didSet { if sharesToShow != nil { sharesSaved = false } }
    }
    /// Whether the shares on screen have been written somewhere durable.
    /// Read by the quit guard — the sheet's own state dies with the sheet.
    var sharesSaved = false
    var confirmReplace = false
    /// Set when a source is refused for being already encrypted; the view
    /// offers to hand it to the section that can actually open it.
    var wrongSection: (path: String, section: AppSection)?

    private var task: Task<Void, Never>?
    private var statsTask: Task<Void, Never>?

    init(core: CoreClient) {
        self.core = core
    }

    // MARK: Source and output

    func chooseSource() {
        guard let url = Panels.chooseFileOrFolder(message: "Choose a file or folder to encrypt.") else { return }
        setSource(url.path)
    }

    /// Take `path` as the source. Returns false — and says why in `status`
    /// — while an encrypt is running, so callers never switch the UI to a
    /// file that was not actually loaded.
    @discardableResult
    func setSource(_ path: String) -> Bool {
        guard !isRunning else {
            status = Self.busyMessage(for: path)
            return false
        }
        // Encrypt is the default section, so someone who wants their file
        // back lands here first. Accepting a .qcx produced notes.txt.qcx.qcx
        // and a success card.
        if let section = Self.alreadyEncrypted(path) {
            wrongSection = (path, section)
            return false
        }
        wrongSection = nil
        // An output the user picked belongs to the source it was picked for;
        // a new source gets the default name again so the replace prompt can
        // protect the previous run's ciphertext.
        if path != sourcePath { outputChosenByUser = false }
        sourcePath = path
        sourceIsFolder = Paths.isDirectory(path)
        result = nil
        error = nil
        status = nil
        if !outputChosenByUser { outputPath = Self.defaultOutput(for: path) }
        describeSource(path)
        return true
    }

    static func busyMessage(for path: String) -> String {
        "Finish or cancel the current job to open \(Format.fileName(path))."
    }

    /// The section that can open `path`, when it is already a QuantaCrypt
    /// container and so cannot sensibly be an encryption source.
    static func alreadyEncrypted(_ path: String) -> AppSection? {
        switch URL(fileURLWithPath: path).pathExtension.lowercased() {
        case "qcx": return .decrypt
        case "qcv": return .volumes
        default: return nil
        }
    }

    static func defaultOutput(for source: String) -> String {
        let dir = Paths.defaultOutputFolder ?? Format.directory(source)
        return (dir as NSString).appendingPathComponent(Format.fileName(source) + ".qcx")
    }

    private func describeSource(_ path: String) {
        statsTask?.cancel()
        if sourceIsFolder {
            sourceDetail = "Scanning folder…"
            statsTask = Task.detached(priority: .utility) {
                let (count, bytes) = Self.folderStats(path)
                guard !Task.isCancelled else { return }
                await MainActor.run { [weak self] in
                    guard self?.sourcePath == path else { return }
                    self?.sourceDetail = "Folder · \(count) items · \(Format.bytes(bytes))"
                }
            }
        } else {
            let size = (try? FileManager.default.attributesOfItem(atPath: path)[.size] as? Int) ?? 0
            sourceDetail = "\(Format.bytes(size)) · \(Format.tildePath(Format.directory(path)))"
        }
    }

    nonisolated private static func folderStats(_ path: String) -> (Int, Int) {
        var count = 0
        var bytes = 0
        let url = URL(fileURLWithPath: path)
        if let e = FileManager.default.enumerator(at: url, includingPropertiesForKeys: [.fileSizeKey, .isRegularFileKey]) {
            for case let item as URL in e {
                guard !Task.isCancelled else { break }
                let values = try? item.resourceValues(forKeys: [.fileSizeKey, .isRegularFileKey])
                if values?.isRegularFile == true {
                    count += 1
                    bytes += values?.fileSize ?? 0
                }
            }
        }
        return (count, bytes)
    }

    func chooseOutput() {
        let suggested = outputPath.map(Format.fileName) ?? "Encrypted.qcx"
        let dir = outputPath.map { URL(fileURLWithPath: Format.directory($0)) }
        guard let url = Panels.save(suggestedName: suggested, type: .qcx, message: "Save the encrypted file as…",
                                    directory: dir) else { return }
        outputPath = url.path
        outputChosenByUser = true
    }

    // MARK: Validation

    var validationMessage: String? {
        guard sourcePath != nil else { return "Choose a file or folder to encrypt." }
        guard outputPath != nil else { return "Choose where to save the encrypted file." }
        switch mode {
        case .password:
            if password.isEmpty { return "Enter a password." }
            if password.count < PasswordStrength.minimumLength {
                return "Use at least \(PasswordStrength.minimumLength) characters."
            }
            if password != confirmation { return "The two passwords don't match." }
        case .splitKey:
            if !(2...20).contains(threshold) || !(2...20).contains(total) || threshold > total {
                return "Enter numbers between 2 and 20, with Required to unlock no larger than Total people."
            }
        }
        return nil
    }

    var canRun: Bool { !isRunning && validationMessage == nil }

    // MARK: Run

    func encrypt() {
        guard canRun, let output = outputPath else { return }
        // Always ask, even after the save panel's own replace prompt: the
        // source or output may have changed since, and the file being
        // replaced may be the only ciphertext of an earlier run.
        if Paths.exists(output) {
            confirmReplace = true
            return
        }
        start()
    }

    func encryptReplacingExisting() {
        start()
    }

    private func start() {
        guard let source = sourcePath, let output = outputPath else { return }
        let credential: CoreRequest.Credential = mode == .password
            ? .password(password)
            : .splitKey(k: threshold, n: total)
        isRunning = true
        isCancelling = false
        progress = nil
        error = nil
        status = nil
        result = nil
        task = Task { [core] in
            do {
                let result: EncryptResult = try await core.perform(
                    .encrypt(source: source, output: output, credential: credential)
                ) { p in
                    Task { @MainActor [weak self] in self?.progress = p }
                }
                finish(result)
            } catch let error as CoreError {
                fail(error)
            } catch {
                fail(CoreError(code: .internal, message: error.localizedDescription, detail: "\(error)"))
            }
        }
    }

    private func finish(_ result: EncryptResult) {
        isRunning = false
        isCancelling = false
        progress = nil
        self.result = result
        password = ""
        confirmation = ""
        if let shares = result.shares, !shares.isEmpty, let k = result.threshold, let n = result.total {
            sharesToShow = SharesPresentation(
                shares: shares,
                context: ShareFiles.Context(stem: Format.stem(result.output),
                                            protectedName: result.filename, k: k, n: n, kind: .qcxFile))
        }
    }

    private func fail(_ error: CoreError) {
        isRunning = false
        isCancelling = false
        progress = nil
        if error.isCancellation {
            status = error.message
        } else {
            self.error = error
        }
    }

    /// The helper has up to `cancelGrace` to acknowledge, so say so rather
    /// than leaving a percentage climbing under a user who asked it to stop.
    func cancel() {
        guard isRunning else { return }
        isCancelling = true
        task?.cancel()
    }

    func reset() {
        guard !isRunning else { return }
        sourcePath = nil
        sourceDetail = nil
        sourceIsFolder = false
        outputPath = nil
        outputChosenByUser = false
        password = ""
        confirmation = ""
        result = nil
        error = nil
        status = nil
        wrongSection = nil
    }
}
