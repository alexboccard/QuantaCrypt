import Foundation
import Observation
import UniformTypeIdentifiers

@MainActor
@Observable
final class DecryptModel {
    static let noRecoveryNote = "There is no way to recover this file without the password."

    private let core: CoreClient
    private let recents: RecentStore

    var filePath: String?
    var info: InspectInfo?
    var inspecting = false
    var inspectError: CoreError?

    var password = ""
    var shares: [String] = []
    var outputDir: String = Paths.defaultOutputFolder ?? Paths.homeDirectory
    private var outputChosenByUser = false

    var progress: CoreProgress?
    var isRunning = false
    var isVerifying = false
    var error: CoreError?
    var errorNote: String?
    var status: String?
    var result: DecryptResult?
    var verifiedNote: String?
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

    func load(path: String) {
        guard !isRunning else { return }
        filePath = path
        info = nil
        inspectError = nil
        result = nil
        error = nil
        errorNote = nil
        status = nil
        verifiedNote = nil
        wrongPasswordCount = 0
        password = ""
        if !outputChosenByUser { outputDir = Paths.defaultOutputFolder ?? Format.directory(path) }
        inspecting = true
        Task { [core] in
            do {
                let info: InspectInfo = try await core.perform(.inspect(path: path))
                guard filePath == path else { return }
                self.info = info
                let needed = info.threshold ?? 2
                if info.isSplitKey, shares.count < needed {
                    shares = Array(repeating: "", count: needed)
                } else if !info.isSplitKey {
                    shares = []
                }
            } catch let error as CoreError {
                if filePath == path { inspectError = error }
            } catch {
                if filePath == path {
                    inspectError = CoreError(code: .internal, message: error.localizedDescription, detail: "\(error)")
                }
            }
            if filePath == path { inspecting = false }
        }
    }

    func chooseOutputDir() {
        guard let url = Panels.chooseFolder(message: "Choose where the decrypted file goes.",
                                            directory: URL(fileURLWithPath: outputDir)) else { return }
        outputDir = url.path
        outputChosenByUser = true
    }

    func loadSharesFromFiles() {
        let urls = Panels.chooseFiles(types: [.plainText, .text, .item], message: "Choose one or more share files.")
        guard !urls.isEmpty else { return }
        var loaded: [String] = []
        for url in urls {
            guard let text = try? String(contentsOf: url, encoding: .utf8) else { continue }
            loaded.append(contentsOf: ShareFiles.parse(text))
        }
        guard !loaded.isEmpty else {
            status = "No shares were found in \(urls.count == 1 ? "that file" : "those files")."
            return
        }
        status = nil
        var merged = shares.filter { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
        for share in loaded where !merged.contains(share) { merged.append(share) }
        let needed = info?.threshold ?? merged.count
        while merged.count < needed { merged.append("") }
        if let total = info?.total, merged.count > total { merged = Array(merged.prefix(total)) }
        shares = merged
    }

    // MARK: Validation

    private var trimmedShares: [String] {
        shares.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
    }

    var validationMessage: String? {
        guard filePath != nil else { return "Choose an encrypted file." }
        guard let info else { return inspectError == nil ? "Reading the file…" : "This file can't be read." }
        if info.isSplitKey {
            let filled = trimmedShares.filter { !$0.isEmpty }
            let needed = info.threshold ?? 2
            if filled.count < needed {
                let empty = trimmedShares.enumerated().filter { $0.element.isEmpty }.map { "\($0.offset + 1)" }
                return "Enter \(needed) shares — share\(empty.count == 1 ? "" : "s") \(empty.joined(separator: ", ")) \(empty.count == 1 ? "is" : "are") empty."
            }
            var seen: [String: Int] = [:]
            for (i, share) in filled.enumerated() {
                if let first = seen[share] { return "Shares \(first + 1) and \(i + 1) are the same share." }
                seen[share] = i
            }
        } else if password.isEmpty {
            return "Enter the password."
        }
        return nil
    }

    var canRun: Bool { !isRunning && validationMessage == nil }

    // MARK: Run

    func decrypt() { start(verifyOnly: false) }
    func verify() { start(verifyOnly: true) }

    private func start(verifyOnly: Bool) {
        guard canRun, let path = filePath, let info else { return }
        let credential: CoreRequest.Credential = info.isSplitKey
            ? .shares(trimmedShares.filter { !$0.isEmpty })
            : .password(password)
        isRunning = true
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
                    finishVerify()
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

    private func finishVerify() {
        isRunning = false
        progress = nil
        verifiedNote = info?.isSplitKey == true
            ? "These shares unlock the file. Nothing was written."
            : "The password is correct. Nothing was written."
    }

    private func finish(_ result: DecryptResult, path: String) {
        isRunning = false
        progress = nil
        self.result = result
        password = ""
        recents.add(path, kind: .decrypted)
    }

    private func fail(_ error: CoreError, info: InspectInfo) {
        isRunning = false
        progress = nil
        if error.isCancellation {
            status = error.message
            return
        }
        guard error.code == .wrongCredentials else {
            self.error = error
            return
        }
        if info.isSplitKey {
            let k = info.threshold.map(String.init) ?? "the required"
            let n = info.total.map(String.init) ?? "its"
            self.error = CoreError(
                code: error.code,
                message: "These shares don't unlock this file. Any \(k) of the \(n) shares will work, so try swapping in a different share — QuantaCrypt can't tell which one is wrong.",
                detail: error.detail)
        } else {
            wrongPasswordCount += 1
            self.error = CoreError(code: error.code,
                                   message: "The password is incorrect. Check Caps Lock and try again.",
                                   detail: error.detail)
            if wrongPasswordCount >= 3 { errorNote = Self.noRecoveryNote }
        }
    }

    func cancel() {
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
