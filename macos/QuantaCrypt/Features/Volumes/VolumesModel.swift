import Foundation
import Observation

@MainActor
@Observable
final class VolumesModel {
    enum Job { case create, mount }
    enum MountCredential: String, CaseIterable, Identifiable {
        case password = "Password"
        case shares = "Split key"
        var id: String { rawValue }
    }

    static let brewCommand = "brew install --cask fuse-t"
    static let brewAlternative = "brew install --cask macfuse"
    static let mountRoot = (Paths.homeDirectory as NSString).appendingPathComponent("QuantaCrypt Volumes")

    private let core: CoreClient
    private let recents: RecentStore

    // FUSE gate
    var fuse: FuseCheck?
    var fuseChecking = false
    var fuseCheckNote: String?
    var fuseError: CoreError?

    // Which section the toolbar's primary action drives.
    var activeJob: Job = .mount

    // Create
    var createName = ""
    var createDirectory = (Paths.homeDirectory as NSString).appendingPathComponent("Documents")
    var createMode: ProtectionMode = .password
    var createPassword = ""
    var createConfirmation = ""
    var createThreshold = 2
    var createTotal = 3
    var createProgress: CoreProgress?
    var createRunning = false
    var createError: CoreError?
    var createStatus: String?
    var createResult: VolumeCreateResult?
    var sharesToShow: SharesPresentation?
    var offerMountAfterCreate = false

    // Mount
    var mountPath: String?
    var mountInfo: VolumeInspectInfo?
    var mountInspecting = false
    var mountPoint = ""
    private var mountPointChosenByUser = false
    var mountCredential: MountCredential = .password
    var mountPassword = ""
    var mountShares: [String] = ["", ""]
    var mountProgress: CoreProgress?
    var mountRunning = false
    var mountError: CoreError?
    var mountStatus: String?
    var mountedNote: String?
    var suspiciousVolume: MountedVolume?

    // Mounted list
    var mounted: [MountedVolume] = []
    var listLoaded = false
    var unmountCandidate: MountedVolume?
    var unmounting: Set<String> = []
    var unmountError: CoreError?

    private var createTask: Task<Void, Never>?
    private var mountTask: Task<Void, Never>?

    init(core: CoreClient, recents: RecentStore) {
        self.core = core
        self.recents = recents
    }

    // MARK: FUSE

    var mountingAvailable: Bool { fuse?.ok ?? false }

    func checkFuse(userInitiated: Bool = false) async {
        fuseChecking = true
        let before = fuse
        do {
            let check: FuseCheck = try await core.perform(.fuseCheck)
            fuse = check
            fuseError = nil
            if userInitiated {
                fuseCheckNote = check.ok
                    ? "Disk mounting is ready."
                    : (before == check ? "Checked just now — still missing: \(check.missingSummary)."
                                       : "Still missing: \(check.missingSummary).")
            }
        } catch let error as CoreError {
            fuseError = error
        } catch {
            fuseError = CoreError(code: .internal, message: error.localizedDescription, detail: "\(error)")
        }
        fuseChecking = false
    }

    // MARK: Create

    var createPath: String {
        let name = createName.trimmingCharacters(in: .whitespacesAndNewlines)
        let file = name.lowercased().hasSuffix(".qcv") ? name : name + ".qcv"
        return (createDirectory as NSString).appendingPathComponent(file)
    }

    func chooseCreateLocation() {
        let name = createName.isEmpty ? "Vault" : createName
        guard let url = Panels.save(suggestedName: name.lowercased().hasSuffix(".qcv") ? name : name + ".qcv",
                                    type: .qcv, message: "Choose a name and location for the new volume.",
                                    directory: URL(fileURLWithPath: createDirectory)) else { return }
        createName = url.deletingPathExtension().lastPathComponent
        createDirectory = url.deletingLastPathComponent().path
    }

    var createValidationMessage: String? {
        let name = createName.trimmingCharacters(in: .whitespacesAndNewlines)
        if name.isEmpty { return "Give the volume a name." }
        if name.contains("/") { return "The name can't contain a slash." }
        if Paths.exists(createPath) { return "\(Format.fileName(createPath)) already exists — choose another name or location." }
        switch createMode {
        case .password:
            if createPassword.isEmpty { return "Enter a password." }
            if createPassword.count < PasswordStrength.minimumLength {
                return "Use at least \(PasswordStrength.minimumLength) characters."
            }
            if createPassword != createConfirmation { return "The two passwords don't match." }
        case .splitKey:
            if !(2...20).contains(createThreshold) || !(2...20).contains(createTotal) || createThreshold > createTotal {
                return "Enter numbers between 2 and 20, with Required to unlock no larger than Total people."
            }
        }
        return nil
    }

    var canCreate: Bool { !createRunning && createValidationMessage == nil }

    func createVolume() {
        guard canCreate else { return }
        let path = createPath
        let credential: CoreRequest.Credential = createMode == .password
            ? .password(createPassword)
            : .splitKey(k: createThreshold, n: createTotal)
        createRunning = true
        createProgress = nil
        createError = nil
        createStatus = nil
        createResult = nil
        createTask = Task { [core] in
            do {
                let result: VolumeCreateResult = try await core.perform(
                    .volumeCreate(path: path, credential: credential)
                ) { p in
                    Task { @MainActor [weak self] in self?.createProgress = p }
                }
                finishCreate(result)
            } catch let error as CoreError {
                createRunning = false
                createProgress = nil
                if error.isCancellation { createStatus = error.message } else { createError = error }
            } catch {
                createRunning = false
                createProgress = nil
                createError = CoreError(code: .internal, message: error.localizedDescription, detail: "\(error)")
            }
        }
    }

    private func finishCreate(_ result: VolumeCreateResult) {
        createRunning = false
        createProgress = nil
        createResult = result
        createPassword = ""
        createConfirmation = ""
        if !result.shares.isEmpty, let k = result.threshold, let n = result.total {
            sharesToShow = SharesPresentation(
                shares: result.shares,
                context: ShareFiles.Context(stem: Format.stem(result.path),
                                            protectedName: Format.fileName(result.path), k: k, n: n))
        } else {
            offerMountAfterCreate = true
        }
    }

    func sharesSheetDismissed() {
        if createResult != nil { offerMountAfterCreate = true }
    }

    func cancelCreate() {
        createTask?.cancel()
    }

    func mountCreatedVolume() {
        guard let result = createResult else { return }
        prepareMount(path: result.path)
        mountCredential = result.mode == "shamir" ? .shares : .password
        activeJob = .mount
    }

    // MARK: Mount

    static func defaultMountPoint(for volumePath: String) -> String {
        (mountRoot as NSString).appendingPathComponent(Format.stem(volumePath))
    }

    func chooseVolumeToMount() {
        guard let url = Panels.chooseFile(types: [.qcv], message: "Choose a volume to mount.") else { return }
        prepareMount(path: url.path)
    }

    static func accepts(_ url: URL) -> Bool {
        url.pathExtension.lowercased() == "qcv"
    }

    func prepareMount(path: String) {
        guard !mountRunning else { return }
        mountPath = path
        mountError = nil
        mountStatus = nil
        mountedNote = nil
        if !mountPointChosenByUser { mountPoint = Self.defaultMountPoint(for: path) }
        activeJob = .mount
        mountInfo = nil
        mountInspecting = true
        // Read the auth block so the right credential entry appears without
        // asking the user how the volume is protected.
        Task { [core] in
            defer { if mountPath == path { mountInspecting = false } }
            guard let info: VolumeInspectInfo = try? await core.perform(.volumeInspect(path: path)),
                  mountPath == path else { return }
            mountInfo = info
            mountCredential = info.isSplitKey ? .shares : .password
            let needed = info.threshold ?? 2
            if info.isSplitKey, mountShares.count < needed {
                mountShares = Array(repeating: "", count: needed)
            }
        }
    }

    func chooseMountPoint() {
        guard let url = Panels.chooseFolder(message: "Choose an empty folder to mount the volume at.",
                                            prompt: "Mount Here",
                                            directory: URL(fileURLWithPath: Self.mountRoot)) else { return }
        mountPoint = url.path
        mountPointChosenByUser = true
    }

    func loadMountSharesFromFiles() {
        let urls = Panels.chooseFiles(types: [.plainText, .text, .item], message: "Choose one or more share files.")
        guard !urls.isEmpty else { return }
        var loaded: [String] = []
        for url in urls {
            guard let text = try? String(contentsOf: url, encoding: .utf8) else { continue }
            loaded.append(contentsOf: ShareFiles.parse(text))
        }
        guard !loaded.isEmpty else {
            mountStatus = "No shares were found in \(urls.count == 1 ? "that file" : "those files")."
            return
        }
        var merged = mountShares.filter { !$0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty }
        for share in loaded where !merged.contains(share) { merged.append(share) }
        while merged.count < 2 { merged.append("") }
        mountShares = merged
        mountStatus = nil
    }

    private var trimmedMountShares: [String] {
        mountShares.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
    }

    var mountValidationMessage: String? {
        guard mountPath != nil else { return "Choose a volume file." }
        if mountPoint.trimmingCharacters(in: .whitespaces).isEmpty { return "Choose where to mount it." }
        switch mountCredential {
        case .password:
            if mountPassword.isEmpty { return "Enter the password." }
        case .shares:
            let filled = trimmedMountShares
            if filled.count < 2 { return "Enter at least 2 shares." }
            var seen: [String: Int] = [:]
            for (i, share) in filled.enumerated() {
                if let first = seen[share] { return "Shares \(first + 1) and \(i + 1) are the same share." }
                seen[share] = i
            }
        }
        return nil
    }

    var canMount: Bool { !mountRunning && mountValidationMessage == nil }

    func mount() {
        guard canMount, let path = mountPath else { return }
        let credential: CoreRequest.Credential = mountCredential == .password
            ? .password(mountPassword)
            : .shares(trimmedMountShares)
        let target = (mountPoint as NSString).expandingTildeInPath
        mountRunning = true
        mountProgress = nil
        mountError = nil
        mountStatus = nil
        mountedNote = nil
        mountTask = Task { [core] in
            do {
                let result: VolumeMountResult = try await core.perform(
                    .volumeMount(path: path, mountPoint: target, credential: credential)
                ) { p in
                    Task { @MainActor [weak self] in self?.mountProgress = p }
                }
                finishMount(result, path: path)
            } catch let error as CoreError {
                mountRunning = false
                mountProgress = nil
                if error.isCancellation {
                    mountStatus = error.message
                } else {
                    mountError = friendlyMountError(error, path: path)
                }
            } catch {
                mountRunning = false
                mountProgress = nil
                mountError = CoreError(code: .internal, message: error.localizedDescription, detail: "\(error)")
            }
        }
    }

    private func friendlyMountError(_ error: CoreError, path: String) -> CoreError {
        switch error.code {
        case .wrongCredentials where mountCredential == .password:
            return CoreError(code: error.code, message: "The password is incorrect. Check Caps Lock and try again.",
                             detail: error.detail)
        case .wrongCredentials:
            return CoreError(code: error.code,
                             message: "These shares don't unlock this volume. Try swapping in a different share — QuantaCrypt can't tell which one is wrong.",
                             detail: error.detail)
        case .io where error.detail.contains("PermissionError"):
            return CoreError(code: error.code,
                             message: "QuantaCrypt can't create the mount point. Choose a folder inside your home folder, such as ~/QuantaCrypt Volumes/\(Format.stem(path)).",
                             detail: error.detail)
        default:
            return error
        }
    }

    private func finishMount(_ result: VolumeMountResult, path: String) {
        mountRunning = false
        mountProgress = nil
        mountPassword = ""
        recents.add(path, kind: .mounted)
        let volume = MountedVolume(mountPoint: result.mountPoint, volumePath: result.volumePath ?? path, stats: nil)
        if result.journalSuspicious {
            suspiciousVolume = volume
        } else {
            mountedNote = "Mounted \(volume.name) at \(Format.tildePath(result.mountPoint))."
        }
        Task { await refreshMounted() }
    }

    func cancelMount() {
        mountTask?.cancel()
    }

    // MARK: Mounted list

    func refreshMounted() async {
        do {
            let list: VolumeListResult = try await core.perform(.volumeList)
            mounted = list.volumes.sorted { $0.mountPoint < $1.mountPoint }
            listLoaded = true
        } catch {
            // Polling: a transient failure just keeps the last list.
            listLoaded = true
        }
    }

    /// Poll while the Volumes screen is on screen; cancelled with the view.
    func pollMounted() async {
        if fuse == nil { await checkFuse() }
        while !Task.isCancelled {
            await refreshMounted()
            try? await Task.sleep(for: .seconds(3))
        }
    }

    func requestUnmount(_ volume: MountedVolume) {
        unmountCandidate = volume
    }

    func unmount(_ volume: MountedVolume) {
        guard !unmounting.contains(volume.mountPoint) else { return }
        unmounting.insert(volume.mountPoint)
        unmountError = nil
        Task { [core] in
            do {
                _ = try await core.perform(.volumeUnmount(mountPoint: volume.mountPoint))
                mountedNote = "Unmounted \(volume.name)."
            } catch let error as CoreError {
                unmountError = error.code == .busy || error.code == .io
                    ? CoreError(code: error.code,
                                message: "Something is still using \(volume.name). Close Finder windows or apps opened from it, then try again.",
                                detail: error.detail)
                    : error
            } catch {
                unmountError = CoreError(code: .internal, message: error.localizedDescription, detail: "\(error)")
            }
            unmounting.remove(volume.mountPoint)
            await refreshMounted()
        }
    }
}
