import Foundation
import Observation

@MainActor
@Observable
final class VolumesModel {
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
    var createCancelling = false
    var createError: CoreError?
    var createStatus: String?
    var createResult: VolumeCreateResult?
    var sharesToShow: SharesPresentation? {
        didSet { if sharesToShow != nil { sharesSaved = false } }
    }
    /// Whether the shares on screen have been written somewhere durable.
    /// Read by the quit guard — the sheet's own state dies with the sheet.
    var sharesSaved = false
    var offerMountAfterCreate = false

    // Mount
    var mountPath: String?
    var mountInfo: VolumeInspectInfo?
    var mountInspecting = false
    /// Why the auth block could not be read; the credential picker then
    /// stands in for it.
    var mountInspectError: CoreError?
    var mountPoint = ""
    private var mountPointChosenByUser = false
    var mountCredential: MountCredential = .password
    var mountPassword = ""
    var mountShares: [String] = ["", ""]
    var mountProgress: CoreProgress?
    var mountRunning = false
    var mountCancelling = false
    var mountError: CoreError?
    var mountStatus: String?
    var mountedNote: String?
    var suspiciousVolume: MountedVolume?

    // Mounted list
    var mounted: [MountedVolume] = []
    var listLoaded = false
    /// Consecutive `volume_list` failures. The list is a poll, so one miss is
    /// noise; a run of them means what is on screen is fiction.
    private var listFailures = 0
    var listIsStale: Bool { listFailures >= 2 }
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

    enum MountSupport: Equatable { case unknown, missing, ready }

    /// `fuse == nil` is "not checked yet", not "not installed" — sending the
    /// user to Homebrew because a check is still in flight, or because the
    /// helper is down, wastes their time on the wrong problem.
    var mountSupport: MountSupport {
        guard let fuse else { return .unknown }
        return fuse.ok ? .ready : .missing
    }

    var mountingAvailable: Bool { mountSupport == .ready }

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
        if mountRunning { return "Wait for the volume that is opening to finish." }
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
        createCancelling = false
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
                createCancelling = false
                createProgress = nil
                if error.isCancellation { createStatus = error.message } else { createError = error }
            } catch {
                createRunning = false
                createCancelling = false
                createProgress = nil
                createError = CoreError(code: .internal, message: error.localizedDescription, detail: "\(error)")
            }
        }
    }

    private func finishCreate(_ result: VolumeCreateResult) {
        createRunning = false
        createCancelling = false
        createProgress = nil
        createResult = result
        createPassword = ""
        createConfirmation = ""
        if !result.shares.isEmpty, let k = result.threshold, let n = result.total {
            sharesToShow = SharesPresentation(
                shares: result.shares,
                context: ShareFiles.Context(stem: Format.stem(result.path),
                                            protectedName: Format.fileName(result.path), k: k, n: n, kind: .qcvVolume))
        } else {
            offerMountAfterCreate = true
        }
    }

    func sharesSheetDismissed() {
        if createResult != nil { offerMountAfterCreate = true }
    }

    func cancelCreate() {
        guard createRunning else { return }
        createCancelling = true
        createTask?.cancel()
    }

    /// Second chance at the shares of a volume that has already been created
    /// — without it, one click on "Discard shares" seals the volume forever.
    func showSharesAgain() {
        guard let result = createResult, !result.shares.isEmpty,
              let k = result.threshold, let n = result.total else { return }
        sharesToShow = SharesPresentation(
            shares: result.shares,
            context: ShareFiles.Context(stem: Format.stem(result.path),
                                        protectedName: Format.fileName(result.path),
                                        k: k, n: n, kind: .qcvVolume))
    }

    var canShowSharesAgain: Bool {
        guard let result = createResult else { return false }
        return !result.shares.isEmpty && result.threshold != nil && result.total != nil
    }

    func mountCreatedVolume() {
        guard let result = createResult else { return }
        prepareMount(path: result.path)
        mountCredential = result.mode == "shamir" ? .shares : .password
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

    /// Select `path` for mounting. Returns false — with the reason in
    /// `mountStatus` — while a mount is running.
    @discardableResult
    func prepareMount(path: String) -> Bool {
        guard !mountRunning else {
            mountStatus = EncryptModel.busyMessage(for: path)
            return false
        }
        mountPath = path
        mountError = nil
        mountStatus = nil
        mountedNote = nil
        if !mountPointChosenByUser { mountPoint = Self.defaultMountPoint(for: path) }
        mountInfo = nil
        mountInspectError = nil
        mountInspecting = true
        // Read the auth block so the right credential entry appears without
        // asking the user how the volume is protected. When that fails the
        // reason is shown and the "Unlock with" picker takes over.
        Task { [core] in
            defer { if mountPath == path { mountInspecting = false } }
            do {
                let info: VolumeInspectInfo = try await core.perform(.volumeInspect(path: path))
                guard mountPath == path else { return }
                mountInfo = info
                mountCredential = info.isSplitKey ? .shares : .password
                let needed = info.threshold ?? 2
                if info.isSplitKey, mountShares.count < needed {
                    mountShares = Array(repeating: "", count: needed)
                }
            } catch let error as CoreError {
                guard mountPath == path else { return }
                mountInspectError = Self.inspectFailure(error)
            } catch {
                guard mountPath == path else { return }
                mountInspectError = Self.inspectFailure(
                    CoreError(code: .internal, message: error.localizedDescription, detail: "\(error)"))
            }
        }
        return true
    }

    static func inspectFailure(_ error: CoreError) -> CoreError {
        CoreError(code: error.code, message: "Couldn't read this volume: \(error.message)", detail: error.detail)
    }

    func chooseMountPoint() {
        guard let url = Panels.chooseFolder(message: "Choose an empty folder to mount the volume at.",
                                            prompt: "Mount Here",
                                            directory: URL(fileURLWithPath: Self.mountRoot)) else { return }
        mountPoint = url.path
        mountPointChosenByUser = true
    }

    func loadMountSharesFromFiles() {
        let urls = Panels.chooseFiles(types: ShareFiles.fileTypes, message: "Choose one or more share files.")
        guard !urls.isEmpty else { return }
        let (loaded, problems) = ShareFiles.load(urls)
        guard !loaded.isEmpty else {
            mountStatus = problems.first ?? "No shares were found in \(urls.count == 1 ? "that file" : "those files")."
            return
        }
        mountShares = ShareValidation.merge(loaded, into: mountShares,
                                            threshold: mountInfo?.threshold ?? 2, total: mountInfo?.total)
        mountStatus = problems.first
    }

    var mountValidationMessage: String? {
        if createRunning { return "Wait for the volume being created to finish." }
        guard mountPath != nil else { return "Choose a volume file." }
        if mountPoint.trimmingCharacters(in: .whitespaces).isEmpty { return "Choose where to mount it." }
        switch mountCredential {
        case .password:
            if mountPassword.isEmpty { return "Enter the password." }
        case .shares:
            // The inspected threshold when the auth block was readable;
            // otherwise any two or more and the helper says how many it needs.
            return ShareValidation.message(shares: mountShares, threshold: mountInfo?.threshold)
        }
        return nil
    }

    var canMount: Bool { !mountRunning && mountValidationMessage == nil }

    /// The form is complete *and* this Mac can mount: the toolbar button,
    /// its ⌘↩ shortcut and the inline button all key off this one gate.
    var canMountNow: Bool { canMount && mountingAvailable }

    /// Why the mount action is unavailable, for the buttons' help text.
    var mountBlockedMessage: String? {
        if let message = mountValidationMessage { return message }
        switch mountSupport {
        case .ready: return nil
        case .unknown:
            return fuseError == nil
                ? "Checking whether this Mac can open volumes as drives…"
                : "Couldn't check whether this Mac can mount volumes — the helper isn't responding."
        case .missing: return "Install disk mounting support first."
        }
    }

    func mount() {
        guard canMountNow, let path = mountPath else { return }
        let credential: CoreRequest.Credential = mountCredential == .password
            ? .password(mountPassword)
            : .shares(ShareValidation.prepared(mountShares))
        let target = (mountPoint as NSString).expandingTildeInPath
        mountRunning = true
        mountCancelling = false
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
                mountCancelling = false
                mountProgress = nil
                if error.isCancellation {
                    mountStatus = error.message
                } else {
                    mountError = Self.friendlyMountError(error, credential: mountCredential, path: path)
                }
            } catch {
                mountRunning = false
                mountCancelling = false
                mountProgress = nil
                mountError = CoreError(code: .internal, message: error.localizedDescription, detail: "\(error)")
            }
        }
    }

    /// Only `wrong_credentials`, `permission_denied` and a FUSE startup
    /// failure are reworded; a `format` (damaged payload) or `invalid_input`
    /// (unreadable share) error keeps the helper's message.
    static func friendlyMountError(_ error: CoreError, credential: MountCredential, path: String) -> CoreError {
        switch error.code {
        case .wrongCredentials where credential == .password:
            return CoreError(code: error.code, message: "The password is incorrect. Check Caps Lock and try again.",
                             detail: error.detail)
        case .wrongCredentials:
            return CoreError(code: error.code,
                             message: "These shares don't unlock this volume. Try swapping in a different share — QuantaCrypt can't tell which one is wrong.",
                             detail: error.detail)
        case .permissionDenied:
            return CoreError(code: error.code,
                             message: "QuantaCrypt can't create the mount point. Choose a folder inside your home folder, such as ~/QuantaCrypt Volumes/\(Format.stem(path)).",
                             detail: error.detail)
        case .io where error.message.contains("FUSE mount failed"):
            // The helper interpolates the raw OSError here, so the two most
            // common real failures arrive as "[Errno 1] Operation not
            // permitted" with no cause and nowhere to go.
            return CoreError(
                code: error.code,
                message: "Couldn't open the volume as a drive. Check that the folder it mounts at is empty and not already in use, and that macFUSE or FUSE-T is allowed in System Settings ▸ Privacy & Security.",
                detail: error.detail.isEmpty ? error.message : "\(error.message)\n\(error.detail)")
        default:
            return error
        }
    }

    private func finishMount(_ result: VolumeMountResult, path: String) {
        mountRunning = false
        mountCancelling = false
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
        guard mountRunning else { return }
        mountCancelling = true
        mountTask?.cancel()
        // The FUSE startup wait has no cancel check inside it, so a cancelled
        // mount often succeeds anyway. Refresh straight away rather than
        // leaving "Cancelled" standing next to a volume that did mount.
        Task { await refreshMounted() }
    }

    // MARK: Mounted list

    func refreshMounted() async {
        do {
            let list: VolumeListResult = try await core.perform(.volumeList)
            mounted = list.volumes.sorted { $0.mountPoint < $1.mountPoint }
            listFailures = 0
            listLoaded = true
        } catch {
            // Polling: one transient failure just keeps the last list, but a
            // run of them means the rows on screen no longer describe reality.
            listFailures += 1
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
