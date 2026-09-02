import AppKit
import os
import Observation

enum AppSection: String, CaseIterable, Identifiable, Hashable {
    case encrypt, decrypt, volumes

    var id: String { rawValue }

    var title: String {
        switch self {
        case .encrypt: return "Encrypt"
        case .decrypt: return "Decrypt"
        case .volumes: return "Volumes"
        }
    }

    var systemImage: String {
        switch self {
        case .encrypt: return "lock"
        case .decrypt: return "lock.open"
        case .volumes: return "externaldrive"
        }
    }
}

enum HelperStatus: Equatable {
    case starting
    case ready(VersionInfo)
    case failed(CoreError)
}

/// Everything the window, the menu bar and the delegate share.
@MainActor
@Observable
final class AppState {
    let core: CoreClient
    let recents: RecentStore
    let encrypt: EncryptModel
    let decrypt: DecryptModel
    let volumes: VolumesModel

    var section: AppSection? = .encrypt
    var helperStatus: HelperStatus = .starting

    static let readmeURL = URL(string: "https://github.com/alexboccard/QuantaCrypt#readme")!

    init(core: CoreClient = .live(), recents: RecentStore = RecentStore()) {
        self.core = core
        self.recents = recents
        self.encrypt = EncryptModel(core: core)
        self.decrypt = DecryptModel(core: core, recents: recents)
        self.volumes = VolumesModel(core: core, recents: recents)
    }

    /// Launch the helper and read its version for the status item.
    func start() {
        Task { await refreshHelperStatus() }
    }

    func refreshHelperStatus() async {
        helperStatus = .starting
        do {
            let info: VersionInfo = try await core.perform(.version)
            helperStatus = .ready(info)
            Logger.client.info("helper ready: qc-core \(info.version, privacy: .public)")
        } catch let error as CoreError {
            helperStatus = .failed(error)
        } catch {
            helperStatus = .failed(CoreError(code: .helperUnavailable, message: error.localizedDescription, detail: ""))
        }
    }

    func restartHelper() {
        Task {
            await core.restart()
            await refreshHelperStatus()
        }
    }

    // MARK: Routing

    func open(_ urls: [URL]) {
        for url in urls { open(url) }
    }

    func open(_ url: URL) {
        switch url.pathExtension.lowercased() {
        case "qcx":
            section = .decrypt
            decrypt.load(path: url.path)
        case "qcv":
            section = .volumes
            volumes.prepareMount(path: url.path)
        default:
            section = .encrypt
            encrypt.setSource(url.path)
        }
    }

    // MARK: Menu commands

    func openDocument() {
        guard let url = Panels.chooseFile(types: [.qcx, .qcv], message: "Choose an encrypted file or volume.") else { return }
        open(url)
    }

    func encryptFile() {
        section = .encrypt
        encrypt.chooseSource()
    }

    func decryptFile() {
        section = .decrypt
        decrypt.chooseFile()
    }

    func mountVolume() {
        section = .volumes
        volumes.chooseVolumeToMount()
    }
}
