import Foundation
import Security

/// Finds the `qc-core` helper. Order: user override (Settings) → bundled
/// auxiliary executable → `Contents/Helpers/qc-core` → (DEBUG only)
/// `QC_CORE_PATH`, then the development virtualenv.
///
/// Every password and every Shamir share is written to the resolved binary's
/// stdin, and the app is unsandboxed — so a `defaults write
/// com.alexboccard.quantacrypt helperPathOverride …` by any user-level
/// process used to redirect all of it silently, surviving app deletion
/// because macOS keeps preference domains. An override outside the app
/// bundle is therefore refused until the user approves that exact path in
/// Settings, in this session.
enum HelperLocator {
    static let overrideDefaultsKey = "helperPathOverride"
    static let devVenv = "/Users/xelaboc/Projects/Quantacrypt/.venv"

    /// What a helper's code signature is checked against.
    ///
    /// `scripts/build.py --helper` ad-hoc signs the helper bundle (`codesign
    /// --sign -`), whose signing identifier is its bundle id; the two older
    /// layouts sign a bare Mach-O, whose identifier is its file name. Ad-hoc
    /// signing has no team ID and no certificate chain, so this is the only
    /// thing a requirement can name today — and anyone can run `codesign
    /// --sign - --identifier com.alexboccard.quantacrypt.core evil`. It is an
    /// integrity check, not an authenticity one, which is exactly why
    /// `overrideRefusal` also requires the user's approval for anything
    /// outside the app bundle. **After notarization** this becomes
    /// `anchor apple generic and certificate leaf[subject.OU] = "<TEAMID>"`,
    /// which does prove authorship, and the approval step can relax to
    /// "refuse anything that fails the requirement".
    static let requirementString =
        #"identifier "com.alexboccard.quantacrypt.core" or identifier "qc-core""#

    struct Resolution: Sendable {
        let launch: HelperLaunch?
        let searched: [String]
        /// An override that pointed at a real executable but was refused, and
        /// why. Surfaced by Settings — a silently ignored override looks like
        /// the app is honouring it.
        let refusal: Refusal?

        init(launch: HelperLaunch?, searched: [String], refusal: Refusal? = nil) {
            self.launch = launch
            self.searched = searched
            self.refusal = refusal
        }
    }

    /// A refused override: the path, and the sentence shown to the user.
    struct Refusal: Sendable, Equatable {
        let path: String
        let reason: String
        /// False when no approval can rescue it (an unsigned binary), so the
        /// UI does not offer a button that cannot work.
        let approvable: Bool
    }

    /// What the code signature of a candidate says about it.
    ///
    /// `satisfiesPin` carries the code directory hash — the identity of
    /// *these bytes*, not of the path they happen to sit at.
    enum SignatureStatus: Sendable, Equatable {
        case satisfiesPin(cdHash: Data)
        case signedButUnpinned(String)
        case unsigned(String)

        var cdHash: Data? {
            guard case .satisfiesPin(let hash) = self else { return nil }
            return hash
        }
    }

    // MARK: Per-launch approval

    /// Approvals live in memory only: a second `defaults write` must not be
    /// able to grant what the first one asked for. The user re-approves after
    /// every launch, which is the point — the prompt is the signal.
    ///
    /// The value is the code hash the user was shown, not just the path. An
    /// approval used to be "this path is trusted for the session", so anything
    /// that could write to the approved path could swap in a different binary
    /// — signed with anything, ad-hoc included — and inherit the click.
    private final class Approvals: @unchecked Sendable {
        private let lock = NSLock()
        private var hashes: [String: Data] = [:]
        func matches(_ path: String, _ cdHash: Data) -> Bool {
            lock.withLock { hashes[path] == cdHash }
        }
        func insert(_ path: String, _ cdHash: Data) { lock.withLock { hashes[path] = cdHash } }
    }
    private static let approvals = Approvals()

    /// Record that the user chose to trust the binary now at `path` for the
    /// rest of this run. Only ever called from an explicit click in Settings.
    /// Returns false when the file no longer satisfies the pin, in which case
    /// nothing is recorded — the click approved what was on screen.
    @discardableResult
    static func approve(_ path: String) -> Bool {
        let url = URL(fileURLWithPath: (path as NSString).expandingTildeInPath).standardizedFileURL
        guard let cdHash = signatureStatus(of: url).cdHash else { return false }
        approvals.insert(url.path, cdHash)
        return true
    }

    static func isApproved(_ path: String, cdHash: Data) -> Bool { approvals.matches(path, cdHash) }

    // MARK: Resolution

    static func resolve(override: String? = UserDefaults.standard.string(forKey: overrideDefaultsKey),
                        environment: [String: String] = ProcessInfo.processInfo.environment,
                        bundle: Bundle = .main,
                        fileManager: FileManager = .default,
                        signature: @Sendable (URL) -> SignatureStatus = signatureStatus(of:),
                        approved: @Sendable (String, Data) -> Bool = isApproved(_:cdHash:)) -> Resolution {
        var searched: [String] = []
        var refusal: Refusal?

        func executable(_ path: String) -> Bool {
            fileManager.isExecutableFile(atPath: path)
        }

        if let override = override?.trimmingCharacters(in: .whitespacesAndNewlines), !override.isEmpty {
            let path = (override as NSString).expandingTildeInPath
            searched.append("Settings override: \(path)")
            if executable(path) {
                let url = URL(fileURLWithPath: path)
                let status = signature(url)
                if let denial = overrideRefusal(url, status: status, bundle: bundle, approved: approved) {
                    refusal = denial
                    searched.append("Refused: \(denial.reason)")
                } else {
                    // Carried to the launch so the bytes are re-measured
                    // immediately before `exec`: `resolve()` runs on every
                    // (re)launch, and the file can change between the two.
                    return Resolution(launch: HelperLaunch(executable: url, arguments: [], origin: "settings",
                                                           approvedCDHash: status.cdHash),
                                      searched: searched)
                }
            }
        }

        if let url = bundle.url(forAuxiliaryExecutable: "qc-core") {
            searched.append("Bundle auxiliary executable: \(url.path)")
            if executable(url.path) {
                return Resolution(launch: HelperLaunch(executable: url, arguments: [], origin: "bundle"),
                                  searched: searched, refusal: refusal)
            }
        }

        // scripts/build.py --helper ships a headless bundle at
        // Helpers/qc-core.app (nested code that codesign accepts); the two
        // older layouts (onedir folder, single file) are kept as fallbacks.
        for rel in ["Contents/Helpers/qc-core.app/Contents/MacOS/qc-core",
                    "Contents/Helpers/qc-core/qc-core",
                    "Contents/Helpers/qc-core"] {
            let helpers = bundle.bundleURL.appending(path: rel)
            searched.append("Bundle: \(helpers.path)")
            if executable(helpers.path), !isDirectory(helpers.path, fileManager) {
                return Resolution(launch: HelperLaunch(executable: helpers, arguments: [], origin: "bundle"),
                                  searched: searched, refusal: refusal)
            }
        }

        #if DEBUG
        // A shipped build must not take its helper from the environment: an
        // env var is one more way to redirect the credential pipe, and
        // build.py and release.yml both assert the bundled helper exists, so
        // nothing outside development ever reached this branch.
        if let env = environment["QC_CORE_PATH"], !env.isEmpty {
            searched.append("QC_CORE_PATH: \(env)")
            if executable(env) {
                return Resolution(launch: HelperLaunch(executable: URL(fileURLWithPath: env), arguments: [],
                                                       origin: "QC_CORE_PATH"), searched: searched, refusal: refusal)
            }
        }

        let devScript = devVenv + "/bin/qc-core"
        searched.append("Development venv: \(devScript)")
        if executable(devScript) {
            return Resolution(launch: HelperLaunch(executable: URL(fileURLWithPath: devScript), arguments: [],
                                                   origin: "dev venv"), searched: searched, refusal: refusal)
        }
        // The venv exists but the entry point was never installed
        // (`pip install -e .` fixes it); `python -m quantacrypt.cli` is the same program.
        let devPython = devVenv + "/bin/python"
        searched.append("Development venv: \(devPython) -m quantacrypt.cli")
        if executable(devPython) {
            return Resolution(launch: HelperLaunch(executable: URL(fileURLWithPath: devPython),
                                                   arguments: ["-m", "quantacrypt.cli"], origin: "dev venv (module)"),
                              searched: searched, refusal: refusal)
        }
        #endif

        return Resolution(launch: nil, searched: searched, refusal: refusal)
    }

    /// Why `url` may not be launched as the helper, or nil when it may.
    ///
    /// Inside the app bundle needs no approval: the app's own signature
    /// covers its payload, so replacing the bundled helper already breaks the
    /// bundle. Everything else needs a signature *and* a click, because a
    /// planted preference is the whole attack and only a person can tell the
    /// two apart.
    ///
    /// Only a binary that satisfies the pin can be approved. Compiling the
    /// requirement and then treating "signed by someone else" exactly like
    /// "signed by us" made the pin decorative — the check ran, its answer
    /// changed nothing, and the next reader would have counted it as a second
    /// layer. The override exists to point at a *qc-core*, so anything else
    /// is refused outright: an ad-hoc signature is trivial to forge, but
    /// forging it under our identifier is at least a deliberate act, and after
    /// notarization the same branch starts proving authorship for real.
    static func overrideRefusal(_ url: URL, status: SignatureStatus, bundle: Bundle,
                                approved: (String, Data) -> Bool) -> Refusal? {
        let path = url.standardizedFileURL.path
        let bundleRoot = bundle.bundleURL.standardizedFileURL.path
        if path == bundleRoot || path.hasPrefix(bundleRoot + "/") { return nil }
        switch status {
        case .unsigned(let detail):
            return Refusal(path: path,
                           reason: "\(path) isn't code-signed, so QuantaCrypt can't tell what it is (\(detail)). It stays unused — clear the path above to use the bundled helper.",
                           approvable: false)
        case .signedButUnpinned(let detail):
            return Refusal(path: path,
                           reason: "\(path) is signed, but not as QuantaCrypt's qc-core helper (\(detail)). It stays unused — clear the path above to use the bundled helper.",
                           approvable: false)
        case .satisfiesPin(let cdHash):
            guard !approved(path, cdHash) else { return nil }
            return Refusal(path: path,
                           reason: "\(path) is outside QuantaCrypt, and every password and share you type goes to it. It stays unused until you approve it here.",
                           approvable: true)
        }
    }

    /// The code signature of the file at `url`, measured with Security's own
    /// checks so a tampered or unsigned binary is caught before it is run.
    static func signatureStatus(of url: URL) -> SignatureStatus {
        var staticCode: SecStaticCode?
        let created = SecStaticCodeCreateWithPath(url as CFURL, [], &staticCode)
        guard created == errSecSuccess, let staticCode else {
            return .unsigned("SecStaticCodeCreateWithPath returned \(created)")
        }
        let valid = SecStaticCodeCheckValidity(staticCode, [], nil)
        guard valid == errSecSuccess else {
            return .unsigned("its signature is missing or damaged, OSStatus \(valid)")
        }
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(requirementString as CFString, [], &requirement) == errSecSuccess,
              let requirement else {
            return .signedButUnpinned("QuantaCrypt's own requirement string could not be compiled")
        }
        guard SecStaticCodeCheckValidity(staticCode, [], requirement) == errSecSuccess else {
            return .signedButUnpinned("it is signed by someone else")
        }
        // An approval has to name the bytes, not the path. Without a hash to
        // record there is nothing to approve, so this is a refusal rather than
        // an unpinned pass.
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, [], &info) == errSecSuccess,
              let cdHash = (info as? [String: Any])?[kSecCodeInfoUnique as String] as? Data else {
            return .signedButUnpinned("its code hash could not be read")
        }
        return .satisfiesPin(cdHash: cdHash)
    }

    private static func isDirectory(_ path: String, _ fm: FileManager) -> Bool {
        var isDir: ObjCBool = false
        return fm.fileExists(atPath: path, isDirectory: &isDir) && isDir.boolValue
    }
}
