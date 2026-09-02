import Foundation

/// Finds the `qc-core` helper. Order: user override (Settings) → bundled
/// auxiliary executable → `Contents/Helpers/qc-core` → `QC_CORE_PATH` →
/// (DEBUG only) the development virtualenv.
enum HelperLocator {
    static let overrideDefaultsKey = "helperPathOverride"
    static let devVenv = "/Users/xelaboc/Projects/Quantacrypt/.venv"

    struct Resolution: Sendable {
        let launch: HelperLaunch?
        let searched: [String]
    }

    static func resolve(override: String? = UserDefaults.standard.string(forKey: overrideDefaultsKey),
                        environment: [String: String] = ProcessInfo.processInfo.environment,
                        bundle: Bundle = .main,
                        fileManager: FileManager = .default) -> Resolution {
        var searched: [String] = []

        func executable(_ path: String) -> Bool {
            fileManager.isExecutableFile(atPath: path)
        }

        if let override = override?.trimmingCharacters(in: .whitespacesAndNewlines), !override.isEmpty {
            let path = (override as NSString).expandingTildeInPath
            searched.append("Settings override: \(path)")
            if executable(path) {
                return Resolution(launch: HelperLaunch(executable: URL(fileURLWithPath: path), arguments: [],
                                                       origin: "settings"), searched: searched)
            }
        }

        if let url = bundle.url(forAuxiliaryExecutable: "qc-core") {
            searched.append("Bundle auxiliary executable: \(url.path)")
            if executable(url.path) {
                return Resolution(launch: HelperLaunch(executable: url, arguments: [], origin: "bundle"),
                                  searched: searched)
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
                                  searched: searched)
            }
        }

        if let env = environment["QC_CORE_PATH"], !env.isEmpty {
            searched.append("QC_CORE_PATH: \(env)")
            if executable(env) {
                return Resolution(launch: HelperLaunch(executable: URL(fileURLWithPath: env), arguments: [],
                                                       origin: "QC_CORE_PATH"), searched: searched)
            }
        }

        #if DEBUG
        let devScript = devVenv + "/bin/qc-core"
        searched.append("Development venv: \(devScript)")
        if executable(devScript) {
            return Resolution(launch: HelperLaunch(executable: URL(fileURLWithPath: devScript), arguments: [],
                                                   origin: "dev venv"), searched: searched)
        }
        // The venv exists but the entry point was never installed
        // (`pip install -e .` fixes it); `python -m quantacrypt.cli` is the same program.
        let devPython = devVenv + "/bin/python"
        searched.append("Development venv: \(devPython) -m quantacrypt.cli")
        if executable(devPython) {
            return Resolution(launch: HelperLaunch(executable: URL(fileURLWithPath: devPython),
                                                   arguments: ["-m", "quantacrypt.cli"], origin: "dev venv (module)"),
                              searched: searched)
        }
        #endif

        return Resolution(launch: nil, searched: searched)
    }

    private static func isDirectory(_ path: String, _ fm: FileManager) -> Bool {
        var isDir: ObjCBool = false
        return fm.fileExists(atPath: path, isDirectory: &isDir) && isDir.boolValue
    }
}
