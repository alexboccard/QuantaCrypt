import Foundation

enum Format {
    static func bytes(_ count: Int) -> String {
        ByteCountFormatter.string(fromByteCount: Int64(count), countStyle: .file)
    }

    static func tildePath(_ path: String) -> String {
        (path as NSString).abbreviatingWithTildeInPath
    }

    static func fileName(_ path: String) -> String {
        URL(fileURLWithPath: path).lastPathComponent
    }

    static func stem(_ path: String) -> String {
        URL(fileURLWithPath: path).deletingPathExtension().lastPathComponent
    }

    static func directory(_ path: String) -> String {
        URL(fileURLWithPath: path).deletingLastPathComponent().path
    }
}

enum Paths {
    static let homeDirectory = FileManager.default.homeDirectoryForCurrentUser.path

    /// User-chosen default output folder from Settings, when it still exists.
    static var defaultOutputFolder: String? {
        guard let raw = UserDefaults.standard.string(forKey: "defaultOutputFolder"),
              !raw.isEmpty else { return nil }
        let path = (raw as NSString).expandingTildeInPath
        var isDir: ObjCBool = false
        return FileManager.default.fileExists(atPath: path, isDirectory: &isDir) && isDir.boolValue ? path : nil
    }

    static func isDirectory(_ path: String) -> Bool {
        var isDir: ObjCBool = false
        return FileManager.default.fileExists(atPath: path, isDirectory: &isDir) && isDir.boolValue
    }

    static func exists(_ path: String) -> Bool {
        FileManager.default.fileExists(atPath: path)
    }
}
