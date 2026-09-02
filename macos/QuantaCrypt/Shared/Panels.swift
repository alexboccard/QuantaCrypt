import AppKit
import UniformTypeIdentifiers

extension UTType {
    static let qcx = UTType(exportedAs: "com.alexboccard.quantacrypt.qcx", conformingTo: .data)
    static let qcv = UTType(exportedAs: "com.alexboccard.quantacrypt.qcv", conformingTo: .data)
}

/// Thin wrappers over the system open/save panels.
@MainActor
enum Panels {
    static func chooseFile(types: [UTType], message: String, directory: URL? = nil) -> URL? {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = false
        panel.allowedContentTypes = types
        panel.message = message
        panel.directoryURL = directory
        return panel.runModal() == .OK ? panel.url : nil
    }

    static func chooseFiles(types: [UTType], message: String) -> [URL] {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = false
        panel.allowsMultipleSelection = true
        panel.allowedContentTypes = types
        panel.message = message
        return panel.runModal() == .OK ? panel.urls : []
    }

    static func chooseFileOrFolder(message: String) -> URL? {
        let panel = NSOpenPanel()
        panel.canChooseFiles = true
        panel.canChooseDirectories = true
        panel.allowsMultipleSelection = false
        panel.message = message
        return panel.runModal() == .OK ? panel.url : nil
    }

    static func chooseFolder(message: String, prompt: String = "Choose", directory: URL? = nil) -> URL? {
        let panel = NSOpenPanel()
        panel.canChooseFiles = false
        panel.canChooseDirectories = true
        panel.canCreateDirectories = true
        panel.allowsMultipleSelection = false
        panel.message = message
        panel.prompt = prompt
        panel.directoryURL = directory
        return panel.runModal() == .OK ? panel.url : nil
    }

    static func save(suggestedName: String, type: UTType?, message: String, directory: URL? = nil) -> URL? {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = suggestedName
        if let type { panel.allowedContentTypes = [type] }
        panel.canCreateDirectories = true
        panel.message = message
        panel.directoryURL = directory
        return panel.runModal() == .OK ? panel.url : nil
    }
}

@MainActor
enum Finder {
    static func reveal(_ path: String) {
        NSWorkspace.shared.activateFileViewerSelecting([URL(fileURLWithPath: path)])
    }

    static func open(_ path: String) {
        NSWorkspace.shared.open(URL(fileURLWithPath: path))
    }
}
