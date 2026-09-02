import Foundation
import Observation

/// Recently decrypted `.qcx` files and recently mounted `.qcv` volumes,
/// persisted in UserDefaults. Paths only — never credentials.
@MainActor
@Observable
final class RecentStore {
    enum Kind: String, CaseIterable {
        case decrypted = "recentDecrypted"
        case mounted = "recentMounted"
    }

    static let limit = 8

    private(set) var decrypted: [String]
    private(set) var mounted: [String]
    private let defaults: UserDefaults

    init(defaults: UserDefaults = .standard) {
        self.defaults = defaults
        decrypted = defaults.stringArray(forKey: Kind.decrypted.rawValue) ?? []
        mounted = defaults.stringArray(forKey: Kind.mounted.rawValue) ?? []
    }

    func add(_ path: String, kind: Kind) {
        var list = self[kind].filter { $0 != path }
        list.insert(path, at: 0)
        if list.count > Self.limit { list.removeLast(list.count - Self.limit) }
        set(list, kind: kind)
    }

    func remove(_ path: String, kind: Kind) {
        set(self[kind].filter { $0 != path }, kind: kind)
    }

    func clear() {
        for kind in Kind.allCases { set([], kind: kind) }
    }

    var isEmpty: Bool { decrypted.isEmpty && mounted.isEmpty }

    private subscript(kind: Kind) -> [String] {
        switch kind {
        case .decrypted: return decrypted
        case .mounted: return mounted
        }
    }

    private func set(_ list: [String], kind: Kind) {
        switch kind {
        case .decrypted: decrypted = list
        case .mounted: mounted = list
        }
        defaults.set(list, forKey: kind.rawValue)
    }
}
