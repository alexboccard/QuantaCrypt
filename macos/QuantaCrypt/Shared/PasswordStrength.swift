import Foundation

/// Local, dependency-free estimate. Good enough to steer users away from
/// short or single-class passwords; the helper never sees this value.
struct PasswordStrength: Equatable, Sendable {
    enum Level: Int, Comparable, Sendable {
        case empty = 0, weak, fair, good, strong
        static func < (a: Level, b: Level) -> Bool { a.rawValue < b.rawValue }

        var label: String {
            switch self {
            case .empty: return ""
            case .weak: return "Weak"
            case .fair: return "Fair"
            case .good: return "Good"
            case .strong: return "Strong"
            }
        }
    }

    let level: Level
    let bits: Double
    let advice: String?

    static let minimumLength = 8

    static func estimate(_ password: String) -> PasswordStrength {
        if password.isEmpty { return PasswordStrength(level: .empty, bits: 0, advice: nil) }
        let scalars = password.unicodeScalars
        var pool = 0
        if scalars.contains(where: { CharacterSet.lowercaseLetters.contains($0) }) { pool += 26 }
        if scalars.contains(where: { CharacterSet.uppercaseLetters.contains($0) }) { pool += 26 }
        if scalars.contains(where: { CharacterSet.decimalDigits.contains($0) }) { pool += 10 }
        if scalars.contains(where: {
            !CharacterSet.alphanumerics.contains($0)
        }) { pool += 33 }
        pool = max(pool, 10)

        var bits = Double(password.count) * log2(Double(pool))

        // Penalise structure that dictionary attacks exploit.
        let lower = password.lowercased()
        let distinct = Set(lower).count
        if distinct <= 2 { bits *= 0.35 }
        else if Double(distinct) < Double(password.count) * 0.5 { bits *= 0.7 }
        if isSequential(lower) { bits *= 0.5 }
        if commonFragments.contains(where: { lower.contains($0) }) { bits *= 0.6 }

        let level: Level
        var advice: String?
        if password.count < minimumLength {
            level = .weak
            advice = "Use at least \(minimumLength) characters."
        } else if bits < 40 {
            level = .weak
            advice = "Add more words, numbers or symbols."
        } else if bits < 60 {
            level = .fair
            advice = "Longer is stronger. A few unrelated words work well."
        } else if bits < 80 {
            level = .good
        } else {
            level = .strong
        }
        return PasswordStrength(level: level, bits: bits, advice: advice)
    }

    private static let commonFragments = ["password", "qwerty", "letmein", "welcome", "admin",
                                          "123456", "iloveyou", "abc123", "quantacrypt"]

    private static func isSequential(_ s: String) -> Bool {
        let values = s.unicodeScalars.map { Int($0.value) }
        guard values.count >= 4 else { return false }
        var runs = 0
        for i in 1..<values.count where abs(values[i] - values[i - 1]) == 1 { runs += 1 }
        return runs >= values.count - 2
    }
}
