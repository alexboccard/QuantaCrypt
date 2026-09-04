import SwiftUI

/// Password + confirmation with a local strength read-out.
struct NewPasswordFields: View {
    @Binding var password: String
    @Binding var confirmation: String
    var onSubmit: () -> Void = {}

    private var strength: PasswordStrength { PasswordStrength.estimate(password) }

    var body: some View {
        SecureField("Password", text: $password)
            .textContentType(.newPassword)
        SecureField("Confirm password", text: $confirmation)
            .textContentType(.newPassword)
            .onSubmit(onSubmit)
        if strength.level != .empty {
            LabeledContent("Strength") {
                VStack(alignment: .trailing, spacing: 4) {
                    HStack(spacing: 8) {
                        ProgressView(value: Double(strength.level.rawValue), total: 4)
                            .tint(tint)
                            // Not a fixed width: at accessibility text sizes
                            // the label beside it needs the room more than the
                            // meter does.
                            .frame(minWidth: 80, idealWidth: 120)
                        Text(strength.level.label)
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                    if let advice = strength.advice {
                        Text(advice)
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                }
            }
        }
        if !confirmation.isEmpty && confirmation != password {
            Text("The two passwords don't match.")
                .font(.callout)
                .foregroundStyle(.red)
        }
    }

    private var tint: Color {
        switch strength.level {
        case .empty, .weak: return .red
        case .fair: return .orange
        case .good, .strong: return .green
        }
    }
}

/// "Required to unlock" / "Total people" steppers with the three presets.
struct SplitKeyFields: View {
    @Binding var threshold: Int
    @Binding var total: Int

    static let presets: [(k: Int, n: Int)] = [(2, 3), (3, 5), (3, 7)]
    static let range = 2...20

    var body: some View {
        LabeledContent("Preset") {
            HStack(spacing: 6) {
                ForEach(Self.presets, id: \.n) { preset in
                    Button("\(preset.k) of \(preset.n)") {
                        threshold = preset.k
                        total = preset.n
                    }
                    .buttonStyle(.bordered)
                    .tint(isActive(preset) ? .accentColor : nil)
                }
            }
        }
        Stepper("Required to unlock: \(threshold)", value: $threshold, in: Self.range)
            .onChange(of: threshold) { _, k in if total < k { total = k } }
        Stepper("Total people: \(total)", value: $total, in: Self.range)
            .onChange(of: total) { _, n in if threshold > n { threshold = n } }
        Text("Any \(threshold) of the \(total) people can unlock it together; fewer than \(threshold) cannot. Each person gets one share.")
            .font(.callout)
            .foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func isActive(_ preset: (k: Int, n: Int)) -> Bool {
        preset.k == threshold && preset.n == total
    }
}

/// Share entry for unlocking: k text fields, load-from-files, add-another.
struct ShareEntryFields: View {
    @Binding var shares: [ShareEntry]
    let required: Int?
    let total: Int?
    let onLoadFiles: () -> Void

    var body: some View {
        if let required, let total {
            Text("Enter any \(required) of the \(total) shares. Paste a QCSHARE- code or type the 50-word phrase.")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        // Identified rows, not `shares.indices`: the array shrinks under this
        // view (blanks dropped by a file load, "Remove last share"), and an
        // index-keyed row body re-evaluated against the old count traps on
        // `$shares[index]`.
        ForEach(Array($shares.enumerated()), id: \.element.id) { index, $entry in
            TextField("Share \(index + 1)", text: $entry.text, axis: .vertical)
                .lineLimit(1...4)
                .font(.body.monospaced())
                .autocorrectionDisabled()
        }
        HStack {
            Button("Load from files…", action: onLoadFiles)
            Button("Add another share") { shares.append(ShareEntry()) }
                .disabled(total.map { shares.count >= $0 } ?? (shares.count >= 20))
            if shares.count > (required ?? 1) {
                Button("Remove last share") { shares.removeLast() }
            }
        }
    }
}
