import SwiftUI

struct VolumesView: View {
    @Bindable var model: VolumesModel
    @FocusState private var focus: Field?

    enum Field: Hashable {
        case createName, createPassword, createConfirmation
        case mountPoint, mountPassword, mountShare(Int)

        var job: VolumesModel.Job {
            switch self {
            case .createName, .createPassword, .createConfirmation: return .create
            case .mountPoint, .mountPassword, .mountShare: return .mount
            }
        }
    }

    var body: some View {
        Form {
            if let fuse = model.fuse, !fuse.ok {
                setupSection(fuse)
            } else if let error = model.fuseError {
                Section("Disk mounting") { ErrorPanel(error: error) }
            }
            createSection
            mountSection
            mountedSection
        }
        .formStyle(.grouped)
        .task { await model.pollMounted() }
        .onChange(of: focus) { _, field in
            if let field { model.activeJob = field.job }
        }
        .toolbar {
            ToolbarItem(placement: .primaryAction) {
                switch model.activeJob {
                case .create:
                    Button("Create volume", systemImage: "externaldrive.badge.plus", action: model.createVolume)
                        .buttonStyle(.borderedProminent)
                        .keyboardShortcut(.return, modifiers: .command)
                        .disabled(!model.canCreate)
                        .help(model.createValidationMessage ?? "Create the encrypted volume (⌘↩)")
                case .mount:
                    Button("Mount volume", systemImage: "externaldrive.badge.checkmark", action: model.mount)
                        .buttonStyle(.borderedProminent)
                        .keyboardShortcut(.return, modifiers: .command)
                        .disabled(!model.canMount)
                        .help(model.mountValidationMessage ?? "Unlock and mount the volume (⌘↩)")
                }
            }
        }
        .sheet(item: $model.sharesToShow) { presentation in
            SharesSheet(shares: presentation.shares, context: presentation.context,
                        onDismiss: model.sharesSheetDismissed)
        }
        .confirmationDialog("Mount the new volume now?", isPresented: $model.offerMountAfterCreate, titleVisibility: .visible) {
            Button("Mount volume now", action: model.mountCreatedVolume)
            Button("Not now", role: .cancel) {}
        } message: {
            Text("\(model.createResult.map { Format.fileName($0.path) } ?? "The volume") was created. Mount it to start adding files.")
        }
        .confirmationDialog("Unmount \(model.unmountCandidate?.name ?? "volume")?",
                            isPresented: Binding(get: { model.unmountCandidate != nil },
                                                 set: { if !$0 { model.unmountCandidate = nil } }),
                            titleVisibility: .visible, presenting: model.unmountCandidate) { volume in
            Button("Unmount", role: .destructive) { model.unmount(volume) }
            Button("Keep mounted", role: .cancel) {}
        } message: { volume in
            Text("Anything still open from \(Format.tildePath(volume.mountPoint)) may lose unsaved work.")
        }
        .alert("This volume may have been altered",
               isPresented: Binding(get: { model.suspiciousVolume != nil },
                                    set: { if !$0 { model.suspiciousVolume = nil } }),
               presenting: model.suspiciousVolume) { volume in
            Button("Unmount now", role: .destructive) { model.unmount(volume) }
            Button("Keep mounted", role: .cancel) {}
        } message: { volume in
            Text("\(volume.name)'s records don't match what QuantaCrypt last wrote — it may have been altered. Unmounting now keeps it untouched.")
        }
    }

    // MARK: Setup

    private func setupSection(_ fuse: FuseCheck) -> some View {
        Section("Set up disk mounting") {
            Text("Mounting a volume as a drive needs one extra component. Creating volumes works without it.")
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            componentRow("Disk mounting support (macFUSE or FUSE-T)", fuse.fuseBackend)
            componentRow("Mounting helper", fuse.fusepy)
            LabeledContent("Install with Homebrew") {
                TextField("", text: .constant(VolumesModel.brewCommand))
                    .font(.body.monospaced())
                    .textFieldStyle(.roundedBorder)
                    .frame(minWidth: 260)
            }
            Text("Needs an administrator password. FUSE-T is recommended (no kernel extension); macFUSE also works: \(VolumesModel.brewAlternative)")
                .font(.callout)
                .foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack {
                Button("Check again") {
                    Task { await model.checkFuse(userInitiated: true) }
                }
                .disabled(model.fuseChecking)
                if model.fuseChecking {
                    ProgressView().controlSize(.small)
                } else if let note = model.fuseCheckNote {
                    Text(note)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    private func componentRow(_ title: String, _ component: FuseCheck.Component) -> some View {
        LabeledContent {
            Text(component.detail)
                .foregroundStyle(.secondary)
                .multilineTextAlignment(.trailing)
        } label: {
            Label(title, systemImage: component.ok ? "checkmark.circle.fill" : "xmark.circle")
                .foregroundStyle(component.ok ? Color.green : Color.primary)
        }
    }

    // MARK: Create

    private var createSection: some View {
        Section("Create a volume") {
            TextField("Name", text: $model.createName)
                .focused($focus, equals: .createName)
            LabeledContent("Location") {
                HStack {
                    Text(Format.tildePath(model.createDirectory))
                        .foregroundStyle(.secondary)
                        .lineLimit(1)
                        .truncationMode(.middle)
                    Button("Change…", action: model.chooseCreateLocation)
                }
            }
            Picker("Protect with", selection: $model.createMode) {
                ForEach(ProtectionMode.allCases) { Text($0.rawValue).tag($0) }
            }
            .pickerStyle(.segmented)
            switch model.createMode {
            case .password:
                SecureField("Password", text: $model.createPassword)
                    .textContentType(.newPassword)
                    .focused($focus, equals: .createPassword)
                SecureField("Confirm password", text: $model.createConfirmation)
                    .textContentType(.newPassword)
                    .focused($focus, equals: .createConfirmation)
                    .onSubmit(model.createVolume)
                strengthRow
            case .splitKey:
                SplitKeyFields(threshold: $model.createThreshold, total: $model.createTotal)
            }
            Text("The volume grows as you add files — no fixed size to choose.")
                .font(.callout)
                .foregroundStyle(.secondary)
            if model.fuse != nil && !model.mountingAvailable {
                WarningStrip(text: "You can create this volume now, but it can't be mounted on this Mac until disk mounting support is installed.")
            }
            if model.createRunning {
                ProgressPanel(progress: model.createProgress, onCancel: model.cancelCreate)
            } else {
                HStack {
                    Button("Create volume", action: model.createVolume)
                        .disabled(!model.canCreate)
                    if let message = model.createValidationMessage, !model.createName.isEmpty {
                        Text(message)
                            .font(.callout)
                            .foregroundStyle(.secondary)
                    }
                }
            }
            if let error = model.createError { ErrorPanel(error: error) }
            if let status = model.createStatus { StatusNote(text: status) }
            if let result = model.createResult, !model.createRunning {
                HStack {
                    Label("Created \(Format.fileName(result.path))", systemImage: "checkmark.circle.fill")
                        .foregroundStyle(.green)
                    Button("Show in Finder") { Finder.reveal(result.path) }
                    Button("Mount volume now", action: model.mountCreatedVolume)
                        .disabled(!model.mountingAvailable)
                }
            }
        }
    }

    @ViewBuilder
    private var strengthRow: some View {
        let strength = PasswordStrength.estimate(model.createPassword)
        if strength.level != .empty {
            LabeledContent("Strength") {
                HStack(spacing: 8) {
                    ProgressView(value: Double(strength.level.rawValue), total: 4)
                        .tint(strength.level >= .good ? .green : (strength.level == .fair ? .orange : .red))
                        .frame(width: 120)
                    Text(strength.advice ?? strength.level.label)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
            }
        }
        if !model.createConfirmation.isEmpty && model.createConfirmation != model.createPassword {
            Text("The two passwords don't match.")
                .font(.callout)
                .foregroundStyle(.red)
        }
    }

    // MARK: Mount

    private var mountSection: some View {
        Section("Mount a volume") {
            if let path = model.mountPath {
                PathRow(path: path, detail: nil, systemImage: "externaldrive",
                        changeTitle: "Change…", onChange: model.chooseVolumeToMount)
            } else {
                DropZone(title: "Drop a volume here",
                         subtitle: "Volumes end in .qcv.",
                         systemImage: "externaldrive.badge.plus",
                         chooseTitle: "Choose volume…",
                         onChoose: model.chooseVolumeToMount,
                         accepts: VolumesModel.accepts,
                         onDrop: { model.prepareMount(path: $0.path) })
            }
            if model.mountPath != nil {
                if let info = model.mountInfo {
                    Text(info.protectionSummary)
                        .font(.callout)
                        .foregroundStyle(.secondary)
                }
                LabeledContent("Mount point") {
                    HStack {
                        TextField("", text: $model.mountPoint)
                            .textFieldStyle(.roundedBorder)
                            .labelsHidden()
                            .focused($focus, equals: .mountPoint)
                        Button("Change…", action: model.chooseMountPoint)
                    }
                }
                // The auth block says how the volume is protected; the picker
                // is only a fallback when it could not be read.
                if model.mountInfo == nil && !model.mountInspecting {
                    Picker("Unlock with", selection: $model.mountCredential) {
                        ForEach(VolumesModel.MountCredential.allCases) { Text($0.rawValue).tag($0) }
                    }
                    .pickerStyle(.segmented)
                }
                switch model.mountCredential {
                case .password:
                    SecureField("Password", text: $model.mountPassword)
                        .textContentType(.password)
                        .focused($focus, equals: .mountPassword)
                        .onSubmit(model.mount)
                case .shares:
                    ShareEntryFields(shares: $model.mountShares, required: nil, total: nil,
                                     onLoadFiles: model.loadMountSharesFromFiles)
                }
                if model.fuse != nil && !model.mountingAvailable {
                    WarningStrip(text: "Install disk mounting support above before mounting.")
                }
                if model.mountRunning {
                    ProgressPanel(progress: model.mountProgress, onCancel: model.cancelMount)
                } else {
                    Button("Mount volume", action: model.mount)
                        .disabled(!model.canMount || !model.mountingAvailable)
                }
            }
            if let error = model.mountError { ErrorPanel(error: error) }
            if let status = model.mountStatus { StatusNote(text: status) }
            if let note = model.mountedNote {
                Label(note, systemImage: "checkmark.circle.fill")
                    .foregroundStyle(.green)
            }
        }
    }

    // MARK: Mounted

    private var mountedSection: some View {
        Section("Mounted volumes") {
            if let error = model.unmountError { ErrorPanel(error: error) }
            if model.mounted.isEmpty {
                Text(model.listLoaded ? "No volumes mounted." : "Checking…")
                    .foregroundStyle(.secondary)
            }
            ForEach(model.mounted) { volume in
                HStack {
                    Label {
                        VStack(alignment: .leading, spacing: 2) {
                            Text(volume.name)
                                .font(.body.weight(.medium))
                            Text(volumeDetail(volume))
                                .font(.callout)
                                .foregroundStyle(.secondary)
                                .lineLimit(1)
                                .truncationMode(.middle)
                        }
                    } icon: {
                        Image(systemName: "externaldrive.fill.badge.checkmark")
                            .foregroundStyle(.secondary)
                    }
                    Spacer()
                    if model.unmounting.contains(volume.mountPoint) {
                        ProgressView().controlSize(.small)
                        Text("Unmounting…").foregroundStyle(.secondary)
                    } else {
                        Button("Show in Finder") { Finder.open(volume.mountPoint) }
                        Button("Unmount") { model.requestUnmount(volume) }
                    }
                }
            }
        }
    }

    private func volumeDetail(_ volume: MountedVolume) -> String {
        var parts = [Format.tildePath(volume.mountPoint)]
        if let stats = volume.stats, let files = stats.fileCount {
            parts.append("\(files) file\(files == 1 ? "" : "s")")
            if let size = stats.totalPlaintextSize { parts.append(Format.bytes(size)) }
        }
        return parts.joined(separator: " · ")
    }
}
