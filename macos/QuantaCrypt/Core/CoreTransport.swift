import Foundation
import os

/// A byte pipe to one helper instance: send request lines, receive event lines.
/// `ProcessTransport` is the real one; tests substitute a fake.
protocol CoreTransport: Sendable {
    /// Launch the helper and return its stdout as a stream of lines. The
    /// stream ends when the helper exits.
    func start() async throws -> AsyncThrowingStream<String, any Error>
    /// Write one line (already newline-terminated) to the helper's stdin.
    func send(_ line: String) async throws
    /// Close stdin so the helper can finish gracefully.
    func closeInput() async
    /// Wait up to `timeout` for exit, then escalate SIGTERM → SIGKILL.
    func terminate(timeout: Duration) async
}

/// Where and how to launch the helper.
struct HelperLaunch: Sendable, Equatable {
    let executable: URL
    let arguments: [String]
    /// Which resolution rule produced this launch, for the status line.
    let origin: String
    /// The code hash this binary had when it was resolved, for a helper
    /// outside the app bundle. Nil inside the bundle, whose payload the app's
    /// own signature already covers.
    let approvedCDHash: Data?

    init(executable: URL, arguments: [String], origin: String, approvedCDHash: Data? = nil) {
        self.executable = executable
        self.arguments = arguments
        self.origin = origin
        self.approvedCDHash = approvedCDHash
    }

    var displayPath: String { (executable.path as NSString).abbreviatingWithTildeInPath }
}

extension Logger {
    static let helper = Logger(subsystem: "com.alexboccard.quantacrypt", category: "helper")
    static let client = Logger(subsystem: "com.alexboccard.quantacrypt", category: "core-client")
}

/// Spawns `qc-core` with `Process` and pipes. Stdout lines are the protocol;
/// stderr is forwarded to the unified log (it never carries params).
actor ProcessTransport: CoreTransport {
    private let launch: HelperLaunch
    private var process: Process?
    private var input: FileHandle?

    init(launch: HelperLaunch) {
        self.launch = launch
    }

    func start() async throws -> AsyncThrowingStream<String, any Error> {
        // A write to a pipe whose reader died raises SIGPIPE, which would kill
        // the app instead of surfacing an error.
        signal(SIGPIPE, SIG_IGN)

        try verifyStillTheApprovedBinary()

        let process = Process()
        process.executableURL = launch.executable
        process.arguments = launch.arguments
        var env = ProcessInfo.processInfo.environment
        env["PYTHONUNBUFFERED"] = "1"
        env["PYTHONIOENCODING"] = "utf-8"
        process.environment = env

        let stdin = Pipe()
        let stdout = Pipe()
        let stderr = Pipe()
        process.standardInput = stdin
        process.standardOutput = stdout
        process.standardError = stderr

        try process.run()
        self.process = process
        self.input = stdin.fileHandleForWriting
        Logger.client.info("helper started pid=\(process.processIdentifier, privacy: .public) via \(self.launch.origin, privacy: .public)")

        // Plain blocking reads on dedicated threads.  `FileHandle.bytes.lines`
        // proved unreliable on a pipe here (it delivered the first line or
        // nothing, depending on timing), and a helper that answers "never"
        // is the worst failure mode this client can have.
        // Tracebacks and unmount failures are the only trace of why a
        // volume was torn down uncleanly, so they must survive the default
        // log level. Stderr never carries params, hence `.public`.
        Self.readLines(from: stderr.fileHandleForReading, name: "stderr") { line in
            if line.contains("Traceback") || line.contains("Error") {
                Logger.helper.error("\(line, privacy: .public)")
            } else {
                Logger.helper.info("\(line, privacy: .public)")
            }
        } onEnd: { _ in }

        let outHandle = stdout.fileHandleForReading
        return AsyncThrowingStream { continuation in
            Self.readLines(from: outHandle, name: "stdout") { line in
                continuation.yield(line)
            } onEnd: { error in
                continuation.finish(throwing: error)
            }
            continuation.onTermination = { _ in try? outHandle.close() }
        }
    }

    /// Re-measure an out-of-bundle helper immediately before `exec`.
    ///
    /// `HelperLocator.resolve()` runs once per launch and the approval it
    /// consults is per session, so between the check and `Process.run()` the
    /// file can be replaced by anything — and everything the user types is
    /// about to be written to whatever gets exec'd. `Process` takes a path,
    /// not a descriptor, so this narrows the window rather than closing it;
    /// closing it needs `fexecve`, which `Process` does not expose.
    private func verifyStillTheApprovedBinary() throws {
        guard let expected = launch.approvedCDHash else { return }
        let now = HelperLocator.signatureStatus(of: launch.executable)
        guard now.cdHash == expected else {
            Logger.client.error("helper at \(self.launch.executable.path, privacy: .public) changed after it was approved")
            throw CoreError(
                code: .helperUnavailable,
                message: "The helper at \(launch.displayPath) changed since you approved it, so QuantaCrypt did not run it. Approve it again in Settings if you made the change.",
                detail: "code hash no longer matches the approved one")
        }
    }

    /// Read newline-delimited UTF-8 from `handle` on its own thread and hand
    /// each line to `onLine`; `onEnd` fires once at EOF (or with an error).
    private static func readLines(from handle: FileHandle, name: String,
                                  onLine: @escaping @Sendable (String) -> Void,
                                  onEnd: @escaping @Sendable ((any Error)?) -> Void) {
        let thread = Thread {
            var buffer = Data()
            while true {
                let chunk = handle.availableData   // blocks until data or EOF
                if chunk.isEmpty { break }
                buffer.append(chunk)
                while let nl = buffer.firstIndex(of: 0x0A) {
                    let lineData = buffer.subdata(in: buffer.startIndex..<nl)
                    buffer.removeSubrange(buffer.startIndex...nl)
                    onLine(String(decoding: lineData, as: UTF8.self))
                }
            }
            if !buffer.isEmpty { onLine(String(decoding: buffer, as: UTF8.self)) }
            Logger.helper.debug("\(name, privacy: .public) reached EOF")
            onEnd(nil)
        }
        thread.name = "qc-core-\(name)-reader"
        thread.qualityOfService = .userInitiated
        thread.start()
    }

    func send(_ line: String) async throws {
        guard let input, let process, process.isRunning else {
            throw CoreError.helperExited
        }
        do {
            try input.write(contentsOf: Data(line.utf8))
        } catch {
            throw CoreError(code: .helperExited,
                            message: CoreError.helperExited.message,
                            detail: "stdin write failed: \(error.localizedDescription)")
        }
    }

    func closeInput() async {
        try? input?.close()
        input = nil
    }

    func terminate(timeout: Duration) async {
        guard let process else { return }
        await closeInput()
        if await Self.waitForExit(process, timeout: timeout) { return }
        Logger.client.warning("helper did not exit after EOF; sending SIGTERM")
        process.terminate()
        if await Self.waitForExit(process, timeout: .seconds(3)) { return }
        Logger.client.error("helper ignored SIGTERM; sending SIGKILL")
        kill(process.processIdentifier, SIGKILL)
        _ = await Self.waitForExit(process, timeout: .seconds(1))
    }

    private static func waitForExit(_ process: Process, timeout: Duration) async -> Bool {
        let clock = ContinuousClock()
        let deadline = clock.now + timeout
        while process.isRunning {
            if clock.now >= deadline { return false }
            try? await Task.sleep(for: .milliseconds(50))
        }
        return true
    }
}
