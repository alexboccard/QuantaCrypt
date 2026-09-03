import Foundation
import os

/// Owns one helper process and routes its events to the request that asked.
///
/// Every request gets an `AsyncStream<CoreEvent>`; `perform` collapses that
/// into progress callbacks plus a typed result. If the helper dies, pending
/// requests fail with `.helperExited` and the next request relaunches it.
/// Params are never logged — they carry passwords and shares.
actor CoreClient {
    typealias TransportFactory = @Sendable () throws -> any CoreTransport

    private let makeTransport: TransportFactory
    private var transport: (any CoreTransport)?
    private var generation = 0
    private var readTask: Task<Void, Never>?
    private var launching: Task<any CoreTransport, any Error>?
    private var pending: [String: AsyncStream<CoreEvent>.Continuation] = [:]
    private var counter = 0
    private var shuttingDown = false
    /// Set while `restart()` is stopping the old helper and launching the
    /// new one; requests arriving meanwhile wait for it instead of hitting
    /// the dying transport.
    private var restarting: Task<Void, Never>?
    private let idPrefix: String

    /// Number of times the helper had to be (re)launched after an exit.
    private(set) var restartCount = 0

    /// Called when the helper dies without being asked to. Lets the window
    /// show the failure instead of leaving a stale "ready" indicator up.
    private var unexpectedExitHandler: (@Sendable () -> Void)?

    func onUnexpectedExit(_ handler: @escaping @Sendable () -> Void) {
        unexpectedExitHandler = handler
    }

    /// How long a cancelled request waits for the helper's own `cancelled`
    /// event before being failed locally.
    private let cancelGrace: Duration

    init(transportFactory: @escaping TransportFactory, cancelGrace: Duration = .seconds(5)) {
        self.makeTransport = transportFactory
        self.cancelGrace = cancelGrace
        self.idPrefix = String(UInt32.random(in: 0...UInt32.max), radix: 36)
    }

    /// Production client: resolves the helper on each launch so a Settings
    /// change takes effect after the next restart.
    static func live() -> CoreClient {
        CoreClient {
            let resolution = HelperLocator.resolve()
            guard let launch = resolution.launch else {
                throw CoreError(
                    code: .helperUnavailable,
                    message: "The encryption helper (qc-core) could not be found. Set its location in Settings, or reinstall QuantaCrypt.",
                    detail: resolution.searched.joined(separator: "\n"))
            }
            return ProcessTransport(launch: launch)
        }
    }

    var isRunning: Bool { transport != nil }

    // MARK: Requests

    /// Register a request and return its event stream. The stream finishes
    /// after `done`, `error`, or a helper exit.
    func events(for request: CoreRequest) async throws -> (id: String, events: AsyncStream<CoreEvent>) {
        if shuttingDown && request.op != "shutdown" {
            throw CoreError(code: .helperUnavailable, message: "QuantaCrypt is quitting.", detail: "")
        }
        if let restarting, request.op != "shutdown" {
            await restarting.value
        }
        counter += 1
        let id = "\(idPrefix)-\(counter)"
        let (stream, continuation) = AsyncStream<CoreEvent>.makeStream(bufferingPolicy: .unbounded)
        pending[id] = continuation

        do {
            let transport = try await ensureTransport()
            let line = try WireRequest(id: id, request: request).encodedLine()
            try await transport.send(line)
            Logger.client.debug("sent \(request.op, privacy: .public) as \(id, privacy: .public)")
        } catch {
            pending.removeValue(forKey: id)
            continuation.finish()
            throw error
        }
        return (id, stream)
    }

    /// Run a request to completion. Progress events call `progress`;
    /// `done` returns its payload; `error` throws `CoreError`. Cancelling the
    /// calling task sends a `cancel` for this request, after which the helper
    /// answers with a `cancelled` error.
    func perform(_ request: CoreRequest,
                 progress: (@Sendable (CoreProgress) -> Void)? = nil) async throws -> JSONValue {
        let (id, stream) = try await events(for: request)
        // Iterate in an unstructured task: an AsyncStream stops yielding as
        // soon as the consuming task is cancelled, but we need the helper's
        // own `cancelled` error to know nothing was written.
        let consumer = Task {
            for await event in stream {
                switch event {
                case .progress(let p):
                    progress?(p)
                case .done(let result):
                    return result
                case .error(let error):
                    throw error
                }
            }
            throw CoreError.helperExited
        }
        return try await withTaskCancellationHandler {
            try await consumer.value
        } onCancel: {
            Task {
                await self.cancel(id: id)
                await self.giveUpAfterGrace(id: id)
            }
        }
    }

    /// A helper that never acknowledges a cancel (hung worker, dead pipe)
    /// must not pin the caller forever: after `cancelGrace` the request is
    /// failed locally with a `cancelled` error.
    private func giveUpAfterGrace(id: String) async {
        try? await Task.sleep(for: cancelGrace)
        guard let continuation = pending.removeValue(forKey: id) else { return }
        Logger.client.warning("request \(id, privacy: .public) ignored cancel for \(self.cancelGrace.components.seconds, privacy: .public)s; failing locally")
        continuation.yield(.error(CoreError(
            code: .cancelled,
            message: "Cancelled — the helper did not confirm, so check the destination before assuming nothing was written.",
            detail: "no cancelled event within \(cancelGrace.components.seconds)s")))
        continuation.finish()
    }

    func perform<T: Decodable & Sendable>(_ request: CoreRequest, as type: T.Type = T.self,
                                          progress: (@Sendable (CoreProgress) -> Void)? = nil) async throws -> T {
        let raw = try await perform(request, progress: progress)
        do {
            return try raw.decoded(as: T.self)
        } catch {
            throw CoreError(code: .protocolError,
                            message: "The helper answered in a format this version of QuantaCrypt does not understand.",
                            detail: "\(request.op): \(error)")
        }
    }

    /// Ask the helper to stop request `id`. Best effort: a request that has
    /// already finished simply reports `cancelled: false`.
    func cancel(id: String) async {
        guard pending[id] != nil, !shuttingDown, restarting == nil else { return }
        do {
            // Fire and forget: a hung helper would never answer, and the
            // caller is already waiting on the original request's stream.
            let (_, acknowledgement) = try await events(for: .cancel(target: id))
            Task { for await _ in acknowledgement {} }
        } catch {
            Logger.client.debug("cancel \(id, privacy: .public) failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    /// Launch the helper now so the first real request does not pay for it.
    func start() async throws {
        _ = try await ensureTransport()
    }

    /// What the helper reported when it stopped.
    struct ShutdownOutcome: Sendable, Equatable {
        /// Mount points the helper could not unmount (files still open).
        var unmountFailed: [String] = []
    }

    /// How long `shutdown` waits for the helper's `done`. The helper cancels
    /// in-flight work and unmounts every volume *before* answering, so this
    /// has to cover that work; the EOF grace only starts once it arrives.
    static let shutdownTimeout: Duration = .seconds(30)

    /// Graceful stop: `shutdown` (the helper cancels work and unmounts every
    /// volume, then answers), EOF, then escalate if it hangs. Safe to call
    /// twice.
    @discardableResult
    func shutdown() async -> ShutdownOutcome {
        shuttingDown = true
        guard let transport else { return ShutdownOutcome() }
        let gen = generation
        var outcome = ShutdownOutcome()
        do {
            let result = try await withTimeout(Self.shutdownTimeout) {
                try await self.perform(.shutdown)
            }
            if case .array(let failed)? = result["unmount_failed"] {
                outcome.unmountFailed = failed.compactMap(\.stringValue)
            }
        } catch {
            Logger.client.warning("shutdown request failed: \(error.localizedDescription, privacy: .public)")
        }
        await transport.terminate(timeout: .seconds(10))
        if generation == gen { transportEnded(generation: gen) }
        return outcome
    }

    /// Stop the current helper (if any) and launch a fresh one, e.g. after the
    /// helper path changed in Settings. Pending requests fail with `.helperExited`.
    func restart() async {
        // A second caller joins the restart in progress rather than
        // stopping the helper the first one is about to launch.
        if let restarting {
            await restarting.value
            return
        }
        let task = Task { await performRestart() }
        restarting = task
        await task.value
        restarting = nil
    }

    private func performRestart() async {
        if let transport {
            let gen = generation
            try? await withTimeout(Self.shutdownTimeout) {
                _ = try await self.perform(.shutdown)
            }
            await transport.terminate(timeout: .seconds(5))
            if generation == gen { transportEnded(generation: gen) }
        }
        shuttingDown = false
        do {
            try await start()
        } catch {
            Logger.client.error("restart failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    // MARK: Transport lifecycle

    private func ensureTransport() async throws -> any CoreTransport {
        if let transport { return transport }
        // Actor reentrancy: a second caller arriving while `start()` is
        // suspended must wait for the same launch, not spawn a second helper.
        if let launching {
            return try await launching.value
        }
        let launch = Task<any CoreTransport, any Error> {
            let transport = try makeTransport()
            let lines = try await transport.start()
            attach(transport, lines: lines)
            return transport
        }
        launching = launch
        defer { launching = nil }
        return try await launch.value
    }

    private func attach(_ transport: any CoreTransport, lines: AsyncThrowingStream<String, any Error>) {
        generation += 1
        let gen = generation
        self.transport = transport
        readTask = Task { [weak self] in
            do {
                for try await line in lines {
                    Logger.client.debug("read loop got \(line.utf8.count, privacy: .public) bytes")
                    await self?.handle(line: line)
                }
                Logger.client.debug("read loop ended (stream finished)")
            } catch {
                Logger.client.error("helper stdout failed: \(error.localizedDescription, privacy: .public)")
            }
            await self?.transportEnded(generation: gen)
        }
    }

    private func transportEnded(generation gen: Int) {
        Logger.client.debug("transportEnded gen=\(gen, privacy: .public) current=\(self.generation, privacy: .public)")
        guard gen == generation, transport != nil else { return }
        transport = nil
        readTask = nil
        // A stop we asked for (quit or restart) is not a crash.
        if !shuttingDown && restarting == nil {
            restartCount += 1
            Logger.client.error("helper exited with \(self.pending.count, privacy: .public) request(s) pending")
            unexpectedExitHandler?()
        }
        let waiting = pending
        pending.removeAll()
        for (_, continuation) in waiting {
            continuation.yield(.error(.helperExited))
            continuation.finish()
        }
    }

    private func handle(line: String) {
        let trimmed = line.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        let wire: WireEvent
        do {
            wire = try WireEvent.parse(line: trimmed)
        } catch {
            Logger.client.error("unparseable helper line (\(trimmed.count, privacy: .public) bytes): \(error.localizedDescription, privacy: .public)")
            return
        }
        guard let id = wire.id else {
            Logger.client.error("helper error without id: \(wire.message ?? "", privacy: .public)")
            return
        }
        Logger.client.debug("event \(wire.event, privacy: .public) for \(id, privacy: .public); pending=\(self.pending.count, privacy: .public)")
        guard let continuation = pending[id] else {
            Logger.client.debug("event for unknown request \(id, privacy: .public)")
            return
        }
        guard let event = wire.coreEvent else {
            Logger.client.debug("unknown event kind \(wire.event, privacy: .public)")
            return
        }
        continuation.yield(event)
        switch event {
        case .done, .error:
            pending.removeValue(forKey: id)
            continuation.finish()
        case .progress:
            break
        }
    }
}

/// Run `body`, failing with `TimeoutError` if it takes longer than `limit`.
func withTimeout<T: Sendable>(_ limit: Duration,
                              _ body: @escaping @Sendable () async throws -> T) async throws -> T {
    try await withThrowingTaskGroup(of: T.self) { group in
        group.addTask { try await body() }
        group.addTask {
            try await Task.sleep(for: limit)
            throw TimeoutError()
        }
        guard let first = try await group.next() else { throw TimeoutError() }
        group.cancelAll()
        return first
    }
}

struct TimeoutError: Error, Sendable {}
