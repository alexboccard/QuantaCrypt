import XCTest
@testable import QuantaCrypt

final class CoreClientTests: XCTestCase {
    /// One shared transport per client; `Holder` lets the factory hand it out.
    private final class Holder: @unchecked Sendable {
        var transports: [FakeTransport] = []
        let lock = NSLock()
        func make() -> FakeTransport {
            let t = FakeTransport()
            lock.lock(); transports.append(t); lock.unlock()
            return t
        }
        var count: Int { lock.lock(); defer { lock.unlock() }; return transports.count }
        var last: FakeTransport { lock.lock(); defer { lock.unlock() }; return transports.last! }
    }

    private func makeClient() -> (CoreClient, Holder) {
        let holder = Holder()
        let client = CoreClient { holder.make() }
        return (client, holder)
    }

    func testEventsAreRoutedByIdAcrossConcurrentRequests() async throws {
        let (client, holder) = makeClient()

        async let first: JSONValue = client.perform(.ping)
        async let second: JSONValue = client.perform(.version)

        let transport = await waitForTransport(holder)
        await transport.waitForRequests(2)
        // `async let` children start in no guaranteed order; find each by op.
        let requests = [await transport.request(0), await transport.request(1)]
        let idPing = try XCTUnwrap(requests.first { $0.op == "ping" }?.id)
        let idVersion = try XCTUnwrap(requests.first { $0.op == "version" }?.id)
        XCTAssertNotEqual(idPing, idVersion)

        // Answer out of order.
        await transport.emit(["id": idVersion, "event": "done", "result": ["version": "9.9.9", "format_version": 1, "platform": "darwin"]])
        await transport.emit(["id": idPing, "event": "done", "result": [:]])

        let pingResult = try await first
        let versionResult = try await second
        XCTAssertEqual(pingResult, .object([:]))
        XCTAssertEqual(versionResult["version"], .string("9.9.9"))
    }

    func testProgressThenDone() async throws {
        let (client, holder) = makeClient()
        let seen = ProgressSink()

        async let result: JSONValue = client.perform(.fuseCheck) { seen.append($0) }
        let transport = await waitForTransport(holder)
        await transport.waitForRequests(1)
        let req0 = await transport.request(0)
        let id = try XCTUnwrap(req0.id)
        await transport.emit(["id": id, "event": "progress", "stage": "kdf", "label": "Securing password", "pct": 0.5, "message": "m"])
        await transport.emit(["id": id, "event": "progress", "stage": "payload", "label": "Encrypting file", "pct": NSNull(), "message": "m2"])
        await transport.emit(["id": id, "event": "done", "result": ["ok": true]])

        let r = try await result
        XCTAssertEqual(r["ok"], .bool(true))
        XCTAssertEqual(seen.labels, ["Securing password", "Encrypting file"])
    }

    func testErrorEventThrowsCoreError() async throws {
        let (client, holder) = makeClient()
        async let result: JSONValue = client.perform(.inspect(path: "/nope"))
        let transport = await waitForTransport(holder)
        await transport.waitForRequests(1)
        let req0 = await transport.request(0)
        let id = try XCTUnwrap(req0.id)
        await transport.emit(["id": id, "event": "error", "code": "not_found", "message": "File not found", "detail": "FileNotFoundError"])

        do {
            _ = try await result
            XCTFail("expected throw")
        } catch let error as CoreError {
            XCTAssertEqual(error.code, .notFound)
            XCTAssertEqual(error.detail, "FileNotFoundError")
        }
    }

    func testEventsForUnknownIdAreIgnored() async throws {
        let (client, holder) = makeClient()
        async let result: JSONValue = client.perform(.ping)
        let transport = await waitForTransport(holder)
        await transport.waitForRequests(1)
        let req0 = await transport.request(0)
        let id = try XCTUnwrap(req0.id)
        await transport.emit(["id": "stranger", "event": "done", "result": ["x": 1]])
        await transport.emit("not json at all")
        await transport.emit(["id": id, "event": "done", "result": ["x": 2]])
        let r = try await result
        XCTAssertEqual(r["x"], .number(2))
    }

    func testHelperExitFailsPendingAndRestartsOnNextRequest() async throws {
        let (client, holder) = makeClient()
        async let result: JSONValue = client.perform(.ping)
        let transport = await waitForTransport(holder)
        await transport.waitForRequests(1)
        await transport.crash()

        do {
            _ = try await result
            XCTFail("expected helperExited")
        } catch let error as CoreError {
            XCTAssertEqual(error.code, .helperExited)
        }

        async let second: JSONValue = client.perform(.ping)
        while holder.count < 2 { await Task.yield() }
        let fresh = holder.last
        await fresh.waitForRequests(1)
        let freshReq = await fresh.request(0)
        let id = try XCTUnwrap(freshReq.id)
        await fresh.emit(["id": id, "event": "done", "result": [:]])
        _ = try await second
        let restarts = await client.restartCount
        XCTAssertEqual(restarts, 1)
        XCTAssertEqual(holder.count, 2)
    }

    func testTaskCancellationSendsCancelRequest() async throws {
        let (client, holder) = makeClient()
        let task = Task { try await client.perform(.encrypt(source: "/a", output: "/a.qcx", credential: .password("pw"))) }
        let transport = await waitForTransport(holder)
        await transport.waitForRequests(1)
        let req0 = await transport.request(0)
        let id = try XCTUnwrap(req0.id)

        task.cancel()
        await transport.waitForRequests(2)
        let cancelReq = await transport.request(1)
        XCTAssertEqual(cancelReq.op, "cancel")
        XCTAssertEqual(cancelReq.params?["target"]?.stringValue, id)

        // The helper answers the cancel, then the original request errors out.
        let cancelId = try XCTUnwrap(cancelReq.id)
        await transport.emit(["id": cancelId, "event": "done", "result": ["cancelled": true]])
        await transport.emit(["id": id, "event": "error", "code": "cancelled", "message": "Cancelled — nothing was written.", "detail": ""])
        do {
            _ = try await task.value
            XCTFail("expected cancelled")
        } catch let error as CoreError {
            XCTAssertTrue(error.isCancellation)
        }
    }

    func testCancelIgnoredByHelperFailsLocallyAfterGrace() async throws {
        let holder = Holder()
        let client = CoreClient(transportFactory: { holder.make() }, cancelGrace: .milliseconds(100))
        let task = Task { try await client.perform(.encrypt(source: "/a", output: "/a.qcx", credential: .password("pw"))) }
        let transport = await waitForTransport(holder)
        await transport.waitForRequests(1)
        task.cancel()
        await transport.waitForRequests(2)   // the cancel request went out; the helper never answers
        do {
            _ = try await task.value
            XCTFail("expected cancelled")
        } catch let error as CoreError {
            XCTAssertEqual(error.code, .cancelled)
            XCTAssertTrue(error.detail.contains("no cancelled event"))
        }
    }

    func testShutdownSendsShutdownThenTerminates() async throws {
        let (client, holder) = makeClient()
        try await client.start()
        let transport = await waitForTransport(holder)
        let shutdownTask = Task { await client.shutdown() }
        await transport.waitForRequests(1)
        let req = await transport.request(0)
        XCTAssertEqual(req.op, "shutdown")
        await transport.emit(["id": req.id!, "event": "done", "result": [:]])
        await shutdownTask.value
        let terminated = await transport.terminated
        XCTAssertTrue(terminated)
        let running = await client.isRunning
        XCTAssertFalse(running)

        do {
            _ = try await client.perform(.ping)
            XCTFail("requests after shutdown must fail")
        } catch let error as CoreError {
            XCTAssertEqual(error.code, .helperUnavailable)
        }
    }

    func testTransportFactoryFailureSurfacesAsCoreError() async {
        let client = CoreClient {
            throw CoreError(code: .helperUnavailable, message: "missing", detail: "searched")
        }
        do {
            _ = try await client.perform(.ping)
            XCTFail("expected throw")
        } catch let error as CoreError {
            XCTAssertEqual(error.code, .helperUnavailable)
        } catch {
            XCTFail("wrong error \(error)")
        }
    }

    // MARK: Helpers

    private func waitForTransport(_ holder: Holder) async -> FakeTransport {
        while holder.count == 0 { await Task.yield() }
        return holder.last
    }
}

/// Thread-safe collector for progress callbacks.
private final class ProgressSink: @unchecked Sendable {
    private let lock = NSLock()
    private var items: [CoreProgress] = []
    func append(_ p: CoreProgress) { lock.lock(); items.append(p); lock.unlock() }
    var labels: [String] { lock.lock(); defer { lock.unlock() }; return items.map(\.label) }
}
