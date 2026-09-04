import Foundation
@testable import QuantaCrypt

/// Scriptable stand-in for the helper process: records every request line
/// and lets the test push event lines back, or end the stream to simulate
/// a crash.
actor FakeTransport: CoreTransport {
    private(set) var sent: [String] = []
    private var continuation: AsyncThrowingStream<String, any Error>.Continuation?
    private(set) var started = false
    private(set) var terminated = false
    /// How long the client was willing to wait for EOF before escalating.
    private(set) var terminateTimeout: Duration?
    private(set) var inputClosed = false
    private var waiters: [CheckedContinuation<Void, Never>] = []

    func start() async throws -> AsyncThrowingStream<String, any Error> {
        started = true
        let (stream, continuation) = AsyncThrowingStream<String, any Error>.makeStream()
        self.continuation = continuation
        return stream
    }

    func send(_ line: String) async throws {
        sent.append(line)
        let pending = waiters
        waiters.removeAll()
        for w in pending { w.resume() }
    }

    func closeInput() async {
        inputClosed = true
    }

    func terminate(timeout: Duration) async {
        terminated = true
        terminateTimeout = timeout
        continuation?.finish()
    }

    // MARK: Test controls

    func emit(_ line: String) {
        continuation?.yield(line)
    }

    func emit(_ object: [String: Any]) {
        let data = try! JSONSerialization.data(withJSONObject: object)
        emit(String(decoding: data, as: UTF8.self))
    }

    /// Simulate the helper dying.
    func crash() {
        continuation?.finish()
    }

    /// Wait until `count` requests have been written.
    func waitForRequests(_ count: Int) async {
        while sent.count < count {
            await withCheckedContinuation { waiters.append($0) }
        }
    }

    /// Parsed request number `index` (0-based).
    func request(_ index: Int) -> SentRequest {
        let data = Data(sent[index].utf8)
        return (try? JSONDecoder().decode(SentRequest.self, from: data)) ?? SentRequest(id: nil, op: nil, params: nil)
    }
}

struct SentRequest: Decodable, Sendable {
    let id: String?
    let op: String?
    let params: [String: JSONValue]?
}
