import XCTest
@testable import QuantaCrypt

final class CoreProtocolTests: XCTestCase {
    func testProgressEventParses() throws {
        let line = #"{"id":"r1","event":"progress","stage":"kdf","label":"Securing password","pct":0.25,"message":"Deriving key"}"#
        let event = try WireEvent.parse(line: line).coreEvent
        XCTAssertEqual(event, .progress(CoreProgress(stage: "kdf", label: "Securing password", pct: 0.25, message: "Deriving key")))
    }

    func testProgressWithNullPct() throws {
        let line = #"{"id":"r1","event":"progress","stage":"mount","label":"Mounting","pct":null,"message":"Mounting..."}"#
        guard case .progress(let p)? = try WireEvent.parse(line: line).coreEvent else { return XCTFail("not progress") }
        XCTAssertNil(p.pct)
        XCTAssertEqual(p.stage, "mount")
    }

    func testDoneEventCarriesResult() throws {
        let line = #"{"id":"r1","event":"done","result":{"version":"1.3.0","format_version":1,"platform":"darwin"}}"#
        guard case .done(let result)? = try WireEvent.parse(line: line).coreEvent else { return XCTFail("not done") }
        let info: VersionInfo = try result.decoded()
        XCTAssertEqual(info.version, "1.3.0")
        XCTAssertEqual(info.formatVersion, 1)
        XCTAssertNil(info.python)
    }

    func testErrorEventMapsCode() throws {
        let line = #"{"id":"r1","event":"error","code":"wrong_credentials","message":"Wrong.","detail":"InvalidTag"}"#
        guard case .error(let error)? = try WireEvent.parse(line: line).coreEvent else { return XCTFail("not error") }
        XCTAssertEqual(error.code, .wrongCredentials)
        XCTAssertEqual(error.message, "Wrong.")
        XCTAssertEqual(error.detail, "InvalidTag")
    }

    func testUnknownErrorCodeFallsBackToInternal() throws {
        let line = #"{"id":"r1","event":"error","code":"brand_new","message":"?","detail":""}"#
        guard case .error(let error)? = try WireEvent.parse(line: line).coreEvent else { return XCTFail("not error") }
        XCTAssertEqual(error.code, .internal)
    }

    func testErrorWithoutIdParses() throws {
        let line = #"{"id":null,"event":"error","code":"invalid_request","message":"bad","detail":""}"#
        let wire = try WireEvent.parse(line: line)
        XCTAssertNil(wire.id)
    }

    func testUnknownEventKindIsNil() throws {
        let line = #"{"id":"r1","event":"heartbeat"}"#
        XCTAssertNil(try WireEvent.parse(line: line).coreEvent)
    }

    func testRequestEncodingOmitsParamsForControlOps() throws {
        let line = try WireRequest(id: "a", request: .version).encodedLine()
        XCTAssertEqual(line, #"{"id":"a","op":"version"}"# + "\n")
    }

    func testEncryptRequestParams() throws {
        let req = CoreRequest.encrypt(source: "/tmp/in.txt", output: "/tmp/in.txt.qcx", credential: .splitKey(k: 3, n: 5))
        let line = try WireRequest(id: "e1", request: req).encodedLine()
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any])
        XCTAssertEqual(json["op"] as? String, "encrypt")
        let params = try XCTUnwrap(json["params"] as? [String: Any])
        XCTAssertEqual(params["mode"] as? String, "shamir")
        XCTAssertEqual(params["k"] as? Int, 3)
        XCTAssertEqual(params["n"] as? Int, 5)
        XCTAssertEqual(params["source"] as? String, "/tmp/in.txt")
        XCTAssertNil(params["password"])
    }

    func testDecryptVerifyOnlyOmitsOutputDir() throws {
        let req = CoreRequest.decrypt(path: "/f.qcx", outputDir: nil, credential: .shares(["QCSHARE-1", "QCSHARE-2"]), verifyOnly: true)
        let line = try WireRequest(id: "d", request: req).encodedLine()
        let json = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(line.utf8)) as? [String: Any])
        let params = try XCTUnwrap(json["params"] as? [String: Any])
        XCTAssertEqual(params["verify_only"] as? Bool, true)
        XCTAssertNil(params["output_dir"])
        XCTAssertEqual(params["shares"] as? [String], ["QCSHARE-1", "QCSHARE-2"])
    }

    func testCancelRequestTargets() throws {
        let line = try WireRequest(id: "c", request: .cancel(target: "r9")).encodedLine()
        XCTAssertEqual(line, #"{"id":"c","op":"cancel","params":{"target":"r9"}}"# + "\n")
    }

    func testResultStructsDecode() throws {
        let encrypt: JSONValue = ["output": "/o.qcx", "size": 10, "filename": "o.txt", "mode": "shamir",
                                  "threshold": 2, "total": 3,
                                  "shares": [["index": 1, "code": "QCSHARE-A", "mnemonic": "a b c"]]]
        let e: EncryptResult = try encrypt.decoded()
        XCTAssertEqual(e.shares?.first?.code, "QCSHARE-A")
        XCTAssertEqual(e.threshold, 2)

        let decrypt: JSONValue = ["output": "/x_2.txt", "filename": "x.txt", "size": 5, "original_size": 5,
                                  "timestamp": 1.0, "renamed": true]
        let d: DecryptResult = try decrypt.decoded()
        XCTAssertTrue(d.renamed)

        let fuse: JSONValue = ["fuse_backend": ["ok": false, "detail": "no backend"],
                               "fusepy": ["ok": true, "detail": "installed"], "ok": false]
        let f: FuseCheck = try fuse.decoded()
        XCTAssertFalse(f.ok)
        XCTAssertEqual(f.missingSummary, "disk mounting support")

        let list: JSONValue = ["volumes": [["mount_point": "/Users/x/QuantaCrypt Volumes/v", "volume_path": "/Users/x/v.qcv",
                                            "stats": ["file_count": 2, "dir_count": 0, "total_plaintext_size": 99]]]]
        let l: VolumeListResult = try list.decoded()
        XCTAssertEqual(l.volumes.first?.name, "v")
        XCTAssertEqual(l.volumes.first?.stats?.fileCount, 2)

        let inspect: JSONValue = ["path": "/f.qcx", "size": 1, "version": 1, "mode": "shamir", "threshold": 2,
                                  "total": 3, "embedded": false]
        let i: InspectInfo = try inspect.decoded()
        XCTAssertEqual(i.protectionSummary, "Protected by a split key — any 2 of the 3 shares unlock it.")
    }
}
