import Foundation
import CardanoHWKit
@testable import CardanoHWWalletTrezor

/// A ``TrezorTransport`` that speaks the Cardano protobuf dialogue to the **trezor-user-env emulator**
/// (real `trezor-firmware`) over its node-bridge HTTP API, confirming each on-device `ButtonRequest`
/// via the WebSocket controller. This lets a real ``TrezorSignSession`` run end-to-end against actual
/// firmware — no physical Trezor. Test-only; not shipped in the library.
///
/// Wire details (see `Tools/emulator/` + the emulator memory): the bridge HTTP is on `:21328`
/// (`:21325` is UDP debug only); `/call` bodies are JSON `{data, protocol:"bridge"}` where
/// `data = msgType(2B BE) ‖ length(4B BE) ‖ protobuf`; Cardano needs `Initialize{derive_cardano=true}`
/// first; and the WS controller (`:9001`) presses the emulator's buttons (`emulator-press-yes`).
///
/// Requires the emulator to be up and seeded (run `Tools/emulator/bootstrap.mjs` first). The
/// integration tests that use it are gated on the `TREZOR_EMULATOR=1` environment variable.
actor TrezorEmulatorBridge: TrezorTransport {
    private let bridgeBase = "http://127.0.0.1:21328"
    private let wsURL = URL(string: "ws://127.0.0.1:9001")!

    private var session: String = ""
    private var isOpen = false
    private var ws: URLSessionWebSocketTask?
    private var wsConnected = false

    init() {}

    // MARK: - TrezorTransport

    func open() async throws {
        if isOpen { return }
        try await connectWebSocket()
        // Standard account paths + own-address outputs are "safe", but allow-unsafe-paths is harmless
        // and keeps the session usable if a test reaches for a non-standard path.
        _ = try? await wsCommand("emulator-allow-unsafe-paths")

        let devices = try await enumerate()
        guard let device = devices.first,
              let path = device["path"] as? String else {
            throw TrezorError.transport("No emulator device on the bridge — run Tools/emulator/bootstrap.mjs.")
        }
        let previous = (device["session"] as? String) ?? "null"
        let acquired = try await postJSON("/acquire/\(path)/\(previous)", body: nil)
        guard let sessionId = acquired["session"] as? String else {
            throw TrezorError.transport("Bridge acquire returned no session id.")
        }
        session = sessionId

        // Initialize { derive_cardano = true } (field 3) — required before any Cardano call.
        var initWriter = ProtobufWriter()
        initWriter.varint(3, 1)
        _ = try await call(type: 0, payload: initWriter.data)
        isOpen = true
    }

    /// Send one typed message and read one typed response, transparently confirming any interleaved
    /// `ButtonRequest`s on the emulator and surfacing device `Failure`s.
    func exchange(_ message: TrezorMessage) async throws -> (type: UInt16, payload: Data) {
        var response = try await call(type: message.type, payload: message.payload)
        while response.type == messageTypeButtonRequest {
            _ = try await wsCommand("emulator-press-yes")
            response = try await call(type: messageTypeButtonAck, payload: Data())
        }
        if response.type == TrezorMessageType.failure {
            let reader = try ProtobufReader(response.payload)
            throw TrezorError.failure(code: Int(reader.varint(1) ?? 0), message: reader.string(2) ?? "")
        }
        return response
    }

    func release() async {
        if !session.isEmpty { _ = try? await postText("/release/\(session)", body: nil) }
        ws?.cancel(with: .goingAway, reason: nil)
        isOpen = false
        wsConnected = false
    }

    private let messageTypeButtonRequest: UInt16 = 26
    private let messageTypeButtonAck: UInt16 = 27

    // MARK: - Bridge calls

    private func enumerate() async throws -> [[String: Any]] {
        let text = try await postText("/enumerate", body: nil)
        guard let array = try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [[String: Any]] else {
            throw TrezorError.transport("Bridge /enumerate returned unexpected JSON: \(text)")
        }
        return array
    }

    /// One `POST /call/{session}` → one framed response `(type, payload)`.
    private func call(type: UInt16, payload: Data) async throws -> (type: UInt16, payload: Data) {
        let data = be16(type) + be32(UInt32(payload.count)) + payload.toHex
        let bodyObject: [String: Any] = ["data": data, "protocol": "bridge"]
        let bodyData = try JSONSerialization.data(withJSONObject: bodyObject)
        let respText = try await postText("/call/\(session)", body: String(decoding: bodyData, as: UTF8.self))
        guard let json = try JSONSerialization.jsonObject(with: Data(respText.utf8)) as? [String: Any],
              let hex = json["data"] as? String else {
            throw TrezorError.transport("Bridge /call returned unexpected JSON: \(respText)")
        }
        return try parseFramed(hex)
    }

    private func parseFramed(_ hex: String) throws -> (type: UInt16, payload: Data) {
        guard hex.count >= 12, let framed = Data(hexString: hex) else {
            throw TrezorError.malformedResponse("Bridge response frame too short: \(hex)")
        }
        let type = (UInt16(framed[0]) << 8) | UInt16(framed[1])
        let length = (Int(framed[2]) << 24) | (Int(framed[3]) << 16) | (Int(framed[4]) << 8) | Int(framed[5])
        guard framed.count >= 6 + length else {
            throw TrezorError.malformedResponse("Bridge response payload truncated (want \(length), have \(framed.count - 6)).")
        }
        let payload = framed.subdata(in: 6..<(6 + length))
        return (type, payload)
    }

    // MARK: - HTTP

    private func postJSON(_ path: String, body: String?) async throws -> [String: Any] {
        let text = try await postText(path, body: body)
        guard let json = try JSONSerialization.jsonObject(with: Data(text.utf8)) as? [String: Any] else {
            throw TrezorError.transport("Bridge \(path) returned unexpected JSON: \(text)")
        }
        return json
    }

    private func postText(_ path: String, body: String?) async throws -> String {
        guard let url = URL(string: bridgeBase + path) else {
            throw TrezorError.transport("Bad bridge URL: \(path)")
        }
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        // Match the JS harness: string body, no Origin header (the bridge allow-lists by Host).
        request.setValue("text/plain;charset=UTF-8", forHTTPHeaderField: "Content-Type")
        if let body { request.httpBody = Data(body.utf8) }
        let (data, response) = try await URLSession.shared.data(for: request)
        let text = String(decoding: data, as: UTF8.self)
        guard let http = response as? HTTPURLResponse, (200..<300).contains(http.statusCode) else {
            let code = (response as? HTTPURLResponse)?.statusCode ?? -1
            throw TrezorError.transport("Bridge \(path) -> \(code): \(text)")
        }
        return text
    }

    // MARK: - WebSocket controller

    private func connectWebSocket() async throws {
        if wsConnected { return }
        let task = URLSession.shared.webSocketTask(with: wsURL)
        task.resume()
        ws = task
        // The first frame after connect is a welcome/version blob with no id — drain it.
        _ = try? await receive(timeout: .seconds(5))
        wsConnected = true
    }

    /// Send a controller command and read one acknowledgement frame (best-effort; commands are
    /// serialized, so we don't match on id).
    @discardableResult
    private func wsCommand(_ type: String, timeout: Duration = .seconds(30)) async throws -> String? {
        guard let ws else { throw TrezorError.transport("WS controller not connected.") }
        let payload = try JSONSerialization.data(withJSONObject: ["id": 1, "type": type])
        try await ws.send(.string(String(decoding: payload, as: UTF8.self)))
        return try await receive(timeout: timeout)
    }

    private func receive(timeout: Duration) async throws -> String? {
        guard let ws else { return nil }
        return try await withThrowingTaskGroup(of: String?.self) { group in
            group.addTask {
                switch try await ws.receive() {
                case .string(let string): return string
                case .data(let data): return String(decoding: data, as: UTF8.self)
                @unknown default: return nil
                }
            }
            group.addTask {
                try await Task.sleep(for: timeout)
                return nil
            }
            let first = try await group.next() ?? nil
            group.cancelAll()
            return first
        }
    }

    // MARK: - Hex helpers

    private func be16(_ value: UInt16) -> String { String(format: "%04x", value) }
    private func be32(_ value: UInt32) -> String { String(format: "%08x", value) }
}
