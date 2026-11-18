import Foundation
import CardanoHWKit

/// The transport a ``TrezorSignSession`` runs its Cardano protobuf dialogue over. Two implementations:
/// ``TrezorV1Transport`` (legacy Codec-v1 framing, Model T / One / older Safe firmware) and
/// ``TrezorTHPSession`` (the encrypted THP v2 channel, newest firmware). The session logic is
/// identical above this seam — it just sends typed messages and reads typed responses.
public protocol TrezorTransport: Sendable {
    /// Prepare the transport (open the link; for THP: allocate a channel + run the handshake).
    func open() async throws
    /// Send one typed message and read one typed response, surfacing device `Failure`s.
    func exchange(_ message: TrezorMessage) async throws -> (type: UInt16, payload: Data)
}

/// The legacy Trezor **Codec v1** transport: `##`+type+len framing over 64-byte HID reports on a
/// ``HardwarePacketLink``. Unencrypted; used by pre-THP firmware.
///
/// ``open()`` sends `Initialize { derive_cardano = true }` (the firmware refuses Cardano calls
/// without it), and ``exchange(_:)`` answers the device's `ButtonRequest`s with `ButtonAck` while
/// the user confirms on the device, calling `onButtonRequest` each time so the app can say so.
public final class TrezorV1Transport: TrezorTransport {
    private let link: HardwarePacketLink
    private let onButtonRequest: (@Sendable () -> Void)?

    public init(link: HardwarePacketLink, onButtonRequest: (@Sendable () -> Void)? = nil) {
        self.link = link
        self.onButtonRequest = onButtonRequest
    }

    public func open() async throws {
        try await link.open()
        var initialize = ProtobufWriter()
        initialize.bool(3, true)   // derive_cardano
        let response = try await exchange(TrezorMessage(type: TrezorMessageType.initialize, payload: initialize.data))
        guard response.type == TrezorMessageType.features else {
            throw TrezorError.unexpectedMessage(type: response.type)
        }
    }

    public func exchange(_ message: TrezorMessage) async throws -> (type: UInt16, payload: Data) {
        var response = try await call(message)
        while response.type == TrezorMessageType.buttonRequest {
            onButtonRequest?()
            response = try await call(TrezorMessage(type: TrezorMessageType.buttonAck, payload: Data()))
        }
        if response.type == TrezorMessageType.failure {
            throw try TrezorError.fromFailurePayload(response.payload)
        }
        return response
    }

    private func call(_ message: TrezorMessage) async throws -> (type: UInt16, payload: Data) {
        for report in TrezorProtocolV1.encode(messageType: message.type, payload: message.payload) {
            try await link.write(report)
        }
        var decoder = TrezorProtocolV1.Decoder()
        while true {
            let report = try await link.read()
            if let (type, payload) = try decoder.push(report) {
                return (type, payload)
            }
        }
    }
}
