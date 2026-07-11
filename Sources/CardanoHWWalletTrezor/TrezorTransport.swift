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
public final class TrezorV1Transport: TrezorTransport {
    private let link: HardwarePacketLink

    public init(link: HardwarePacketLink) { self.link = link }

    public func open() async throws { try await link.open() }

    public func exchange(_ message: TrezorMessage) async throws -> (type: UInt16, payload: Data) {
        for report in TrezorProtocolV1.encode(messageType: message.type, payload: message.payload) {
            try await link.write(report)
        }
        var decoder = TrezorProtocolV1.Decoder()
        while true {
            let report = try await link.read()
            if let (type, payload) = try decoder.push(report) {
                if type == TrezorMessageType.failure {
                    let reader = try ProtobufReader(payload)
                    throw TrezorError.failure(code: Int(reader.varint(1) ?? 0), message: reader.string(2) ?? "")
                }
                return (type, payload)
            }
        }
    }
}
