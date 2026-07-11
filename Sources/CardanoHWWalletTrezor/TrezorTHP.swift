import Foundation

/// Trezor Host Protocol (THP, v2) **transport-layer** framing: fixed-size packets (64-byte USB
/// reports) carrying a channel id, an ABP sequence bit in the control byte, and a CRC-32 over the
/// segmented payload. Pure codec — the Noise secure channel (``NoiseXXHandshake``) rides on top.
///
/// Reference: Trezor `docs/common/thp/specification.md` (Transport layer).
public enum TrezorTHP {
    public static let reportSize = 64
    public static let broadcastChannel: UInt16 = 0xFFFF

    /// Control-byte patterns (see the spec's transport-packet table). Handshake/transport variants
    /// carry the ABP sequence bit; use ``control(_:sequence:)`` to set it.
    public enum Control {
        public static let channelAllocationRequest: UInt8 = 0x40
        public static let channelAllocationResponse: UInt8 = 0x41
        public static let ack: UInt8 = 0x20                     // 0010_X000; sequence bit = bit 3
        public static let handshakeInitRequest: UInt8 = 0x00    // 000_XX_000
        public static let handshakeInitResponse: UInt8 = 0x01
        public static let handshakeCompletionRequest: UInt8 = 0x02
        public static let handshakeCompletionResponse: UInt8 = 0x03
        public static let encryptedTransport: UInt8 = 0x04
        public static let continuation: UInt8 = 0x80
    }

    /// Set the ABP sequence bit (bit 4, `0x10`) on a handshake/transport control byte.
    public static func control(_ base: UInt8, sequence: Int) -> UInt8 {
        base | (sequence == 1 ? 0x10 : 0x00)
    }

    /// Set the ACK sequence bit (bit 3, `0x08`).
    public static func ackControl(sequence: Int) -> UInt8 {
        Control.ack | (sequence == 1 ? 0x08 : 0x00)
    }

    // MARK: - Encode

    /// Split a full transport payload into 64-byte packets: an initiation packet
    /// (`control ‖ cid ‖ length ‖ …`) plus continuation packets, with a CRC-32 appended over
    /// `header ‖ payload`. Packets are zero-padded to `reportSize`.
    public static func packets(control: UInt8, channel: UInt16, payload: Data) -> [Data] {
        let length = UInt16(payload.count + 4)   // payload + CRC-32
        var header = Data([control])
        header.append(contentsOf: beUInt16(channel))
        header.append(contentsOf: beUInt16(length))

        var body = payload
        body.append(contentsOf: beUInt32(crc32(header + payload)))

        var packets: [Data] = []
        // Initiation packet: 5-byte header + first (reportSize-5) body bytes.
        var offset = 0
        let firstRoom = reportSize - 5
        var first = header
        let firstEnd = min(firstRoom, body.count)
        first.append(body[body.startIndex..<body.startIndex.advanced(by: firstEnd)])
        pad(&first)
        packets.append(first)
        offset = firstEnd

        // Continuation packets: control 0x80 + cid + (reportSize-3) body bytes.
        while offset < body.count {
            var cont = Data([Control.continuation])
            cont.append(contentsOf: beUInt16(channel))
            let end = min(offset + reportSize - 3, body.count)
            cont.append(body[body.startIndex.advanced(by: offset)..<body.startIndex.advanced(by: end)])
            pad(&cont)
            packets.append(cont)
            offset = end
        }
        return packets
    }

    // MARK: - Decode

    /// Reassembles THP packets into `(control, channel, payload)`. Feed packets via ``push(_:)``;
    /// returns `nil` until the declared length is collected and the CRC validates.
    public struct Reassembler {
        private var control: UInt8?
        private var channel: UInt16 = 0
        private var header = Data()
        private var expectedLength: Int?     // transport payload with CRC
        private var body = Data()

        public init() {}

        public mutating func push(_ packet: Data) throws -> (control: UInt8, channel: UInt16, payload: Data)? {
            let bytes = Array(packet)
            guard let ctrl = bytes.first else { throw TrezorError.malformedResponse("empty THP packet") }

            if ctrl & 0x80 == 0x80 {
                // Continuation packet: 0x80 + cid(2) + body.
                guard expectedLength != nil, bytes.count >= 3 else {
                    throw TrezorError.malformedResponse("unexpected THP continuation packet")
                }
                body.append(contentsOf: bytes[3...])
            } else {
                // Initiation packet: control + cid(2) + length(2) + body.
                guard bytes.count >= 5 else { throw TrezorError.malformedResponse("short THP initiation packet") }
                control = ctrl
                channel = (UInt16(bytes[1]) << 8) | UInt16(bytes[2])
                let length = Int((UInt16(bytes[3]) << 8) | UInt16(bytes[4]))
                expectedLength = length
                header = Data(bytes[0..<5])
                body = Data(bytes[5...])
            }

            guard let expectedLength, let control, body.count >= expectedLength else { return nil }
            let full = body.prefix(expectedLength)
            let payload = Data(full.prefix(expectedLength - 4))
            let crcBytes = Array(full.suffix(4))
            let crc = (UInt32(crcBytes[0]) << 24) | (UInt32(crcBytes[1]) << 16) | (UInt32(crcBytes[2]) << 8) | UInt32(crcBytes[3])
            guard crc == crc32(header + payload) else {
                throw TrezorError.malformedResponse("THP CRC mismatch")
            }
            return (control, channel, payload)
        }
    }

    // MARK: - CRC-32-IEEE (reversed poly 0xEDB88320)

    public static func crc32(_ data: Data) -> UInt32 {
        var crc: UInt32 = 0xFFFF_FFFF
        for byte in data {
            crc ^= UInt32(byte)
            for _ in 0..<8 {
                crc = (crc & 1) == 1 ? (crc >> 1) ^ 0xEDB8_8320 : crc >> 1
            }
        }
        return crc ^ 0xFFFF_FFFF
    }

    // MARK: - Helpers

    private static func pad(_ packet: inout Data) {
        if packet.count < reportSize { packet.append(Data(repeating: 0, count: reportSize - packet.count)) }
    }
    private static func beUInt16(_ v: UInt16) -> [UInt8] { [UInt8(v >> 8), UInt8(v & 0xff)] }
    private static func beUInt32(_ v: UInt32) -> [UInt8] {
        [UInt8((v >> 24) & 0xff), UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)]
    }
}
