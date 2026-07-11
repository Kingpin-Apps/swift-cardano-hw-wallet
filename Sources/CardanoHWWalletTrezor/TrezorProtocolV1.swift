import Foundation

/// Trezor wire protocol **v1** framing over 64-byte HID reports. Pure codec — no I/O, no protobuf.
///
/// A message is `payload` (protobuf-serialized bytes) tagged with a 16-bit message type. The v1
/// header is:
///
///     '#' '#'  [msgType: 2B BE]  [length: 4B BE]  [payload…]
///
/// The header+payload byte-stream is then split into 63-byte chunks, each prefixed with `'?'`
/// (0x3f) to form a 64-byte HID report. Decoding reverses this: strip the `'?'` from each report,
/// read the `##`-header from the first, and accumulate `length` payload bytes.
///
/// Newer firmware negotiates the encrypted **THP** (v2) protocol; that's a documented follow-up.
/// This targets protocol-v1 (Model T / One / older Safe firmware).
public enum TrezorProtocolV1 {
    static let reportMarker: UInt8 = 0x3f   // '?'
    static let headerMagic: UInt8 = 0x23    // '#'
    public static let reportSize: Int = 64
    static let chunkSize: Int = 63          // reportSize - 1 marker byte

    // MARK: - Encode

    /// Encode a typed message into a sequence of 64-byte HID reports (zero-padded last report).
    public static func encode(messageType: UInt16, payload: Data) -> [Data] {
        var stream = Data([headerMagic, headerMagic])
        stream.append(contentsOf: bigEndian16(messageType))
        stream.append(contentsOf: bigEndian32(UInt32(payload.count)))
        stream.append(payload)

        var reports: [Data] = []
        var offset = 0
        while offset < stream.count {
            var report = Data([reportMarker])
            let end = min(offset + chunkSize, stream.count)
            report.append(stream[stream.startIndex.advanced(by: offset)..<stream.startIndex.advanced(by: end)])
            if report.count < reportSize { report.append(Data(repeating: 0, count: reportSize - report.count)) }
            reports.append(report)
            offset = end
        }
        return reports
    }

    // MARK: - Decode

    /// Reassembles HID reports into one typed message. Feed reports via ``push(_:)``; returns `nil`
    /// until the full payload is collected, then `(type, payload)`.
    public struct Decoder {
        private var stream = Data()
        private var messageType: UInt16?
        private var expectedLength: Int?

        public init() {}

        /// Consume one 64-byte HID report. Returns the decoded message once complete, else `nil`.
        public mutating func push(_ report: Data) throws -> (type: UInt16, payload: Data)? {
            guard let first = report.first else {
                throw TrezorError.malformedResponse("Empty Trezor report.")
            }
            guard first == TrezorProtocolV1.reportMarker else {
                throw TrezorError.malformedResponse("Trezor report missing 0x3f marker (got 0x\(String(first, radix: 16))).")
            }
            stream.append(report.dropFirst())

            if messageType == nil {
                // Need at least the 8-byte header (## + type:2 + len:4).
                guard stream.count >= 8 else { return nil }
                let bytes = Array(stream.prefix(8))
                guard bytes[0] == TrezorProtocolV1.headerMagic, bytes[1] == TrezorProtocolV1.headerMagic else {
                    throw TrezorError.malformedResponse("Trezor stream missing ## header.")
                }
                messageType = (UInt16(bytes[2]) << 8) | UInt16(bytes[3])
                let len = (UInt32(bytes[4]) << 24) | (UInt32(bytes[5]) << 16) | (UInt32(bytes[6]) << 8) | UInt32(bytes[7])
                expectedLength = Int(len)
                stream.removeFirst(8)
            }

            guard let expectedLength, let messageType else { return nil }
            guard stream.count >= expectedLength else { return nil }
            let payload = Data(stream.prefix(expectedLength))
            return (messageType, payload)
        }
    }

    // MARK: - Helpers

    private static func bigEndian16(_ v: UInt16) -> [UInt8] { [UInt8(v >> 8), UInt8(v & 0xff)] }
    private static func bigEndian32(_ v: UInt32) -> [UInt8] {
        [UInt8((v >> 24) & 0xff), UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)]
    }
}

/// Errors surfaced by the Trezor device / transport layer.
public enum TrezorError: Error, Sendable, Equatable {
    /// The device returned a `Failure` message.
    case failure(code: Int, message: String)
    /// A response frame/message was malformed or unexpected.
    case malformedResponse(String)
    /// Transport-level failure (USB not connected, write/read failed).
    case transport(String)
    /// An unexpected message type where a specific one was required.
    case unexpectedMessage(type: UInt16)
}
