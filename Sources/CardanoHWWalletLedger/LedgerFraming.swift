import Foundation

/// Ledger's APDU transport framing (the "APDU-over-HID/BLE" wrapping), used by the USB-HID transport.
///
/// A full APDU is split into fixed-size transport packets. Each packet carries:
///
///     [channel: 2B BE]?  [tag: 1B = 0x05]  [seq: 2B BE]  [totalLen: 2B BE (seq 0 only)]  [chunk…]
///
/// The 2-byte channel is present on **USB-HID** and absent on **BLE** (BLE goes through the vendor
/// SDK, so in practice we only frame the USB case, but the `channel == nil` path is kept symmetric
/// and unit-tested). USB packets are zero-padded to `packetSize` (64). This is a pure codec — no I/O.
public enum LedgerFraming {
    public static let tag: UInt8 = 0x05

    /// Ledger's conventional USB-HID channel and report size.
    public static let usbChannel: UInt16 = 0x0101
    public static let usbPacketSize: Int = 64

    // MARK: - Encode

    /// Split a full APDU `message` into transport packets. USB packets (`channel != nil`) are
    /// zero-padded to `packetSize`.
    public static func frame(message: Data, channel: UInt16?, packetSize: Int = usbPacketSize) -> [Data] {
        precondition(packetSize > headerSize(channel: channel, first: true), "packetSize too small for a Ledger frame header")

        var packets: [Data] = []
        var offset = 0
        var seq: UInt16 = 0
        // Guard against an empty message: still emit one (header-only) frame declaring length 0.
        repeat {
            var packet = Data()
            if let channel { packet.append(contentsOf: bigEndian(channel)) }
            packet.append(tag)
            packet.append(contentsOf: bigEndian(seq))
            if seq == 0 { packet.append(contentsOf: bigEndian(UInt16(message.count))) }

            let room = packetSize - packet.count
            let end = min(offset + room, message.count)
            if offset < end { packet.append(message[message.startIndex.advanced(by: offset)..<message.startIndex.advanced(by: end)]) }
            offset = end

            if channel != nil, packet.count < packetSize {
                packet.append(Data(repeating: 0, count: packetSize - packet.count))
            }
            packets.append(packet)
            seq &+= 1
        } while offset < message.count
        return packets
    }

    // MARK: - Decode

    /// Reassembles response packets into a full APDU. Feed packets in order via ``push(_:)``; it
    /// returns `nil` until the declared length is collected, then the full message.
    public struct Reassembler {
        private let channelIncluded: Bool
        private var expectedLength: Int?
        private var buffer = Data()
        private var nextSeq: UInt16 = 0

        public init(channelIncluded: Bool) {
            self.channelIncluded = channelIncluded
        }

        /// Consume one transport packet. Returns the full message once complete, else `nil`.
        public mutating func push(_ packet: Data) throws -> Data? {
            var idx = packet.startIndex
            func take(_ n: Int) throws -> Data {
                guard packet.distance(from: idx, to: packet.endIndex) >= n else {
                    throw LedgerError.malformedResponse("Ledger frame shorter than header (\(packet.count) bytes).")
                }
                let end = packet.index(idx, offsetBy: n)
                defer { idx = end }
                return packet[idx..<end]
            }

            if channelIncluded { _ = try take(2) }
            let tagByte = try take(1).first!
            guard tagByte == LedgerFraming.tag else {
                throw LedgerError.malformedResponse("Unexpected Ledger frame tag 0x\(String(tagByte, radix: 16)).")
            }
            let seq = LedgerFraming.readUInt16(try take(2))
            guard seq == nextSeq else {
                throw LedgerError.malformedResponse("Out-of-order Ledger frame: expected seq \(nextSeq), got \(seq).")
            }
            if seq == 0 {
                expectedLength = Int(LedgerFraming.readUInt16(try take(2)))
                buffer.removeAll(keepingCapacity: true)
            }
            guard let expectedLength else {
                throw LedgerError.malformedResponse("First Ledger frame missing (no declared length).")
            }

            let remaining = expectedLength - buffer.count
            if remaining > 0 {
                let avail = packet.distance(from: idx, to: packet.endIndex)
                let chunk = try take(min(remaining, avail))
                buffer.append(chunk)
            }
            nextSeq &+= 1
            return buffer.count >= expectedLength ? buffer : nil
        }
    }

    // MARK: - Helpers

    private static func headerSize(channel: UInt16?, first: Bool) -> Int {
        (channel != nil ? 2 : 0) + 1 + 2 + (first ? 2 : 0)
    }

    private static func bigEndian(_ v: UInt16) -> [UInt8] { [UInt8(v >> 8), UInt8(v & 0xff)] }

    static func readUInt16(_ d: Data) -> UInt16 {
        let b = Array(d)
        return (UInt16(b[0]) << 8) | UInt16(b[1])
    }
}
