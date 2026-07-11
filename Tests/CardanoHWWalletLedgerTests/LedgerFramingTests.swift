import Testing
import Foundation
@testable import CardanoHWWalletLedger

@Suite("Ledger APDU framing")
struct LedgerFramingTests {

    /// Feed the framed packets straight back through a reassembler and expect the original bytes.
    private func roundTrip(_ message: Data, channel: UInt16?, packetSize: Int) throws {
        let packets = LedgerFraming.frame(message: message, channel: channel, packetSize: packetSize)
        var reasm = LedgerFraming.Reassembler(channelIncluded: channel != nil)
        var out: Data?
        for p in packets {
            if channel != nil { #expect(p.count == packetSize) }   // USB frames are padded
            out = try reasm.push(p)
        }
        #expect(out == message)
    }

    @Test("USB round-trip across sizes")
    func usbRoundTrip() throws {
        for len in [0, 1, 5, 56, 57, 58, 59, 60, 200, 1024] {
            let msg = Data((0..<len).map { UInt8($0 & 0xff) })
            try roundTrip(msg, channel: LedgerFraming.usbChannel, packetSize: LedgerFraming.usbPacketSize)
        }
    }

    @Test("BLE-style (no channel) round-trip")
    func bleRoundTrip() throws {
        for len in [0, 10, 153, 900] {
            let msg = Data((0..<len).map { UInt8(($0 * 7) & 0xff) })
            try roundTrip(msg, channel: nil, packetSize: 155)
        }
    }

    @Test("First USB frame carries channel, tag, seq 0, and total length")
    func firstFrameHeader() throws {
        let msg = Data(repeating: 0xAA, count: 100)
        let packets = LedgerFraming.frame(message: msg, channel: 0x0101, packetSize: 64)
        let head = Array(packets[0])
        #expect(head[0] == 0x01 && head[1] == 0x01)          // channel BE
        #expect(head[2] == LedgerFraming.tag)                // 0x05
        #expect(head[3] == 0x00 && head[4] == 0x00)          // seq 0
        #expect(head[5] == 0x00 && head[6] == 100)           // total length BE = 100
        #expect(packets.count == 2)                          // 57 + 43 bytes over two frames
        // Second frame: channel, tag, seq 1, no length.
        let two = Array(packets[1])
        #expect(two[2] == LedgerFraming.tag)
        #expect(two[3] == 0x00 && two[4] == 0x01)            // seq 1
    }

    @Test("Reassembler rejects an out-of-order frame")
    func rejectsOutOfOrder() throws {
        let msg = Data(repeating: 0x11, count: 100)
        let packets = LedgerFraming.frame(message: msg, channel: 0x0101, packetSize: 64)
        var reasm = LedgerFraming.Reassembler(channelIncluded: true)
        _ = try reasm.push(packets[0])
        #expect(throws: LedgerError.self) {
            _ = try reasm.push(packets[0])   // seq 0 again instead of seq 1
        }
    }

    @Test("Reassembler rejects a bad tag")
    func rejectsBadTag() throws {
        var frame = Data([0x01, 0x01, 0x06, 0x00, 0x00, 0x00, 0x01, 0x00])   // tag 0x06
        frame.append(Data(repeating: 0, count: 64 - frame.count))
        var reasm = LedgerFraming.Reassembler(channelIncluded: true)
        #expect(throws: LedgerError.self) {
            _ = try reasm.push(frame)
        }
    }
}
