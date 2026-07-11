import Testing
import Foundation
@testable import CardanoHWWalletTrezor

@Suite("Trezor protocol v1 framing")
struct TrezorProtocolV1Tests {

    private func roundTrip(type: UInt16, payload: Data) throws {
        let reports = TrezorProtocolV1.encode(messageType: type, payload: payload)
        for r in reports { #expect(r.count == TrezorProtocolV1.reportSize) }   // all reports 64 bytes
        var decoder = TrezorProtocolV1.Decoder()
        var out: (type: UInt16, payload: Data)?
        for r in reports { out = try decoder.push(r) }
        #expect(out?.type == type)
        #expect(out?.payload == payload)
    }

    @Test("Round-trip across payload sizes")
    func roundTripSizes() throws {
        for len in [0, 1, 55, 56, 57, 63, 100, 512, 4096] {
            let payload = Data((0..<len).map { UInt8(($0 * 13) & 0xff) })
            try roundTrip(type: 0x0129, payload: payload)   // arbitrary msg type
        }
    }

    @Test("First report carries ? marker then ## header, type, length")
    func firstReportHeader() throws {
        let payload = Data(repeating: 0x42, count: 10)
        let reports = TrezorProtocolV1.encode(messageType: 0x0102, payload: payload)
        let head = Array(reports[0])
        #expect(head[0] == 0x3f)                     // '?'
        #expect(head[1] == 0x23 && head[2] == 0x23)  // '##'
        #expect(head[3] == 0x01 && head[4] == 0x02)  // msg type BE
        #expect(head[5] == 0 && head[6] == 0 && head[7] == 0 && head[8] == 10)  // length BE = 10
    }

    @Test("A payload spanning many reports reassembles")
    func multiReport() throws {
        // 200 payload bytes + 8 header = 208 stream bytes → ceil(208/63) = 4 reports.
        let payload = Data((0..<200).map { UInt8($0 & 0xff) })
        let reports = TrezorProtocolV1.encode(messageType: 0x1234, payload: payload)
        #expect(reports.count == 4)
        var decoder = TrezorProtocolV1.Decoder()
        var out: (type: UInt16, payload: Data)?
        for r in reports { out = try decoder.push(r) }
        #expect(out?.type == 0x1234)
        #expect(out?.payload == payload)
    }

    @Test("Decoder rejects a report without the 0x3f marker")
    func rejectsBadMarker() throws {
        var bad = Data([0x00, 0x23, 0x23])
        bad.append(Data(repeating: 0, count: 64 - bad.count))
        var decoder = TrezorProtocolV1.Decoder()
        #expect(throws: TrezorError.self) {
            _ = try decoder.push(bad)
        }
    }
}
