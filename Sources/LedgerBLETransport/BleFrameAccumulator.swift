//
//  BleFrameAccumulator.swift
//  LedgerBLETransport (swift-cardano-hw-wallet)
//
//  Added to the vendored Ledger BLE transport. It replaces the original hex-string reassembly,
//  which indexed notifications without checking their length, tag or frame index.
//

import Foundation

/// Reassembles one Ledger BLE response from `0x05`-tagged notification frames.
///
/// Frame 0 is `0x05 ‖ index(2) ‖ length(2) ‖ data`; later frames are `0x05 ‖ index(2) ‖ data`.
/// Every frame must carry the `0x05` tag and the next expected index, and the response is cut to the
/// declared length. Any violation throws instead of trapping.
struct BleFrameAccumulator {
    enum FrameError: Error, Equatable {
        case shortFrame(Int)
        case badTag(UInt8)
        case unexpectedIndex(expected: UInt16, got: UInt16)
    }

    private var expectedIndex: UInt16 = 0
    private var declaredLength = 0
    private var response = Data()

    /// Clears any partial response. Call at the start of every exchange.
    mutating func reset() {
        expectedIndex = 0
        declaredLength = 0
        response = Data()
    }

    /// Adds one notification frame. Returns the full response once the declared length is reached.
    mutating func push(_ frame: Data) throws -> Data? {
        let bytes = [UInt8](frame)
        let first = expectedIndex == 0
        let header = first ? 5 : 3
        guard bytes.count >= header else { throw FrameError.shortFrame(bytes.count) }
        guard bytes[0] == 0x05 else { throw FrameError.badTag(bytes[0]) }
        let index = UInt16(bytes[1]) << 8 | UInt16(bytes[2])
        guard index == expectedIndex else { throw FrameError.unexpectedIndex(expected: expectedIndex, got: index) }
        if first { declaredLength = Int(UInt16(bytes[3]) << 8 | UInt16(bytes[4])) }
        response.append(contentsOf: bytes[header...])
        expectedIndex &+= 1
        guard response.count >= declaredLength else { return nil }
        let full = Data(response.prefix(declaredLength))
        reset()
        return full
    }
}

extension APDU {
    /// The MTU the SDK assumes until the device reports one.
    static let defaultMTUSize = 153

    /// The MTU reported in an `0x08` infer-MTU reply (byte 5), or nil if the reply is malformed or the
    /// value is too small to carry a frame header plus data.
    static func mtu(fromInferReply data: Data) -> Int? {
        let bytes = [UInt8](data)
        guard bytes.count >= 6, bytes[0] == 0x08 else { return nil }
        let mtu = Int(bytes[5])
        return mtu >= 6 ? mtu : nil
    }
}
