import Foundation
import CardanoHWKit
@testable import CardanoHWWalletTrezor

/// A scripted ``HardwarePacketLink`` for driving the Trezor state machine without a device: it
/// replays canned inbound reports in order and records every report written to it.
actor MockPacketLink: HardwarePacketLink {
    private var inbound: [Data]
    private(set) var written: [Data] = []
    private(set) var opened = false
    private(set) var closed = false

    /// - Parameter inbound: HID reports the device would send back, delivered one per `read()`.
    init(inbound: [Data]) {
        self.inbound = inbound
    }

    func open() async throws { opened = true }

    func write(_ packet: Data) async throws { written.append(packet) }

    func read() async throws -> Data {
        guard !inbound.isEmpty else {
            throw TrezorError.transport("MockPacketLink exhausted after delivering all inbound reports.")
        }
        return inbound.removeFirst()
    }

    func close() async { closed = true }

    func recordedReports() -> [Data] { written }
}
