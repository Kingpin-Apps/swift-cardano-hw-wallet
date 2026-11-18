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

    /// - Parameters:
    ///   - inbound: HID reports the device would send back, delivered one per `read()`.
    ///   - answersInitialize: Prepend the `Features` reply to the `Initialize` that
    ///     ``TrezorV1Transport/open()`` sends. Turn off for raw exchanges and THP links.
    init(inbound: [Data], answersInitialize: Bool = true) {
        self.inbound = (answersInitialize
            ? TrezorProtocolV1.encode(messageType: TrezorMessageType.features, payload: Data())
            : []) + inbound
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
