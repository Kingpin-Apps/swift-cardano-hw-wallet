import Foundation
@testable import CardanoHWWalletLedger

/// A scripted `LedgerTransport` for driving the sign/import state machines without a device: it
/// replays canned response payloads in order and records every APDU it was asked to send.
actor MockLedgerTransport: LedgerTransport {
    private var responses: [Data]
    private(set) var sent: [Data] = []

    /// - Parameter responses: response payloads (status word already stripped), one per `exchange`.
    init(responses: [Data]) {
        self.responses = responses
    }

    func exchange(_ apdu: Data) async throws -> Data {
        sent.append(apdu)
        guard !responses.isEmpty else {
            throw LedgerError.transport("MockLedgerTransport exhausted after \(sent.count) exchanges.")
        }
        return responses.removeFirst()
    }

    /// The APDUs recorded so far (for asserting the serializer's staged output).
    func recordedAPDUs() -> [Data] { sent }
}
