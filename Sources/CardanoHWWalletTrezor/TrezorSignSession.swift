import Foundation
import SwiftCardanoCore
import CardanoHWKit

/// A ``HardwareSigner`` for Trezor devices. Speaks the Cardano protobuf dialogue over a
/// ``HardwarePacketLink`` (USB-HID), framed by ``TrezorProtocolV1``. Trezor returns each witness's
/// public key alongside its signature, so the witness set is assembled directly from device
/// responses — no local key derivation, no private key.
///
/// Assumes the device is already in a ready state (the transport layer performs the
/// Initialize/Features handshake). macOS-only in practice (USB), though the message logic is
/// platform-neutral.
public actor TrezorSignSession: HardwareSigner {
    public nonisolated let deviceKind = HardwareDeviceKind.trezor

    private let link: HardwarePacketLink
    private let network: TrezorNetwork
    private let options: TrezorSigningOptions

    public init(link: HardwarePacketLink, network: TrezorNetwork, options: TrezorSigningOptions = .init()) {
        self.link = link
        self.network = network
        self.options = options
    }

    // MARK: - Import

    public func importAccount(network netId: NetworkId, accountIndex: Int) async throws -> HardwareAccountModel {
        try await link.open()
        let request = try TrezorAccountImport.getPublicKeyMessage(accountIndex: accountIndex, derivationType: options.derivationType)
        let response = try await exchange(request)
        try expect(response.type, TrezorMessageType.cardanoPublicKey)
        return try TrezorAccountImport.parsePublicKey(payload: response.payload, accountIndex: accountIndex, network: netId)
    }

    // MARK: - Sign

    public func sign(_ request: HardwareSignRequest) async throws -> String {
        try await link.open()

        let witnessPaths = try witnessPaths(for: request)

        // Init → ItemAck.
        let initMessage = try TrezorCardanoSerializer.initMessage(
            request.unsigned, witnessCount: witnessPaths.count, network: network, options: options,
            certificateCount: request.certificates.count, withdrawalCount: request.withdrawals.count
        )
        try expect(try await exchange(initMessage).type, TrezorMessageType.cardanoTxItemAck)

        // Each body item → ItemAck.
        let bodyItems = try TrezorCardanoSerializer.bodyItemMessages(
            request.unsigned, certificates: request.certificates, withdrawals: request.withdrawals
        )
        for item in bodyItems {
            try expect(try await exchange(item).type, TrezorMessageType.cardanoTxItemAck)
        }

        // Each witness request → WitnessResponse (carries pub_key + signature).
        var witnesses: [VerificationKeyWitness] = []
        for path in witnessPaths {
            let response = try await exchange(TrezorCardanoSerializer.witnessRequestMessage(path: path))
            try expect(response.type, TrezorMessageType.cardanoTxWitnessResponse)
            witnesses.append(try witness(fromResponse: response.payload))
        }

        // HostAck → BodyHash (verify it matches our body), HostAck → Finished.
        let bodyHashResponse = try await exchange(TrezorCardanoSerializer.hostAckMessage())
        try expect(bodyHashResponse.type, TrezorMessageType.cardanoTxBodyHash)
        try verifyBodyHash(bodyHashResponse.payload, against: request.unsigned)

        let finished = try await exchange(TrezorCardanoSerializer.hostAckMessage())
        try expect(finished.type, TrezorMessageType.cardanoSignTxFinished)

        let set = TransactionWitnessSet(vkeyWitnesses: .nonEmptyOrderedSet(NonEmptyOrderedSet(witnesses)))
        do {
            return try set.toCBORHex()
        } catch {
            throw TrezorError.malformedResponse("Could not encode the assembled witness set: \(error)")
        }
    }

    // MARK: - Wire exchange

    /// Send one protobuf message and read one response message, surfacing device `Failure`s.
    private func exchange(_ message: TrezorMessage) async throws -> (type: UInt16, payload: Data) {
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

    private func expect(_ got: UInt16, _ want: UInt16) throws {
        guard got == want else { throw TrezorError.unexpectedMessage(type: got) }
    }

    // MARK: - Internals

    private func witnessPaths(for request: HardwareSignRequest) throws -> [[UInt32]] {
        var seen = Set<String>()
        var paths: [[UInt32]] = []
        func add(_ pathString: String) throws {
            if seen.insert(pathString).inserted {
                paths.append(try TrezorBIP32Path.parse(pathString))
            }
        }
        for utxo in request.spentUTxOs {
            let address: String
            do { address = try utxo.output.address.toBech32() }
            catch { throw TrezorError.malformedResponse("A spent UTxO has an unencodable address: \(error)") }
            guard let pathString = request.addressPaths[address] else {
                throw TrezorError.malformedResponse("No derivation path for input address \(address).")
            }
            try add(pathString)
        }
        for certificate in request.certificates { try add(certificate.stakePath) }
        for withdrawal in request.withdrawals { try add(withdrawal.stakePath) }
        guard !paths.isEmpty else { throw TrezorError.malformedResponse("Sign request has no keys to witness.") }
        return paths
    }

    /// Build a vkey witness from a `CardanoTxWitnessResponse` (`pub_key` field 2, `signature` field 3).
    private func witness(fromResponse payload: Data) throws -> VerificationKeyWitness {
        let reader = try ProtobufReader(payload)
        guard let pubKey = reader.bytes(2), let signature = reader.bytes(3) else {
            throw TrezorError.malformedResponse("Witness response missing pub_key or signature.")
        }
        guard pubKey.count == 32, signature.count == 64 else {
            throw TrezorError.malformedResponse("Unexpected witness sizes: pub_key \(pubKey.count), signature \(signature.count).")
        }
        let vkey = try VerificationKeyType(from: .bytes(pubKey))
        return VerificationKeyWitness(vkey: vkey, signature: signature)
    }

    private func verifyBodyHash(_ payload: Data, against unsigned: Transaction) throws {
        let reader = try ProtobufReader(payload)
        guard let deviceHash = reader.bytes(1) else {
            throw TrezorError.malformedResponse("CardanoTxBodyHash missing tx_hash.")
        }
        let expected = unsigned.transactionBody.hash()
        guard deviceHash == expected else {
            throw TrezorError.malformedResponse(
                "Device tx hash \(deviceHash.toHex) ≠ expected \(expected.toHex) — serialization mismatch (check tagCborSets)."
            )
        }
    }
}
