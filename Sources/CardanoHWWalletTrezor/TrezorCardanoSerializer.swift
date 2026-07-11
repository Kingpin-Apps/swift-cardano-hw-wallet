import Foundation
import SwiftCardanoCore

/// Trezor wire message-type ids (`messages.proto` `MessageType_*`), used in the v1 framing header.
public enum TrezorMessageType {
    public static let failure: UInt16 = 3
    public static let cardanoGetPublicKey: UInt16 = 305
    public static let cardanoPublicKey: UInt16 = 306
    public static let cardanoTxItemAck: UInt16 = 313
    public static let cardanoTxWitnessRequest: UInt16 = 315
    public static let cardanoTxWitnessResponse: UInt16 = 316
    public static let cardanoTxHostAck: UInt16 = 317
    public static let cardanoTxBodyHash: UInt16 = 318
    public static let cardanoSignTxFinished: UInt16 = 319
    public static let cardanoSignTxInit: UInt16 = 320
    public static let cardanoTxInput: UInt16 = 321
    public static let cardanoTxOutput: UInt16 = 322
    public static let cardanoAssetGroup: UInt16 = 323
    public static let cardanoToken: UInt16 = 324
}

/// Cardano key-derivation scheme the device uses (`CardanoDerivationType`). Import and signing must
/// use the same value, or the account node (and its addresses) won't match.
public enum TrezorDerivationType: UInt64, Sendable, Equatable {
    case ledger = 0
    case icarus = 1
    case icarusTrezor = 2
}

/// Trezor network parameters.
public struct TrezorNetwork: Sendable, Equatable {
    public let networkId: UInt32       // mainnet = 1, testnet = 0
    public let protocolMagic: UInt32

    public init(networkId: UInt32, protocolMagic: UInt32) {
        self.networkId = networkId
        self.protocolMagic = protocolMagic
    }

    public static let mainnet = TrezorNetwork(networkId: 1, protocolMagic: 764_824_073)
    public static let preprod = TrezorNetwork(networkId: 0, protocolMagic: 1)
    public static let preview = TrezorNetwork(networkId: 0, protocolMagic: 2)
}

/// Options affecting how the device reconstructs the CBOR (and thus the body hash).
public struct TrezorSigningOptions: Sendable, Equatable {
    /// Whether the device uses CBOR tag 258 for sets — must match `swift-cardano-core`'s encoding, or
    /// the returned `tx_hash` won't equal `transactionBody.hash()`. Device-validated.
    public let tagCborSets: Bool
    public let derivationType: TrezorDerivationType

    public init(tagCborSets: Bool = false, derivationType: TrezorDerivationType = .icarusTrezor) {
        self.tagCborSets = tagCborSets
        self.derivationType = derivationType
    }
}

/// One protobuf request in the sign dialogue.
public struct TrezorMessage: Sendable, Equatable {
    public let type: UInt16
    public let payload: Data
}

/// Builds the Trezor Cardano protobuf messages for a plain-ADA / native-asset send. Certificates,
/// withdrawals, mint, collateral, governance, and datums are rejected (later pass).
public enum TrezorCardanoSerializer {
    private static let signingModeOrdinary: UInt64 = 0   // Trezor `CardanoTxSigningMode.ORDINARY_TRANSACTION`

    static func assertInScope(_ body: TransactionBody) throws {
        func present(_ name: String, _ isThere: Bool) throws {
            if isThere { throw TrezorError.malformedResponse("Hardware signing does not yet support \(name).") }
        }
        try present("certificates", (body.certificates?.count ?? 0) > 0)
        try present("withdrawals", body.withdrawals != nil)
        try present("minting", body.mint != nil)
        try present("collateral", (body.collateral?.count ?? 0) > 0)
        try present("required signers", (body.requiredSigners?.count ?? 0) > 0)
        try present("a script data hash", body.scriptDataHash != nil)
        try present("voting procedures", body.votingProcedures != nil)
        try present("proposal procedures", body.proposalProcedures != nil)
        for output in body.outputs {
            try present("output datums", output.datumHash != nil || output.datumOption != nil)
            try present("reference scripts in outputs", output.script != nil)
        }
    }

    /// The `CardanoSignTxInit` message.
    public static func initMessage(
        _ tx: Transaction,
        witnessCount: Int,
        network: TrezorNetwork,
        options: TrezorSigningOptions
    ) throws -> TrezorMessage {
        let body = tx.transactionBody
        try assertInScope(body)

        var w = ProtobufWriter()
        w.varint(1, signingModeOrdinary)                       // signing_mode
        w.varint(2, UInt64(network.protocolMagic))             // protocol_magic
        w.varint(3, UInt64(network.networkId))                 // network_id
        w.varint(4, UInt64(body.inputs.count))                 // inputs_count
        w.varint(5, UInt64(body.outputs.count))                // outputs_count
        w.varint(6, UInt64(body.fee))                          // fee
        if let ttl = body.ttl { w.varint(7, UInt64(ttl)) }     // ttl
        w.varint(8, 0)                                         // certificates_count
        w.varint(9, 0)                                         // withdrawals_count
        w.bool(10, false)                                      // has_auxiliary_data
        if let vis = body.validityStart { w.varint(11, UInt64(vis)) }  // validity_interval_start
        w.varint(12, UInt64(witnessCount))                     // witness_requests_count
        w.varint(13, 0)                                        // minting_asset_groups_count
        w.varint(14, options.derivationType.rawValue)          // derivation_type
        w.bool(15, body.networkId != nil)                      // include_network_id
        w.varint(17, 0)                                        // collateral_inputs_count
        w.varint(18, 0)                                        // required_signers_count
        w.bool(19, false)                                      // has_collateral_return
        w.varint(21, 0)                                        // reference_inputs_count
        w.bool(23, options.tagCborSets)                        // tag_cbor_sets
        return TrezorMessage(type: TrezorMessageType.cardanoSignTxInit, payload: w.data)
    }

    /// The ordered body-item messages: each input, then each output followed by its asset groups and
    /// tokens (the exact order the device consumes them).
    public static func bodyItemMessages(_ tx: Transaction) throws -> [TrezorMessage] {
        let body = tx.transactionBody
        try assertInScope(body)
        var messages: [TrezorMessage] = []

        for input in body.inputs.asArray {
            var w = ProtobufWriter()
            w.bytes(1, input.transactionId.payload)            // prev_hash
            w.varint(2, UInt64(input.index))                   // prev_index
            messages.append(TrezorMessage(type: TrezorMessageType.cardanoTxInput, payload: w.data))
        }

        for output in body.outputs {
            let groups = canonicalAssetGroups(output.amount.multiAsset)
            var w = ProtobufWriter()
            w.string(1, try output.address.toBech32())         // address
            w.varint(3, UInt64(output.amount.coin))            // amount
            w.varint(4, UInt64(groups.count))                  // asset_groups_count
            w.varint(6, output.postAlonzo ? 1 : 0)             // format: MAP_BABBAGE=1 / ARRAY_LEGACY=0
            messages.append(TrezorMessage(type: TrezorMessageType.cardanoTxOutput, payload: w.data))

            for group in groups {
                var g = ProtobufWriter()
                g.bytes(1, group.policyId)                     // policy_id
                g.varint(2, UInt64(group.tokens.count))        // tokens_count
                messages.append(TrezorMessage(type: TrezorMessageType.cardanoAssetGroup, payload: g.data))
                for token in group.tokens {
                    var t = ProtobufWriter()
                    t.bytes(1, token.name)                     // asset_name_bytes
                    t.varint(2, UInt64(token.amount))          // amount
                    messages.append(TrezorMessage(type: TrezorMessageType.cardanoToken, payload: t.data))
                }
            }
        }
        return messages
    }

    /// A `CardanoTxWitnessRequest` for a BIP32 path (`repeated uint32 path`).
    public static func witnessRequestMessage(path: [UInt32]) -> TrezorMessage {
        var w = ProtobufWriter()
        w.repeatedUInt32(1, path)
        return TrezorMessage(type: TrezorMessageType.cardanoTxWitnessRequest, payload: w.data)
    }

    /// An empty `CardanoTxHostAck`.
    public static func hostAckMessage() -> TrezorMessage {
        TrezorMessage(type: TrezorMessageType.cardanoTxHostAck, payload: Data())
    }

    // MARK: - Token canonical ordering (matches a canonical CBOR encoder)

    private static func canonicalAssetGroups(_ multiAsset: MultiAsset) -> [(policyId: Data, tokens: [(name: Data, amount: Int64)])] {
        multiAsset.data
            .map { (policy, asset) in
                let tokens = asset.data
                    .map { (name, amount) in (name: name.payload, amount: amount) }
                    .sorted { canonicalLess($0.name, $1.name) }
                return (policyId: policy.payload, tokens: tokens)
            }
            .sorted { canonicalLess($0.policyId, $1.policyId) }
    }

    private static func canonicalLess(_ a: Data, _ b: Data) -> Bool {
        a.count != b.count ? a.count < b.count : a.lexicographicallyPrecedes(b)
    }
}
