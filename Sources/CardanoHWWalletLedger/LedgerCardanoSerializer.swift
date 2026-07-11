import Foundation
import SwiftCardanoCore
import CardanoHWKit

/// Ledger network parameters the device needs to render/validate a transaction.
public struct LedgerNetwork: Sendable, Equatable {
    public let networkId: UInt8       // mainnet = 1, testnet = 0
    public let protocolMagic: UInt32

    public init(networkId: UInt8, protocolMagic: UInt32) {
        self.networkId = networkId
        self.protocolMagic = protocolMagic
    }

    public static let mainnet = LedgerNetwork(networkId: 1, protocolMagic: 764_824_073)
    public static let preprod = LedgerNetwork(networkId: 0, protocolMagic: 1)
    public static let preview = LedgerNetwork(networkId: 0, protocolMagic: 2)
}

/// Options affecting how the device reconstructs the transaction's CBOR (and therefore its hash).
public struct LedgerSigningOptions: Sendable, Equatable {
    /// Whether the device tags set-like fields with CBOR tag 258 when reconstructing the body. **Must
    /// match how `swift-cardano-core` encodes the unsigned body**, or the device's tx hash won't match
    /// `transactionBody.hash()` and the witness won't verify. Device-validated (see wiki risk note).
    public let tagCborSets: Bool

    public init(tagCborSets: Bool = false) {
        self.tagCborSets = tagCborSets
    }
}

/// Reproduces Ledger's **v8** custom transaction serialization (`serializeTransactionRaw` +
/// `serializeTxInitData`), which the device parses, re-CBORs, hashes, and signs. This is *not* CBOR —
/// it's Ledger's flat wire format. Scoped to the first cut: **plain ADA + native-asset sends** (any
/// inputs, third-party + native-token outputs, fee, ttl, validity start). Certificates, withdrawals,
/// mint, collateral, governance, and datums are rejected here and handled in a later pass.
public enum LedgerCardanoSerializer {

    // Wire constants (`v8/serialization/wireTypes.ts`).
    private static let includedNo: UInt8 = 0x01
    private static let includedYes: UInt8 = 0x02
    private static let signingModeOrdinary: UInt8 = 3
    private static let destThirdParty: UInt8 = 1
    private static let credentialKeyPath: UInt8 = 0   // Ledger CredentialType.KEY_PATH

    private static func included(_ flag: Bool) -> UInt8 { flag ? includedYes : includedNo }

    // MARK: - Scope guard

    /// Throws if the transaction uses features outside the current hardware scope. Certificates and
    /// withdrawals ARE supported (staking + governance); they're emitted from the request's
    /// device-neutral descriptions, so we don't inspect `body.certificates` here.
    static func assertInScope(_ body: TransactionBody) throws {
        func present(_ name: String, _ isThere: Bool) throws {
            if isThere { throw LedgerError.app("Hardware signing does not yet support \(name).") }
        }
        try present("minting", body.mint != nil)
        try present("collateral", (body.collateral?.count ?? 0) > 0)
        try present("required signers", (body.requiredSigners?.count ?? 0) > 0)
        try present("a script data hash", body.scriptDataHash != nil)
        try present("voting procedures", body.votingProcedures != nil)
        try present("proposal procedures", body.proposalProcedures != nil)
        try present("treasury operations", body.currentTreasuryAmount != nil || body.treasuryDonation != nil)
        for output in body.outputs {
            try present("output datums", output.datumHash != nil || output.datumOption != nil)
            try present("reference scripts in outputs", output.script != nil)
        }
    }

    // MARK: - Raw serialization

    /// The flat wire form the device streams and hashes.
    public static func serializeTransactionRaw(
        _ tx: Transaction,
        certificates: [HardwareCertificate] = [],
        withdrawals: [HardwareWithdrawal] = []
    ) throws -> Data {
        let body = tx.transactionBody
        try assertInScope(body)
        var out = Data()

        for input in body.inputs.asArray {
            out.append(input.transactionId.payload)                       // 32-byte tx hash
            out.append(contentsOf: LedgerBytes.uint32BE(UInt32(input.index)))
        }

        for output in body.outputs {
            let outputBytes = try serializeOutput(output)
            out.append(contentsOf: LedgerBytes.uint16BE(UInt16(outputBytes.count)))
            out.append(outputBytes)
        }

        out.append(contentsOf: LedgerBytes.uint64BE(UInt64(body.fee)))

        if let ttl = body.ttl {
            out.append(contentsOf: LedgerBytes.uint64BE(UInt64(ttl)))
        }
        for certificate in certificates {
            out.append(try serializeCertificate(certificate))
        }
        for withdrawal in withdrawals {
            out.append(contentsOf: LedgerBytes.uint64BE(withdrawal.amount))
            out.append(try serializeCredential(path: withdrawal.stakePath))
        }
        if let validityStart = body.validityStart {
            out.append(contentsOf: LedgerBytes.uint64BE(UInt64(validityStart)))
        }
        // mint / scriptDataHash / collateral / … : none (scope-guarded)
        return out
    }

    // MARK: - Certificates

    private static func serializeCredential(path: String) throws -> Data {
        var out = Data([credentialKeyPath])
        out.append(try LedgerBIP32Path(path).encoded())
        return out
    }

    private static func serializeCertificate(_ certificate: HardwareCertificate) throws -> Data {
        var out = Data()
        switch certificate {
        case .stakeDelegation(let stakePath, let poolKeyHashHex):
            out.append(2)
            out.append(try serializeCredential(path: stakePath))
            out.append(try hex(poolKeyHashHex, "pool key hash"))
        case .stakeRegistrationConway(let stakePath, let deposit):
            out.append(7)
            out.append(try serializeCredential(path: stakePath))
            out.append(contentsOf: LedgerBytes.uint64BE(deposit))
        case .stakeDeregistrationConway(let stakePath, let deposit):
            out.append(8)
            out.append(try serializeCredential(path: stakePath))
            out.append(contentsOf: LedgerBytes.uint64BE(deposit))
        case .voteDelegation(let stakePath, let drep):
            out.append(9)
            out.append(try serializeCredential(path: stakePath))
            out.append(try serializeDRep(drep))
        }
        return out
    }

    private static func serializeDRep(_ drep: HardwareDRepKind) throws -> Data {
        switch drep {
        case .keyHash(let h): return Data([0]) + (try hex(h, "DRep key hash"))
        case .scriptHash(let h): return Data([1]) + (try hex(h, "DRep script hash"))
        case .abstain: return Data([2])
        case .noConfidence: return Data([3])
        }
    }

    private static func hex(_ string: String, _ label: String) throws -> Data {
        guard let data = Data(ledgerHex: string) else {
            throw LedgerError.app("Invalid \(label) hex: \(string)")
        }
        return data
    }

    private static func serializeOutput(_ output: TransactionOutput) throws -> Data {
        var out = Data()

        // Destination: always third-party (raw address bytes). Change-as-path is a UX-only
        // optimization; third-party is correct for every output.
        let address = output.address.toBytes()
        out.append(destThirdParty)
        out.append(contentsOf: LedgerBytes.uint16BE(UInt16(address.count)))
        out.append(address)

        out.append(contentsOf: LedgerBytes.uint64BE(UInt64(output.amount.coin)))
        out.append(output.postAlonzo ? 1 : 0)          // TxOutputFormat: MAP_BABBAGE=1 / ARRAY_LEGACY=0
        out.append(included(false))                     // datum
        out.append(included(false))                     // reference script

        let groups = canonicalAssetGroups(output.amount.multiAsset)
        out.append(contentsOf: LedgerBytes.uint16BE(UInt16(groups.count)))
        for group in groups {
            out.append(group.policyId)                  // 28-byte policy id
            out.append(contentsOf: LedgerBytes.uint16BE(UInt16(group.tokens.count)))
            for token in group.tokens {
                out.append(UInt8(token.name.count))
                out.append(token.name)
                out.append(contentsOf: LedgerBytes.uint64BE(UInt64(token.amount)))
            }
        }
        return out
    }

    /// Multi-asset groups in canonical order (policy id, then asset name — both by raw bytes), so the
    /// device's reconstructed CBOR matches a canonical encoder.
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

    /// Canonical CBOR key order: shorter first, then lexicographic.
    private static func canonicalLess(_ a: Data, _ b: Data) -> Bool {
        a.count != b.count ? a.count < b.count : a.lexicographicallyPrecedes(b)
    }

    // MARK: - Init data

    /// The SignTx INIT payload (`serializeTxInitData`) describing the transaction shape + witness count.
    public static func serializeTxInitData(
        _ tx: Transaction,
        witnessPaths: [LedgerBIP32Path],
        rawTxLength: Int,
        network: LedgerNetwork,
        options: LedgerSigningOptions,
        certificateCount: Int = 0,
        withdrawalCount: Int = 0
    ) throws -> Data {
        let body = tx.transactionBody
        try assertInScope(body)
        var out = Data()

        let optionFlags: UInt64 = options.tagCborSets ? 1 : 0
        out.append(contentsOf: LedgerBytes.uint64BE(optionFlags))
        out.append(network.networkId)
        out.append(contentsOf: LedgerBytes.uint32BE(network.protocolMagic))
        out.append(signingModeOrdinary)
        out.append(contentsOf: LedgerBytes.uint16BE(UInt16(body.inputs.count)))
        out.append(contentsOf: LedgerBytes.uint16BE(UInt16(body.outputs.count)))
        out.append(included(body.ttl != nil))
        out.append(contentsOf: LedgerBytes.uint16BE(UInt16(certificateCount)))
        out.append(contentsOf: LedgerBytes.uint16BE(UInt16(withdrawalCount)))
        out.append(included(false))                          // auxiliary data
        out.append(included(body.validityStart != nil))
        out.append(contentsOf: LedgerBytes.uint16BE(0))     // mint
        out.append(included(false))                          // script data hash
        out.append(contentsOf: LedgerBytes.uint16BE(0))     // collateral inputs
        out.append(contentsOf: LedgerBytes.uint16BE(0))     // required signers
        out.append(included(body.networkId != nil))          // include network id in body
        out.append(included(false))                          // collateral output
        out.append(included(false))                          // total collateral
        out.append(contentsOf: LedgerBytes.uint16BE(0))     // reference inputs
        out.append(contentsOf: LedgerBytes.uint16BE(0))     // voting procedures
        out.append(included(false))                          // treasury
        out.append(included(false))                          // donation
        out.append(contentsOf: LedgerBytes.uint16BE(UInt16(witnessPaths.count)))
        out.append(contentsOf: LedgerBytes.uint16BE(UInt16(rawTxLength)))
        return out
    }

    // MARK: - APDU stream

    /// The full ordered APDU stream for a SignTx: INIT → CBOR chunks (last is CONFIRM) → one witness
    /// request per path. Callers exchange these in order; the CONFIRM response is the tx hash and each
    /// witness response is a 64-byte signature.
    public static func signTxAPDUs(
        _ tx: Transaction,
        witnessPaths: [LedgerBIP32Path],
        network: LedgerNetwork,
        options: LedgerSigningOptions,
        certificates: [HardwareCertificate] = [],
        withdrawals: [HardwareWithdrawal] = []
    ) throws -> [Data] {
        let rawTx = try serializeTransactionRaw(tx, certificates: certificates, withdrawals: withdrawals)
        let initData = try serializeTxInitData(
            tx, witnessPaths: witnessPaths, rawTxLength: rawTx.count, network: network, options: options,
            certificateCount: certificates.count, withdrawalCount: withdrawals.count
        )

        var apdus: [Data] = [
            LedgerAPDU.command(ins: LedgerAPDU.INS.signTx, p1: LedgerAPDU.SignP1.initTx, p2: LedgerAPDU.p2Unused, data: initData)
        ]

        var offset = 0
        while offset < rawTx.count {
            let end = min(offset + LedgerAPDU.maxChunkSize, rawTx.count)
            let chunk = rawTx.subdata(in: offset..<end)
            offset = end
            let isLast = offset >= rawTx.count
            apdus.append(LedgerAPDU.command(
                ins: LedgerAPDU.INS.signTx,
                p1: isLast ? LedgerAPDU.SignP1.confirm : LedgerAPDU.SignP1.chunk,
                p2: LedgerAPDU.p2Unused,
                data: chunk
            ))
        }
        // Empty tx would produce no chunk (impossible in scope), but guard the CONFIRM anyway.
        if rawTx.isEmpty {
            apdus.append(LedgerAPDU.command(ins: LedgerAPDU.INS.signTx, p1: LedgerAPDU.SignP1.confirm, p2: LedgerAPDU.p2Unused, data: Data()))
        }

        for path in witnessPaths {
            apdus.append(LedgerAPDU.command(
                ins: LedgerAPDU.INS.signTx, p1: LedgerAPDU.SignP1.signWitness, p2: LedgerAPDU.p2Unused, data: path.encoded()
            ))
        }
        return apdus
    }
}
