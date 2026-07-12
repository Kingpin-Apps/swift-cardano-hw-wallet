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

/// Builds the Ledger Cardano **SignTx** APDU stream in the real app's **per-field staged** protocol
/// (`LedgerHQ/app-cardano`, verified against its `command_builder.py` + the Speculos emulator): a
/// separate APDU (or group of sub-APDUs) for INIT, each input, each output (basic → asset groups /
/// tokens → confirm), fee, ttl, each certificate, each withdrawal, validity start, a final tx-confirm
/// (which returns the body hash), then one witness request per path. Scope: **plain ADA + native-asset
/// sends + staking/governance certificates + withdrawals.** Mint, collateral, datums, plutus, and
/// pool-registration are rejected here and handled in a later pass.
public enum LedgerCardanoSerializer {

    // Wire constants (`app-cardano` enums, confirmed against the emulator).
    private static let includedNo: UInt8 = 0x01
    private static let includedYes: UInt8 = 0x02
    private static let signingModeOrdinary: UInt8 = 0x03      // TransactionSigningMode.ORDINARY_TRANSACTION
    private static let destThirdParty: UInt8 = 0x01           // TxOutputDestinationType.THIRD_PARTY
    private static let credentialKeyPath: UInt8 = 0           // CredentialType.KEY_PATH
    private static let optionTagCborSets: UInt64 = 1          // TX_OPTIONS_TAG_CBOR_SETS (bit 0)

    private static func included(_ flag: Bool) -> UInt8 { flag ? includedYes : includedNo }

    private static func apdu(_ p1: UInt8, _ p2: UInt8, _ data: Data) -> Data {
        LedgerAPDU.command(ins: LedgerAPDU.INS.signTx, p1: p1, p2: p2, data: data)
    }

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

    // MARK: - Per-field payloads

    /// INPUTS (P1=0x02): 32-byte prev tx hash ‖ 4-byte output index.
    private static func inputData(_ input: TransactionInput) -> Data {
        var out = input.transactionId.payload
        out.append(contentsOf: LedgerBytes.uint32BE(UInt32(input.index)))
        return out
    }

    /// OUTPUTS basic data (P1=0x03, P2=0x30): format ‖ third-party destination ‖ coin ‖ tokenBundleLen
    /// ‖ datum flag ‖ reference-script flag. (Datum + reference script are out of scope → NO.)
    private static func outputBasicData(_ output: TransactionOutput, assetGroupCount: Int) -> Data {
        var out = Data()
        out.append(output.postAlonzo ? 1 : 0)                       // MAP_BABBAGE=1 / ARRAY_LEGACY=0
        let address = output.address.toBytes()
        out.append(destThirdParty)
        out.append(contentsOf: LedgerBytes.uint32BE(UInt32(address.count)))
        out.append(address)
        out.append(contentsOf: LedgerBytes.uint64BE(UInt64(output.amount.coin)))
        out.append(contentsOf: LedgerBytes.uint32BE(UInt32(assetGroupCount)))
        out.append(included(false))                                  // datum
        out.append(included(false))                                  // reference script
        return out
    }

    /// ASSET GROUP (P1=0x03, P2=0x31): 28-byte policy id ‖ 4-byte token count.
    private static func assetGroupData(policyId: Data, tokenCount: Int) -> Data {
        var out = policyId
        out.append(contentsOf: LedgerBytes.uint32BE(UInt32(tokenCount)))
        return out
    }

    /// TOKEN (P1=0x03, P2=0x32): 4-byte name length ‖ asset name ‖ 8-byte signed amount.
    private static func tokenData(name: Data, amount: Int64) -> Data {
        var out = Data()
        out.append(contentsOf: LedgerBytes.uint32BE(UInt32(name.count)))
        out.append(name)
        out.append(contentsOf: LedgerBytes.uint64BE(UInt64(bitPattern: amount)))
        return out
    }

    /// WITHDRAWALS (P1=0x07): 8-byte amount ‖ stake credential (KEY_PATH).
    private static func withdrawalData(_ withdrawal: HardwareWithdrawal) throws -> Data {
        var out = Data(LedgerBytes.uint64BE(withdrawal.amount))
        out.append(try serializeCredential(path: withdrawal.stakePath))
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

    /// The SignTx INIT payload: options ‖ network ‖ per-field option flags ‖ signing mode ‖ 4-byte
    /// element counts ‖ witness-path count. Byte order matches the app's `sign_tx_init`.
    public static func serializeTxInitData(
        _ tx: Transaction,
        witnessPaths: [LedgerBIP32Path],
        network: LedgerNetwork,
        options: LedgerSigningOptions,
        certificateCount: Int = 0,
        withdrawalCount: Int = 0
    ) throws -> Data {
        let body = tx.transactionBody
        try assertInScope(body)
        var out = Data()

        let optionFlags: UInt64 = options.tagCborSets ? optionTagCborSets : 0
        out.append(contentsOf: LedgerBytes.uint64BE(optionFlags))     // options (8B)
        out.append(network.networkId)                                 // network id (1B)
        out.append(contentsOf: LedgerBytes.uint32BE(network.protocolMagic))  // protocol magic (4B)
        out.append(included(body.ttl != nil))                         // ttl
        out.append(included(false))                                   // auxiliary data
        out.append(included(body.validityStart != nil))              // validity interval start
        out.append(included(false))                                   // mint
        out.append(included(false))                                   // script data hash
        out.append(included(body.networkId != nil))                  // include network id in body
        out.append(included(false))                                   // collateral output
        out.append(included(false))                                   // total collateral
        out.append(included(false))                                   // treasury
        out.append(included(false))                                   // donation
        out.append(signingModeOrdinary)                              // signing mode (1B)
        out.append(contentsOf: LedgerBytes.uint32BE(UInt32(body.inputs.count)))    // inputs (4B)
        out.append(contentsOf: LedgerBytes.uint32BE(UInt32(body.outputs.count)))   // outputs (4B)
        out.append(contentsOf: LedgerBytes.uint32BE(UInt32(certificateCount)))     // certificates (4B)
        out.append(contentsOf: LedgerBytes.uint32BE(UInt32(withdrawalCount)))      // withdrawals (4B)
        out.append(contentsOf: LedgerBytes.uint32BE(0))              // collateral inputs (4B)
        out.append(contentsOf: LedgerBytes.uint32BE(0))              // required signers (4B)
        out.append(contentsOf: LedgerBytes.uint32BE(0))              // reference inputs (4B)
        out.append(contentsOf: LedgerBytes.uint32BE(0))              // voting procedures (4B)
        out.append(contentsOf: LedgerBytes.uint32BE(UInt32(witnessPaths.count)))   // witness paths (4B)
        return out
    }

    // MARK: - APDU stream

    /// The full ordered SignTx APDU stream in the app's staged protocol: INIT → each input → each
    /// output (basic → asset groups/tokens → confirm) → fee → ttl → certificates → withdrawals →
    /// validity start → **tx-confirm (returns the body hash)** → one witness request per path (each
    /// returns a 64-byte signature).
    public static func signTxAPDUs(
        _ tx: Transaction,
        witnessPaths: [LedgerBIP32Path],
        network: LedgerNetwork,
        options: LedgerSigningOptions,
        certificates: [HardwareCertificate] = [],
        withdrawals: [HardwareWithdrawal] = []
    ) throws -> [Data] {
        let body = tx.transactionBody
        try assertInScope(body)

        let initData = try serializeTxInitData(
            tx, witnessPaths: witnessPaths, network: network, options: options,
            certificateCount: certificates.count, withdrawalCount: withdrawals.count
        )
        var apdus: [Data] = [apdu(LedgerAPDU.SignP1.initTx, LedgerAPDU.p2Unused, initData)]

        for input in body.inputs.asArray {
            apdus.append(apdu(LedgerAPDU.SignP1.inputs, LedgerAPDU.p2Unused, inputData(input)))
        }

        for output in body.outputs {
            let groups = canonicalAssetGroups(output.amount.multiAsset)
            apdus.append(apdu(LedgerAPDU.SignP1.outputs, LedgerAPDU.SignP2.outputBasic,
                              outputBasicData(output, assetGroupCount: groups.count)))
            for group in groups {
                apdus.append(apdu(LedgerAPDU.SignP1.outputs, LedgerAPDU.SignP2.outputAssetGroup,
                                  assetGroupData(policyId: group.policyId, tokenCount: group.tokens.count)))
                for token in group.tokens {
                    apdus.append(apdu(LedgerAPDU.SignP1.outputs, LedgerAPDU.SignP2.outputToken,
                                      tokenData(name: token.name, amount: token.amount)))
                }
            }
            apdus.append(apdu(LedgerAPDU.SignP1.outputs, LedgerAPDU.SignP2.outputConfirm, Data()))
        }

        apdus.append(apdu(LedgerAPDU.SignP1.fee, LedgerAPDU.p2Unused, Data(LedgerBytes.uint64BE(UInt64(body.fee)))))
        if let ttl = body.ttl {
            apdus.append(apdu(LedgerAPDU.SignP1.ttl, LedgerAPDU.p2Unused, Data(LedgerBytes.uint64BE(UInt64(ttl)))))
        }
        for certificate in certificates {
            apdus.append(apdu(LedgerAPDU.SignP1.certificates, LedgerAPDU.p2Unused, try serializeCertificate(certificate)))
        }
        for withdrawal in withdrawals {
            apdus.append(apdu(LedgerAPDU.SignP1.withdrawals, LedgerAPDU.p2Unused, try withdrawalData(withdrawal)))
        }
        if let validityStart = body.validityStart {
            apdus.append(apdu(LedgerAPDU.SignP1.validityStart, LedgerAPDU.p2Unused, Data(LedgerBytes.uint64BE(UInt64(validityStart)))))
        }

        // Final review + confirm → returns the 32-byte tx hash.
        apdus.append(apdu(LedgerAPDU.SignP1.txConfirm, LedgerAPDU.p2Unused, Data()))

        for path in witnessPaths {
            apdus.append(apdu(LedgerAPDU.SignP1.witnesses, LedgerAPDU.p2Unused, path.encoded()))
        }
        return apdus
    }
}
