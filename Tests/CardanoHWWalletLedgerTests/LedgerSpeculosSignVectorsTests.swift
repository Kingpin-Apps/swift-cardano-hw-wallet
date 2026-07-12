import Testing
import Foundation
import Crypto
import SwiftCardanoCore
import CardanoHWKit
@testable import CardanoHWWalletLedger

/// **Offline** golden-vector regression for the full Ledger **staged** SignTx dialogue, pinned to bytes
/// captured from the real Ledger `app-cardano` in Speculos (`LedgerSpeculosTests.liveSign`). No device:
/// it rebuilds the exact ordinary self-send, asserts our staged serializer reproduces the
/// **firmware-agreed body hash** (proving `tagCborSets = false` for `swift-cardano-core`'s set
/// encoding), then replays the device's real signature through `LedgerSignSession` and checks the
/// assembled witness matches the firmware bytes and verifies. The Ledger analogue of
/// `TrezorEmulatorSignVectorsTests`.
@Suite("Ledger Speculos — offline sign vectors")
struct LedgerSpeculosSignVectorsTests {
    // Account xpub for the run.sh seed, m/1852'/1815'/0', mainnet (from firmware).
    private let xpubHex = "78d137231e6346f17b1d442bace1f7ba1d54a88ef8509464e2e786a854bd4815acafe34e34bf401b4b0164607ee506c4aac63a0828f1dc20ab73ec39f2fe11f3"
    // Captured from the emulator for the self-send below (input 0xAB×32:0, output → own addr,
    // amount 1_000_000, fee 170_000, ttl 500_000, mainnet).
    private let expectedBodyHash = "e015ef7568af57cbd734088379d530aafab2650bc312d44c512c3677765f248c"
    private let devicePubKey = "a2407e58763716a3923508a49489a4897e1f36d3b623c120554c6257dc3dc0b9"
    private let deviceSignature = "8ef13c452b9959a55808f7b7aa7890623ad108ecb2d9ea17ab5e404345bcbddf9a1c245fc6dd2dacc3923b383b31fb606231b046e1a3a6c8fc0255e4698b9505"
    private let expectedWitnessSet = "a100d9010281825820a2407e58763716a3923508a49489a4897e1f36d3b623c120554c6257dc3dc0b958408ef13c452b9959a55808f7b7aa7890623ad108ecb2d9ea17ab5e404345bcbddf9a1c245fc6dd2dacc3923b383b31fb606231b046e1a3a6c8fc0255e4698b9505"

    @Test("Staged serializer reproduces the firmware body hash and replays a verifying witness")
    func offlineSignVector() async throws {
        let derivation = try PublicHDDerivation(accountXPub: Self.hex(xpubHex), accountPath: "m/1852'/1815'/0'", network: .mainnet)
        let address = try derivation.address(role: 0, index: 0)
        let spendPath = "m/1852'/1815'/0'/0/0"

        // The exact tx the live emulator run signed.
        let input = TransactionInput(transactionId: TransactionId(payload: Data(repeating: 0xAB, count: 32)), index: 0)
        let output = TransactionOutput(address: try Address.fromBech32(address), amount: Value(coin: 1_000_000))
        var body = TransactionBody(inputs: .list([input]), outputs: [output], fee: Coin(170_000))
        body.ttl = 500_000
        let tx = Transaction(transactionBody: body, transactionWitnessSet: TransactionWitnessSet())

        // Our staged serialization must reproduce the body hash the firmware reconstructed + signed
        // (i.e. tagCborSets=false matches swift-cardano-core's ordinary-tx set encoding).
        #expect(tx.transactionBody.hash().toHex == expectedBodyHash)

        // Replay the device responses for the staged flow: INIT, input, out-basic, out-confirm, fee,
        // ttl (all empty), tx-confirm (body hash), witness (signature) = 8 exchanges.
        let signature = Self.hex(deviceSignature)
        let responses: [Data] = [Data(), Data(), Data(), Data(), Data(), Data(), Self.hex(expectedBodyHash), signature]
        let session = LedgerSignSession(
            transport: MockLedgerTransport(responses: responses), network: .mainnet,
            options: LedgerSigningOptions(tagCborSets: false), derivation: derivation
        )

        let spentUTxO = UTxO(input: input, output: TransactionOutput(address: try Address.fromBech32(address), amount: Value(coin: 2_000_000)))
        let request = HardwareSignRequest(
            requestId: "emu-ledger-vector", unsigned: tx, spentUTxOs: [spentUTxO],
            addressPaths: [address: spendPath],
            masterFingerprint: Data(repeating: 0, count: 4), origin: "LedgerSpeculosSignVectorsTests"
        )

        let witnessSetHex = try await session.sign(request)

        // Matches the firmware witness bytes exactly...
        #expect(witnessSetHex == expectedWitnessSet)
        let witnesses = (try TransactionWitnessSet.fromCBORHex(witnessSetHex)).vkeyWitnesses?.asList ?? []
        #expect(witnesses.count == 1)
        // ...carries the account's own derived pub key...
        #expect(witnesses.first?.vkey.payload == Self.hex(devicePubKey))
        #expect(witnesses.first?.vkey.payload == (try derivation.paymentVerificationKey(role: 0, index: 0).payload))
        // ...and the signature verifies over the body hash.
        let verifier = try Curve25519.Signing.PublicKey(rawRepresentation: Self.hex(devicePubKey))
        #expect(verifier.isValidSignature(signature, for: tx.transactionBody.hash()))
    }

    private static func hex(_ s: String) -> Data {
        var out = [UInt8](); out.reserveCapacity(s.count / 2)
        var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            out.append(UInt8(s[i..<j], radix: 16)!)
            i = j
        }
        return Data(out)
    }
}
