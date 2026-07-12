import Testing
import Foundation
import Crypto
import SwiftCardanoCore
@testable import CardanoHWKit

/// End-to-end Keystone validation against the **actual device signing code**. Keystone is air-gapped
/// (QR-only) with no scriptable emulator, so instead of a live device we run Keystone's own
/// `keystone3-firmware/rust/apps/cardano` `sign_tx_hash` (the exact BIP32-Ed25519 derive+sign the
/// device performs per witness) as an offline oracle over our transaction's body hash — see
/// `Tools/emulator-keystone/`. This test rebuilds that transaction, confirms our body hash matches the
/// one handed to the oracle, then feeds the oracle's returned witness set through our consumption path
/// (`TransactionWitnessSet` decode → Ed25519 verify → `WitnessMerge`) — proving the device's signature
/// merges into a submittable tx and verifies against our locally derived key.
@Suite("Keystone device-Rust oracle")
struct KeystoneOracleVectorsTests {
    private let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

    // Captured from the oracle (Tools/emulator-keystone/keystone_oracle) for the self-send below.
    private let expectedBodyHash = "e64cc4bf64e5cdd1d8f33e301bda62cb26752705f51d788db405589c19ddaf98"
    private let oracleWitnessSet = "a100d90102818258207ea09a34aebb13c9841c71397b1cabfec5ddf950405293dee496cac2f437480a5840969bac16f04854bd4dc17c67136388865b8e03345beac1c01b5f907b8e72c3983cb77799f695fbbd047574765e2c59387ea18494335517b5ad6b9041fe5e0302"

    @Test("Our body hash matches, and the device oracle's witness verifies + merges")
    func oracleWitnessRoundTrip() async throws {
        let root = try HDWallet.fromMnemonic(mnemonic: mnemonic)
        let account = try root.derive(fromPath: "m/1852'/1815'/0'")
        let xpub = Data(account.publicKey) + Data(account.chainCode)
        let derivation = try PublicHDDerivation(accountXPub: xpub, accountPath: "m/1852'/1815'/0'", network: .mainnet)
        let address = try derivation.address(role: 0, index: 0)

        let input = TransactionInput(transactionId: TransactionId(payload: Data(repeating: 0xAB, count: 32)), index: 0)
        let output = TransactionOutput(address: try Address.fromBech32(address), amount: Value(coin: 1_000_000))
        var body = TransactionBody(inputs: .list([input]), outputs: [output], fee: Coin(170_000))
        body.ttl = 500_000
        let tx = Transaction(transactionBody: body, transactionWitnessSet: TransactionWitnessSet())
        let bodyHash = tx.transactionBody.hash()
        print("KEYSTONE-ORACLE bodyHash=\(bodyHash.toHex)")

        // Once pinned, verify the oracle's witness against this tx.
        if oracleWitnessSet != "__WITNESS__" {
            #expect(bodyHash.toHex == expectedBodyHash)
            let set = try TransactionWitnessSet.fromCBORHex(oracleWitnessSet)
            let witnesses = set.vkeyWitnesses?.asList ?? []
            #expect(witnesses.count == 1)
            guard let witness = witnesses.first else { return }
            #expect(witness.vkey.payload == (try derivation.paymentVerificationKey(role: 0, index: 0).payload))
            let verifier = try Curve25519.Signing.PublicKey(rawRepresentation: witness.vkey.payload)
            #expect(verifier.isValidSignature(witness.signature, for: bodyHash))
            #expect(try !WitnessMerge.mergedCBORHex(unsigned: tx, witnessSetHex: oracleWitnessSet).isEmpty)
        }
    }
}
