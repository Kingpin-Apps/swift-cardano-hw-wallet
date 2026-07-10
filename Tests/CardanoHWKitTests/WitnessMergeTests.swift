import Testing
import Foundation
import SwiftCardanoCore
@testable import CardanoHWKit

@Suite("Witness merge")
struct WitnessMergeTests {

    /// A synthetic witness set (one vkey witness) as CBOR hex — stands in for a device response.
    private func syntheticWitnessSetHex() throws -> String {
        let pub = Data(repeating: 0xab, count: 32)
        let vkeyType = try VerificationKeyType(from: .bytes(pub))
        let witness = VerificationKeyWitness(vkey: vkeyType, signature: Data(repeating: 0xcd, count: 64))
        let set = TransactionWitnessSet(vkeyWitnesses: .nonEmptyOrderedSet(NonEmptyOrderedSet([witness])))
        return try set.toCBORHex()
    }

    /// A minimal unsigned transaction (one input, one output, a fee) with an empty witness set.
    private func unsignedTx() throws -> Transaction {
        let input = TransactionInput(
            transactionId: TransactionId(payload: Data(repeating: 0x11, count: 32)),
            index: 0
        )
        let address = try Address.fromBech32("addr_test1qq8ac7qqy0vtulyl7wntmsxc6wex80gvcyjy33qffrhm7sh927ysx5sftuw0dlft05dz3c7revpf7jx0xnlcjz3g69mqkt5dmn")
        let output = TransactionOutput(address: address, amount: Value(coin: 1_000_000))
        let body = TransactionBody(inputs: .list([input]), outputs: [output], fee: 200_000)
        return Transaction(transactionBody: body, transactionWitnessSet: TransactionWitnessSet())
    }

    @Test("A device witness set round-trips through CBOR hex")
    func witnessSetRoundTrips() throws {
        let hex = try syntheticWitnessSetHex()
        let decoded = try TransactionWitnessSet.fromCBORHex(hex)
        #expect(decoded.vkeyWitnesses != nil)
    }

    @Test("Merge injects the device vkey witnesses and leaves the body untouched")
    func mergeInjectsWitnesses() throws {
        let unsigned = try unsignedTx()
        #expect(unsigned.transactionWitnessSet.vkeyWitnesses == nil)
        let hex = try syntheticWitnessSetHex()

        let merged = try WitnessMerge.merge(unsigned: unsigned, witnessSetHex: hex)
        #expect(merged.transactionWitnessSet.vkeyWitnesses != nil)
        // The body is the thing signed over — it must be byte-identical after the merge.
        #expect(merged.transactionBody.hash() == unsigned.transactionBody.hash())
        // And the merged tx re-encodes to CBOR.
        #expect(try WitnessMerge.mergedCBORHex(unsigned: unsigned, witnessSetHex: hex).isEmpty == false)
    }

    @Test("Garbage witness CBOR is rejected")
    func rejectsGarbage() throws {
        let unsigned = try unsignedTx()
        #expect(throws: HardwareWalletError.self) {
            _ = try WitnessMerge.merge(unsigned: unsigned, witnessSetHex: "zznotcbor")
        }
    }
}
