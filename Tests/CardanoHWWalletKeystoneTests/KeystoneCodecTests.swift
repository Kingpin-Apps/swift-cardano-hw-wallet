// Keystone support is iOS-only: its URRegistryFFI XCFramework ships no macOS slice.
#if canImport(KeystoneSDK)
import Testing
import Foundation
import SwiftCardanoCore
import CardanoHWKit
@testable import CardanoHWWalletKeystone

@Suite("Keystone sign-request codec")
struct KeystoneCodecTests {
    private let address = "addr_test1qq8ac7qqy0vtulyl7wntmsxc6wex80gvcyjy33qffrhm7sh927ysx5sftuw0dlft05dz3c7revpf7jx0xnlcjz3g69mqkt5dmn"
    private let path = "m/1852'/1815'/0'/0/0"

    private func request(addressPaths: [String: String]? = nil) throws -> HardwareSignRequest {
        let addr = try Address.fromBech32(address)
        let input = TransactionInput(transactionId: TransactionId(payload: Data(repeating: 0x11, count: 32)), index: 0)
        let output = TransactionOutput(address: addr, amount: Value(coin: 5_000_000))
        let utxo = UTxO(input: input, output: output)
        let body = TransactionBody(inputs: .list([input]), outputs: [output], fee: 200_000)
        let unsigned = Transaction(transactionBody: body, transactionWitnessSet: TransactionWitnessSet())
        return HardwareSignRequest(
            requestId: "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
            unsigned: unsigned,
            spentUTxOs: [utxo],
            addressPaths: addressPaths ?? [address: path],
            masterFingerprint: Data([0xde, 0xad, 0xbe, 0xef]),
            origin: "MansAmanaTest"
        )
    }

    @Test("The full encode path produces animated UR frames")
    func encodePath() throws {
        // Exercises the whole chain: our field mapping → Keystone's Rust FFI
        // (generate_cardano_sign_request) → UR fountain encoding.
        let encoder = try KeystoneSignRequestCodec.encoder(for: try request())
        #expect(encoder.seqLen >= 1)
        let part = encoder.nextPart()
        #expect(part.lowercased().hasPrefix("ur:"))
        #expect(part.lowercased().contains("cardano"))
    }

    @Test("A spent input with no known derivation path is rejected")
    func missingPath() throws {
        #expect(throws: HardwareWalletError.self) {
            _ = try KeystoneSignRequestCodec.cardanoSignRequest(from: try request(addressPaths: ["addr_test1other": path]))
        }
    }
}
#endif
