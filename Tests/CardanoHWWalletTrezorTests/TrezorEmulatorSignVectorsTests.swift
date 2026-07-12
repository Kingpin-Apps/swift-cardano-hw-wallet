import Testing
import Foundation
import Crypto
import SwiftCardanoCore
import CardanoHWKit
@testable import CardanoHWWalletTrezor

/// **Offline** golden-vector regression for the full Trezor `CardanoSignTx` dialogue. The bytes were
/// captured from the **Trezor emulator** (real `trezor-firmware`, seed "all all …") by the live
/// `TrezorEmulatorSignTests.liveSign` run — see `Tools/emulator/`. This test needs no device: it
/// rebuilds the exact ordinary self-send, asserts our serializer reproduces the **firmware-agreed
/// body hash** (proving `tagCborSets = false` is correct for `swift-cardano-core`'s set encoding),
/// then replays the device's real witness through ``TrezorSignSession`` and checks the assembled
/// witness set matches the firmware bytes and verifies cryptographically.
@Suite("Trezor emulator — offline sign vectors")
struct TrezorEmulatorSignVectorsTests {
    // Account xpub for m/1852'/1815'/0' under the "all all …" seed (ICARUS_TREZOR), from firmware.
    private let xpubHex = "d507c8f866691bd96e131334c355188b1a1d0b2fa0ab11545075aab332d77d9eb19657ad13ee581b56b0f8d744d66ca356b93d42fe176b3de007d53e9c4c4e7a"
    // Captured 2026-07-11 from the emulator bridge for the self-send below (input 0xAB×32:0,
    // output → own addr, amount 1_000_000, fee 170_000, ttl 500_000, mainnet).
    private let expectedBodyHash = "cace8bf17970bb40401261ed94d8de087e6b4df37ba9eda512c396761923fb7a"
    private let devicePubKey = "5d010cf16fdeff40955633d6c565f3844a288a24967cf6b76acbeb271b4f13c1"
    private let deviceSignature = "e8226e9ac3d8971bb0e2babd9fb754894e92866192e34a0b872d5ecee3d39d1b6c01c867c0468b8d90ff6cdc4c916133151af47b797d95a4a7bc0c73c6d0d90c"
    private let expectedWitnessSet = "a100d90102818258205d010cf16fdeff40955633d6c565f3844a288a24967cf6b76acbeb271b4f13c15840e8226e9ac3d8971bb0e2babd9fb754894e92866192e34a0b872d5ecee3d39d1b6c01c867c0468b8d90ff6cdc4c916133151af47b797d95a4a7bc0c73c6d0d90c"

    @Test("Serializer reproduces the firmware body hash and replays a verifying witness")
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

        // Our serialization must reproduce the body hash the firmware reconstructed and signed —
        // i.e. tagCborSets=false matches swift-cardano-core's ordinary-tx set encoding.
        #expect(tx.transactionBody.hash().toHex == expectedBodyHash)

        // Script the device's framed responses (Init ack, input ack, output ack, witness, body hash,
        // finished) using the REAL firmware pub key + signature.
        let pubKey = Self.hex(devicePubKey)
        let signature = Self.hex(deviceSignature)
        var inbound: [Data] = []
        func queue(_ type: UInt16, _ payload: Data) {
            inbound.append(contentsOf: TrezorProtocolV1.encode(messageType: type, payload: payload))
        }
        queue(TrezorMessageType.cardanoTxItemAck, Data())   // init
        queue(TrezorMessageType.cardanoTxItemAck, Data())   // input
        queue(TrezorMessageType.cardanoTxItemAck, Data())   // output
        var witness = ProtobufWriter()
        witness.varint(1, 1)            // type SHELLEY_WITNESS
        witness.bytes(2, pubKey)
        witness.bytes(3, signature)
        queue(TrezorMessageType.cardanoTxWitnessResponse, witness.data)
        var bodyHashMessage = ProtobufWriter()
        bodyHashMessage.bytes(1, Self.hex(expectedBodyHash))
        queue(TrezorMessageType.cardanoTxBodyHash, bodyHashMessage.data)
        queue(TrezorMessageType.cardanoSignTxFinished, Data())

        let session = TrezorSignSession(
            link: MockPacketLink(inbound: inbound), network: .mainnet,
            options: TrezorSigningOptions(tagCborSets: false, derivationType: .icarusTrezor)
        )

        let spentUTxO = UTxO(input: input, output: TransactionOutput(address: try Address.fromBech32(address), amount: Value(coin: 2_000_000)))
        let request = HardwareSignRequest(
            requestId: "emu-vector", unsigned: tx, spentUTxOs: [spentUTxO],
            addressPaths: [address: spendPath],
            masterFingerprint: Data(repeating: 0, count: 4), origin: "TrezorEmulatorSignVectorsTests"
        )

        let witnessSetHex = try await session.sign(request)

        // The assembled witness set matches the firmware bytes exactly...
        #expect(witnessSetHex == expectedWitnessSet)
        // ...contains the device's witness...
        let witnesses = (try TransactionWitnessSet.fromCBORHex(witnessSetHex)).vkeyWitnesses?.asList ?? []
        #expect(witnesses.count == 1)
        #expect(witnesses.first?.vkey.payload == pubKey)
        #expect(witnesses.first?.signature == signature)
        // ...and the signature cryptographically verifies over the body hash.
        let verifier = try Curve25519.Signing.PublicKey(rawRepresentation: pubKey)
        #expect(verifier.isValidSignature(signature, for: tx.transactionBody.hash()))
        // ...and merges into a submittable signed tx.
        #expect(try !WitnessMerge.mergedCBORHex(unsigned: tx, witnessSetHex: witnessSetHex).isEmpty)
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
