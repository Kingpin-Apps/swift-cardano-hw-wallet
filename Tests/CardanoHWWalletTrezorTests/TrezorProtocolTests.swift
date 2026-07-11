import Testing
import Foundation
import SwiftCardanoCore
import CardanoHWKit
@testable import CardanoHWWalletTrezor

@Suite("Trezor Cardano protocol")
struct TrezorProtocolTests {
    private let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private let accountPath = "m/1852'/1815'/0'"

    private func wallet() throws -> (PublicHDDerivation, HDWallet) {
        let root = try HDWallet.fromMnemonic(mnemonic: mnemonic)
        let account = try root.derive(fromPath: accountPath)
        let xpub = Data(account.publicKey) + Data(account.chainCode)
        return (try PublicHDDerivation(accountXPub: xpub, accountPath: accountPath, network: .testnet), root)
    }

    // MARK: - Protobuf codec

    @Test("Protobuf writer/reader round-trips varint, bytes, string, repeated")
    func protobufRoundTrip() throws {
        var w = ProtobufWriter()
        w.varint(1, 300)
        w.bytes(2, Data([0xDE, 0xAD, 0xBE, 0xEF]))
        w.string(3, "hi")
        w.repeatedUInt32(4, [0x8000_073c, 5])
        let r = try ProtobufReader(w.data)
        #expect(r.varint(1) == 300)
        #expect(r.bytes(2) == Data([0xDE, 0xAD, 0xBE, 0xEF]))
        #expect(r.string(3) == "hi")
    }

    // MARK: - Account import

    @Test("CardanoGetPublicKey encodes the account path + derivation type")
    func getPublicKeyMessage() throws {
        let msg = try TrezorAccountImport.getPublicKeyMessage(accountIndex: 0, derivationType: .icarusTrezor)
        #expect(msg.type == 305)
        let r = try ProtobufReader(msg.payload)
        #expect(r.varint(3) == 2)   // derivation_type = ICARUS_TREZOR
    }

    @Test("Parsing CardanoPublicKey yields the account model")
    func parsePublicKey() throws {
        let xpub = Data(repeating: 0x7a, count: 64)
        var w = ProtobufWriter()
        w.string(1, xpub.toHex)                       // xpub hex
        let model = try TrezorAccountImport.parsePublicKey(payload: w.data, accountIndex: 0, network: .testnet)
        #expect(model.deviceKind == .trezor)
        #expect(model.accountXPub == xpub)
        #expect(model.accountPath == "m/1852'/1815'/0'")
    }

    // MARK: - Init serialization

    @Test("SignTxInit declares ordinary mode, counts, and network")
    func initSerialization() throws {
        let (engine, _) = try wallet()
        let tx = try Self.simpleTx(spendAddress: try engine.address(role: 0, index: 0), txidByte: 0x11, fee: 200_000, ttl: 900)
        let msg = try TrezorCardanoSerializer.initMessage(tx, witnessCount: 1, network: .preprod, options: .init())
        #expect(msg.type == 320)
        let r = try ProtobufReader(msg.payload)
        #expect(r.varint(1) == 0)          // signing_mode ORDINARY
        #expect(r.varint(2) == 1)          // protocol_magic (preprod)
        #expect(r.varint(3) == 0)          // network_id testnet
        #expect(r.varint(4) == 1)          // inputs_count
        #expect(r.varint(5) == 1)          // outputs_count
        #expect(r.varint(6) == 200_000)    // fee
        #expect(r.varint(7) == 900)        // ttl
        #expect(r.varint(12) == 1)         // witness_requests_count
    }

    // MARK: - Full sign round-trip (real signature)

    @Test("sign() drives the dialogue and assembles a verifying witness")
    func signRoundTrip() async throws {
        let (engine, root) = try wallet()
        let spendAddr = try engine.address(role: 0, index: 0)
        let tx = try Self.simpleTx(spendAddress: spendAddr, txidByte: 0x33, fee: 180_000, ttl: nil)
        let bodyHash = tx.transactionBody.hash()

        // Device-side signature with the private key at the input path.
        let leaf = try root.derive(fromPath: "\(accountPath)/0/0")
        let priv = try BIP32ED25519PrivateKey(privateKey: Data(leaf.xPrivateKey), chainCode: Data(leaf.chainCode))
        let signature = try priv.sign(message: bodyHash)
        let pubKey = Data(leaf.publicKey)

        // Script the device's framed responses in order:
        // Init→Ack, input→Ack, output→Ack, witnessReq→WitnessResponse, hostAck→BodyHash, hostAck→Finished.
        var inbound: [Data] = []
        func queue(type: UInt16, payload: Data) {
            inbound.append(contentsOf: TrezorProtocolV1.encode(messageType: type, payload: payload))
        }
        queue(type: TrezorMessageType.cardanoTxItemAck, payload: Data())   // init ack
        queue(type: TrezorMessageType.cardanoTxItemAck, payload: Data())   // input ack
        queue(type: TrezorMessageType.cardanoTxItemAck, payload: Data())   // output ack
        var wr = ProtobufWriter()
        wr.varint(1, 1)            // type SHELLEY_WITNESS
        wr.bytes(2, pubKey)        // pub_key
        wr.bytes(3, signature)     // signature
        queue(type: TrezorMessageType.cardanoTxWitnessResponse, payload: wr.data)
        var bh = ProtobufWriter()
        bh.bytes(1, bodyHash)      // tx_hash
        queue(type: TrezorMessageType.cardanoTxBodyHash, payload: bh.data)
        queue(type: TrezorMessageType.cardanoSignTxFinished, payload: Data())

        let link = MockPacketLink(inbound: inbound)
        let session = TrezorSignSession(link: link, network: .preprod)

        let input = TransactionInput(transactionId: TransactionId(payload: Data(repeating: 0x33, count: 32)), index: 0)
        let spentUTxO = UTxO(input: input, output: TransactionOutput(address: try Address.fromBech32(spendAddr), amount: Value(coin: 5_000_000)))
        let request = HardwareSignRequest(
            requestId: "t-req", unsigned: tx, spentUTxOs: [spentUTxO],
            addressPaths: [spendAddr: "\(accountPath)/0/0"],
            masterFingerprint: Data(repeating: 0, count: 4), origin: "MansAmanaTests"
        )

        let witnessSetHex = try await session.sign(request)

        let set = try TransactionWitnessSet.fromCBORHex(witnessSetHex)
        let witnesses = set.vkeyWitnesses?.asList ?? []
        #expect(witnesses.count == 1)
        #expect(witnesses.first?.signature == signature)

        // Cryptographically verifies against the device pub key + body hash.
        let verifier = BIP32ED25519PublicKey(publicKey: pubKey, chainCode: Data(leaf.chainCode))
        #expect(throws: Never.self) {
            _ = try verifier.verify(signature: signature, message: bodyHash)
        }
        // And merges into a submittable signed tx.
        #expect(try !WitnessMerge.mergedCBORHex(unsigned: tx, witnessSetHex: witnessSetHex).isEmpty)

        // The session wrote the expected framed messages, opening the link first.
        #expect(await link.opened)
        let written = await link.recordedReports()
        // Decode the outbound reports back into messages: Init + input + output + witnessReq + 2×hostAck.
        var decoder = TrezorProtocolV1.Decoder()
        var outboundTypes: [UInt16] = []
        for report in written {
            if let (type, _) = try decoder.push(report) {
                outboundTypes.append(type)
                decoder = TrezorProtocolV1.Decoder()
            }
        }
        #expect(outboundTypes == [320, 321, 322, 315, 317, 317])
    }

    @Test("A device Failure is surfaced as a TrezorError")
    func failureSurfaced() async throws {
        let (engine, _) = try wallet()
        let spendAddr = try engine.address(role: 0, index: 0)
        let tx = try Self.simpleTx(spendAddress: spendAddr, txidByte: 0x44, fee: 180_000, ttl: nil)
        var f = ProtobufWriter()
        f.varint(1, 99)                 // code
        f.string(2, "user cancelled")  // message
        let inbound = TrezorProtocolV1.encode(messageType: TrezorMessageType.failure, payload: f.data)
        let link = MockPacketLink(inbound: inbound)
        let session = TrezorSignSession(link: link, network: .preprod)

        let input = TransactionInput(transactionId: TransactionId(payload: Data(repeating: 0x44, count: 32)), index: 0)
        let spentUTxO = UTxO(input: input, output: TransactionOutput(address: try Address.fromBech32(spendAddr), amount: Value(coin: 5_000_000)))
        let request = HardwareSignRequest(
            requestId: "t", unsigned: tx, spentUTxOs: [spentUTxO],
            addressPaths: [spendAddr: "\(accountPath)/0/0"],
            masterFingerprint: Data(repeating: 0, count: 4), origin: "t"
        )
        await #expect(throws: TrezorError.self) {
            _ = try await session.sign(request)
        }
    }

    // MARK: - Fixtures

    private static func simpleTx(spendAddress: String, txidByte: UInt8, fee: UInt64, ttl: UInt64?) throws -> Transaction {
        let input = TransactionInput(transactionId: TransactionId(payload: Data(repeating: txidByte, count: 32)), index: 0)
        let recipient = try Address.fromBech32("addr_test1qq8ac7qqy0vtulyl7wntmsxc6wex80gvcyjy33qffrhm7sh927ysx5sftuw0dlft05dz3c7revpf7jx0xnlcjz3g69mqkt5dmn")
        let output = TransactionOutput(address: recipient, amount: Value(coin: 1_500_000))
        var body = TransactionBody(inputs: .list([input]), outputs: [output], fee: Coin(fee))
        body.ttl = ttl
        return Transaction(transactionBody: body, transactionWitnessSet: TransactionWitnessSet())
    }
}
