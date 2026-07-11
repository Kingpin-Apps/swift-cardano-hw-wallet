import Testing
import Foundation
import SwiftCardanoCore
import CardanoHWKit
@testable import CardanoHWWalletLedger

@Suite("Ledger protocol (v8)")
struct LedgerProtocolTests {
    private let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private let accountPath = "m/1852'/1815'/0'"

    /// (public derivation engine from the account xpub, root wallet for private signing).
    private func wallet() throws -> (PublicHDDerivation, HDWallet) {
        let root = try HDWallet.fromMnemonic(mnemonic: mnemonic)
        let account = try root.derive(fromPath: accountPath)
        let xpub = Data(account.publicKey) + Data(account.chainCode)
        return (try PublicHDDerivation(accountXPub: xpub, accountPath: accountPath, network: .testnet), root)
    }

    // MARK: - Account import

    @Test("getExtendedPublicKey APDU encodes CLA/INS and the hardened account path")
    func extPubKeyAPDU() throws {
        let apdu = try LedgerAccountImport.getExtendedPublicKeyAPDU(accountIndex: 0)
        let bytes = Array(apdu)
        #expect(bytes[0] == 0xD7)                     // CLA
        #expect(bytes[1] == 0x10)                     // INS getExtendedPublicKey
        #expect(bytes[2] == 0x00 && bytes[3] == 0x00) // P1/P2 unused
        #expect(bytes[4] == 13)                       // Lc: 1 (len) + 3*4
        #expect(bytes[5] == 3)                        // path length
        // 1852' = 0x8000073c, 1815' = 0x80000717, 0' = 0x80000000
        #expect(Array(bytes[6...9]) == [0x80, 0x00, 0x07, 0x3c])
        #expect(Array(bytes[10...13]) == [0x80, 0x00, 0x07, 0x17])
        #expect(Array(bytes[14...17]) == [0x80, 0x00, 0x00, 0x00])
    }

    @Test("Parsing a 64-byte extPubKey response yields the account model")
    func parseImport() throws {
        let response = Data(repeating: 0xA1, count: 32) + Data(repeating: 0xB2, count: 32)
        let model = try LedgerAccountImport.parse(response: response, accountIndex: 0, network: .testnet)
        #expect(model.deviceKind == .ledger)
        #expect(model.accountXPub == response)
        #expect(model.accountPath == "m/1852'/1815'/0'")
        #expect(model.masterFingerprint == Data(repeating: 0, count: 4))
    }

    @Test("A too-short extPubKey response is rejected")
    func rejectsShortImport() {
        #expect(throws: LedgerError.self) {
            _ = try LedgerAccountImport.parse(response: Data(repeating: 0, count: 40), accountIndex: 0, network: .testnet)
        }
    }

    // MARK: - Serialization

    @Test("Raw tx serialization leads with the input hash + index and INIT declares the shape")
    func serialization() throws {
        let (engine, _) = try wallet()
        let spendAddr = try engine.address(role: 0, index: 0)
        let tx = try Self.simpleTx(spendAddress: spendAddr, txidByte: 0x11, fee: 200_000, ttl: 900)

        let raw = try LedgerCardanoSerializer.serializeTransactionRaw(tx)
        #expect(Array(raw.prefix(32)) == Array(repeating: 0x11, count: 32))   // input tx hash
        #expect(Array(raw[32...35]) == [0x00, 0x00, 0x00, 0x00])              // input index 0 (BE)

        let path = try LedgerBIP32Path("\(accountPath)/0/0")
        let initData = try LedgerCardanoSerializer.serializeTxInitData(
            tx, witnessPaths: [path], rawTxLength: raw.count, network: .preprod, options: .init()
        )
        let b = Array(initData)
        #expect(Array(b[0...7]) == [0, 0, 0, 0, 0, 0, 0, 0])   // option flags (tagCborSets=false)
        #expect(b[8] == 0)                                      // networkId (preprod testnet)
        #expect(Array(b[9...12]) == [0, 0, 0, 1])               // protocol magic (preprod = 1)
        #expect(b[13] == 3)                                     // signing mode ORDINARY
        #expect(Array(b[14...15]) == [0, 1])                    // input count
        #expect(Array(b[16...17]) == [0, 1])                    // output count
        #expect(b[18] == 2)                                     // ttl included = YES
    }

    @Test("Certificates/mint are rejected as out of scope")
    func scopeGuard() throws {
        let (engine, _) = try wallet()
        let spendAddr = try engine.address(role: 0, index: 0)
        var tx = try Self.simpleTx(spendAddress: spendAddr, txidByte: 0x22, fee: 170_000, ttl: nil)
        var body = tx.transactionBody
        body.mint = MultiAsset([:])
        tx = Transaction(transactionBody: body, transactionWitnessSet: tx.transactionWitnessSet)
        #expect(throws: LedgerError.self) {
            _ = try LedgerCardanoSerializer.serializeTransactionRaw(tx)
        }
    }

    // MARK: - Full sign round-trip (real signature)

    @Test("sign() assembles a witness that verifies against the body hash")
    func signRoundTrip() async throws {
        let (engine, root) = try wallet()
        let spendAddr = try engine.address(role: 0, index: 0)
        let tx = try Self.simpleTx(spendAddress: spendAddr, txidByte: 0x33, fee: 180_000, ttl: nil)

        // The device signs the body hash with the private key at the input path.
        let bodyHash = tx.transactionBody.hash()
        let leaf = try root.derive(fromPath: "\(accountPath)/0/0")
        let priv = try BIP32ED25519PrivateKey(privateKey: Data(leaf.xPrivateKey), chainCode: Data(leaf.chainCode))
        let signature = try priv.sign(message: bodyHash)
        #expect(signature.count == 64)

        // Build the request the app would produce.
        let input = TransactionInput(transactionId: TransactionId(payload: Data(repeating: 0x33, count: 32)), index: 0)
        let spentUTxO = UTxO(input: input, output: TransactionOutput(address: try Address.fromBech32(spendAddr), amount: Value(coin: 5_000_000)))
        let request = HardwareSignRequest(
            requestId: "req-1",
            unsigned: tx,
            spentUTxOs: [spentUTxO],
            addressPaths: [spendAddr: "\(accountPath)/0/0"],
            masterFingerprint: Data(repeating: 0, count: 4),
            origin: "MansAmanaTests"
        )

        // Scripted transport: INIT → (single chunk == CONFIRM, returns tx hash) → witness (returns sig).
        let transport = MockLedgerTransport(responses: [Data(), bodyHash, signature])
        let session = LedgerSignSession(transport: transport, network: .preprod, derivation: engine)

        let witnessSetHex = try await session.sign(request)

        // The assembled witness set merges and carries exactly our (derived pubkey, device signature).
        let set = try TransactionWitnessSet.fromCBORHex(witnessSetHex)
        let witnesses = set.vkeyWitnesses?.asList ?? []
        #expect(witnesses.count == 1)

        let derivedPub = try engine.paymentVerificationKey(role: 0, index: 0).payload
        #expect(witnesses.first?.signature == signature)

        // The signature cryptographically verifies against the derived public key + body hash.
        let verifier = BIP32ED25519PublicKey(publicKey: derivedPub, chainCode: Data(leaf.chainCode))
        #expect(throws: Never.self) {
            _ = try verifier.verify(signature: signature, message: bodyHash)
        }

        // And the whole thing merges into a submittable signed transaction.
        let signedHex = try WitnessMerge.mergedCBORHex(unsigned: tx, witnessSetHex: witnessSetHex)
        #expect(!signedHex.isEmpty)

        // The session sent INIT + one CONFIRM chunk + one witness request = 3 APDUs.
        let sent = await transport.recordedAPDUs()
        #expect(sent.count == 3)
        #expect(Array(sent[0])[1] == 0x21 && Array(sent[0])[2] == 0x10)   // SIGN_TX, INIT
        #expect(Array(sent[1])[2] == 0x12)                                 // CONFIRM (last chunk)
        #expect(Array(sent[2])[2] == 0x0f)                                 // SIGN_WITNESS
    }

    @Test("sign() fails loudly when the device tx hash disagrees")
    func signHashMismatch() async throws {
        let (engine, _) = try wallet()
        let spendAddr = try engine.address(role: 0, index: 0)
        let tx = try Self.simpleTx(spendAddress: spendAddr, txidByte: 0x44, fee: 180_000, ttl: nil)
        let input = TransactionInput(transactionId: TransactionId(payload: Data(repeating: 0x44, count: 32)), index: 0)
        let spentUTxO = UTxO(input: input, output: TransactionOutput(address: try Address.fromBech32(spendAddr), amount: Value(coin: 5_000_000)))
        let request = HardwareSignRequest(
            requestId: "req-2", unsigned: tx, spentUTxOs: [spentUTxO],
            addressPaths: [spendAddr: "\(accountPath)/0/0"],
            masterFingerprint: Data(repeating: 0, count: 4), origin: "t"
        )
        // CONFIRM returns a wrong tx hash → integrity guard must throw before witnessing.
        let transport = MockLedgerTransport(responses: [Data(), Data(repeating: 0xFF, count: 32), Data(repeating: 0xAB, count: 64)])
        let session = LedgerSignSession(transport: transport, network: .preprod, derivation: engine)
        await #expect(throws: LedgerError.self) {
            _ = try await session.sign(request)
        }
    }

    // MARK: - Staking (certificate)

    @Test("Stake delegation adds a cert to the stream + a stake-key witness")
    func delegationSign() async throws {
        let (engine, root) = try wallet()
        let spendAddr = try engine.address(role: 0, index: 0)
        let tx = try Self.simpleTx(spendAddress: spendAddr, txidByte: 0x55, fee: 180_000, ttl: nil)
        let bodyHash = tx.transactionBody.hash()

        let stakePath = "\(accountPath)/2/0"
        let poolHashHex = String(repeating: "ab", count: 28)
        let cert = HardwareCertificate.stakeDelegation(stakePath: stakePath, poolKeyHashHex: poolHashHex)

        // INIT declares certificates_count = 1.
        let paymentPath = try LedgerBIP32Path("\(accountPath)/0/0")
        let raw = try LedgerCardanoSerializer.serializeTransactionRaw(tx, certificates: [cert])
        let initData = try LedgerCardanoSerializer.serializeTxInitData(
            tx, witnessPaths: [paymentPath], rawTxLength: raw.count, network: .preprod, options: .init(),
            certificateCount: 1, withdrawalCount: 0
        )
        #expect(Array(initData)[19...20] == [0, 1])   // certificates count

        // Device signs the body hash with both the payment key (input) and the stake key (cert).
        let paymentLeaf = try root.derive(fromPath: "\(accountPath)/0/0")
        let stakeLeaf = try root.derive(fromPath: stakePath)
        let paySig = try BIP32ED25519PrivateKey(privateKey: Data(paymentLeaf.xPrivateKey), chainCode: Data(paymentLeaf.chainCode)).sign(message: bodyHash)
        let stakeSig = try BIP32ED25519PrivateKey(privateKey: Data(stakeLeaf.xPrivateKey), chainCode: Data(stakeLeaf.chainCode)).sign(message: bodyHash)

        let input = TransactionInput(transactionId: TransactionId(payload: Data(repeating: 0x55, count: 32)), index: 0)
        let spentUTxO = UTxO(input: input, output: TransactionOutput(address: try Address.fromBech32(spendAddr), amount: Value(coin: 5_000_000)))
        let request = HardwareSignRequest(
            requestId: "deleg", unsigned: tx, spentUTxOs: [spentUTxO],
            addressPaths: [spendAddr: "\(accountPath)/0/0"],
            masterFingerprint: Data(repeating: 0, count: 4), origin: "t",
            certificates: [cert]
        )
        // INIT → CONFIRM(tx hash) → payment witness → stake witness.
        let transport = MockLedgerTransport(responses: [Data(), bodyHash, paySig, stakeSig])
        let session = LedgerSignSession(transport: transport, network: .preprod, derivation: engine)

        let witnessSetHex = try await session.sign(request)
        let witnesses = (try TransactionWitnessSet.fromCBORHex(witnessSetHex)).vkeyWitnesses?.asList ?? []
        #expect(witnesses.count == 2)   // payment + stake

        // The stake witness carries the derived stake pubkey and verifies.
        let stakePub = try engine.stakeVerificationKey(index: 0).payload
        #expect(witnesses.contains { $0.signature == stakeSig })
        let verifier = BIP32ED25519PublicKey(publicKey: stakePub, chainCode: Data(stakeLeaf.chainCode))
        #expect(throws: Never.self) { _ = try verifier.verify(signature: stakeSig, message: bodyHash) }

        // Four APDUs: INIT, CONFIRM chunk, 2 witness requests.
        let sent = await transport.recordedAPDUs()
        #expect(sent.count == 4)
        #expect(Array(sent[2])[2] == 0x0f && Array(sent[3])[2] == 0x0f)   // both witness requests
    }

    // MARK: - Fixtures

    /// A single-input, single-output plain-ADA transaction paying a fixed recipient.
    private static func simpleTx(spendAddress: String, txidByte: UInt8, fee: UInt64, ttl: UInt64?) throws -> Transaction {
        let input = TransactionInput(transactionId: TransactionId(payload: Data(repeating: txidByte, count: 32)), index: 0)
        let recipient = try Address.fromBech32("addr_test1qq8ac7qqy0vtulyl7wntmsxc6wex80gvcyjy33qffrhm7sh927ysx5sftuw0dlft05dz3c7revpf7jx0xnlcjz3g69mqkt5dmn")
        let output = TransactionOutput(address: recipient, amount: Value(coin: 1_500_000))
        var body = TransactionBody(inputs: .list([input]), outputs: [output], fee: Coin(fee))
        body.ttl = ttl
        return Transaction(transactionBody: body, transactionWitnessSet: TransactionWitnessSet())
    }
}
