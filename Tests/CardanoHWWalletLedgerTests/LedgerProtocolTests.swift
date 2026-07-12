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

    @Test("SignTx stages per-field APDUs in order and INIT declares the shape")
    func serialization() throws {
        let (engine, _) = try wallet()
        let spendAddr = try engine.address(role: 0, index: 0)
        let tx = try Self.simpleTx(spendAddress: spendAddr, txidByte: 0x11, fee: 200_000, ttl: 900)
        let path = try LedgerBIP32Path("\(accountPath)/0/0")

        let apdus = try LedgerCardanoSerializer.signTxAPDUs(tx, witnessPaths: [path], network: .preprod, options: .init())
        // INIT, input, output-basic, output-confirm, fee, ttl, tx-confirm, witness.
        #expect(apdus.map { Self.p1($0) } == [0x01, 0x02, 0x03, 0x03, 0x04, 0x05, 0x0A, 0x0F])
        // Every APDU is SIGN_TX (INS 0x21) on CLA 0xD7.
        #expect(apdus.allSatisfy { Array($0)[0] == 0xD7 && Array($0)[1] == 0x21 })

        // The input APDU carries the 32-byte prev hash + 4-byte index.
        let inputData = Array(apdus[1].dropFirst(5))
        #expect(Array(inputData.prefix(32)) == Array(repeating: 0x11, count: 32))
        #expect(Array(inputData[32...35]) == [0, 0, 0, 0])

        // INIT payload byte layout (data starts after the 5-byte APDU header).
        let b = Array(apdus[0].dropFirst(5))
        #expect(Array(b[0...7]) == [0, 0, 0, 0, 0, 0, 0, 0])   // options (tagCborSets=false)
        #expect(b[8] == 0)                                      // networkId (preprod testnet)
        #expect(Array(b[9...12]) == [0, 0, 0, 1])               // protocol magic (preprod = 1)
        #expect(b[13] == 2)                                     // ttl flag = YES
        #expect(b[23] == 3)                                     // signing mode ORDINARY
        #expect(Array(b[24...27]) == [0, 0, 0, 1])              // inputs count
        #expect(Array(b[28...31]) == [0, 0, 0, 1])              // outputs count
        #expect(Array(b[56...59]) == [0, 0, 0, 1])              // witness-path count
    }

    @Test("Mint is rejected as out of scope")
    func scopeGuard() throws {
        let (engine, _) = try wallet()
        let spendAddr = try engine.address(role: 0, index: 0)
        var tx = try Self.simpleTx(spendAddress: spendAddr, txidByte: 0x22, fee: 170_000, ttl: nil)
        var body = tx.transactionBody
        body.mint = MultiAsset([:])
        tx = Transaction(transactionBody: body, transactionWitnessSet: tx.transactionWitnessSet)
        let path = try LedgerBIP32Path("\(accountPath)/0/0")
        #expect(throws: LedgerError.self) {
            _ = try LedgerCardanoSerializer.signTxAPDUs(tx, witnessPaths: [path], network: .preprod, options: .init())
        }
    }

    /// The P1 byte (index 2) of an assembled APDU.
    private static func p1(_ apdu: Data) -> UInt8 { Array(apdu)[2] }

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
            origin: "HardwareTests"
        )

        // Scripted transport for the staged flow: INIT, input, output-basic, output-confirm, fee
        // (all empty), tx-confirm (returns tx hash), witness (returns signature) = 7 exchanges.
        let transport = MockLedgerTransport(responses: [Data(), Data(), Data(), Data(), Data(), bodyHash, signature])
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

        // Staged APDUs: INIT, input, out-basic, out-confirm, fee, tx-confirm, witness = 7.
        let sent = await transport.recordedAPDUs()
        #expect(sent.count == 7)
        #expect(Self.p1(sent[0]) == 0x01)   // INIT
        #expect(Self.p1(sent[5]) == 0x0A)   // TX_CONFIRM (returns tx hash)
        #expect(Self.p1(sent[6]) == 0x0F)   // WITNESS
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
        // TX_CONFIRM returns a wrong tx hash → integrity guard must throw before witnessing.
        let transport = MockLedgerTransport(responses: [Data(), Data(), Data(), Data(), Data(), Data(repeating: 0xFF, count: 32), Data(repeating: 0xAB, count: 64)])
        let session = LedgerSignSession(transport: transport, network: .preprod, derivation: engine)
        await #expect(throws: LedgerError.self) {
            _ = try await session.sign(request)
        }
    }

    // MARK: - Native assets

    @Test("A multi-asset output serializes its token bundle (policy + name + count)")
    func multiAssetOutput() throws {
        let policyHex = String(repeating: "9a", count: 28)
        let nameHex = "74657374"   // "test"
        let multiAsset = try MultiAsset(from: [policyHex: [nameHex: Int64(7)]])
        let recipient = try Address.fromBech32("addr_test1qq8ac7qqy0vtulyl7wntmsxc6wex80gvcyjy33qffrhm7sh927ysx5sftuw0dlft05dz3c7revpf7jx0xnlcjz3g69mqkt5dmn")
        let output = TransactionOutput(address: recipient, amount: Value(coin: 2_000_000, multiAsset: multiAsset))
        let input = TransactionInput(transactionId: TransactionId(payload: Data(repeating: 0x77, count: 32)), index: 0)
        let body = TransactionBody(inputs: .list([input]), outputs: [output], fee: 200_000)
        let tx = Transaction(transactionBody: body, transactionWitnessSet: TransactionWitnessSet())

        let path = try LedgerBIP32Path("\(accountPath)/0/0")
        let apdus = try LedgerCardanoSerializer.signTxAPDUs(tx, witnessPaths: [path], network: .preprod, options: .init())
        // The output stage emits an asset-group APDU (P2=0x31) with the policy id and a token APDU
        // (P2=0x32) with the asset name.
        let assetGroup = apdus.first { Self.p1($0) == 0x03 && Array($0)[3] == 0x31 }
        let token = apdus.first { Self.p1($0) == 0x03 && Array($0)[3] == 0x32 }
        #expect(assetGroup?.range(of: Data(ledgerHex: policyHex)!) != nil)
        #expect(token?.range(of: Data(ledgerHex: nameHex)!) != nil)
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

        // INIT declares certificates_count = 1, and the stream has a certificate APDU (P1=0x06).
        let paymentPath = try LedgerBIP32Path("\(accountPath)/0/0")
        let stagedApdus = try LedgerCardanoSerializer.signTxAPDUs(
            tx, witnessPaths: [paymentPath], network: .preprod, options: .init(), certificates: [cert]
        )
        let initData = Array(stagedApdus[0].dropFirst(5))
        #expect(Array(initData[32...35]) == [0, 0, 0, 1])           // certificates count (4B)
        #expect(stagedApdus.contains { Self.p1($0) == 0x06 })        // certificate stage present

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
        // Staged: INIT, input, out-basic, out-confirm, fee, cert, tx-confirm, pay-witness, stake-witness
        // = 9 exchanges; the tx-confirm (index 6) returns the body hash.
        let transport = MockLedgerTransport(responses: [Data(), Data(), Data(), Data(), Data(), Data(), bodyHash, paySig, stakeSig])
        let session = LedgerSignSession(transport: transport, network: .preprod, derivation: engine)

        let witnessSetHex = try await session.sign(request)
        let witnesses = (try TransactionWitnessSet.fromCBORHex(witnessSetHex)).vkeyWitnesses?.asList ?? []
        #expect(witnesses.count == 2)   // payment + stake

        // The stake witness carries the derived stake pubkey and verifies.
        let stakePub = try engine.stakeVerificationKey(index: 0).payload
        #expect(witnesses.contains { $0.signature == stakeSig })
        let verifier = BIP32ED25519PublicKey(publicKey: stakePub, chainCode: Data(stakeLeaf.chainCode))
        #expect(throws: Never.self) { _ = try verifier.verify(signature: stakeSig, message: bodyHash) }

        // Nine APDUs; the last two are the payment + stake witness requests.
        let sent = await transport.recordedAPDUs()
        #expect(sent.count == 9)
        #expect(Self.p1(sent[7]) == 0x0F && Self.p1(sent[8]) == 0x0F)
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
