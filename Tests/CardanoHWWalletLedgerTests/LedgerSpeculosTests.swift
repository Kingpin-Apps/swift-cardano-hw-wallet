import Testing
import Foundation
import Crypto
import SwiftCardanoCore
import CardanoHWKit
@testable import CardanoHWWalletLedger

/// **Live** integration tests that drive the real Ledger `app-cardano` in Speculos over
/// ``LedgerSpeculosTransport``. Gated on `LEDGER_EMULATOR=1`; require the emulator up (see
/// `Tools/emulator-ledger/`). These confirm the APDU transport, the `getVersion`/`getExtendedPublicKey`
/// exchange, and that `PublicHDDerivation` from the firmware xpub reproduces the device's own address.
@Suite("Ledger Speculos — live", .serialized)
struct LedgerSpeculosTests {
    static var emulatorEnabled: Bool { ProcessInfo.processInfo.environment["LEDGER_EMULATOR"] == "1" }

    // Golden vectors for the run.sh seed, m/1852'/1815'/0', mainnet — see Tools/emulator-ledger/README.
    private let xpubHex = "78d137231e6346f17b1d442bace1f7ba1d54a88ef8509464e2e786a854bd4815acafe34e34bf401b4b0164607ee506c4aac63a0828f1dc20ab73ec39f2fe11f3"
    private let deviceAddressHex = "016dfa09426959db1023639e8d1f07bb1e478e722c6ebc1d57ba8703b9db219ee5ce9a74f98fdadc2de13efced5a154ef8d4d41929d5bf9ff6"

    @Test("getVersion returns the Cardano app version", .enabled(if: emulatorEnabled))
    func liveVersion() async throws {
        let transport = LedgerSpeculosTransport()
        let response = try await transport.exchange(Data([0xD7, 0x00, 0x00, 0x00, 0x00]))
        transport.close()
        // Cardano ADA 7.3.1 → major.minor.patch.flags.
        #expect(response.count == 4)
        #expect(Array(response.prefix(3)) == [7, 3, 1])
    }

    @Test("importAccount returns the firmware account xpub", .enabled(if: emulatorEnabled))
    func liveImport() async throws {
        let transport = LedgerSpeculosTransport()
        let session = LedgerSignSession(transport: transport, network: .mainnet)
        let account = try await session.importAccount(network: .mainnet, accountIndex: 0)
        transport.close()

        #expect(account.deviceKind == .ledger)
        #expect(account.accountPath == "m/1852'/1815'/0'")
        #expect(account.accountXPub.toHex == xpubHex)
    }

    @Test("PublicHDDerivation from the firmware xpub reproduces the device's own address", .enabled(if: emulatorEnabled))
    func liveDeriveAddressMatches() async throws {
        let transport = LedgerSpeculosTransport()
        let session = LedgerSignSession(transport: transport, network: .mainnet)
        let account = try await session.importAccount(network: .mainnet, accountIndex: 0)

        // Ask the device for its own base address (m/1852'/1815'/0'/0/0 + stake …/2/0, mainnet).
        let deviceAddress = try await transport.exchange(Self.deriveAddressAPDU())
        transport.close()
        #expect(deviceAddress.toHex == deviceAddressHex)

        // Our public derivation must reproduce it byte-for-byte.
        let derivation = try PublicHDDerivation(accountXPub: account.accountXPub, accountPath: account.accountPath, network: .mainnet)
        let derived = try derivation.address(role: 0, index: 0)
        #expect(try Address.fromBech32(derived).toBytes() == deviceAddress)
    }

    @Test("sign() drives the staged dialogue and the device witness verifies", .enabled(if: emulatorEnabled))
    func liveSign() async throws {
        let transport = LedgerSpeculosTransport()

        // Import → derivation → the device's own receive address (self-send, one witness).
        let account = try await LedgerSignSession(transport: transport, network: .mainnet)
            .importAccount(network: .mainnet, accountIndex: 0)
        let derivation = try PublicHDDerivation(accountXPub: account.accountXPub, accountPath: account.accountPath, network: .mainnet)
        let address = try derivation.address(role: 0, index: 0)
        let spendPath = "m/1852'/1815'/0'/0/0"

        let input = TransactionInput(transactionId: TransactionId(payload: Data(repeating: 0xAB, count: 32)), index: 0)
        let output = TransactionOutput(address: try Address.fromBech32(address), amount: Value(coin: 1_000_000))
        var body = TransactionBody(inputs: .list([input]), outputs: [output], fee: Coin(170_000))
        body.ttl = 500_000
        let tx = Transaction(transactionBody: body, transactionWitnessSet: TransactionWitnessSet())
        let bodyHash = tx.transactionBody.hash()

        let spentUTxO = UTxO(input: input, output: TransactionOutput(address: try Address.fromBech32(address), amount: Value(coin: 2_000_000)))
        let request = HardwareSignRequest(
            requestId: "emu-ledger-send", unsigned: tx, spentUTxOs: [spentUTxO],
            addressPaths: [address: spendPath],
            masterFingerprint: Data(repeating: 0, count: 4), origin: "LedgerSpeculosTests"
        )

        let session = LedgerSignSession(transport: transport, network: .mainnet, options: LedgerSigningOptions(tagCborSets: false), derivation: derivation)
        let witnessSetHex = try await session.sign(request)
        transport.close()

        // sign() already guarded the device tx hash == body.hash() (so tagCborSets is correct against
        // real firmware). Verify the returned witness.
        let witnesses = (try TransactionWitnessSet.fromCBORHex(witnessSetHex)).vkeyWitnesses?.asList ?? []
        #expect(witnesses.count == 1)
        guard let witness = witnesses.first else { return }
        let pubKey = witness.vkey.payload
        #expect(pubKey == (try derivation.paymentVerificationKey(role: 0, index: 0).payload))
        let verifier = try Curve25519.Signing.PublicKey(rawRepresentation: pubKey)
        #expect(verifier.isValidSignature(witness.signature, for: bodyHash))
        #expect(try !WitnessMerge.mergedCBORHex(unsigned: tx, witnessSetHex: witnessSetHex).isEmpty)

        print("EMU-LEDGER-SIGN bodyHash=\(bodyHash.toHex)")
        print("EMU-LEDGER-SIGN pubKey=\(pubKey.toHex)")
        print("EMU-LEDGER-SIGN signature=\(witness.signature.toHex)")
        print("EMU-LEDGER-SIGN witnessSet=\(witnessSetHex)")
    }

    @Test("sign() a rewards withdrawal — device hash matches, payment + stake witnesses verify", .enabled(if: emulatorEnabled))
    func liveWithdraw() async throws {
        let transport = LedgerSpeculosTransport()
        let (tx, request, derivation) = try await Self.stakingTx(transport: transport) { _, rewardAccount, base in
            var body = base
            body.withdrawals = Withdrawals([rewardAccount: Coin(1_500_000)])
            return (body, [], [HardwareWithdrawal(stakePath: Self.stakePath, rewardAccountHex: rewardAccount.toHex, amount: 1_500_000)])
        }
        let witnessSetHex = try await request.session.sign(request.request)
        transport.close()
        try Self.expectStakingWitnesses(witnessSetHex, bodyHash: tx.transactionBody.hash(), derivation: derivation)
    }

    @Test("sign() a stake deregistration — device hash matches, payment + stake witnesses verify", .enabled(if: emulatorEnabled))
    func liveDeregister() async throws {
        let transport = LedgerSpeculosTransport()
        let (tx, request, derivation) = try await Self.stakingTx(transport: transport) { stakeCred, _, base in
            var body = base
            body.certificates = .list([.unregister(Unregister(stakeCredential: stakeCred, coin: Coin(2_000_000)))])
            return (body, [.stakeDeregistrationConway(stakePath: Self.stakePath, deposit: 2_000_000)], [])
        }
        let witnessSetHex = try await request.session.sign(request.request)
        transport.close()
        try Self.expectStakingWitnesses(witnessSetHex, bodyHash: tx.transactionBody.hash(), derivation: derivation)
    }

    // MARK: - Staking fixtures

    private static let stakePath = "m/1852'/1815'/0'/2/0"

    /// Import → derivation → a base staking tx (1 input, 1 self-output, fee, ttl) the caller augments
    /// with withdrawals/certs, plus the packaged sign request bound to a signing session.
    private static func stakingTx(
        transport: LedgerSpeculosTransport,
        _ augment: (StakeCredential, RewardAccount, TransactionBody) throws -> (TransactionBody, [HardwareCertificate], [HardwareWithdrawal])
    ) async throws -> (Transaction, (session: LedgerSignSession, request: HardwareSignRequest), PublicHDDerivation) {
        let account = try await LedgerSignSession(transport: transport, network: .mainnet)
            .importAccount(network: .mainnet, accountIndex: 0)
        let derivation = try PublicHDDerivation(accountXPub: account.accountXPub, accountPath: account.accountPath, network: .mainnet)
        let address = try derivation.address(role: 0, index: 0)
        let spendPath = "m/1852'/1815'/0'/0/0"
        let stakeHash = try derivation.stakeVerificationKey(index: 0).hash()
        let stakeCred = StakeCredential(credential: .verificationKeyHash(stakeHash))
        let rewardAccount = try Address(stakingPart: .verificationKeyHash(stakeHash), network: .mainnet).toBytes()

        let input = TransactionInput(transactionId: TransactionId(payload: Data(repeating: 0xCD, count: 32)), index: 0)
        let output = TransactionOutput(address: try Address.fromBech32(address), amount: Value(coin: 1_000_000))
        var base = TransactionBody(inputs: .list([input]), outputs: [output], fee: Coin(170_000))
        base.ttl = 500_000
        let (body, hwCerts, hwWithdrawals) = try augment(stakeCred, rewardAccount, base)
        let tx = Transaction(transactionBody: body, transactionWitnessSet: TransactionWitnessSet())

        let spentUTxO = UTxO(input: input, output: TransactionOutput(address: try Address.fromBech32(address), amount: Value(coin: 2_000_000)))
        let hwRequest = HardwareSignRequest(
            requestId: "emu-staking", unsigned: tx, spentUTxOs: [spentUTxO],
            addressPaths: [address: spendPath],
            masterFingerprint: Data(repeating: 0, count: 4), origin: "LedgerSpeculosTests",
            certificates: hwCerts, withdrawals: hwWithdrawals
        )
        let session = LedgerSignSession(transport: transport, network: .mainnet, options: LedgerSigningOptions(tagCborSets: false), derivation: derivation)
        return (tx, (session, hwRequest), derivation)
    }

    private static func expectStakingWitnesses(_ witnessSetHex: String, bodyHash: Data, derivation: PublicHDDerivation) throws {
        let witnesses = (try TransactionWitnessSet.fromCBORHex(witnessSetHex)).vkeyWitnesses?.asList ?? []
        #expect(witnesses.count == 2)   // payment + stake
        for witness in witnesses {
            let verifier = try Curve25519.Signing.PublicKey(rawRepresentation: witness.vkey.payload)
            #expect(verifier.isValidSignature(witness.signature, for: bodyHash))
        }
        let stakePub = try derivation.stakeVerificationKey(index: 0).payload
        #expect(witnesses.contains { $0.vkey.payload == stakePub })
    }

    // deriveAddress APDU (INS 0x11, P1_RETURN=0x01): addrType BASE(0) + networkId mainnet(1) +
    // spending path + staking source KEY_PATH(0x22) + staking path.
    private static func deriveAddressAPDU() throws -> Data {
        let spend = try LedgerBIP32Path("m/1852'/1815'/0'/0/0").encoded()
        let stake = try LedgerBIP32Path("m/1852'/1815'/0'/2/0").encoded()
        var data = Data([0x00, 0x01])
        data.append(spend)
        data.append(0x22)
        data.append(stake)
        return LedgerAPDU.command(ins: LedgerAPDU.INS.deriveAddress, p1: 0x01, p2: 0x00, data: data)
    }
}
