import Testing
import Foundation
import Crypto
import SwiftCardanoCore
import CardanoHWKit
@testable import CardanoHWWalletTrezor

/// **Live** integration tests that run a real ``TrezorSignSession`` against the trezor-user-env
/// emulator (actual `trezor-firmware`) over ``TrezorEmulatorBridge``. Gated on `TREZOR_EMULATOR=1`
/// and require the emulator up + seeded (run `Tools/emulator/bootstrap.mjs` first). These prove the
/// full `CardanoSignTx` dialogue — Init → body items → witness requests → BodyHash → Finished — is
/// accepted by firmware, that the device's reconstructed body hash equals `swift-cardano-core`'s
/// `transactionBody.hash()` (i.e. the `tagCborSets` value is correct), and that the returned witness
/// cryptographically verifies.
@Suite("Trezor emulator — live sign", .serialized)
struct TrezorEmulatorSignTests {
    static var emulatorEnabled: Bool { ProcessInfo.processInfo.environment["TREZOR_EMULATOR"] == "1" }

    // The device signs its ORDINARY body; tag_cbor_sets must match swift-cardano-core's set encoding.
    private static let options = TrezorSigningOptions(tagCborSets: false, derivationType: .icarusTrezor)

    @Test("importAccount returns the firmware's account xpub", .enabled(if: emulatorEnabled))
    func liveImport() async throws {
        let bridge = TrezorEmulatorBridge()
        let session = TrezorSignSession(transport: bridge, network: .mainnet, options: Self.options)
        let account = try await session.importAccount(network: .mainnet, accountIndex: 0)
        await bridge.release()

        #expect(account.deviceKind == .trezor)
        #expect(account.accountPath == "m/1852'/1815'/0'")
        #expect(account.accountXPub.count == 64)
        // Known xpub for the "all all …" seed (matches TrezorEmulatorVectorsTests golden vector).
        #expect(account.accountXPub.toHex == "d507c8f866691bd96e131334c355188b1a1d0b2fa0ab11545075aab332d77d9eb19657ad13ee581b56b0f8d744d66ca356b93d42fe176b3de007d53e9c4c4e7a")
    }

    @Test("sign() drives the full dialogue and the device witness verifies", .enabled(if: emulatorEnabled))
    func liveSign() async throws {
        let bridge = TrezorEmulatorBridge()
        let session = TrezorSignSession(transport: bridge, network: .mainnet, options: Self.options)

        // Derive the device's own receive address from its exported xpub; spend an input at that path
        // and send back to it (an ordinary self-send — no unsafe paths, one witness).
        let account = try await session.importAccount(network: .mainnet, accountIndex: 0)
        let derivation = try PublicHDDerivation(accountXPub: account.accountXPub, accountPath: account.accountPath, network: .mainnet)
        let address = try derivation.address(role: 0, index: 0)
        let spendPath = "m/1852'/1815'/0'/0/0"

        let tx = try Self.selfSend(to: address, txidByte: 0xAB, amount: 1_000_000, fee: 170_000, ttl: 500_000)
        let bodyHash = tx.transactionBody.hash()

        let input = TransactionInput(transactionId: TransactionId(payload: Data(repeating: 0xAB, count: 32)), index: 0)
        let spentUTxO = UTxO(input: input, output: TransactionOutput(address: try Address.fromBech32(address), amount: Value(coin: 2_000_000)))
        let request = HardwareSignRequest(
            requestId: "emu-send", unsigned: tx, spentUTxOs: [spentUTxO],
            addressPaths: [address: spendPath],
            masterFingerprint: Data(repeating: 0, count: 4), origin: "TrezorEmulatorSignTests"
        )

        let witnessSetHex = try await session.sign(request)
        await bridge.release()

        // sign() already asserted the device body hash == body.hash() (verifyBodyHash) — so reaching
        // here proves tagCborSets is correct against real firmware. Now verify the witness itself.
        let set = try TransactionWitnessSet.fromCBORHex(witnessSetHex)
        let witnesses = set.vkeyWitnesses?.asList ?? []
        #expect(witnesses.count == 1)
        guard let witness = witnesses.first else { return }

        let pubKey = witness.vkey.payload
        let signature = witness.signature
        #expect(pubKey.count == 32)
        #expect(signature.count == 64)

        // Cross-check the device's returned pub key is the account's own spending key (derived
        // independently from the exported xpub).
        let expectedPub = try derivation.paymentVerificationKey(role: 0, index: 0).payload
        #expect(pubKey == expectedPub)

        // Cryptographically verify the Ed25519 signature over the body hash with the device pub key.
        // Cardano vkey witnesses are standard Ed25519 over the blake2b body hash, so Crypto verifies it.
        let verifier = try Curve25519.Signing.PublicKey(rawRepresentation: pubKey)
        #expect(verifier.isValidSignature(signature, for: bodyHash))

        // Merges into a submittable signed tx.
        #expect(try !WitnessMerge.mergedCBORHex(unsigned: tx, witnessSetHex: witnessSetHex).isEmpty)

        // Emit the captured vectors so the offline regression test (TrezorEmulatorSignVectorsTests)
        // can be pinned to real-firmware bytes without the emulator.
        print("EMU-SIGN-VECTOR bodyHash=\(bodyHash.toHex)")
        print("EMU-SIGN-VECTOR pubKey=\(pubKey.toHex)")
        print("EMU-SIGN-VECTOR signature=\(signature.toHex)")
        print("EMU-SIGN-VECTOR witnessSet=\(witnessSetHex)")
    }

    @Test("sign() a rewards withdrawal — device hash matches, payment + stake witnesses verify", .enabled(if: emulatorEnabled))
    func liveWithdraw() async throws {
        let bridge = TrezorEmulatorBridge()
        let session = TrezorSignSession(transport: bridge, network: .mainnet, options: Self.options)
        let (tx, request, derivation) = try await Self.stakingTx(session: session) { _, rewardAccount, base in
            var body = base
            body.withdrawals = Withdrawals([rewardAccount: Coin(1_500_000)])
            return (body, [], [HardwareWithdrawal(stakePath: Self.stakePath, rewardAccountHex: rewardAccount.toHex, amount: 1_500_000)])
        }
        let witnessSetHex = try await session.sign(request)
        await bridge.release()
        try Self.expectStakingWitnesses(witnessSetHex, bodyHash: tx.transactionBody.hash(), derivation: derivation)
    }

    @Test("sign() a stake deregistration — device hash matches, payment + stake witnesses verify", .enabled(if: emulatorEnabled))
    func liveDeregister() async throws {
        let bridge = TrezorEmulatorBridge()
        let session = TrezorSignSession(transport: bridge, network: .mainnet, options: Self.options)
        let (tx, request, derivation) = try await Self.stakingTx(session: session) { stakeCred, _, base in
            var body = base
            body.certificates = .list([.unregister(Unregister(stakeCredential: stakeCred, coin: Coin(2_000_000)))])
            return (body, [.stakeDeregistrationConway(stakePath: Self.stakePath, deposit: 2_000_000)], [])
        }
        let witnessSetHex = try await session.sign(request)
        await bridge.release()
        try Self.expectStakingWitnesses(witnessSetHex, bodyHash: tx.transactionBody.hash(), derivation: derivation)
    }

    // MARK: - Fixtures

    private static let stakePath = "m/1852'/1815'/0'/2/0"

    /// Import → derivation → a base staking tx (1 input, 1 self-output, fee, ttl) that the caller
    /// augments with withdrawals/certs, plus the packaged sign request (payment + stake witnesses).
    private static func stakingTx(
        session: TrezorSignSession,
        _ augment: (StakeCredential, RewardAccount, TransactionBody) throws -> (TransactionBody, [HardwareCertificate], [HardwareWithdrawal])
    ) async throws -> (Transaction, HardwareSignRequest, PublicHDDerivation) {
        let account = try await session.importAccount(network: .mainnet, accountIndex: 0)
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
        let request = HardwareSignRequest(
            requestId: "emu-staking", unsigned: tx, spentUTxOs: [spentUTxO],
            addressPaths: [address: spendPath],
            masterFingerprint: Data(repeating: 0, count: 4), origin: "TrezorEmulatorSignTests",
            certificates: hwCerts, withdrawals: hwWithdrawals
        )
        return (tx, request, derivation)
    }

    /// The witness set has two witnesses (payment + stake), both verify over the body hash, and the
    /// stake key is present — proving the withdrawal/cert wire encoding produced the same body the
    /// firmware reconstructed.
    private static func expectStakingWitnesses(_ witnessSetHex: String, bodyHash: Data, derivation: PublicHDDerivation) throws {
        let witnesses = (try TransactionWitnessSet.fromCBORHex(witnessSetHex)).vkeyWitnesses?.asList ?? []
        #expect(witnesses.count == 2)
        for witness in witnesses {
            let verifier = try Curve25519.Signing.PublicKey(rawRepresentation: witness.vkey.payload)
            #expect(verifier.isValidSignature(witness.signature, for: bodyHash))
        }
        let stakePub = try derivation.stakeVerificationKey(index: 0).payload
        #expect(witnesses.contains { $0.vkey.payload == stakePub })
    }

    private static func selfSend(to address: String, txidByte: UInt8, amount: UInt64, fee: UInt64, ttl: UInt64?) throws -> Transaction {
        let input = TransactionInput(transactionId: TransactionId(payload: Data(repeating: txidByte, count: 32)), index: 0)
        let output = TransactionOutput(address: try Address.fromBech32(address), amount: Value(coin: Int64(amount)))
        var body = TransactionBody(inputs: .list([input]), outputs: [output], fee: Coin(fee))
        body.ttl = ttl
        return Transaction(transactionBody: body, transactionWitnessSet: TransactionWitnessSet())
    }
}
