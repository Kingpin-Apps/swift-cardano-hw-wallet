import Testing
import Foundation
import SwiftCardanoCore
@testable import CardanoHWKit

/// The gating check: our public (no-private-key) address derivation from an account xpub must
/// reproduce the SDK's own private-key derivation for the same seed. If these match, deriving
/// addresses from a hardware wallet's exported account xpub is correct.
@Suite("Public HD derivation (public == private)")
struct PublicHDDerivationTests {
    private let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private let accountPath = "m/1852'/1815'/0'"

    private func engine() throws -> (PublicHDDerivation, HDWallet) {
        let root = try HDWallet.fromMnemonic(mnemonic: mnemonic)
        let account = try root.derive(fromPath: accountPath)
        let xpub = Data(account.publicKey) + Data(account.chainCode)   // 32-byte key ‖ 32-byte chain code
        let engine = try PublicHDDerivation(accountXPub: xpub, accountPath: accountPath, network: .testnet)
        return (engine, root)
    }

    @Test("Public child keys match private derivation for payment + stake roles")
    func publicMatchesPrivate() throws {
        let (engine, root) = try engine()
        // role 0 (external) and role 1 (change) → payment keys; role 2 → stake key.
        for (role, index) in [(UInt32(0), UInt32(0)), (0, 3), (1, 0)] {
            let priv = try root.derive(fromPath: "\(accountPath)/\(role)/\(index)")
            let mine = try engine.paymentVerificationKey(role: role, index: index).payload
            #expect(mine == Data(priv.publicKey), "payment role \(role) index \(index)")
        }
        let stakePriv = try root.derive(fromPath: "\(accountPath)/2/0")
        #expect(try engine.stakeVerificationKey(index: 0).payload == Data(stakePriv.publicKey))
    }

    @Test("Derived base address matches the private-key base address")
    func addressMatchesPrivate() throws {
        let (engine, root) = try engine()
        let leaf = try root.derive(fromPath: "\(accountPath)/0/0")
        let stake = try root.derive(fromPath: "\(accountPath)/2/0")
        let expected = try Address(
            paymentPart: .verificationKeyHash(PaymentVerificationKey(payload: Data(leaf.publicKey), type: nil, description: nil).hash()),
            stakingPart: .verificationKeyHash(StakeVerificationKey(payload: Data(stake.publicKey), type: nil, description: nil).hash()),
            network: .testnet
        ).toBech32()
        #expect(try engine.address(role: 0, index: 0) == expected)
        #expect(try engine.address(role: 0, index: 0).hasPrefix("addr_test1"))
    }

    @Test("Address table covers external + change roles and is all-distinct")
    func addressTable() throws {
        let (engine, _) = try engine()
        let table = try engine.deriveAddressTable(gapLimit: 5)
        #expect(table.count == 10)                       // 5 external + 5 change
        #expect(Set(table.keys).count == 10)             // distinct addresses
        #expect(Set(table.values).count == 10)           // distinct paths
        #expect(table.values.contains("\(accountPath)/0/0"))
        #expect(table.values.contains("\(accountPath)/1/4"))
    }

    @Test("A malformed account xpub is rejected")
    func rejectsBadXPub() {
        #expect(throws: HardwareWalletError.self) {
            _ = try PublicHDDerivation(accountXPub: Data(repeating: 0, count: 32), accountPath: accountPath, network: .mainnet)
        }
    }
}
