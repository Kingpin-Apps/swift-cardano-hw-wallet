import Foundation
import SwiftCardanoCore

/// Derives Cardano addresses from a hardware wallet's **account extended public key** using
/// BIP32-Ed25519 *public, non-hardened* derivation — no private key involved.
///
/// CIP-1852 paths are `m/1852'/1815'/account'/role/index`. The `account'` node is hardened and comes
/// from the device (exported once); `role` (0 external, 1 change, 2 stake) and `index` are
/// non-hardened, so every address the wallet ever needs is derivable offline from the account xpub.
/// The engine is `HDWallet.derivePublicChildKeyByIndex` (swift-cardano-core), which reads only its
/// `publicNode` argument, so a throwaway root node drives it.
public struct PublicHDDerivation: Sendable {
    private let accountPublicKey: Data   // 32 bytes
    private let accountChainCode: Data   // 32 bytes
    private let accountPath: String      // e.g. "m/1852'/1815'/0'"
    private let network: NetworkId

    private static let externalRole: UInt32 = 0
    private static let changeRole: UInt32 = 1
    private static let stakeRole: UInt32 = 2

    public init(account: HardwareAccountModel) throws {
        try self.init(accountXPub: account.accountXPub, accountPath: account.accountPath, network: account.network)
    }

    public init(accountXPub: Data, accountPath: String, network: NetworkId) throws {
        guard accountXPub.count == 64 else {
            throw HardwareWalletError.invalidAccountKey("Account xpub must be 64 bytes (32-byte key + 32-byte chain code), got \(accountXPub.count).")
        }
        self.accountPublicKey = Data(accountXPub.prefix(32))
        self.accountChainCode = Data(accountXPub.suffix(32))
        self.accountPath = accountPath
        self.network = network
    }

    // MARK: - Verification keys

    /// The payment verification key at `role`/`index`.
    public func paymentVerificationKey(role: UInt32 = 0, index: UInt32 = 0) throws -> PaymentVerificationKey {
        let (key, _) = try childPublicKey(role: role, index: index)
        return PaymentVerificationKey(payload: key, type: nil, description: nil)
    }

    /// The stake verification key at stake-role `index` (default 0).
    public func stakeVerificationKey(index: UInt32 = 0) throws -> StakeVerificationKey {
        let (key, _) = try childPublicKey(role: Self.stakeRole, index: index)
        return StakeVerificationKey(payload: key, type: nil, description: nil)
    }

    // MARK: - Addresses

    /// A base address (payment + stake) at `role`/`index`, bech32.
    public func address(role: UInt32 = 0, index: UInt32 = 0, stakeIndex: UInt32 = 0) throws -> String {
        do {
            let pHash = try paymentVerificationKey(role: role, index: index).hash()
            let sHash = try stakeVerificationKey(index: stakeIndex).hash()
            let address = try Address(
                paymentPart: .verificationKeyHash(pHash),
                stakingPart: .verificationKeyHash(sHash),
                network: network
            )
            return try address.toBech32()
        } catch let error as HardwareWalletError {
            throw error
        } catch {
            throw HardwareWalletError.derivationFailed("address(role:\(role), index:\(index)): \(error)")
        }
    }

    /// A map of bech32 address → full derivation path across the external and change roles for
    /// indices `0..<gapLimit`, all sharing stake index 0. Used to resolve which wallet address (and
    /// path) holds each spent UTxO when building a hardware sign request.
    public func deriveAddressTable(gapLimit: Int = 20) throws -> [String: String] {
        var table: [String: String] = [:]
        for role in [Self.externalRole, Self.changeRole] {
            for index in 0..<UInt32(max(0, gapLimit)) {
                let addr = try address(role: role, index: index)
                table[addr] = path(role: role, index: index)
            }
        }
        return table
    }

    /// The full derivation-path string for a leaf, e.g. `m/1852'/1815'/0'/0/3`.
    public func path(role: UInt32, index: UInt32) -> String {
        "\(accountPath)/\(role)/\(index)"
    }

    // MARK: - Internals

    /// The public key (32 bytes) + path at `role`/`index`, via two non-hardened public derivations
    /// (account → role → index).
    private func childPublicKey(role: UInt32, index: UInt32) throws -> (key: Data, path: String) {
        do {
            let root = Self.throwawayNode()
            let roleNode = try root.derivePublicChildKeyByIndex(
                publicNode: (accountPublicKey, accountChainCode, accountPath), index: role
            )
            let leaf = try root.derivePublicChildKeyByIndex(
                publicNode: (roleNode.publicKey, roleNode.chainCode, roleNode.path), index: index
            )
            return (leaf.publicKey, leaf.path)
        } catch {
            throw HardwareWalletError.derivationFailed("child(role:\(role), index:\(index)): \(error)")
        }
    }

    /// A zero-filled `HDWallet` used only to reach `derivePublicChildKeyByIndex`, which reads solely
    /// its `publicNode` argument (the instance's own fields are copied through, unused).
    private static func throwawayNode() -> HDWallet {
        HDWallet(
            rootXPrivateKey: Data(), rootPublicKey: Data(), rootChainCode: Data(),
            xPrivateKey: Data(), publicKey: Data(), chainCode: Data(),
            path: "m", seed: nil, mnemonic: nil, passphrase: nil, entropy: nil
        )
    }
}
