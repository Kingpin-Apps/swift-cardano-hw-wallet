import Foundation
import SwiftCardanoCore

/// Errors from the device-agnostic hardware core.
public enum HardwareWalletError: Error, Sendable, Equatable {
    case invalidAccountKey(String)
    case derivationFailed(String)
    case witnessDecodeFailed(String)
    case buildFailed(String)
    case invalidRequest(String)
}

/// A device-neutral account import product: the account-level extended public key exported by a
/// hardware wallet (CIP-1852 node `m/1852'/1815'/account'`), from which the wallet derives receive /
/// change / stake addresses **with no private key**. This is what the device's account-export QR (or
/// BLE/USB account read) is decoded into, regardless of vendor.
public struct HardwareAccountModel: Sendable, Codable, Hashable {
    public let deviceKind: HardwareDeviceKind
    /// Account extended public key: 32-byte Ed25519 public key ‖ 32-byte chain code (64 bytes).
    public let accountXPub: Data
    /// The device's master-key fingerprint (BIP-32 `xfp`), 4 bytes — echoed back in sign requests so
    /// the device recognizes its own keys.
    public let masterFingerprint: Data
    /// The account node's derivation path, e.g. `m/1852'/1815'/0'`.
    public let accountPath: String
    public let network: NetworkId

    public init(
        deviceKind: HardwareDeviceKind,
        accountXPub: Data,
        masterFingerprint: Data,
        accountPath: String,
        network: NetworkId
    ) {
        self.deviceKind = deviceKind
        self.accountXPub = accountXPub
        self.masterFingerprint = masterFingerprint
        self.accountPath = accountPath
        self.network = network
    }

    public var accountXPubHex: String { accountXPub.toHex }
    public var masterFingerprintHex: String { masterFingerprint.toHex }
}
