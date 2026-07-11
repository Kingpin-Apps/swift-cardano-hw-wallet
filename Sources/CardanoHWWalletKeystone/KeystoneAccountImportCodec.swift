// Keystone support is iOS-only: its URRegistryFFI XCFramework ships no macOS slice.
#if canImport(KeystoneSDK)
import Foundation
import SwiftCardanoCore
import CardanoHWKit
import KeystoneSDK
import URKit

/// Parse a Keystone **account-export** `UR` (a `crypto-multi-accounts` payload) into a device-neutral
/// ``HardwareAccountModel``. The device shows this QR once when the user adds the wallet.
public enum KeystoneAccountImportCodec {

    /// Extract the Cardano account (xpub + chain code + master fingerprint + path) from a scanned
    /// multi-accounts export. Throws if the export carries no Cardano key.
    public static func account(from ur: UR, network: NetworkId) throws -> HardwareAccountModel {
        let multi: MultiAccounts
        do {
            multi = try KeystoneSDK().parseMultiAccounts(ur: ur)
        } catch {
            throw HardwareWalletError.invalidAccountKey("Could not parse the Keystone account export: \(error)")
        }

        guard let ada = multi.keys.first(where: { isCardano($0.chain) }) else {
            throw HardwareWalletError.invalidAccountKey("The scanned export has no Cardano (ADA) account. On the Keystone, export the Cardano account.")
        }

        guard let publicKey = Data(hexString: ada.publicKey), publicKey.count == 32 else {
            throw HardwareWalletError.invalidAccountKey("Cardano account public key is not a 32-byte hex value.")
        }
        guard let chainCode = Data(hexString: ada.chainCode), chainCode.count == 32 else {
            throw HardwareWalletError.invalidAccountKey("Cardano account chain code is not a 32-byte hex value.")
        }
        guard let fingerprint = Data(hexString: multi.masterFingerprint), !fingerprint.isEmpty else {
            throw HardwareWalletError.invalidAccountKey("Account export is missing a master fingerprint.")
        }

        return HardwareAccountModel(
            deviceKind: .keystone,
            accountXPub: publicKey + chainCode,
            masterFingerprint: fingerprint,
            accountPath: normalizedPath(ada.path),
            network: network
        )
    }

    private static func isCardano(_ chain: String) -> Bool {
        let c = chain.uppercased()
        return c == "ADA" || c == "CARDANO"
    }

    /// Keystone paths may come with or without the leading `m/`; store the canonical `m/…` form the
    /// derivation engine expects.
    private static func normalizedPath(_ path: String) -> String {
        path.hasPrefix("m/") || path.hasPrefix("M/") ? path : "m/" + path
    }
}
#endif
