// Keystone support is iOS-only: its URRegistryFFI XCFramework ships no macOS slice.
#if canImport(KeystoneSDK)
import Foundation
import SwiftCardanoCore
import CardanoHWKit
import KeystoneSDK

/// Accumulates a scanned Keystone **account-export** animated QR (multi-part `crypto-multi-accounts`
/// UR) and yields a device-neutral ``HardwareAccountModel`` once complete. `@MainActor` — owns a
/// non-`Sendable` UR decoder; hides `UR` / `KeystoneSDK` from the app UI.
@MainActor
public final class KeystoneAccountImportSession {
    private let sdk = KeystoneSDK()
    private let network: NetworkId
    public private(set) var progress: Int = 0

    public init(network: NetworkId) {
        self.network = network
    }

    /// Feed a scanned QR frame. Returns `nil` while more frames are needed, or the imported account
    /// once the multi-part export is whole.
    public func ingest(scanned: String) throws -> HardwareAccountModel? {
        let result: DecodeResult
        do {
            result = try sdk.decodeQR(qrCode: scanned)
        } catch {
            throw HardwareWalletError.invalidAccountKey("Could not decode the scanned QR: \(error)")
        }
        progress = result.progress
        guard let ur = result.ur else { return nil }
        return try KeystoneAccountImportCodec.account(from: ur, network: network)
    }

    /// Discard a partial scan (e.g. the user re-aims the camera).
    public func reset() {
        sdk.resetQRDecoder()
        progress = 0
    }
}
#endif
