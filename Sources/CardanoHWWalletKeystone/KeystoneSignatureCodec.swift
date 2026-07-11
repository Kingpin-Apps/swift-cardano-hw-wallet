// Keystone support is iOS-only: its URRegistryFFI XCFramework ships no macOS slice.
#if canImport(KeystoneSDK)
import Foundation
import CardanoHWKit
import KeystoneSDK
import URKit

/// Pure mapping: a completed Keystone signature `UR` → the witness-set CBOR hex that
/// ``WitnessMerge`` injects. No camera/state (multipart accumulation lives in the session).
public enum KeystoneSignatureCodec {

    /// Parse a scanned signature `UR` into the device-returned witness-set CBOR hex. When
    /// `expectedRequestId` is given, verifies the device answered *this* request.
    public static func witnessSetHex(from ur: UR, expectedRequestId: String? = nil) throws -> String {
        let signature: CardanoSignature
        do {
            signature = try KeystoneSDK().cardano.parseSignature(ur: ur)
        } catch {
            throw HardwareWalletError.witnessDecodeFailed("Could not parse the Keystone signature UR: \(error)")
        }
        if let expectedRequestId, signature.requestId != expectedRequestId {
            throw HardwareWalletError.invalidRequest("Scanned a signature for a different request (expected \(expectedRequestId), got \(signature.requestId)).")
        }
        guard !signature.witnessSet.isEmpty else {
            throw HardwareWalletError.witnessDecodeFailed("Keystone returned an empty witness set.")
        }
        return signature.witnessSet
    }
}
#endif
