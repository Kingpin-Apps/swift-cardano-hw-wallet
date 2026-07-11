// Keystone support is iOS-only: its URRegistryFFI XCFramework ships no macOS slice.
#if canImport(KeystoneSDK)
import Foundation
import SwiftCardanoCore
import CardanoHWKit
import KeystoneSDK
import URKit

/// Pure mapping: a device-neutral ``HardwareSignRequest`` → Keystone's `CardanoSignRequest` and its
/// animated-QR `UREncoder`. No camera, no state — unit-testable against fixtures.
public enum KeystoneSignRequestCodec {

    /// Map a ``HardwareSignRequest`` into Keystone's `CardanoSignRequest`. Each spent UTxO becomes a
    /// Keystone `Utxo` carrying the input's derivation path (so the device knows which key to sign
    /// with) and the wallet's master fingerprint. `certKeys` is empty for plain payment sends.
    public static func cardanoSignRequest(from request: HardwareSignRequest) throws -> CardanoSignRequest {
        let signData = try request.signDataHex()
        let xfp = request.masterFingerprint.toHex

        let utxos: [CardanoSignRequest.Utxo] = try request.spentUTxOs.map { utxo in
            let address = try addressBech32(utxo)
            guard let path = request.addressPaths[address] else {
                throw HardwareWalletError.invalidRequest("No derivation path for input address \(address).")
            }
            return CardanoSignRequest.Utxo(
                transactionHash: utxo.input.transactionId.payload.toHex,
                index: UInt32(utxo.input.index),
                amount: String(utxo.output.amount.coin),
                xfp: xfp,
                hdPath: path,
                address: address
            )
        }

        return CardanoSignRequest(
            requestId: request.requestId,
            signData: signData,
            utxos: utxos,
            certKeys: [],
            origin: request.origin
        )
    }

    /// The `UREncoder` (animated-QR frame source) for a sign request. Drive it with `nextPart()`.
    public static func encoder(for request: HardwareSignRequest) throws -> UREncoder {
        let signRequest = try cardanoSignRequest(from: request)
        do {
            return try KeystoneSDK().cardano.generateSignRequest(cardanoSignRequest: signRequest)
        } catch {
            throw HardwareWalletError.invalidRequest("Keystone rejected the sign request: \(error)")
        }
    }

    private static func addressBech32(_ utxo: UTxO) throws -> String {
        do {
            return try utxo.output.address.toBech32()
        } catch {
            throw HardwareWalletError.invalidRequest("A spent UTxO has an unencodable address: \(error)")
        }
    }
}
#endif
