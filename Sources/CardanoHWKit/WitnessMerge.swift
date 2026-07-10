import Foundation
import SwiftCardanoCore

/// Merges a hardware wallet's returned witnesses into an unsigned transaction — no private key.
///
/// A Cardano hardware device signs off-device and returns a whole `TransactionWitnessSet` (CBOR).
/// We decode it and overwrite the unsigned transaction's `vkeyWitnesses`, preserving any native
/// scripts already in the unsigned witness set, then rebuild the `Transaction`. This mirrors the
/// SDK's own `PreparedHardwareTransaction.finalise` assembly, but takes a device-returned set
/// instead of file witnesses.
public enum WitnessMerge {

    /// Merge a device-returned witness-set (CBOR hex) into `unsigned`, returning a signed
    /// `Transaction`. Only `vkeyWitnesses` are taken from the device set; native scripts / other
    /// fields already on the unsigned transaction are preserved.
    public static func merge(unsigned: Transaction, witnessSetHex: String) throws -> Transaction {
        let deviceSet: TransactionWitnessSet
        do {
            deviceSet = try TransactionWitnessSet.fromCBORHex(witnessSetHex)
        } catch {
            throw HardwareWalletError.witnessDecodeFailed("Could not decode the device witness set CBOR: \(error)")
        }
        guard deviceSet.vkeyWitnesses != nil else {
            throw HardwareWalletError.witnessDecodeFailed("Device witness set carried no vkey witnesses.")
        }

        var merged = unsigned.transactionWitnessSet
        merged.vkeyWitnesses = deviceSet.vkeyWitnesses

        return Transaction(
            transactionBody: unsigned.transactionBody,
            transactionWitnessSet: merged,
            valid: unsigned.valid,
            auxiliaryData: unsigned.auxiliaryData
        )
    }

    /// Merge and return the signed transaction's CBOR hex — ready to hand to any submit path (e.g.
    /// the app's existing `submitTransactionCBOR`).
    public static func mergedCBORHex(unsigned: Transaction, witnessSetHex: String) throws -> String {
        let signed = try merge(unsigned: unsigned, witnessSetHex: witnessSetHex)
        do {
            return try signed.toCBORHex()
        } catch {
            throw HardwareWalletError.witnessDecodeFailed("Could not re-encode the merged transaction: \(error)")
        }
    }
}
