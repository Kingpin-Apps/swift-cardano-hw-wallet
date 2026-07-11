import Foundation
import SwiftCardanoCore

/// A device-neutral signing request: everything a hardware wallet needs to sign a transaction,
/// independent of vendor transport. A per-device codec (e.g. Keystone) maps this into that device's
/// wire format (UR / APDU / protobuf).
public struct HardwareSignRequest: Sendable {
    /// A unique id echoed back in the device's response so we can match request↔signature.
    public let requestId: String
    /// The unsigned transaction to sign.
    public let unsigned: Transaction
    /// The UTxOs the transaction spends (resolved to full outputs), in input order.
    public let spentUTxOs: [UTxO]
    /// bech32 address → CIP-1852 derivation path, covering every address that holds a spent UTxO.
    public let addressPaths: [String: String]
    /// The device's master-key fingerprint (`xfp`), so it recognizes its own keys.
    public let masterFingerprint: Data
    /// A short label for the requesting app (shown on the device), e.g. "MansAmana".
    public let origin: String
    /// Staking / governance certificates in the transaction (device-neutral). Empty for a plain send.
    public let certificates: [HardwareCertificate]
    /// Rewards withdrawals in the transaction (device-neutral). Empty for a plain send.
    public let withdrawals: [HardwareWithdrawal]

    public init(
        requestId: String,
        unsigned: Transaction,
        spentUTxOs: [UTxO],
        addressPaths: [String: String],
        masterFingerprint: Data,
        origin: String,
        certificates: [HardwareCertificate] = [],
        withdrawals: [HardwareWithdrawal] = []
    ) {
        self.requestId = requestId
        self.unsigned = unsigned
        self.spentUTxOs = spentUTxOs
        self.addressPaths = addressPaths
        self.masterFingerprint = masterFingerprint
        self.origin = origin
        self.certificates = certificates
        self.withdrawals = withdrawals
    }

    /// The unsigned transaction as CBOR hex — the payload a device signs over.
    public func signDataHex() throws -> String {
        do {
            return try unsigned.toCBORHex()
        } catch {
            throw HardwareWalletError.invalidRequest("Could not encode the unsigned transaction: \(error)")
        }
    }
}
