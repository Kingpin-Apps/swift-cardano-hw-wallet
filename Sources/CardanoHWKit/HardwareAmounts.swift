import BigInt
import Foundation
import SwiftCardanoCore

/// An output's amounts as a hardware wallet takes them: each a ledger `Word64`.
public enum HardwareAmounts {
    /// An output's lovelace.
    /// - Throws: ``HardwareWalletError/invalidRequest(_:)`` when it does not fit a `UInt64`.
    public static func lovelace(_ value: Value) throws -> UInt64 {
        try word64(value.coin, "Output lovelace")
    }

    /// An output's tokens grouped by policy, in canonical CBOR order — shorter keys
    /// first, then by bytes — so the CBOR the device rebuilds matches a canonical encoder.
    /// - Throws: ``HardwareWalletError/invalidRequest(_:)`` when a quantity does not fit
    ///   a `UInt64`.
    public static func canonicalGroups(
        _ multiAsset: MultiAsset
    ) throws -> [(policyId: Data, tokens: [(name: Data, amount: UInt64)])] {
        try multiAsset.data
            .map { policy, asset in
                let tokens = try asset.data
                    .map { name, amount in (name: name.payload, amount: try word64(amount, "Token quantity")) }
                    .sorted { canonicalLess($0.name, $1.name) }
                return (policyId: policy.payload, tokens: tokens)
            }
            .sorted { canonicalLess($0.policyId, $1.policyId) }
    }

    private static func word64(_ value: BigInt, _ what: String) throws -> UInt64 {
        guard let result = UInt64(exactly: value) else {
            throw HardwareWalletError.invalidRequest("\(what) \(value) is not a ledger Word64")
        }
        return result
    }

    private static func canonicalLess(_ a: Data, _ b: Data) -> Bool {
        a.count != b.count ? a.count < b.count : a.lexicographicallyPrecedes(b)
    }
}
