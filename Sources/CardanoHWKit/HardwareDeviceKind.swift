import Foundation

/// A supported Cardano hardware-wallet family. Transport differs per device — Keystone is air-gapped
/// (animated QR), Ledger uses BLE / USB-HID, Trezor uses USB — but all sign off-device and return a
/// witness the wallet injects without ever holding a private key.
public enum HardwareDeviceKind: String, Sendable, Codable, CaseIterable, Hashable {
    case keystone
    case ledger
    case trezor

    /// Human-facing device name.
    public var displayName: String {
        switch self {
        case .keystone: return "Keystone"
        case .ledger: return "Ledger"
        case .trezor: return "Trezor"
        }
    }
}
