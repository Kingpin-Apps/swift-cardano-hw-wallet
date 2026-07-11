import Foundation
// BleTransport predates Swift-6 concurrency annotations (its `.shared` singleton and protocol aren't
// Sendable-annotated); `@preconcurrency` downgrades those to warnings. The SDK is internally
// thread-safe, so `BleLedgerTransport` is `@unchecked Sendable`.
@preconcurrency import BleTransport

/// A ``LedgerTransport`` over Bluetooth, wrapping Ledger's official `BleTransport` SDK. The SDK owns
/// the `0x05`-tag BLE framing and MTU handling; we hand it whole APDUs and it returns the full
/// response hex (payload ‖ 2-byte status word). We check the status word and return just the payload.
///
/// Available on iOS **and** macOS (the SDK supports both). Connection/scanning is driven by the app
/// via ``LedgerBLE``; this type assumes an established connection.
public final class BleLedgerTransport: LedgerTransport {
    public init() {}

    public func exchange(_ apdu: Data) async throws -> Data {
        let responseHex: String
        do {
            responseHex = try await BleTransport.shared.exchange(apdu: APDU(data: Array(apdu)))
        } catch {
            throw LedgerError.transport("BLE exchange failed: \(error)")
        }
        return try Self.payloadCheckingStatus(responseHex)
    }

    /// Decode a full Ledger response hex string and return the payload (status word verified/stripped).
    static func payloadCheckingStatus(_ hex: String) throws -> Data {
        guard let response = Data(ledgerHex: hex) else {
            throw LedgerError.malformedResponse("Non-hex Ledger response: \(hex)")
        }
        return try LedgerStatus.payload(response)
    }
}

/// Bluetooth connection helpers for Ledger devices, exposed for the app's connect UI. Thin wrappers
/// over the SDK singleton so the app doesn't import `BleTransport` directly.
public enum LedgerBLE {
    /// Live Bluetooth availability.
    public static var isBluetoothAvailable: Bool { BleTransport.shared.isBluetoothAvailable }

    /// Scan for nearby Ledger devices for `duration` seconds, reporting the discovered set on each
    /// change, and a final completion (with an optional error).
    public static func scan(
        duration: TimeInterval = 5,
        onUpdate: @escaping ([PeripheralIdentifier]) -> Void,
        onStopped: @escaping (BleTransportError?) -> Void
    ) {
        BleTransport.shared.scan(
            duration: duration,
            callback: { infos in onUpdate(infos.map { $0.peripheral }) },
            stopped: { onStopped($0) }
        )
    }

    /// Scan and connect to the first discovered Ledger, returning a ready transport.
    public static func connectFirst(scanDuration: TimeInterval = 5) async throws -> BleLedgerTransport {
        _ = try await BleTransport.shared.create(scanDuration: scanDuration, disconnectedCallback: nil)
        return BleLedgerTransport()
    }

    /// Connect to a specific discovered peripheral, returning a ready transport.
    public static func connect(to peripheral: PeripheralIdentifier) async throws -> BleLedgerTransport {
        _ = try await BleTransport.shared.connect(toPeripheralID: peripheral, disconnectedCallback: nil)
        return BleLedgerTransport()
    }

    /// Ask the device to open the Cardano app (no-op if already open).
    public static func openCardanoApp() async throws {
        try await BleTransport.shared.openAppIfNeeded("Cardano")
    }

    public static func disconnect() async throws {
        try await BleTransport.shared.disconnect()
    }
}

extension Data {
    /// Decode an even-length hex string (no `0x`) into bytes; nil on malformed input.
    init?(ledgerHex hex: String) {
        let chars = Array(hex)
        guard chars.count % 2 == 0 else { return nil }
        var bytes = [UInt8](); bytes.reserveCapacity(chars.count / 2)
        var i = 0
        while i < chars.count {
            guard let hi = chars[i].hexDigitValue, let lo = chars[i + 1].hexDigitValue else { return nil }
            bytes.append(UInt8(hi << 4 | lo)); i += 2
        }
        self = Data(bytes)
    }
}
