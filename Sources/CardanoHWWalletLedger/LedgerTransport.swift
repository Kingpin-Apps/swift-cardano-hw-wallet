import Foundation

/// A Ledger APDU pipe: send one full APDU, get one full APDU response back. The transport hides all
/// physical framing/chunking, so the Cardano protocol layer deals only in whole APDUs.
///
/// Two implementations:
/// - `BleLedgerTransport` — wraps the official `BleTransport` SDK (`exchange(apdu:)`), which owns the
///   `0x05`-tag BLE chunking. iOS + macOS.
/// - `HidLedgerTransport` — IOKit-HID over USB with `LedgerFraming` (the same tag protocol plus a
///   2-byte channel), macOS only.
///
/// The response `Data` is the raw APDU **payload without the trailing status word** — the transport
/// checks the SW (0x9000 == OK) and throws `LedgerError.status` otherwise, so callers see only data.
public protocol LedgerTransport: Sendable {
    /// Send an APDU (`CLA INS P1 P2 Lc data…`) and await the response payload (status word stripped).
    func exchange(_ apdu: Data) async throws -> Data
}

/// Errors surfaced by the Ledger device / transport layer.
public enum LedgerError: Error, Sendable, Equatable {
    /// The device returned a non-`0x9000` status word.
    case status(UInt16)
    /// The response was too short to contain a status word, or otherwise malformed.
    case malformedResponse(String)
    /// Transport-level failure (BLE/USB not connected, write/read failed, disconnected).
    case transport(String)
    /// The Cardano app wasn't open / a required app operation failed.
    case app(String)
}
