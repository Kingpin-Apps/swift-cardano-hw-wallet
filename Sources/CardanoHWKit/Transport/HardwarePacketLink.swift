import Foundation

/// A duplex, packet-oriented physical link to a hardware device — the raw byte pipe under a
/// framed device protocol.
///
/// This is the seam for **raw-packet transports** (USB-HID: fixed-size reports; a device module
/// layers its own framing on top). It is deliberately dumb: one `write` sends one transport packet
/// (e.g. a 64-byte HID report), one `read` returns one inbound packet. Reassembly and framing live
/// in the device module (e.g. `TrezorProtocolV1`), so this protocol stays trivially mockable.
///
/// Ledger BLE does **not** use this — it goes through the official `BleTransport` SDK, which owns
/// its own framing and exposes full-APDU exchange. So this seam is used by the IOKit-HID transports
/// (Trezor, and Ledger-over-USB).
public protocol HardwarePacketLink: AnyObject, Sendable {
    /// Open the link (enumerate/claim the device, start the read loop). Idempotent.
    func open() async throws
    /// Send exactly one transport packet.
    func write(_ packet: Data) async throws
    /// Receive exactly one inbound transport packet (awaits until one arrives).
    func read() async throws -> Data
    /// Release the device and stop the read loop.
    func close() async
}
