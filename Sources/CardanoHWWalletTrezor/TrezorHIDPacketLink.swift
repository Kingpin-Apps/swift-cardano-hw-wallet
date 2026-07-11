#if os(macOS)
import Foundation
import CardanoHWKit

/// A ``HardwarePacketLink`` over USB-HID (macOS) for Trezor devices, delivering the 64-byte reports
/// ``TrezorProtocolV1`` frames. **macOS-only, device-gated.**
///
/// Note: this uses the HID interface, which covers **Trezor One** (HID-class). **Trezor Model T / Safe**
/// expose a WebUSB/vendor interface rather than HID, so they need an `IOUSBHost` transport — a
/// documented follow-up. The framing/protocol layer above is identical regardless of transport.
public final class TrezorHIDPacketLink: HardwarePacketLink, @unchecked Sendable {
    /// Trezor One USB vendor id (`0x534C`).
    public static let trezorVendorID = 0x534C

    private let device: USBHIDDevice

    public init(vendorID: Int = TrezorHIDPacketLink.trezorVendorID) {
        self.device = USBHIDDevice(vendorID: vendorID, reportSize: TrezorProtocolV1.reportSize)
    }

    public func open() async throws { try device.open() }
    public func write(_ packet: Data) async throws { try device.write(packet) }
    public func read() async throws -> Data { try await device.read() }
    public func close() async { device.close() }
}
#endif
