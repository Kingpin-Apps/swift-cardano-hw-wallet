#if os(macOS)
import Foundation
import CardanoHWKit

/// A ``LedgerTransport`` over USB-HID (macOS), for USB-only Ledgers (e.g. Nano S Plus) or as a wired
/// alternative to BLE. Uses ``LedgerFraming`` (`0x05`-tag chunking with the 2-byte USB channel) over
/// an ``USBHIDDevice``. **macOS-only, device-gated** — validated on hardware.
public final class HidLedgerTransport: LedgerTransport, @unchecked Sendable {
    /// Ledger USB vendor id.
    public static let ledgerVendorID = 0x2C97

    private let device: USBHIDDevice
    private let channel: UInt16

    public init(channel: UInt16 = LedgerFraming.usbChannel) {
        self.device = USBHIDDevice(vendorID: Self.ledgerVendorID, reportSize: LedgerFraming.usbPacketSize)
        self.channel = channel
    }

    public func open() throws { try device.open() }
    public func close() { device.close() }

    public func exchange(_ apdu: Data) async throws -> Data {
        try device.open()
        for packet in LedgerFraming.frame(message: apdu, channel: channel, packetSize: LedgerFraming.usbPacketSize) {
            try device.write(packet)
        }
        var reassembler = LedgerFraming.Reassembler(channelIncluded: true)
        while true {
            let report = try await device.read()
            if let full = try reassembler.push(report) {
                return try LedgerStatus.payload(full)
            }
        }
    }
}
#endif
