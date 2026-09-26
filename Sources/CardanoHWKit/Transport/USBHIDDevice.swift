#if os(macOS)
import Foundation
import IOKit
import IOKit.hid

/// A thin async wrapper over an IOKit USB-HID device: matches by vendor id, opens the first device,
/// and exposes fixed-size report read/write. Device modules (Ledger USB, Trezor) layer their own
/// framing on top. **macOS-only** and **device-gated** — validated on hardware, not in unit tests.
///
/// The input-report callback must fire on a run loop, so the instance schedules itself on a dedicated
/// background thread running a `CFRunLoop`.
public final class USBHIDDevice: @unchecked Sendable {
    private let vendorID: Int
    private let usagePage: Int?
    private let reportSize: Int

    private var manager: IOHIDManager?
    private var device: IOHIDDevice?
    private var inputBuffer: UnsafeMutablePointer<UInt8>?
    private var runLoop: CFRunLoop?
    private var readerThread: Thread?

    private let lock = NSLock()
    private var queued: [Data] = []
    private var waiters: [CheckedContinuation<Data, Error>] = []
    private var failure: Error?

    /// - Parameters:
    ///   - vendorID: The USB vendor id to match.
    ///   - usagePage: The HID usage page of the interface to open. A device
    ///     can expose several HID interfaces — a Ledger has its APDU interface
    ///     (`0xFFA0`) beside a FIDO one (`0xF1D0`) — and matching the vendor
    ///     alone opens whichever the system lists first.
    ///   - reportSize: The size of one HID report.
    public init(vendorID: Int, usagePage: Int? = nil, reportSize: Int = 64) {
        self.vendorID = vendorID
        self.usagePage = usagePage
        self.reportSize = reportSize
    }

    // MARK: - Lifecycle

    public func open() throws {
        lock.lock(); defer { lock.unlock() }
        guard device == nil else { return }

        let manager = IOHIDManagerCreate(kCFAllocatorDefault, IOOptionBits(kIOHIDOptionsTypeNone))
        var match: [String: Any] = [kIOHIDVendorIDKey: vendorID]
        if let usagePage { match[kIOHIDPrimaryUsagePageKey] = usagePage }
        IOHIDManagerSetDeviceMatching(manager, match as CFDictionary)
        guard IOHIDManagerOpen(manager, IOOptionBits(kIOHIDOptionsTypeNone)) == kIOReturnSuccess else {
            throw HardwareWalletError.derivationFailed("Could not open the USB-HID manager (permission / entitlement?).")
        }
        guard let devices = IOHIDManagerCopyDevices(manager) as? Set<IOHIDDevice>, let first = devices.first else {
            IOHIDManagerClose(manager, IOOptionBits(kIOHIDOptionsTypeNone))
            let page = usagePage.map { ", usage page 0x\(String($0, radix: 16))" } ?? ""
            throw HardwareWalletError.derivationFailed("No USB-HID device found for vendor 0x\(String(vendorID, radix: 16))\(page).")
        }

        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: reportSize)
        let context = Unmanaged.passUnretained(self).toOpaque()
        IOHIDDeviceRegisterInputReportCallback(first, buffer, reportSize, USBHIDDevice.inputCallback, context)

        self.manager = manager
        self.device = first
        self.inputBuffer = buffer
        startReaderThread(device: first)
    }

    public func close() {
        lock.lock()
        let dev = device; let mgr = manager; let buf = inputBuffer; let rl = runLoop
        device = nil; manager = nil; inputBuffer = nil; runLoop = nil
        for waiter in waiters { waiter.resume(throwing: HardwareWalletError.derivationFailed("USB device closed.")) }
        waiters.removeAll()
        lock.unlock()

        if let rl { CFRunLoopStop(rl) }
        if let dev { IOHIDDeviceClose(dev, IOOptionBits(kIOHIDOptionsTypeNone)) }
        if let mgr { IOHIDManagerClose(mgr, IOOptionBits(kIOHIDOptionsTypeNone)) }
        buf?.deallocate()
    }

    // MARK: - I/O

    /// Write one output report (zero-padded to `reportSize`).
    public func write(_ packet: Data) throws {
        lock.lock(); let dev = device; lock.unlock()
        guard let dev else { throw HardwareWalletError.derivationFailed("USB device is not open.") }
        var report = Array(packet.prefix(reportSize))
        if report.count < reportSize { report.append(contentsOf: repeatElement(0, count: reportSize - report.count)) }
        let result = report.withUnsafeBufferPointer { ptr in
            IOHIDDeviceSetReport(dev, kIOHIDReportTypeOutput, 0, ptr.baseAddress!, ptr.count)
        }
        guard result == kIOReturnSuccess else {
            throw HardwareWalletError.derivationFailed("USB write failed (IOReturn 0x\(String(UInt32(bitPattern: result), radix: 16))).")
        }
    }

    /// Await one input report.
    public func read() async throws -> Data {
        try await withCheckedThrowingContinuation { continuation in
            lock.lock(); defer { lock.unlock() }
            if let failure { continuation.resume(throwing: failure); return }
            if !queued.isEmpty { continuation.resume(returning: queued.removeFirst()); return }
            waiters.append(continuation)
        }
    }

    // MARK: - Internals

    private func startReaderThread(device: IOHIDDevice) {
        let thread = Thread { [weak self] in
            guard let self else { return }
            self.lock.lock(); self.runLoop = CFRunLoopGetCurrent(); self.lock.unlock()
            IOHIDDeviceScheduleWithRunLoop(device, CFRunLoopGetCurrent(), CFRunLoopMode.defaultMode.rawValue)
            CFRunLoopRun()
        }
        thread.name = "CardanoHWKit.USBHIDDevice"
        thread.start()
        readerThread = thread
    }

    fileprivate func deliver(_ report: Data) {
        lock.lock(); defer { lock.unlock() }
        if !waiters.isEmpty {
            waiters.removeFirst().resume(returning: report)
        } else {
            queued.append(report)
        }
    }

    private static let inputCallback: IOHIDReportCallback = { context, _, _, _, _, report, reportLength in
        guard let context else { return }
        let device = Unmanaged<USBHIDDevice>.fromOpaque(context).takeUnretainedValue()
        device.deliver(Data(bytes: report, count: reportLength))
    }
}
#endif
