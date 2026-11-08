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
    /// Signalled by the reader thread once it has scheduled the device and published its run loop.
    private var readerReady: DispatchSemaphore?
    /// Signalled by the reader thread after its run loop has stopped and the device is unscheduled.
    private var readerStopped: DispatchSemaphore?
    private let locationID: Int?

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
    ///   - locationID: The `kIOHIDLocationIDKey` of the device to open, from ``connectedDevices(vendorID:usagePage:)``.
    ///     When `nil` and more than one device matches, ``open()`` throws rather than guessing.
    public init(vendorID: Int, usagePage: Int? = nil, reportSize: Int = 64, locationID: Int? = nil) {
        self.vendorID = vendorID
        self.usagePage = usagePage
        self.reportSize = reportSize
        self.locationID = locationID
    }

    /// A matching HID device the app can show the user before opening it.
    public struct DeviceInfo: Sendable, Hashable {
        public let locationID: Int
        public let productName: String?
        public let serialNumber: String?
    }

    /// Lists the currently attached devices matching `vendorID` (and `usagePage`), so the app can let
    /// the user pick one and pass its `locationID` to ``init(vendorID:usagePage:reportSize:locationID:)``.
    public static func connectedDevices(vendorID: Int, usagePage: Int? = nil) -> [DeviceInfo] {
        let manager = IOHIDManagerCreate(kCFAllocatorDefault, IOOptionBits(kIOHIDOptionsTypeNone))
        IOHIDManagerSetDeviceMatching(manager, matching(vendorID: vendorID, usagePage: usagePage))
        defer { IOHIDManagerClose(manager, IOOptionBits(kIOHIDOptionsTypeNone)) }
        guard IOHIDManagerOpen(manager, IOOptionBits(kIOHIDOptionsTypeNone)) == kIOReturnSuccess,
              let devices = IOHIDManagerCopyDevices(manager) as? Set<IOHIDDevice> else { return [] }
        return devices.compactMap { info(for: $0) }.sorted { $0.locationID < $1.locationID }
    }

    private static func matching(vendorID: Int, usagePage: Int?) -> CFDictionary {
        var match: [String: Any] = [kIOHIDVendorIDKey: vendorID]
        if let usagePage { match[kIOHIDPrimaryUsagePageKey] = usagePage }
        return match as CFDictionary
    }

    private static func info(for device: IOHIDDevice) -> DeviceInfo? {
        guard let location = IOHIDDeviceGetProperty(device, kIOHIDLocationIDKey as CFString) as? Int else { return nil }
        return DeviceInfo(
            locationID: location,
            productName: IOHIDDeviceGetProperty(device, kIOHIDProductKey as CFString) as? String,
            serialNumber: IOHIDDeviceGetProperty(device, kIOHIDSerialNumberKey as CFString) as? String
        )
    }

    // MARK: - Lifecycle

    public func open() throws {
        lock.lock(); defer { lock.unlock() }
        guard device == nil else { return }

        let manager = IOHIDManagerCreate(kCFAllocatorDefault, IOOptionBits(kIOHIDOptionsTypeNone))
        IOHIDManagerSetDeviceMatching(manager, Self.matching(vendorID: vendorID, usagePage: usagePage))
        guard IOHIDManagerOpen(manager, IOOptionBits(kIOHIDOptionsTypeNone)) == kIOReturnSuccess else {
            throw HardwareWalletError.derivationFailed("Could not open the USB-HID manager (permission / entitlement?).")
        }
        let all = (IOHIDManagerCopyDevices(manager) as? Set<IOHIDDevice>) ?? []
        let candidates = locationID.map { wanted in all.filter { Self.info(for: $0)?.locationID == wanted } } ?? Array(all)
        guard let first = candidates.first else {
            IOHIDManagerClose(manager, IOOptionBits(kIOHIDOptionsTypeNone))
            let page = usagePage.map { ", usage page 0x\(String($0, radix: 16))" } ?? ""
            throw HardwareWalletError.derivationFailed("No USB-HID device found for vendor 0x\(String(vendorID, radix: 16))\(page).")
        }
        // Never guess between devices: an attacker-attached second device could otherwise be picked.
        guard candidates.count == 1 else {
            IOHIDManagerClose(manager, IOOptionBits(kIOHIDOptionsTypeNone))
            throw HardwareWalletError.derivationFailed(
                "\(candidates.count) matching USB-HID devices are attached; choose one with connectedDevices(vendorID:usagePage:) and pass its locationID."
            )
        }

        let buffer = UnsafeMutablePointer<UInt8>.allocate(capacity: reportSize)
        let context = Unmanaged.passUnretained(self).toOpaque()
        IOHIDDeviceRegisterInputReportCallback(first, buffer, reportSize, USBHIDDevice.inputCallback, context)

        self.manager = manager
        self.device = first
        self.inputBuffer = buffer
        self.failure = nil
        queued.removeAll()
        startReaderThread(device: first, buffer: buffer)
    }

    /// Stops the reader, then closes the device and frees the report buffer. The buffer is freed only
    /// after the reader thread has stopped its run loop and unregistered the input callback, so IOKit
    /// can no longer write into it.
    public func close() {
        lock.lock()
        let dev = device; let mgr = manager; let buf = inputBuffer; let rl = runLoop
        let stopped = readerStopped; let thread = readerThread
        device = nil; manager = nil; inputBuffer = nil; runLoop = nil
        readerStopped = nil; readerThread = nil; readerReady = nil
        for waiter in waiters { waiter.resume(throwing: HardwareWalletError.derivationFailed("USB device closed.")) }
        waiters.removeAll()
        queued.removeAll()
        lock.unlock()

        if let rl {
            CFRunLoopPerformBlock(rl, CFRunLoopMode.defaultMode.rawValue) { CFRunLoopStop(CFRunLoopGetCurrent()) }
            CFRunLoopWakeUp(rl)
        }
        // Wait for the reader to finish, unless close() was called from the reader thread itself.
        if let stopped, let thread, thread !== Thread.current { stopped.wait() }
        if let dev { IOHIDDeviceClose(dev, IOOptionBits(kIOHIDOptionsTypeNone)) }
        if let mgr { IOHIDManagerClose(mgr, IOOptionBits(kIOHIDOptionsTypeNone)) }
        if thread == nil || thread !== Thread.current { buf?.deallocate() }
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
            guard device != nil else {
                continuation.resume(throwing: HardwareWalletError.derivationFailed("USB device is not open."))
                return
            }
            if !queued.isEmpty { continuation.resume(returning: queued.removeFirst()); return }
            waiters.append(continuation)
        }
    }

    // MARK: - Internals

    /// Called with `lock` held. Returns once the reader has scheduled the device on its run loop, so a
    /// following ``close()`` always finds the run loop to stop.
    private func startReaderThread(device: IOHIDDevice, buffer: UnsafeMutablePointer<UInt8>) {
        let ready = DispatchSemaphore(value: 0)
        let stopped = DispatchSemaphore(value: 0)
        let reportSize = self.reportSize
        let thread = Thread { [self] in
            let loop: CFRunLoop = CFRunLoopGetCurrent()!
            self.lock.lock(); self.runLoop = loop; self.lock.unlock()
            IOHIDDeviceScheduleWithRunLoop(device, loop, CFRunLoopMode.defaultMode.rawValue)
            ready.signal()
            CFRunLoopRun()
            // The run loop has stopped: no more callbacks can be dispatched on this thread. Detach the
            // callback and the run loop before close() frees the buffer.
            IOHIDDeviceRegisterInputReportCallback(device, buffer, reportSize, nil, nil)
            IOHIDDeviceUnscheduleFromRunLoop(device, loop, CFRunLoopMode.defaultMode.rawValue)
            stopped.signal()
        }
        thread.name = "CardanoHWKit.USBHIDDevice"
        readerReady = ready
        readerStopped = stopped
        readerThread = thread
        thread.start()
        // The reader takes `lock` to publish its run loop, so release it while waiting.
        lock.unlock()
        ready.wait()
        lock.lock()
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
