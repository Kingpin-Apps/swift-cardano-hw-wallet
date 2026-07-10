import Foundation

/// The outcome of feeding a scanned response frame into a signing session.
public enum SignIngestResult: Sendable, Equatable {
    /// The response is multi-part; more frames are needed.
    case needMore
    /// The response is complete; carries the device-returned witness set as CBOR hex, ready for
    /// ``WitnessMerge``.
    case complete(witnessSetHex: String)
}

/// The transport seam a per-device module implements and the **app drives**. It's an interactive
/// loop, not a one-shot call, because real transports are stateful and UI-coupled:
///
/// - **Keystone (QR):** `nextFrame()` yields the next animated-QR payload to display; the app scans
///   the device's reply and feeds each part to `ingest(scanned:)` until `.complete`.
/// - **Ledger/Trezor (BLE/USB, later):** the same seam wraps a byte stream — `nextFrame`/`ingest`
///   become send/receive over the transport.
///
/// Class-bound and stateful; concrete implementations own non-`Sendable` codec objects and confine
/// them to a single actor / the main actor.
public protocol HardwareSignSession: AnyObject {
    /// The device this session talks to.
    var deviceKind: HardwareDeviceKind { get }

    /// The next outbound payload to present to the device (e.g. an animated-QR frame). Implementations
    /// cycle through parts; callers display them on a timer.
    func nextFrame() -> String

    /// Feed a scanned/received response frame. Returns `.needMore` until the full response is
    /// assembled, then `.complete(witnessSetHex:)`.
    func ingest(scanned: String) throws -> SignIngestResult
}
