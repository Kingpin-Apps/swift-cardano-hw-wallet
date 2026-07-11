import Foundation
import SwiftCardanoCore

/// The async, one-shot signing seam for **interactive byte-protocol devices** (Ledger, Trezor),
/// implemented per device and driven by the app.
///
/// This sits alongside the QR ``HardwareSignSession`` (a UI-interactive frame-pump): a wired/BLE
/// device shows its own on-screen confirmation, so signing is a single `await signer.sign(request)`
/// that blocks while the user approves on the device, then returns the witness set — no frame loop.
///
/// - ``importAccount(network:accountIndex:)`` reads the device's account-level extended public key
///   (`m/1852'/1815'/account'`) into a device-neutral ``HardwareAccountModel``.
/// - ``sign(_:)`` runs the device's signing dialogue for a ``HardwareSignRequest`` and returns the
///   device's ``TransactionWitnessSet`` as CBOR hex, ready for ``WitnessMerge``.
///
/// Concrete signers own a transport (e.g. a `LedgerTransport` or ``HardwarePacketLink``) and manage
/// their own concurrency; the protocol stays isolation-agnostic so an actor or `@MainActor` class
/// can conform.
public protocol HardwareSigner {
    /// The device family this signer talks to.
    var deviceKind: HardwareDeviceKind { get }

    /// Read the account-level extended public key from the device and wrap it device-neutrally.
    func importAccount(network: NetworkId, accountIndex: Int) async throws -> HardwareAccountModel

    /// Run the device's signing dialogue and return the device's witness set as CBOR hex.
    func sign(_ request: HardwareSignRequest) async throws -> String
}
