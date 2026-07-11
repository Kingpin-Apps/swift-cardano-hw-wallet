import Foundation

/// A DRep target for a vote-delegation certificate, device-neutral.
public enum HardwareDRepKind: Sendable, Equatable, Hashable {
    case keyHash(String)      // 28-byte DRep key hash, hex
    case scriptHash(String)   // 28-byte DRep script hash, hex
    case abstain
    case noConfidence
}

/// A device-neutral certificate description carried in a ``HardwareSignRequest``. The app builds these
/// from what it already knows (pool id, DRep choice, the account's stake path) rather than the device
/// modules re-parsing the SDK `Certificate` out of the tx body. The device reconstructs the same
/// certificate; the sign session's tx-hash guard catches any mismatch with the actual body.
///
/// The device-owned stake credential is always expressed as a **path** (so the device signs it). Wire
/// type codes match both Ledger and Trezor: register-Conway = 7, deregister-Conway = 8,
/// stake-delegation = 2, vote-delegation = 9.
public enum HardwareCertificate: Sendable, Equatable {
    case stakeRegistrationConway(stakePath: String, deposit: UInt64)
    case stakeDeregistrationConway(stakePath: String, deposit: UInt64)
    case stakeDelegation(stakePath: String, poolKeyHashHex: String)
    case voteDelegation(stakePath: String, drep: HardwareDRepKind)

    /// The device-owned stake key path this certificate is signed by.
    public var stakePath: String {
        switch self {
        case .stakeRegistrationConway(let p, _), .stakeDeregistrationConway(let p, _),
             .stakeDelegation(let p, _), .voteDelegation(let p, _):
            return p
        }
    }
}

/// A device-neutral rewards-withdrawal description.
public struct HardwareWithdrawal: Sendable, Equatable {
    /// The device-owned stake key path authorizing the withdrawal.
    public let stakePath: String
    /// The 29-byte reward account (network-tagged stake credential), hex.
    public let rewardAccountHex: String
    /// The amount withdrawn, in lovelace.
    public let amount: UInt64

    public init(stakePath: String, rewardAccountHex: String, amount: UInt64) {
        self.stakePath = stakePath
        self.rewardAccountHex = rewardAccountHex
        self.amount = amount
    }
}
