import Foundation
import SwiftCardanoCore
import CardanoHWKit

/// Pure helpers for the Ledger account-export (getExtendedPublicKey) exchange — the APDU to send and
/// the response parse into a device-neutral ``HardwareAccountModel``. Kept separate from the session
/// so the wire format is unit-testable without a transport.
public enum LedgerAccountImport {

    /// The CIP-1852 account node path for a given account index, e.g. `m/1852'/1815'/0'`.
    public static func accountPath(accountIndex: Int) -> String {
        "m/1852'/1815'/\(accountIndex)'"
    }

    /// The getExtendedPublicKey APDU for the account node.
    public static func getExtendedPublicKeyAPDU(accountIndex: Int) throws -> Data {
        let path = try LedgerBIP32Path(accountPath(accountIndex: accountIndex))
        return LedgerAPDU.command(
            ins: LedgerAPDU.INS.getExtendedPublicKey,
            p1: LedgerAPDU.p1Unused, p2: LedgerAPDU.p2Unused,
            data: path.encoded()
        )
    }

    /// Parse a 64-byte getExtendedPublicKey response (`32-byte key ‖ 32-byte chain code`) into a model.
    ///
    /// Ledger does not expose a master-key fingerprint, and it isn't needed for Ledger signing (which
    /// addresses keys by full path), so `masterFingerprint` is stored as four zero bytes.
    public static func parse(
        response: Data,
        accountIndex: Int,
        network: NetworkId
    ) throws -> HardwareAccountModel {
        guard response.count == LedgerAPDU.extendedPublicKeyLength else {
            throw LedgerError.malformedResponse(
                "getExtendedPublicKey returned \(response.count) bytes, expected \(LedgerAPDU.extendedPublicKeyLength)."
            )
        }
        return HardwareAccountModel(
            deviceKind: .ledger,
            accountXPub: response,
            masterFingerprint: Data(repeating: 0, count: 4),
            accountPath: accountPath(accountIndex: accountIndex),
            network: network
        )
    }
}
