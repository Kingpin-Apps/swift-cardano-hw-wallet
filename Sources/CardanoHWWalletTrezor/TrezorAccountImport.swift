import Foundation
import SwiftCardanoCore
import CardanoHWKit

/// Parses a CIP-1852 path string (`m/1852'/1815'/0'/0/3`) into Trezor's `repeated uint32` form
/// (hardened indices carry the `0x80000000` bit).
public enum TrezorBIP32Path {
    public static func parse(_ path: String) throws -> [UInt32] {
        var out: [UInt32] = []
        for (i, raw) in path.split(separator: "/").enumerated() {
            let token = String(raw)
            if i == 0, token == "m" || token == "M" { continue }
            var hardened = false
            var digits = token
            if let last = digits.last, last == "'" || last == "h" || last == "H" {
                hardened = true
                digits.removeLast()
            }
            guard let value = UInt32(digits) else {
                throw TrezorError.malformedResponse("Invalid BIP32 path element '\(token)' in '\(path)'.")
            }
            out.append(hardened ? value | 0x8000_0000 : value)
        }
        guard !out.isEmpty else { throw TrezorError.malformedResponse("Empty BIP32 path '\(path)'.") }
        return out
    }
}

/// Pure helpers for the Trezor account-export (`CardanoGetPublicKey` → `CardanoPublicKey`) exchange.
public enum TrezorAccountImport {

    public static func accountPath(accountIndex: Int) -> String {
        "m/1852'/1815'/\(accountIndex)'"
    }

    /// The `CardanoGetPublicKey` request message for the account node.
    public static func getPublicKeyMessage(accountIndex: Int, derivationType: TrezorDerivationType) throws -> TrezorMessage {
        let path = try TrezorBIP32Path.parse(accountPath(accountIndex: accountIndex))
        var w = ProtobufWriter()
        w.repeatedUInt32(1, path)                     // address_n
        w.varint(3, derivationType.rawValue)          // derivation_type
        return TrezorMessage(type: TrezorMessageType.cardanoGetPublicKey, payload: w.data)
    }

    /// Parse a `CardanoPublicKey` payload into a device-neutral account model. The `xpub` field (1) is
    /// the hex of `32-byte public key ‖ 32-byte chain code`.
    public static func parsePublicKey(payload: Data, accountIndex: Int, network: NetworkId) throws -> HardwareAccountModel {
        let reader = try ProtobufReader(payload)
        guard let xpubHex = reader.string(1), let xpub = Data(hexString: xpubHex) else {
            throw TrezorError.malformedResponse("CardanoPublicKey missing a valid xpub field.")
        }
        guard xpub.count == 64 else {
            throw TrezorError.malformedResponse("Trezor xpub was \(xpub.count) bytes, expected 64.")
        }
        return HardwareAccountModel(
            deviceKind: .trezor,
            accountXPub: xpub,
            masterFingerprint: Data(repeating: 0, count: 4),   // not exposed / not needed for signing
            accountPath: accountPath(accountIndex: accountIndex),
            network: network
        )
    }
}

/// Pure helpers for `CardanoGetAddress` → `CardanoAddress` for a base address (payment key + stake key).
public enum TrezorAddressDerivation {
    /// `CardanoGetAddress`: show_display (2), protocol_magic (3), network_id (4),
    /// address_parameters (5: address_type BASE = 0, address_n, address_n_staking), derivation_type (6).
    public static func getAddressMessage(
        spendingPath: String, stakingPath: String, network: TrezorNetwork,
        derivationType: TrezorDerivationType, showDisplay: Bool
    ) throws -> TrezorMessage {
        var params = ProtobufWriter()
        params.varint(1, 0)                                            // address_type = BASE
        params.repeatedUInt32(2, try TrezorBIP32Path.parse(spendingPath))
        params.repeatedUInt32(3, try TrezorBIP32Path.parse(stakingPath))
        var w = ProtobufWriter()
        w.bool(2, showDisplay)
        w.varint(3, UInt64(network.protocolMagic))
        w.varint(4, UInt64(network.networkId))
        w.bytes(5, params.data)
        w.varint(6, derivationType.rawValue)
        return TrezorMessage(type: TrezorMessageType.cardanoGetAddress, payload: w.data)
    }

    /// The bech32 address from a `CardanoAddress` payload (field 1).
    public static func parseAddress(payload: Data) throws -> String {
        guard let address = try ProtobufReader(payload).string(1), !address.isEmpty else {
            throw TrezorError.malformedResponse("CardanoAddress missing its address field.")
        }
        return address
    }
}

extension Data {
    /// Decode a hex string (even length, no `0x`) into bytes. Returns nil on malformed input.
    init?(hexString: String) {
        let chars = Array(hexString)
        guard chars.count % 2 == 0 else { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(chars.count / 2)
        var i = 0
        while i < chars.count {
            guard let hi = chars[i].hexDigitValue, let lo = chars[i + 1].hexDigitValue else { return nil }
            bytes.append(UInt8(hi << 4 | lo))
            i += 2
        }
        self = Data(bytes)
    }
}
