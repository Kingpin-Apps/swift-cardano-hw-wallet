import Foundation

/// Low-level Ledger Cardano APDU constants and helpers, matching the **v8** app protocol
/// (`cardano-foundation/ledgerjs-hw-app-cardano`). CLA is `0xD7`; APDU data is capped at 255 bytes.
public enum LedgerAPDU {
    public static let cla: UInt8 = 0xD7

    /// Instruction codes (`interactions/common/ins.ts`).
    public enum INS {
        public static let getVersion: UInt8 = 0x00
        public static let getExtendedPublicKey: UInt8 = 0x10
        public static let deriveAddress: UInt8 = 0x11
        public static let signTx: UInt8 = 0x21
    }

    /// SignTx P1 stages — the real app's **per-field** protocol (`app-cardano`
    /// `command_builder.py` / `signTx.h`), one APDU (or group of sub-APDUs) per transaction field.
    public enum SignP1 {
        public static let initTx: UInt8 = 0x01
        public static let inputs: UInt8 = 0x02
        public static let outputs: UInt8 = 0x03
        public static let fee: UInt8 = 0x04
        public static let ttl: UInt8 = 0x05
        public static let certificates: UInt8 = 0x06
        public static let withdrawals: UInt8 = 0x07
        public static let validityStart: UInt8 = 0x09
        public static let txConfirm: UInt8 = 0x0A       // returns the 32-byte tx hash
        public static let witnesses: UInt8 = 0x0F       // returns a 64-byte signature
    }

    /// SignTx P2 sub-levels for the OUTPUTS stage (basic data → asset groups/tokens → confirm).
    public enum SignP2 {
        public static let outputBasic: UInt8 = 0x30
        public static let outputAssetGroup: UInt8 = 0x31
        public static let outputToken: UInt8 = 0x32
        public static let outputConfirm: UInt8 = 0x33
    }

    public static let p1Unused: UInt8 = 0x00
    public static let p2Unused: UInt8 = 0x00

    /// Response lengths.
    public static let signatureLength = 64
    public static let extendedPublicKeyLength = 64   // 32-byte key ‖ 32-byte chain code
    public static let txHashLength = 32

    /// Assemble an APDU: `CLA INS P1 P2 Lc data…`. `data` must be ≤ 255 bytes.
    public static func command(ins: UInt8, p1: UInt8, p2: UInt8, data: Data) -> Data {
        precondition(data.count <= 255, "Ledger APDU data exceeds 255 bytes")
        var apdu = Data([cla, ins, p1, p2, UInt8(data.count)])
        apdu.append(data)
        return apdu
    }
}

/// A parsed BIP32 path (`m/1852'/1815'/0'/0/3`) with Ledger's wire encoding.
public struct LedgerBIP32Path: Sendable, Equatable {
    public let indices: [UInt32]

    /// Parse a path string. Apostrophe or `h`/`H` marks a hardened index (adds `0x80000000`).
    public init(_ path: String) throws {
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
                throw LedgerError.malformedResponse("Invalid BIP32 path element '\(token)' in '\(path)'.")
            }
            out.append(hardened ? value | 0x8000_0000 : value)
        }
        guard !out.isEmpty else {
            throw LedgerError.malformedResponse("Empty BIP32 path '\(path)'.")
        }
        self.indices = out
    }

    public init(indices: [UInt32]) { self.indices = indices }

    /// Ledger `path_to_buf`: 1-byte length + 4 bytes (big-endian) per element.
    public func encoded() -> Data {
        var data = Data([UInt8(indices.count)])
        for element in indices { data.append(contentsOf: LedgerBytes.uint32BE(element)) }
        return data
    }

    /// The trailing `role` and `index` (the last two elements), for deriving the witness pubkey.
    public var roleAndIndex: (role: UInt32, index: UInt32)? {
        guard indices.count >= 2 else { return nil }
        return (indices[indices.count - 2], indices[indices.count - 1])
    }
}

/// Ledger APDU status-word handling.
public enum LedgerStatus {
    public static let ok: UInt16 = 0x9000

    /// Verify the trailing 2-byte status word of a raw APDU response is `0x9000` and return the
    /// payload without it. Throws ``LedgerError/status(_:)`` on any other status.
    public static func payload(_ response: Data) throws -> Data {
        let bytes = Array(response)
        guard bytes.count >= 2 else {
            throw LedgerError.malformedResponse("Ledger response too short for a status word (\(bytes.count) bytes).")
        }
        let sw = UInt16(bytes[bytes.count - 2]) << 8 | UInt16(bytes[bytes.count - 1])
        guard sw == ok else { throw LedgerError.status(sw) }
        return Data(bytes.dropLast(2))
    }
}

/// Big-endian integer serialization helpers (Ledger encodes everything big-endian).
public enum LedgerBytes {
    public static func uint16BE(_ v: UInt16) -> [UInt8] { [UInt8(v >> 8), UInt8(v & 0xff)] }
    public static func uint32BE(_ v: UInt32) -> [UInt8] {
        [UInt8((v >> 24) & 0xff), UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)]
    }
    public static func uint64BE(_ v: UInt64) -> [UInt8] {
        (0..<8).reversed().map { UInt8((v >> (UInt64($0) * 8)) & 0xff) }
    }
}
