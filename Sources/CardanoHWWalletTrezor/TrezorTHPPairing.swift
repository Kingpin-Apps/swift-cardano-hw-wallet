import Foundation
import Crypto
import BigInt

/// THP **Code Entry** pairing (Trezor `docs/common/thp/specification.md`, Pairing phase).
///
/// The Trezor shows a 6-digit code; the user types it into the host. Both sides turn the code and
/// the channel's handshake hash into a Curve25519 generator (CPace, `CPACE-X25519-SHA512` as in
/// draft-irtf-cfrg-cpace-10 with empty sid/CI/AD), exchange public keys, and prove they derived the
/// same shared secret. The Trezor then reveals its secret, and the host checks it against the
/// commitment it received earlier and recomputes the code, so a man in the middle can't
/// substitute either side.
public enum TrezorTHPPairing {
    /// `ThpPairingMethod` values.
    public enum Method: UInt8, Sendable {
        case skipPairing = 1, codeEntry = 2, qrCode = 3, nfc = 4
    }

    /// The 6-digit code: `SHA-256(CodeEntry ‖ handshake_hash ‖ secret ‖ challenge) mod 1 000 000`,
    /// reading the hash as a big-endian integer.
    public static func code(handshakeHash: Data, secret: Data, challenge: Data) -> Int {
        var input = Data([Method.codeEntry.rawValue])
        input += handshakeHash + secret + challenge
        let digest = Data(SHA256.hash(data: input))
        return Int(BigUInt(digest) % 1_000_000)
    }

    /// The code as the device shows it (six digits, zero-padded).
    public static func codeString(_ code: Int) -> String {
        String(format: "%06d", code)
    }

    /// `pregenerator = SHA-512(prefix ‖ code ‖ padding ‖ handshake_hash ‖ 0x00)[:32]`, then
    /// `generator = ELLIGATOR2(pregenerator)`.
    public static func generator(code: String, handshakeHash: Data) throws -> Data {
        guard code.count == 6, code.allSatisfy(\.isASCII), code.allSatisfy(\.isNumber) else {
            throw TrezorError.pairingFailed("Enter the 6-digit code shown on the Trezor.")
        }
        // 0x08 ‖ "CPace255" ‖ 0x06 — the CPace domain separator plus the length of the 6-byte code.
        var input = Data([0x08, 0x43, 0x50, 0x61, 0x63, 0x65, 0x32, 0x35, 0x35, 0x06])
        input += Data(code.utf8)
        // 0x6f ‖ 0x00^111 ‖ 0x20 — zero padding to the SHA-512 block, then the hash length.
        input += Data([0x6f]) + Data(repeating: 0, count: 111) + Data([0x20])
        input += handshakeHash
        input += Data([0x00])
        let pregenerator = Data(SHA512.hash(data: input)).prefix(32)
        return Elligator2.mapToCurve25519(Data(pregenerator))
    }

    /// The host's CPace message: `(cpace_host_public_key, tag)` for the Trezor's public key.
    public static func hostTag(
        code: String,
        handshakeHash: Data,
        trezorPublicKey: Data,
        hostPrivateKey: Curve25519.KeyAgreement.PrivateKey = .init()
    ) throws -> (publicKey: Data, tag: Data) {
        let generator = try generator(code: code, handshakeHash: handshakeHash)
        let publicKey = try x25519(hostPrivateKey, generator)
        let shared = try x25519(hostPrivateKey, trezorPublicKey)
        guard shared != Data(repeating: 0, count: 32) else {
            throw TrezorError.pairingFailed("The Trezor sent an invalid pairing key.")
        }
        return (publicKey, Data(SHA256.hash(data: shared)))
    }

    /// After the Trezor reveals its secret: it must match the commitment, and the code the user
    /// typed must be the one that secret produces.
    public static func verify(secret: Data, commitment: Data, handshakeHash: Data, challenge: Data, enteredCode: String) throws {
        guard Data(SHA256.hash(data: secret)) == commitment else {
            throw TrezorError.pairingFailed("The Trezor's pairing secret doesn't match its commitment.")
        }
        guard codeString(code(handshakeHash: handshakeHash, secret: secret, challenge: challenge)) == enteredCode else {
            throw TrezorError.pairingFailed("The code doesn't match this connection.")
        }
    }

    /// X25519 of a private key with an arbitrary u-coordinate (a CPace generator or public key).
    static func x25519(_ privateKey: Curve25519.KeyAgreement.PrivateKey, _ u: Data) throws -> Data {
        try NoiseCrypto.dh(privateKey, u)
    }
}

/// A stored THP pairing credential: the Trezor it belongs to, the host static key it was issued
/// for, and the opaque credential bytes. Presenting it in a later handshake skips pairing.
public struct TrezorTHPCredential: Sendable, Codable, Equatable {
    public let trezorStaticPublicKey: Data
    public let hostStaticPrivateKey: Data
    public let credential: Data

    public init(trezorStaticPublicKey: Data, hostStaticPrivateKey: Data, credential: Data) {
        self.trezorStaticPublicKey = trezorStaticPublicKey
        self.hostStaticPrivateKey = hostStaticPrivateKey
        self.credential = credential
    }
}

/// Where a host keeps THP credentials. The app persists them (the host private key is a secret, so
/// the Keychain is the right place).
public protocol TrezorTHPCredentialStore: Sendable {
    func credentials() async -> [TrezorTHPCredential]
    func save(_ credential: TrezorTHPCredential) async
}

/// The app's side of pairing: who is asking, and how to get the code from the user.
public struct TrezorTHPPairingHandler: Sendable {
    public let hostName: String
    public let appName: String
    /// Ask the user for the 6-digit code now on the Trezor's screen.
    public let requestCode: @Sendable () async throws -> String

    public init(hostName: String, appName: String, requestCode: @escaping @Sendable () async throws -> String) {
        self.hostName = hostName
        self.appName = appName
        self.requestCode = requestCode
    }
}

/// RFC 9380 `map_to_curve_elligator2_curve25519`, returning only the u-coordinate — the same
/// procedure as Trezor's `crypto/elligator2.c`. The input is read as a little-endian 255-bit field
/// element (top bit ignored), as ed25519-donna's `curve25519_expand` does.
///
/// Arbitrary-precision arithmetic, not constant-time. The input is derived from a short-lived
/// pairing code and is only computed on the user's own device.
enum Elligator2 {
    static let p = (BigUInt(1) << 255) - 19
    static let j = BigUInt(486662)
    /// sqrt(-1) mod p = 2^((p-1)/4)
    static let sqrtMinusOne = BigUInt(2).power((p - 1) / 4, modulus: p)
    /// c4 = (p - 5) / 8
    static let c4 = (p - 5) / 8

    static func mapToCurve25519(_ input: Data) -> Data {
        var bytes = Array(input.prefix(32))
        bytes += Array(repeating: 0, count: 32 - bytes.count)
        bytes[31] &= 0x7f
        let u = BigUInt(Data(bytes.reversed())) % p

        func mul(_ a: BigUInt, _ b: BigUInt) -> BigUInt { (a * b) % p }
        func add(_ a: BigUInt, _ b: BigUInt) -> BigUInt { (a + b) % p }

        var tv1 = mul(u, u)
        tv1 = add(tv1, tv1)
        let xd = add(tv1, 1)
        let x1n = (p - j) % p
        var tv2 = mul(xd, xd)
        let gxd = mul(tv2, xd)
        var gx1 = mul(j, tv1)
        gx1 = mul(gx1, x1n)
        gx1 = add(gx1, tv2)
        gx1 = mul(gx1, x1n)
        var tv3 = mul(gxd, gxd)
        tv2 = mul(tv3, tv3)
        tv3 = mul(tv3, gxd)
        tv3 = mul(tv3, gx1)
        tv2 = mul(tv2, tv3)
        var y11 = tv2.power(c4, modulus: p)
        y11 = mul(y11, tv3)
        let y12 = mul(y11, sqrtMinusOne)
        tv2 = mul(mul(y11, y11), gxd)
        let y1 = tv2 == gx1 ? y11 : y12
        let x2n = mul(x1n, tv1)
        tv2 = mul(mul(y1, y1), gxd)
        let xn = tv2 == gx1 ? x1n : x2n
        let x = mul(xn, xd.power(p - 2, modulus: p))

        var out = Array(x.serialize().reversed())
        out += Array(repeating: 0, count: 32 - out.count)
        return Data(out.prefix(32))
    }
}
