import Foundation
import Crypto

/// The Noise Protocol Framework `Noise_XX_25519_AESGCM_SHA256` implementation used by Trezor's THP
/// (v2) secure channel. Curve25519 DH, AES-GCM-256 AEAD, SHA-256 hash. Pure crypto over SwiftCrypto —
/// unit-testable via a local initiator↔responder handshake (see the tests), no device required.
///
/// Reference: Trezor `docs/common/thp/specification.md` (Handshake phase) + noiseprotocol.org.

/// A post-handshake transport cipher (one direction). AES-GCM with a 64-bit counter nonce.
public struct NoiseCipherState: Sendable {
    private let key: SymmetricKey
    private var nonce: UInt64 = 0

    init(key: Data) { self.key = SymmetricKey(data: key) }

    public mutating func encrypt(ad: Data = Data(), plaintext: Data) throws -> Data {
        let out = try NoiseCrypto.aesEncrypt(key: key, counter: nonce, ad: ad, plaintext: plaintext)
        nonce &+= 1
        return out
    }

    public mutating func decrypt(ad: Data = Data(), ciphertext: Data) throws -> Data {
        let out = try NoiseCrypto.aesDecrypt(key: key, counter: nonce, ad: ad, ciphertext: ciphertext)
        nonce &+= 1
        return out
    }
}

/// Noise symmetric state: the rolling chaining key `ck`, transcript hash `h`, and current AEAD key.
struct NoiseSymmetricState {
    private(set) var ck: Data
    private(set) var h: Data
    private var k: SymmetricKey?
    private var n: UInt64 = 0

    init(protocolName: Data) {
        var name = protocolName
        if name.count < 32 { name.append(Data(repeating: 0, count: 32 - name.count)) }
        else if name.count > 32 { name = Data(SHA256.hash(data: name)) }
        h = name
        ck = name
    }

    mutating func mixHash(_ data: Data) { h = Data(SHA256.hash(data: h + data)) }

    mutating func mixKey(_ input: Data) {
        let (newCk, tempK) = NoiseCrypto.hkdf2(chainingKey: ck, input: input)
        ck = newCk
        k = SymmetricKey(data: tempK)
        n = 0
    }

    mutating func encryptAndHash(_ plaintext: Data) throws -> Data {
        guard let k else { mixHash(plaintext); return plaintext }
        let ct = try NoiseCrypto.aesEncrypt(key: k, counter: n, ad: h, plaintext: plaintext)
        n &+= 1
        mixHash(ct)
        return ct
    }

    mutating func decryptAndHash(_ ciphertext: Data) throws -> Data {
        guard let k else { mixHash(ciphertext); return ciphertext }
        let pt = try NoiseCrypto.aesDecrypt(key: k, counter: n, ad: h, ciphertext: ciphertext)
        n &+= 1
        mixHash(ciphertext)
        return pt
    }

    /// Derive the two transport keys from the final chaining key.
    func split() -> (Data, Data) { NoiseCrypto.hkdf2(chainingKey: ck, input: Data()) }
}

/// The `Noise_XX` handshake state machine (initiator = host; responder role provided for tests).
public final class NoiseXXHandshake {
    public enum Role: Sendable { case initiator, responder }
    public enum NoiseError: Error, Equatable { case badMessage(String) }

    /// `Noise_XX_25519_AESGCM_SHA256` + 4 zero bytes = exactly 32 bytes.
    static let protocolName = Data("Noise_XX_25519_AESGCM_SHA256".utf8) + Data([0, 0, 0, 0])

    private let role: Role
    private var sym: NoiseSymmetricState
    private let s: Curve25519.KeyAgreement.PrivateKey     // local static
    private var e: Curve25519.KeyAgreement.PrivateKey?    // local ephemeral
    private var rs: Data?                                 // remote static pubkey
    private var re: Data?                                 // remote ephemeral pubkey

    public init(role: Role, staticKey: Curve25519.KeyAgreement.PrivateKey, prologue: Data = Data()) {
        self.role = role
        self.s = staticKey
        self.sym = NoiseSymmetricState(protocolName: Self.protocolName)
        self.sym.mixHash(prologue)
    }

    /// The remote static public key learned during the handshake (Trezor's masked static key).
    public var remoteStaticKey: Data? { rs }

    // MARK: - Message 1 (`-> e`)

    /// Initiator writes message 1: `host_ephemeral_pubkey ‖ payload`.
    public func writeMessage1(payload: Data) throws -> Data {
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        e = ephemeral
        let epub = ephemeral.publicKey.rawRepresentation
        sym.mixHash(epub)
        return epub + (try sym.encryptAndHash(payload))
    }

    /// Responder reads message 1, returning the decrypted payload.
    public func readMessage1(_ message: Data) throws -> Data {
        let bytes = Array(message)
        guard bytes.count >= 32 else { throw NoiseError.badMessage("msg1 too short") }
        re = Data(bytes[0..<32])
        sym.mixHash(re!)
        return try sym.decryptAndHash(Data(bytes[32...]))
    }

    // MARK: - Message 2 (`<- e, ee, s, es`)

    /// Responder writes message 2.
    public func writeMessage2(payload: Data) throws -> Data {
        guard let re else { throw NoiseError.badMessage("no remote ephemeral") }
        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        e = ephemeral
        let epub = ephemeral.publicKey.rawRepresentation
        sym.mixHash(epub)
        sym.mixKey(try NoiseCrypto.dh(ephemeral, re))               // ee
        var out = epub
        out += try sym.encryptAndHash(s.publicKey.rawRepresentation) // s
        sym.mixKey(try NoiseCrypto.dh(s, re))                        // es (responder: static·remote-eph)
        out += try sym.encryptAndHash(payload)
        return out
    }

    /// Initiator reads message 2, returning the decrypted payload.
    public func readMessage2(_ message: Data) throws -> Data {
        guard let e else { throw NoiseError.badMessage("no local ephemeral") }
        let bytes = Array(message)
        guard bytes.count >= 32 + 48 else { throw NoiseError.badMessage("msg2 too short") }
        re = Data(bytes[0..<32])
        sym.mixHash(re!)
        sym.mixKey(try NoiseCrypto.dh(e, re!))                       // ee
        rs = try sym.decryptAndHash(Data(bytes[32..<80]))           // s (48 → 32)
        sym.mixKey(try NoiseCrypto.dh(e, rs!))                      // es (initiator: eph·remote-static)
        return try sym.decryptAndHash(Data(bytes[80...]))
    }

    // MARK: - Message 3 (`-> s, se`)

    /// Initiator writes message 3, returning `(message, sendCipher, receiveCipher)`.
    public func writeMessage3(payload: Data) throws -> (message: Data, send: NoiseCipherState, receive: NoiseCipherState) {
        guard let re else { throw NoiseError.badMessage("no remote ephemeral") }
        var out = try sym.encryptAndHash(s.publicKey.rawRepresentation)   // s
        sym.mixKey(try NoiseCrypto.dh(s, re))                            // se (initiator: static·remote-eph)
        out += try sym.encryptAndHash(payload)
        let (k1, k2) = sym.split()
        return (out, NoiseCipherState(key: k1), NoiseCipherState(key: k2))
    }

    /// Responder reads message 3, returning `(payload, sendCipher, receiveCipher)`.
    public func readMessage3(_ message: Data) throws -> (payload: Data, send: NoiseCipherState, receive: NoiseCipherState) {
        guard let e else { throw NoiseError.badMessage("no local ephemeral") }
        let bytes = Array(message)
        guard bytes.count >= 48 else { throw NoiseError.badMessage("msg3 too short") }
        rs = try sym.decryptAndHash(Data(bytes[0..<48]))               // s
        sym.mixKey(try NoiseCrypto.dh(e, rs!))                         // se (responder: eph·remote-static)
        let payload = try sym.decryptAndHash(Data(bytes[48...]))
        let (k1, k2) = sym.split()
        // Responder's send is k2 (responder→initiator); receive is k1.
        return (payload, NoiseCipherState(key: k2), NoiseCipherState(key: k1))
    }
}

/// Low-level Noise crypto primitives over SwiftCrypto.
enum NoiseCrypto {
    /// AES-GCM encrypt with the Noise nonce (4 zero bytes ‖ 8-byte little-endian counter). Returns
    /// `ciphertext ‖ 16-byte tag`.
    static func aesEncrypt(key: SymmetricKey, counter: UInt64, ad: Data, plaintext: Data) throws -> Data {
        let sealed = try AES.GCM.seal(plaintext, using: key, nonce: try AES.GCM.Nonce(data: nonce(counter)), authenticating: ad)
        return sealed.ciphertext + sealed.tag
    }

    static func aesDecrypt(key: SymmetricKey, counter: UInt64, ad: Data, ciphertext: Data) throws -> Data {
        guard ciphertext.count >= 16 else { throw NoiseXXHandshake.NoiseError.badMessage("ciphertext too short") }
        let ct = ciphertext.prefix(ciphertext.count - 16)
        let tag = ciphertext.suffix(16)
        let box = try AES.GCM.SealedBox(nonce: try AES.GCM.Nonce(data: nonce(counter)), ciphertext: ct, tag: tag)
        return try AES.GCM.open(box, using: key, authenticating: ad)
    }

    /// X25519 raw DH: `privkey · pubkey`.
    static func dh(_ priv: Curve25519.KeyAgreement.PrivateKey, _ pubkey: Data) throws -> Data {
        let pub = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: pubkey)
        let secret = try priv.sharedSecretFromKeyAgreement(with: pub)
        return secret.withUnsafeBytes { Data($0) }
    }

    /// Noise 2-output HKDF-SHA256.
    static func hkdf2(chainingKey: Data, input: Data) -> (Data, Data) {
        let tempKey = hmac(key: chainingKey, data: input)
        let o1 = hmac(key: tempKey, data: Data([0x01]))
        let o2 = hmac(key: tempKey, data: o1 + Data([0x02]))
        return (o1, o2)
    }

    private static func hmac(key: Data, data: Data) -> Data {
        Data(HMAC<SHA256>.authenticationCode(for: data, using: SymmetricKey(data: key)))
    }

    private static func nonce(_ counter: UInt64) -> Data {
        var iv = Data([0, 0, 0, 0])
        var le = counter.littleEndian
        withUnsafeBytes(of: &le) { iv.append(contentsOf: $0) }
        return iv
    }
}
