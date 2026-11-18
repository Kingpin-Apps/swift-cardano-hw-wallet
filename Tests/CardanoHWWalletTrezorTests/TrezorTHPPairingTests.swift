import Testing
import Foundation
import Crypto
@testable import CardanoHWWalletTrezor

@Suite("THP Code Entry pairing")
struct TrezorTHPPairingTests {
    private func hex(_ s: String) -> Data {
        Data(stride(from: 0, to: s.count, by: 2).map { i in
            UInt8(s[s.index(s.startIndex, offsetBy: i)..<s.index(s.startIndex, offsetBy: i + 2)], radix: 16)!
        })
    }

    /// The vectors from trezor-firmware `core/tests/test_trezor.crypto.elligator2.py`
    /// (originally elligator.org `curve25519_direct.vec`).
    @Test("Elligator2 matches Trezor's firmware vectors")
    func elligator2Vectors() {
        let vectors: [(String, String)] = [
            ("0000000000000000000000000000000000000000000000000000000000000000", "0000000000000000000000000000000000000000000000000000000000000000"),
            ("66665895c5bc6e44ba8d65fd9307092e3244bf2c18877832bd568cb3a2d38a12", "04d44290d13100b2c25290c9343d70c12ed4813487a07ac1176daa5925e7975e"),
            ("673a505e107189ee54ca93310ac42e4545e9e59050aaac6f8b5f64295c8ec02f", "242ae39ef158ed60f20b89396d7d7eef5374aba15dc312a6aea6d1e57cacf85e"),
            ("990b30e04e1c3620b4162b91a33429bddb9f1b70f1da6e5f76385ed3f98ab131", "998e98021eb4ee653effaa992f3fae4b834de777a953271baaa1fa3fef6b776e"),
            ("341a60725b482dd0de2e25a585b208433044bc0a1ba762442df3a0e888ca063c", "683a71d7fca4fc6ad3d4690108be808c2e50a5af3174486741d0a83af52aeb01"),
            ("922688fa428d42bc1fa8806998fbc5959ae801817e85a42a45e8ec25a0d7541a", "696f341266c64bcfa7afa834f8c34b2730be11c932e08474d1a22f26ed82410b"),
            ("0d3b0eb88b74ed13d5f6a130e03c4ad607817057dc227152827c0506a538bb3a", "0b00df174d9fb0b6ee584d2cf05613130bad18875268c38b377e86dfefef177f"),
            ("01a3ea5658f4e00622eeacf724e0bd82068992fae66ed2b04a8599be16662e35", "7ae4c58bc647b5646c9f5ae4c2554ccbf7c6e428e7b242a574a5a9c293c21f7e"),
            ("1d991dff82a84afe97874c0f03a60a56616a15212fbe10d6c099aa3afcfabe35", "f81f235696f81df90ac2fc861ceee517bff611a394b5be5faaee45584642fb0a"),
            ("185435d2b005a3b63f3187e64a1ef3582533e1958d30e4e4747b4d1d3376c728", "f938b1b320abb0635930bd5d7ced45ae97fa8b5f71cc21d87b4c60905c125d34"),
        ]
        for (input, output) in vectors {
            #expect(Elligator2.mapToCurve25519(hex(input)) == hex(output), "input \(input)")
        }
    }

    @Test("Host and Trezor sides of CPace agree on the right code and disagree on a wrong one")
    func cpaceRoundTrip() throws {
        let handshakeHash = Data((0..<32).map { _ in UInt8.random(in: 0...255) })
        let secret = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        let challenge = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        let code = TrezorTHPPairing.codeString(TrezorTHPPairing.code(handshakeHash: handshakeHash, secret: secret, challenge: challenge))
        #expect(code.count == 6)

        // Trezor side (spec state TP2 / TP3a).
        let trezorPrivate = Curve25519.KeyAgreement.PrivateKey()
        let trezorPublic = try TrezorTHPPairing.x25519(trezorPrivate, try TrezorTHPPairing.generator(code: code, handshakeHash: handshakeHash))

        // Host side with the right code: the Trezor's check of the tag passes.
        let host = try TrezorTHPPairing.hostTag(code: code, handshakeHash: handshakeHash, trezorPublicKey: trezorPublic)
        let trezorShared = try TrezorTHPPairing.x25519(trezorPrivate, host.publicKey)
        #expect(Data(SHA256.hash(data: trezorShared)) == host.tag)
        try TrezorTHPPairing.verify(secret: secret, commitment: Data(SHA256.hash(data: secret)),
                                    handshakeHash: handshakeHash, challenge: challenge, enteredCode: code)

        // A wrong code yields a different generator, so the Trezor rejects the tag.
        let wrong = code == "000000" ? "000001" : "000000"
        let bad = try TrezorTHPPairing.hostTag(code: wrong, handshakeHash: handshakeHash, trezorPublicKey: trezorPublic)
        #expect(Data(SHA256.hash(data: try TrezorTHPPairing.x25519(trezorPrivate, bad.publicKey))) != bad.tag)
        #expect(throws: TrezorError.self) {
            try TrezorTHPPairing.verify(secret: secret, commitment: Data(SHA256.hash(data: secret)),
                                        handshakeHash: handshakeHash, challenge: challenge, enteredCode: wrong)
        }
        // A secret that doesn't match the commitment is refused.
        #expect(throws: TrezorError.self) {
            try TrezorTHPPairing.verify(secret: secret, commitment: Data(repeating: 0, count: 32),
                                        handshakeHash: handshakeHash, challenge: challenge, enteredCode: code)
        }
    }

    @Test("Codes are rejected unless they're six ASCII digits")
    func codeFormat() {
        let h = Data(repeating: 1, count: 32)
        #expect(throws: TrezorError.self) { _ = try TrezorTHPPairing.generator(code: "12345", handshakeHash: h) }
        #expect(throws: TrezorError.self) { _ = try TrezorTHPPairing.generator(code: "12345a", handshakeHash: h) }
        #expect(throws: TrezorError.self) { _ = try TrezorTHPPairing.generator(code: "١٢٣٤٥٦", handshakeHash: h) }
        #expect(TrezorTHPPairing.codeString(42) == "000042")
    }

    @Test("Noise nonces are big-endian, as THP's IV = 0^95 || 1 requires")
    func bigEndianNonce() throws {
        let key = SymmetricKey(data: Data(repeating: 7, count: 32))
        let ours = try NoiseCrypto.aesEncrypt(key: SymmetricKey(data: Data(repeating: 7, count: 32)), counter: 1, ad: Data(), plaintext: Data("x".utf8))
        let iv = Data(repeating: 0, count: 11) + Data([1])
        let sealed = try AES.GCM.seal(Data("x".utf8), using: key, nonce: try AES.GCM.Nonce(data: iv))
        #expect(ours == sealed.ciphertext + sealed.tag)
    }
}
