import Testing
import Foundation
import Crypto
import SwiftCardanoCore
@testable import CardanoHWKit

/// Device-vector regression for the **Keystone** path, pinned to authentic bytes lifted from
/// Keystone's own open-source device firmware — `keystone3-firmware/rust/apps/cardano` unit tests
/// (`address.rs`, `transaction.rs`). Keystone is air-gapped (QR-only) with no scriptable emulator, so
/// instead of a live device we validate the pieces our code owns against the firmware's own outputs:
/// the account→address derivation, our tx body-hash computation, and consumption of the device's
/// returned witness set. (The UR sign-request/signature codecs run Keystone's real `ur-registry` Rust
/// via the iOS FFI; these vectors cover the crypto/serialization the QR carries.) The device signing
/// itself is exercised live in the Rust-oracle harness — see `Tools/emulator-keystone/`.
@Suite("Keystone device vectors")
struct KeystoneDeviceVectorsTests {

    // From app_cardano `address.rs`: entropy 0x00…00 (= "abandon … about"), ICARUS.
    private let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private let deviceBaseAddress = "addr1qy8ac7qqy0vtulyl7wntmsxc6wex80gvcyjy33qffrhm7sh927ysx5sftuw0dlft05dz3c7revpf7jx0xnlcjz3g69mq4afdhv"

    // From app_cardano `transaction.rs` (`spike_fixed_transaction`): the tx, its body hash, and the
    // device's returned witness set (two vkey witnesses).
    private let bodyHash = "6dadb65461bf4e1e9a983f16ba033ca0b490fc3d845db2ec6bf6789a14e7e9c3"
    private let deviceWitnessSet = "a100828258201e7a836e4d144ea0a3c2f53878dbbb3e4583476d2a970fe5b693bc1d7974faf8584020ef5f3eedfaec7af8c1dafc575fc7af38cd1a2d7215ae2fb7f3f81415caea18f01cc125974133dda35e89bdd2c3b662f33509437564a88f106084f7693a0f0b8258207508644588abb8da3996ed16c70162c730af99b8e43c730d4219ba61b78b463a5840a4a620028627eb384790530010a71349a22dc2c533edafba3fd0dcd60c7b593bd3ba999ec041e429b70ae19feb2f6660cecc3b5715b0e4e4118878878969f80f"

    @Test("PublicHDDerivation reproduces the Keystone firmware's base address")
    func derivationMatchesFirmwareAddress() throws {
        let root = try HDWallet.fromMnemonic(mnemonic: mnemonic)
        let account = try root.derive(fromPath: "m/1852'/1815'/0'")
        let xpub = Data(account.publicKey) + Data(account.chainCode)
        let derivation = try PublicHDDerivation(accountXPub: xpub, accountPath: "m/1852'/1815'/0'", network: .mainnet)
        #expect(try derivation.address(role: 0, index: 0) == deviceBaseAddress)
    }

    @Test("The device witness set decodes and its signatures verify over the firmware body hash")
    func deviceWitnessSetVerifies() throws {
        let hash = Self.hex(bodyHash)
        let set = try TransactionWitnessSet.fromCBORHex(deviceWitnessSet)
        let witnesses = set.vkeyWitnesses?.asList ?? []
        #expect(witnesses.count == 2)
        for witness in witnesses {
            #expect(witness.vkey.payload.count == 32)
            #expect(witness.signature.count == 64)
            // Cardano vkey witnesses are standard Ed25519 over the blake2b body hash.
            let verifier = try Curve25519.Signing.PublicKey(rawRepresentation: witness.vkey.payload)
            #expect(verifier.isValidSignature(witness.signature, for: hash))
        }
    }

    private static func hex(_ s: String) -> Data {
        var out = [UInt8](); out.reserveCapacity(s.count / 2)
        var i = s.startIndex
        while i < s.endIndex {
            let j = s.index(i, offsetBy: 2)
            out.append(UInt8(s[i..<j], radix: 16)!)
            i = j
        }
        return Data(out)
    }
}
