import Testing
import Foundation
import SwiftCardanoCore
import CardanoHWKit
@testable import CardanoHWWalletTrezor

/// Golden vectors captured from the **Trezor emulator** (trezor-user-env, model T2T1, seed
/// "all all all all all all all all all all all all") via the bridge — see `Tools/emulator/`. They
/// pin the Swift Trezor request encoding, the CardanoPublicKey parse, and the xpub→address derivation
/// against **real firmware**: the emulator accepted our exact request bytes and returned this xpub +
/// this address for `m/1852'/1815'/0'/0/0` (ICARUS_TREZOR derivation, mainnet).
@Suite("Trezor emulator golden vectors")
struct TrezorEmulatorVectorsTests {
    // Captured 2026-07-11 from the emulator bridge.
    private let expectedRequestHex = "08bc8e80800808978e8080080880808080081802"
    private let xpubHex = "d507c8f866691bd96e131334c355188b1a1d0b2fa0ab11545075aab332d77d9eb19657ad13ee581b56b0f8d744d66ca356b93d42fe176b3de007d53e9c4c4e7a"
    private let deviceAddress = "addr1qxq0nckg3ekgzuqg7w5p9mvgnd9ym28qh5grlph8xd2z92sj922xhxkn6twlq2wn4q50q352annk3903tj00h45mgfmsl3s9zt"

    @Test("CardanoGetPublicKey request bytes match what the firmware accepted")
    func requestEncodingMatchesFirmware() throws {
        let message = try TrezorAccountImport.getPublicKeyMessage(accountIndex: 0, derivationType: .icarusTrezor)
        #expect(message.type == 305)
        #expect(message.payload.toHex == expectedRequestHex)
    }

    @Test("parsePublicKey extracts the firmware's account xpub")
    func parsesFirmwareXPub() throws {
        // Rebuild the CardanoPublicKey payload the way the device sends it (field 1 = xpub hex string).
        var w = ProtobufWriter()
        w.string(1, xpubHex)
        let model = try TrezorAccountImport.parsePublicKey(payload: w.data, accountIndex: 0, network: .mainnet)
        #expect(model.accountXPub == Self.hex(xpubHex))
        #expect(model.deviceKind == .trezor)
        #expect(model.accountPath == "m/1852'/1815'/0'")
    }

    @Test("PublicHDDerivation from the firmware xpub reproduces the device's own address")
    func derivationMatchesDeviceAddress() throws {
        let xpub = Self.hex(xpubHex)
        let derivation = try PublicHDDerivation(accountXPub: xpub, accountPath: "m/1852'/1815'/0'", network: .mainnet)
        let derived = try derivation.address(role: 0, index: 0)
        #expect(derived == deviceAddress)
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
