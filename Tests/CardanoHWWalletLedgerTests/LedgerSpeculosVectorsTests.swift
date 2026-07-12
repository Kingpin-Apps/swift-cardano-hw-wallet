import Testing
import Foundation
import SwiftCardanoCore
import CardanoHWKit
@testable import CardanoHWWalletLedger

/// **Offline** golden-vector regression pinned to bytes captured from the real Ledger `app-cardano` in
/// Speculos (see `Tools/emulator-ledger/`). No device needed: it proves `PublicHDDerivation` from the
/// firmware account xpub reproduces the device's own mainnet base address — the Ledger analogue of
/// `TrezorEmulatorVectorsTests`.
@Suite("Ledger Speculos — offline vectors")
struct LedgerSpeculosVectorsTests {
    private let xpubHex = "78d137231e6346f17b1d442bace1f7ba1d54a88ef8509464e2e786a854bd4815acafe34e34bf401b4b0164607ee506c4aac63a0828f1dc20ab73ec39f2fe11f3"
    private let deviceAddressHex = "016dfa09426959db1023639e8d1f07bb1e478e722c6ebc1d57ba8703b9db219ee5ce9a74f98fdadc2de13efced5a154ef8d4d41929d5bf9ff6"

    @Test("Firmware xpub → PublicHDDerivation reproduces the device base address")
    func derivationMatchesDeviceAddress() throws {
        let derivation = try PublicHDDerivation(accountXPub: Self.hex(xpubHex), accountPath: "m/1852'/1815'/0'", network: .mainnet)
        let derived = try derivation.address(role: 0, index: 0)
        #expect(try Address.fromBech32(derived).toBytes() == Self.hex(deviceAddressHex))
    }

    @Test("Import parse yields the Ledger account model from the firmware xpub")
    func parseImport() throws {
        let model = try LedgerAccountImport.parse(response: Self.hex(xpubHex), accountIndex: 0, network: .mainnet)
        #expect(model.deviceKind == .ledger)
        #expect(model.accountXPub == Self.hex(xpubHex))
        #expect(model.accountPath == "m/1852'/1815'/0'")
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
