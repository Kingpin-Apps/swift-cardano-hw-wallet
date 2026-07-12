import Testing
import Foundation
import SwiftCardanoCore
import CardanoHWKit
@testable import CardanoHWWalletLedger

/// **Live** integration tests that drive the real Ledger `app-cardano` in Speculos over
/// ``LedgerSpeculosTransport``. Gated on `LEDGER_EMULATOR=1`; require the emulator up (see
/// `Tools/emulator-ledger/`). These confirm the APDU transport, the `getVersion`/`getExtendedPublicKey`
/// exchange, and that `PublicHDDerivation` from the firmware xpub reproduces the device's own address.
@Suite("Ledger Speculos — live", .serialized)
struct LedgerSpeculosTests {
    static var emulatorEnabled: Bool { ProcessInfo.processInfo.environment["LEDGER_EMULATOR"] == "1" }

    // Golden vectors for the run.sh seed, m/1852'/1815'/0', mainnet — see Tools/emulator-ledger/README.
    private let xpubHex = "78d137231e6346f17b1d442bace1f7ba1d54a88ef8509464e2e786a854bd4815acafe34e34bf401b4b0164607ee506c4aac63a0828f1dc20ab73ec39f2fe11f3"
    private let deviceAddressHex = "016dfa09426959db1023639e8d1f07bb1e478e722c6ebc1d57ba8703b9db219ee5ce9a74f98fdadc2de13efced5a154ef8d4d41929d5bf9ff6"

    @Test("getVersion returns the Cardano app version", .enabled(if: emulatorEnabled))
    func liveVersion() async throws {
        let transport = LedgerSpeculosTransport()
        let response = try await transport.exchange(Data([0xD7, 0x00, 0x00, 0x00, 0x00]))
        transport.close()
        // Cardano ADA 7.3.1 → major.minor.patch.flags.
        #expect(response.count == 4)
        #expect(Array(response.prefix(3)) == [7, 3, 1])
    }

    @Test("importAccount returns the firmware account xpub", .enabled(if: emulatorEnabled))
    func liveImport() async throws {
        let transport = LedgerSpeculosTransport()
        let session = LedgerSignSession(transport: transport, network: .mainnet)
        let account = try await session.importAccount(network: .mainnet, accountIndex: 0)
        transport.close()

        #expect(account.deviceKind == .ledger)
        #expect(account.accountPath == "m/1852'/1815'/0'")
        #expect(account.accountXPub.toHex == xpubHex)
    }

    @Test("PublicHDDerivation from the firmware xpub reproduces the device's own address", .enabled(if: emulatorEnabled))
    func liveDeriveAddressMatches() async throws {
        let transport = LedgerSpeculosTransport()
        let session = LedgerSignSession(transport: transport, network: .mainnet)
        let account = try await session.importAccount(network: .mainnet, accountIndex: 0)

        // Ask the device for its own base address (m/1852'/1815'/0'/0/0 + stake …/2/0, mainnet).
        let deviceAddress = try await transport.exchange(Self.deriveAddressAPDU())
        transport.close()
        #expect(deviceAddress.toHex == deviceAddressHex)

        // Our public derivation must reproduce it byte-for-byte.
        let derivation = try PublicHDDerivation(accountXPub: account.accountXPub, accountPath: account.accountPath, network: .mainnet)
        let derived = try derivation.address(role: 0, index: 0)
        #expect(try Address.fromBech32(derived).toBytes() == deviceAddress)
    }

    // deriveAddress APDU (INS 0x11, P1_RETURN=0x01): addrType BASE(0) + networkId mainnet(1) +
    // spending path + staking source KEY_PATH(0x22) + staking path.
    private static func deriveAddressAPDU() throws -> Data {
        let spend = try LedgerBIP32Path("m/1852'/1815'/0'/0/0").encoded()
        let stake = try LedgerBIP32Path("m/1852'/1815'/0'/2/0").encoded()
        var data = Data([0x00, 0x01])
        data.append(spend)
        data.append(0x22)
        data.append(stake)
        return LedgerAPDU.command(ins: LedgerAPDU.INS.deriveAddress, p1: 0x01, p2: 0x00, data: data)
    }
}
