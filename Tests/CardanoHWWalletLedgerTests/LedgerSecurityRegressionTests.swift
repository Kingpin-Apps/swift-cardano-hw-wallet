import Testing
import Foundation
import SwiftCardanoCore
import CardanoHWKit
@testable import CardanoHWWalletLedger
@testable import LedgerBLETransport

/// Regression tests for the 2026-11-07 security audit: oversized transaction content and malformed
/// BLE frames must throw instead of trapping, and addresses can be confirmed on the device.
@Suite("Ledger security regressions")
struct LedgerSecurityRegressionTests {
    private let mnemonic = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
    private let accountPath = "m/1852'/1815'/0'"

    private func engine() throws -> (PublicHDDerivation, HardwareAccountModel) {
        let root = try HDWallet.fromMnemonic(mnemonic: mnemonic)
        let account = try root.derive(fromPath: accountPath)
        let xpub = Data(account.publicKey) + Data(account.chainCode)
        let model = HardwareAccountModel(
            deviceKind: .ledger, accountXPub: xpub, masterFingerprint: Data(repeating: 0, count: 4),
            accountPath: accountPath, network: .testnet
        )
        return (try PublicHDDerivation(account: model), model)
    }

    // MARK: - APDU limits

    @Test("An APDU over 255 data bytes throws")
    func apduTooLong() {
        #expect(throws: LedgerError.self) { _ = try LedgerAPDU.command(ins: 0x21, p1: 0, p2: 0, data: Data(count: 256)) }
        #expect(throws: Never.self) { _ = try LedgerAPDU.command(ins: 0x21, p1: 0, p2: 0, data: Data(count: 255)) }
    }

    @Test("A BIP32 path longer than the Ledger limit throws when encoded")
    func pathTooLong() throws {
        let path = LedgerBIP32Path(indices: Array(repeating: 0, count: 11))
        #expect(throws: LedgerError.self) { _ = try path.encoded() }
    }

    @Test("A transaction with an oversized Byron output address throws instead of trapping")
    func oversizedByronOutput() throws {
        let byron = try ByronAddress.create(
            root: Data(repeating: 0x11, count: 28),
            attributes: ByronAddressAttributes(derivationPath: Data(repeating: 0xAA, count: 300))
        )
        let address = try Address(from: .string(byron.toBase58()))
        #expect(address.toBytes().count > LedgerCardanoSerializer.maxAddressLength)
        let input = TransactionInput(transactionId: TransactionId(payload: Data(repeating: 0x22, count: 32)), index: 0)
        let body = TransactionBody(inputs: .list([input]), outputs: [TransactionOutput(address: address, amount: Value(coin: 2_000_000))], fee: 200_000)
        let tx = Transaction(transactionBody: body, transactionWitnessSet: TransactionWitnessSet())
        #expect(throws: LedgerError.self) {
            _ = try LedgerCardanoSerializer.signTxAPDUs(
                tx, witnessPaths: [try LedgerBIP32Path("\(accountPath)/0/0")], network: .preprod, options: .init()
            )
        }
    }

    // MARK: - On-device address confirmation

    @Test("verifyAddress checks the returned address, then asks the device to display it")
    func verifyAddressMatches() async throws {
        let (derivation, account) = try engine()
        let expected = try derivation.address(role: 0, index: 0)
        let transport = MockLedgerTransport(responses: [try Address.fromBech32(expected).toBytes(), Data()])
        let session = LedgerSignSession(transport: transport, network: .preprod)
        try await session.verifyAddress(expected, account: account, role: 0, index: 0, stakeIndex: 0)
        let sent = await transport.recordedAPDUs()
        #expect(sent.count == 2)
        #expect(Array(sent[0])[1] == LedgerAPDU.INS.deriveAddress && Array(sent[0])[2] == LedgerAddressDerivation.p1Return)
        #expect(Array(sent[1])[2] == LedgerAddressDerivation.p1Display)
    }

    @Test("verifyAddress throws addressMismatch and skips the display step when the device disagrees")
    func verifyAddressMismatch() async throws {
        let (derivation, account) = try engine()
        let expected = try derivation.address(role: 0, index: 0)
        let other = try derivation.address(role: 0, index: 1)
        let transport = MockLedgerTransport(responses: [try Address.fromBech32(other).toBytes(), Data()])
        let session = LedgerSignSession(transport: transport, network: .preprod)
        await #expect(throws: HardwareWalletError.addressMismatch(expected: expected, device: other)) {
            try await session.verifyAddress(expected, account: account, role: 0, index: 0, stakeIndex: 0)
        }
        #expect(await transport.recordedAPDUs().count == 1)
    }

    // MARK: - BLE frame reassembly (vendored transport)

    @Test("Short, wrongly tagged or out-of-order BLE frames throw")
    func bleMalformedFrames() {
        var a = BleFrameAccumulator()
        #expect(throws: BleFrameAccumulator.FrameError.self) { _ = try a.push(Data([0x05, 0x00, 0x00])) }      // 3-byte first frame
        a.reset()
        #expect(throws: BleFrameAccumulator.FrameError.self) { _ = try a.push(Data([0x06, 0x00, 0x00, 0x00, 0x02, 0x90, 0x00])) }
        a.reset()
        #expect(throws: BleFrameAccumulator.FrameError.self) { _ = try a.push(Data([0x05, 0x00, 0x01, 0x00, 0x02, 0x90, 0x00])) }
        a.reset()
        #expect(throws: BleFrameAccumulator.FrameError.self) { _ = try a.push(Data()) }
    }

    @Test("BLE frames reassemble across continuations and are cut to the declared length")
    func bleReassembly() throws {
        var a = BleFrameAccumulator()
        #expect(try a.push(Data([0x05, 0x00, 0x00, 0x00, 0x04, 0xAA, 0xBB])) == nil)
        #expect(throws: BleFrameAccumulator.FrameError.self) { _ = try a.push(Data([0x05, 0x00])) }   // short continuation
        a.reset()
        #expect(try a.push(Data([0x05, 0x00, 0x00, 0x00, 0x04, 0xAA, 0xBB])) == nil)
        #expect(try a.push(Data([0x05, 0x00, 0x01, 0x90, 0x00, 0xFF, 0xFF])) == Data([0xAA, 0xBB, 0x90, 0x00]))
        // State is reset after completion: the next frame must be index 0 again.
        #expect(try a.push(Data([0x05, 0x00, 0x00, 0x00, 0x02, 0x90, 0x00])) == Data([0x90, 0x00]))
    }

    @Test("Malformed or tiny MTU replies are rejected")
    func bleMTU() {
        #expect(APDU.mtu(fromInferReply: Data([0x08, 0x00, 0x00, 0x00, 0x01, 0x99])) == 0x99)
        #expect(APDU.mtu(fromInferReply: Data([0x08])) == nil)
        #expect(APDU.mtu(fromInferReply: Data([0x08, 0x00, 0x00, 0x00, 0x01, 0x03])) == nil)
        #expect(APDU.mtu(fromInferReply: Data([0x07, 0x00, 0x00, 0x00, 0x01, 0x99])) == nil)
    }
}
