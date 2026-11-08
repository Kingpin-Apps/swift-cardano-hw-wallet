import Testing
import Foundation
import Crypto
import CardanoHWKit
@testable import CardanoHWWalletTrezor

/// Regression tests for the 2026-11-07 security audit: device-controlled bytes must produce thrown
/// errors, never traps, and the THP channel can be bound to a known device key.
@Suite("Trezor security regressions")
struct TrezorSecurityRegressionTests {

    // MARK: - Failure code (UInt64 → Int)

    @Test("A Failure with code UInt64.max throws instead of trapping")
    func failureCodeAboveIntMax() async throws {
        var f = ProtobufWriter()
        f.varint(1, UInt64.max)
        f.string(2, "x")
        let link = MockPacketLink(inbound: TrezorProtocolV1.encode(messageType: TrezorMessageType.failure, payload: f.data))
        do {
            _ = try await TrezorV1Transport(link: link).exchange(TrezorCardanoSerializer.hostAckMessage())
            Issue.record("expected a thrown failure")
        } catch TrezorError.failure(let code, let message) {
            #expect(code == Int.max)
            #expect(message == "x")
        }
    }

    // MARK: - Protobuf reader

    @Test("A length-delimited field with a 10-byte maximum length throws")
    func protobufHugeLength() {
        // field 2, wire type 2, length = 2^64 - 1
        let payload = Data([0x12, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01])
        #expect(throws: TrezorError.self) { _ = try ProtobufReader(payload) }
    }

    @Test("Truncated fixed32 and fixed64 fields throw")
    func protobufTruncatedFixed() {
        #expect(throws: TrezorError.self) { _ = try ProtobufReader(Data([0x0d, 0x01, 0x02])) }        // field 1 fixed32, 2 of 4 bytes
        #expect(throws: TrezorError.self) { _ = try ProtobufReader(Data([0x09, 0x01, 0x02, 0x03])) }  // field 1 fixed64, 3 of 8 bytes
        #expect(throws: Never.self) { _ = try ProtobufReader(Data([0x0d, 0x01, 0x02, 0x03, 0x04])) }  // complete fixed32 is skipped
    }

    // MARK: - THP reassembler

    @Test("A THP initiation packet declaring a length below the CRC size throws", arguments: [0, 1, 2, 3])
    func thpLengthBelowCRC(length: Int) {
        var reassembler = TrezorTHP.Reassembler()
        let packet = Data([0x04, 0x00, 0x03, 0x00, UInt8(length)]) + Data(repeating: 0, count: 59)
        #expect(throws: TrezorError.self) { _ = try reassembler.push(packet) }
    }

    @Test("TrezorTHPSession.open() throws on a length-2 packet from the device")
    func thpSessionShortLength() async {
        let link = MockPacketLink(inbound: [Data([0x40, 0xff, 0xff, 0x00, 0x02]) + Data(repeating: 0, count: 59)])
        let session = TrezorTHPSession(link: link)
        await #expect(throws: TrezorError.self) { try await session.open() }
    }

    // MARK: - THP device authentication

    @Test("open() fails closed when the pinned device key does not match")
    func thpPinnedKeyMismatch() async throws {
        let hostToDevice = PacketPipe()
        let deviceToHost = PacketPipe()
        let hostLink = PairedPacketLink(inbound: deviceToHost, outbound: hostToDevice)
        let deviceLink = PairedPacketLink(inbound: hostToDevice, outbound: deviceToHost)
        // The impostor never gets message 3, so it is left waiting; run it unstructured.
        Task { try? await THPDeviceResponder(link: deviceLink).run(channel: 0x0005) }

        let genuine = Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation
        let session = TrezorTHPSession(link: hostLink, deviceKeyVerifier: .pinned(genuine))
        await #expect(throws: TrezorError.self) { try await session.open() }
        #expect(await session.deviceAuthenticated == false)
    }

    @Test("open() succeeds and reports authentication when the verifier accepts the device key")
    func thpVerifierAccepts() async throws {
        let hostToDevice = PacketPipe()
        let deviceToHost = PacketPipe()
        let hostLink = PairedPacketLink(inbound: deviceToHost, outbound: hostToDevice)
        let deviceLink = PairedPacketLink(inbound: hostToDevice, outbound: deviceToHost)
        let deviceKey = Curve25519.KeyAgreement.PrivateKey()
        async let deviceRun: Void = THPDeviceResponder(link: deviceLink, staticKey: deviceKey, completionState: 0x01).run(channel: 0x0006)

        // The in-memory responder sends its raw static key, so accept exactly that key.
        let expected = deviceKey.publicKey.rawRepresentation
        let session = TrezorTHPSession(link: hostLink, deviceKeyVerifier: .init { masked, _ in masked == expected })
        try await session.open()
        #expect(await session.deviceAuthenticated)
        #expect(await session.handshakeState == 0x01)
        _ = try await session.exchange(TrezorMessage(type: 313, payload: Data([0x01])))
        try await deviceRun
    }

    @Test("Without a verifier the session reports the device as unauthenticated")
    func thpDefaultUnauthenticated() async throws {
        let hostToDevice = PacketPipe()
        let deviceToHost = PacketPipe()
        let hostLink = PairedPacketLink(inbound: deviceToHost, outbound: hostToDevice)
        let deviceLink = PairedPacketLink(inbound: hostToDevice, outbound: deviceToHost)
        async let deviceRun: Void = THPDeviceResponder(link: deviceLink).run(channel: 0x0007)
        let session = TrezorTHPSession(link: hostLink)
        try await session.open()
        #expect(await session.deviceAuthenticated == false)
        #expect(await session.handshakeState == 0x00)
        _ = try await session.exchange(TrezorMessage(type: 313, payload: Data([0x01])))
        try await deviceRun
    }

    @Test("The masked static key is X25519(SHA-256(static ‖ ephemeral), static)")
    func maskedStaticKey() throws {
        let staticKey = Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation
        let ephemeral = Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation
        let masked = try TrezorTHPSession.maskedStaticKey(staticKey, deviceEphemeralKey: ephemeral)
        let scalar = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: Data(SHA256.hash(data: staticKey + ephemeral)))
        let manual = try scalar.sharedSecretFromKeyAgreement(with: .init(rawRepresentation: staticKey)).withUnsafeBytes { Data($0) }
        #expect(masked == manual)
        #expect(TrezorTHPSession.DeviceKeyVerifier.pinned(staticKey).accepts(masked, ephemeral))
        #expect(!TrezorTHPSession.DeviceKeyVerifier.pinned(staticKey).accepts(staticKey, ephemeral))
    }

    // MARK: - On-device address confirmation

    @Test("CardanoGetAddress encodes show_display, network and the base-address paths")
    func getAddressMessage() throws {
        let message = try TrezorAddressDerivation.getAddressMessage(
            spendingPath: "m/1852'/1815'/0'/0/0", stakingPath: "m/1852'/1815'/0'/2/0",
            network: .preprod, derivationType: .icarus, showDisplay: true
        )
        #expect(message.type == TrezorMessageType.cardanoGetAddress)
        let reader = try ProtobufReader(message.payload)
        #expect(reader.varint(2) == 1)          // show_display
        #expect(reader.varint(3) == 1)          // protocol_magic (preprod)
        #expect(reader.varint(4) == 0)          // network_id
        #expect(reader.varint(6) == 1)          // derivation_type icarus
        let params = try ProtobufReader(try #require(reader.bytes(5)))
        #expect(params.varint(1) == 0)          // BASE
    }

    @Test("verifyAddress throws addressMismatch when the device derives another address")
    func verifyAddressMismatch() async throws {
        var reply = ProtobufWriter()
        reply.string(1, "addr_test1device")
        let link = MockPacketLink(inbound: TrezorProtocolV1.encode(messageType: TrezorMessageType.cardanoAddress, payload: reply.data))
        let session = TrezorSignSession(link: link, network: .preprod)
        let account = HardwareAccountModel(
            deviceKind: .trezor, accountXPub: Data(repeating: 1, count: 64),
            masterFingerprint: Data(repeating: 0, count: 4), accountPath: "m/1852'/1815'/0'", network: .testnet
        )
        await #expect(throws: HardwareWalletError.addressMismatch(expected: "addr_test1expected", device: "addr_test1device")) {
            try await session.verifyAddress("addr_test1expected", account: account, role: 0, index: 0, stakeIndex: 0)
        }
    }
}
