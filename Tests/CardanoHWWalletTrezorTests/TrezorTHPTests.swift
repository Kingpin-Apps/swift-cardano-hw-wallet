import Testing
import Foundation
import Crypto
@testable import CardanoHWWalletTrezor

@Suite("Trezor THP (v2)")
struct TrezorTHPTests {

    // MARK: - Noise XX handshake (local initiator ↔ responder)

    @Test("A full Noise_XX handshake completes and both sides derive matching transport keys")
    func noiseHandshake() throws {
        let hostStatic = Curve25519.KeyAgreement.PrivateKey()
        let deviceStatic = Curve25519.KeyAgreement.PrivateKey()
        let host = NoiseXXHandshake(role: .initiator, staticKey: hostStatic)
        let device = NoiseXXHandshake(role: .responder, staticKey: deviceStatic)

        // -> e   (with a try_to_unlock byte payload)
        let msg1 = try host.writeMessage1(payload: Data([0x00]))
        #expect(try device.readMessage1(msg1) == Data([0x00]))

        // <- e, ee, s, es
        let msg2 = try device.writeMessage2(payload: Data())
        #expect(msg2.count == 32 + 48 + 16)
        #expect(try host.readMessage2(msg2).isEmpty)
        #expect(host.remoteStaticKey == deviceStatic.publicKey.rawRepresentation)  // host learned device static

        // -> s, se
        let (msg3, hostSendInit, hostRecvInit) = try host.writeMessage3(payload: Data([0x11, 0x22]))
        let (payload3, deviceSendInit, deviceRecvInit) = try device.readMessage3(msg3)
        #expect(payload3 == Data([0x11, 0x22]))
        #expect(device.remoteStaticKey == hostStatic.publicKey.rawRepresentation) // device learned host static

        // Transport works both directions with the split keys.
        var hostSend = hostSendInit, hostRecv = hostRecvInit
        var deviceSend = deviceSendInit, deviceRecv = deviceRecvInit

        let a = try hostSend.encrypt(plaintext: Data("hello device".utf8))
        #expect(try deviceRecv.decrypt(ciphertext: a) == Data("hello device".utf8))

        let b = try deviceSend.encrypt(plaintext: Data("hello host".utf8))
        #expect(try hostRecv.decrypt(ciphertext: b) == Data("hello host".utf8))

        // Nonces advance: a second message still decrypts.
        let c = try hostSend.encrypt(plaintext: Data("second".utf8))
        #expect(try deviceRecv.decrypt(ciphertext: c) == Data("second".utf8))
    }

    @Test("A tampered handshake message is rejected")
    func noiseTamper() throws {
        let host = NoiseXXHandshake(role: .initiator, staticKey: Curve25519.KeyAgreement.PrivateKey())
        let device = NoiseXXHandshake(role: .responder, staticKey: Curve25519.KeyAgreement.PrivateKey())
        _ = try device.readMessage1(try host.writeMessage1(payload: Data([0x00])))
        var msg2 = Array(try device.writeMessage2(payload: Data()))
        msg2[40] ^= 0xFF   // flip a byte inside the encrypted static
        #expect(throws: (any Error).self) {
            _ = try host.readMessage2(Data(msg2))
        }
    }

    // MARK: - Transport framing + CRC

    @Test("CRC-32-IEEE matches the standard check value")
    func crc32Vector() {
        #expect(TrezorTHP.crc32(Data("123456789".utf8)) == 0xCBF4_3926)
    }

    @Test("THP packets round-trip across sizes with CRC validation")
    func packetRoundTrip() throws {
        for len in [0, 1, 58, 59, 60, 61, 122, 500] {
            let payload = Data((0..<len).map { UInt8(($0 * 31) & 0xff) })
            let control = TrezorTHP.control(TrezorTHP.Control.encryptedTransport, sequence: len % 2)
            let packets = TrezorTHP.packets(control: control, channel: 0x1234, payload: payload)
            for p in packets { #expect(p.count == TrezorTHP.reportSize) }

            var reasm = TrezorTHP.Reassembler()
            var out: (control: UInt8, channel: UInt16, payload: Data)?
            for p in packets { out = try reasm.push(p) }
            #expect(out?.control == control)
            #expect(out?.channel == 0x1234)
            #expect(out?.payload == payload)
        }
    }

    @Test("First packet carries control, channel, and the payload+CRC length")
    func initiationHeader() throws {
        let payload = Data(repeating: 0xAB, count: 10)
        let packets = TrezorTHP.packets(control: TrezorTHP.Control.handshakeInitRequest, channel: 0xFFFF, payload: payload)
        let head = Array(packets[0])
        #expect(head[0] == 0x00)                       // handshake_init_request
        #expect(head[1] == 0xFF && head[2] == 0xFF)    // broadcast channel
        #expect(head[3] == 0x00 && head[4] == 14)      // length = 10 payload + 4 CRC
    }

    @Test("A corrupted CRC is rejected")
    func crcRejected() throws {
        var packets = TrezorTHP.packets(control: TrezorTHP.Control.encryptedTransport, channel: 0x1, payload: Data(repeating: 0x01, count: 20))
        var bytes = Array(packets[0])
        bytes[27] ^= 0xFF   // flip a payload byte so the CRC no longer matches
        packets[0] = Data(bytes)
        var reasm = TrezorTHP.Reassembler()
        #expect(throws: TrezorError.self) {
            _ = try reasm.push(packets[0])
        }
    }

    @Test("Sequence + ACK control bytes set the right bits")
    func controlBits() {
        #expect(TrezorTHP.control(TrezorTHP.Control.encryptedTransport, sequence: 0) == 0x04)
        #expect(TrezorTHP.control(TrezorTHP.Control.encryptedTransport, sequence: 1) == 0x14)
        #expect(TrezorTHP.ackControl(sequence: 0) == 0x20)
        #expect(TrezorTHP.ackControl(sequence: 1) == 0x28)
    }
}
