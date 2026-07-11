import Foundation
import Crypto
import CardanoHWKit

/// The host side of a Trezor **THP v2** secure channel, exposed as a ``TrezorTransport`` so the
/// Cardano dialogue in ``TrezorSignSession`` runs over it unchanged. It performs:
///
/// 1. **Channel allocation** — request a channel id from the device on the broadcast channel.
/// 2. **Noise XX handshake** — ``NoiseXXHandshake`` over THP packets, with the Alternating Bit
///    Protocol (each data message is ACKed), yielding the two transport cipher states.
/// 3. **Encrypted transport** — application messages are framed `session_id ‖ msg_type ‖ protobuf`,
///    AEAD-encrypted, THP-packetized, and ABP-sequenced.
///
/// The channel + handshake + encrypted exchange are unit-tested against a local device responder
/// (see the tests). **Device-gated:** the pairing sub-protocol (SkipPairing / Code / QR / NFC), the
/// credential phase, `ThpEndRequest`, and `ThpCreateNewSession` session establishment happen between
/// the handshake and the first app message on a real device — that choreography needs a physical
/// newest-firmware Trezor. This session uses `session_id 0` and assumes a trusted (already-paired or
/// SkipPairing) device.
public actor TrezorTHPSession: TrezorTransport {
    private let link: HardwarePacketLink
    private let hostStatic: Curve25519.KeyAgreement.PrivateKey
    private let sessionId: UInt8

    private var channel: UInt16 = 0
    private var sendCipher: NoiseCipherState?
    private var recvCipher: NoiseCipherState?
    private var hostSeq = 0
    private var opened = false

    public init(link: HardwarePacketLink, sessionId: UInt8 = 0) {
        self.link = link
        self.hostStatic = Curve25519.KeyAgreement.PrivateKey()
        self.sessionId = sessionId
    }

    // MARK: - TrezorTransport

    public func open() async throws {
        guard !opened else { return }
        try await link.open()
        try await allocateChannel()
        try await handshake()
        opened = true
    }

    public func exchange(_ message: TrezorMessage) async throws -> (type: UInt16, payload: Data) {
        if !opened { try await open() }
        guard var send = sendCipher, var recv = recvCipher else {
            throw TrezorError.transport("THP secure channel is not established.")
        }
        // Application layer: session_id ‖ message_type (BE) ‖ protobuf.
        var app = Data([sessionId, UInt8(message.type >> 8), UInt8(message.type & 0xff)])
        app.append(message.payload)

        let ciphertext = try send.encrypt(plaintext: app)
        sendCipher = send
        try await sendData(control: TrezorTHP.Control.encryptedTransport, payload: ciphertext)

        let (_, responseCiphertext) = try await readData()
        let plaintext = try recv.decrypt(ciphertext: responseCiphertext)
        recvCipher = recv

        guard plaintext.count >= 3 else { throw TrezorError.malformedResponse("Short THP application message.") }
        let bytes = Array(plaintext)
        let type = (UInt16(bytes[1]) << 8) | UInt16(bytes[2])
        let payload = Data(bytes[3...])
        if type == TrezorMessageType.failure {
            let reader = try ProtobufReader(payload)
            throw TrezorError.failure(code: Int(reader.varint(1) ?? 0), message: reader.string(2) ?? "")
        }
        return (type, payload)
    }

    // MARK: - Channel allocation

    private func allocateChannel() async throws {
        let nonce = Data((0..<8).map { _ in UInt8.random(in: 0...255) })
        try await writePackets(TrezorTHP.packets(
            control: TrezorTHP.Control.channelAllocationRequest, channel: TrezorTHP.broadcastChannel, payload: nonce
        ))
        let (control, _, payload) = try await readMessage()
        guard control == TrezorTHP.Control.channelAllocationResponse, payload.count >= 10 else {
            throw TrezorError.malformedResponse("Unexpected channel-allocation response.")
        }
        guard payload.prefix(8) == nonce else {
            throw TrezorError.malformedResponse("Channel-allocation nonce mismatch.")
        }
        let b = Array(payload)
        channel = (UInt16(b[8]) << 8) | UInt16(b[9])
    }

    // MARK: - Noise XX handshake

    private func handshake() async throws {
        let noise = NoiseXXHandshake(role: .initiator, staticKey: hostStatic)

        // -> e   (try_to_unlock = 0)
        try await sendData(control: TrezorTHP.Control.handshakeInitRequest, payload: try noise.writeMessage1(payload: Data([0x00])))
        // <- e, ee, s, es
        _ = try noise.readMessage2(try await readData().payload)
        // -> s, se   (empty ThpHandshakeCompletionReqNoisePayload = no pairing credential)
        let (msg3, send, receive) = try noise.writeMessage3(payload: Data())
        try await sendData(control: TrezorTHP.Control.handshakeCompletionRequest, payload: msg3)
        sendCipher = send
        recvCipher = receive

        // Handshake completion response: encrypted trezor state, decrypted with the receive cipher.
        var r = receive
        _ = try r.decrypt(ciphertext: try await readData().payload)
        recvCipher = r
    }

    // MARK: - ABP data send / receive

    /// Send a data message (handshake or encrypted_transport) with the current sequence bit, then wait
    /// for its acknowledgement before returning.
    private func sendData(control base: UInt8, payload: Data) async throws {
        try await writePackets(TrezorTHP.packets(control: TrezorTHP.control(base, sequence: hostSeq), channel: channel, payload: payload))
        while true {
            let (control, _, _) = try await readMessage()
            if control & 0xF7 == TrezorTHP.Control.ack {
                let ackSeq = (control & 0x08) != 0 ? 1 : 0
                if ackSeq == hostSeq { break }
            }
        }
        hostSeq ^= 1
    }

    /// Read a data message, acknowledge it, and return `(control-without-seq, payload)`.
    private func readData() async throws -> (control: UInt8, payload: Data) {
        let (control, _, payload) = try await readMessage()
        let seq = (control & 0x10) != 0 ? 1 : 0
        try await writePackets(TrezorTHP.packets(control: TrezorTHP.ackControl(sequence: seq), channel: channel, payload: Data()))
        return (control & 0xE7, payload)
    }

    // MARK: - Packet I/O

    private func writePackets(_ packets: [Data]) async throws {
        for packet in packets { try await link.write(packet) }
    }

    private func readMessage() async throws -> (control: UInt8, channel: UInt16, payload: Data) {
        var reassembler = TrezorTHP.Reassembler()
        while true {
            if let message = try reassembler.push(try await link.read()) { return message }
        }
    }
}
