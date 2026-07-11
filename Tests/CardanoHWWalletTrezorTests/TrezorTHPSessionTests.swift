import Testing
import Foundation
import Crypto
import CardanoHWKit
@testable import CardanoHWWalletTrezor

/// Drives a real ``TrezorTHPSession`` (host) against a local device responder over a paired in-memory
/// link — proving channel allocation + the Noise XX handshake + the encrypted ABP transport all
/// interoperate end-to-end, without a physical Trezor.
@Suite("Trezor THP session")
struct TrezorTHPSessionTests {

    @Test("open() + exchange() over the encrypted THP channel round-trips an app message")
    func encryptedRoundTrip() async throws {
        let hostToDevice = PacketPipe()
        let deviceToHost = PacketPipe()
        let hostLink = PairedPacketLink(inbound: deviceToHost, outbound: hostToDevice)
        let deviceLink = PairedPacketLink(inbound: hostToDevice, outbound: deviceToHost)

        // The device runs concurrently: allocate a channel, respond to the handshake, echo one app message.
        async let deviceRun: Void = THPDeviceResponder(link: deviceLink).run(channel: 0x0003)

        let session = TrezorTHPSession(link: hostLink)
        try await session.open()

        let response = try await session.exchange(TrezorMessage(type: 313, payload: Data([0xDE, 0xAD, 0xBE, 0xEF])))
        // The responder echoes the payload back under message type 999.
        #expect(response.type == 999)
        #expect(response.payload == Data([0xDE, 0xAD, 0xBE, 0xEF]))

        try await deviceRun
    }
}

// MARK: - Paired in-memory packet link

/// A one-directional async packet queue.
actor PacketPipe {
    private var buffer: [Data] = []
    private var waiters: [CheckedContinuation<Data, Never>] = []

    func send(_ packet: Data) {
        if waiters.isEmpty { buffer.append(packet) } else { waiters.removeFirst().resume(returning: packet) }
    }

    func receive() async -> Data {
        if !buffer.isEmpty { return buffer.removeFirst() }
        return await withCheckedContinuation { waiters.append($0) }
    }
}

/// A ``HardwarePacketLink`` endpoint over a pair of pipes (writes to `outbound`, reads from `inbound`).
final class PairedPacketLink: HardwarePacketLink, @unchecked Sendable {
    private let inbound: PacketPipe
    private let outbound: PacketPipe
    init(inbound: PacketPipe, outbound: PacketPipe) { self.inbound = inbound; self.outbound = outbound }
    func open() async throws {}
    func write(_ packet: Data) async throws { await outbound.send(packet) }
    func read() async throws -> Data { await inbound.receive() }
    func close() async {}
}

// MARK: - Local THP device responder

/// The device side of the THP protocol, just enough to run channel allocation, the Noise XX
/// responder handshake, and echo a single encrypted application message.
actor THPDeviceResponder {
    private let link: PairedPacketLink
    private var channel: UInt16 = 0
    private var deviceSeq = 0
    private var sendCipher: NoiseCipherState?
    private var recvCipher: NoiseCipherState?

    init(link: PairedPacketLink) { self.link = link }

    func run(channel cid: UInt16) async throws {
        channel = cid
        try await allocateChannel()
        try await handshake()
        try await echoOneAppMessage()
    }

    private func allocateChannel() async throws {
        let (control, _, nonce) = try await readMessage()
        #expect(control == TrezorTHP.Control.channelAllocationRequest)
        // Response payload: nonce ‖ cid ‖ (minimal device properties, ignored by the host here).
        var payload = nonce.prefix(8)
        payload.append(UInt8(channel >> 8)); payload.append(UInt8(channel & 0xff))
        payload.append(Data([0x00]))   // placeholder properties
        try await writePackets(TrezorTHP.packets(control: TrezorTHP.Control.channelAllocationResponse, channel: TrezorTHP.broadcastChannel, payload: Data(payload)))
    }

    private func handshake() async throws {
        let noise = NoiseXXHandshake(role: .responder, staticKey: Curve25519.KeyAgreement.PrivateKey())
        _ = try noise.readMessage1(try await readData().payload)                  // -> e
        try await sendData(control: TrezorTHP.Control.handshakeInitResponse, payload: try noise.writeMessage2(payload: Data()))  // <- e, ee, s, es
        let (_, send, receive) = try noise.readMessage3(try await readData().payload)  // -> s, se
        sendCipher = send
        recvCipher = receive
        // Completion response: encrypted device state, sent with the device's send cipher.
        var s = send
        let stateCiphertext = try s.encrypt(plaintext: Data([0x00]))
        sendCipher = s
        try await sendData(control: TrezorTHP.Control.handshakeCompletionResponse, payload: stateCiphertext)
    }

    private func echoOneAppMessage() async throws {
        guard var recv = recvCipher, var send = sendCipher else { return }
        let requestCiphertext = try await readData().payload
        let app = try recv.decrypt(ciphertext: requestCiphertext)
        recvCipher = recv
        // app = session_id ‖ type ‖ payload; echo the payload under type 999.
        let payload = Data(Array(app)[3...])
        var response = Data([app.first ?? 0, UInt8(999 >> 8), UInt8(999 & 0xff)])
        response.append(payload)
        let responseCiphertext = try send.encrypt(plaintext: response)
        sendCipher = send
        try await sendData(control: TrezorTHP.Control.encryptedTransport, payload: responseCiphertext)
    }

    // ABP helpers (device side).
    private func sendData(control base: UInt8, payload: Data) async throws {
        try await writePackets(TrezorTHP.packets(control: TrezorTHP.control(base, sequence: deviceSeq), channel: channel, payload: payload))
        while true {
            let (control, _, _) = try await readMessage()
            if control & 0xF7 == TrezorTHP.Control.ack, ((control & 0x08) != 0 ? 1 : 0) == deviceSeq { break }
        }
        deviceSeq ^= 1
    }

    private func readData() async throws -> (control: UInt8, payload: Data) {
        let (control, _, payload) = try await readMessage()
        let seq = (control & 0x10) != 0 ? 1 : 0
        try await writePackets(TrezorTHP.packets(control: TrezorTHP.ackControl(sequence: seq), channel: channel, payload: Data()))
        return (control & 0xE7, payload)
    }

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
