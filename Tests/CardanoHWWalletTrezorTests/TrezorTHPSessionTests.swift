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

    @Test("A paired Trezor: handshake, end, create session, then an encrypted app message")
    func pairedRoundTrip() async throws {
        let (hostLink, deviceLink) = makeLinks()
        let device = THPDeviceResponder(link: deviceLink, completionState: 0x01)
        async let deviceRun: Void = device.run(channel: 0x0003)

        let session = TrezorTHPSession(link: hostLink)
        try await session.open()
        #expect(await session.handshakeState == 0x01)
        #expect(await session.pairedThisSession == false)

        let response = try await session.exchange(TrezorMessage(type: 313, payload: Data([0xDE, 0xAD, 0xBE, 0xEF])))
        // The responder echoes the payload back under message type 999.
        #expect(response.type == 999)
        #expect(response.payload == Data([0xDE, 0xAD, 0xBE, 0xEF]))
        try await deviceRun
        #expect(await device.createdSession == 1)
        #expect(await device.createdWithCardano)
    }

    @Test("An unpaired Trezor pairs by code entry, issues a credential, and button requests are answered")
    func codeEntryPairing() async throws {
        let (hostLink, deviceLink) = makeLinks()
        let device = THPDeviceResponder(link: deviceLink, completionState: 0x00)
        async let deviceRun: Void = device.run(channel: 0x0004)

        let store = MemoryCredentialStore()
        let buttons = Counter()
        let pairing = TrezorTHPPairingHandler(hostName: "Test Mac", appName: "MansAmana") {
            await device.waitForCode()
        }
        let session = TrezorTHPSession(link: hostLink, credentialStore: store, pairing: pairing,
                                       onButtonRequest: { Task { await buttons.increment() } })
        try await session.open()
        #expect(await session.pairedThisSession)
        #expect(await session.deviceAuthenticated)
        #expect(await device.pairingRequestNames == ["Test Mac", "MansAmana"])

        let saved = await store.credentials()
        #expect(saved.count == 1)
        #expect(saved.first?.trezorStaticPublicKey == (await device.staticPublicKey))
        #expect(saved.first?.credential == (await device.issuedCredential))

        _ = try await session.exchange(TrezorMessage(type: 313, payload: Data([0x01])))
        try await deviceRun
        try await Task.sleep(for: .milliseconds(50))
        #expect(await buttons.value == 1)
    }

    @Test("A wrong pairing code is rejected by the device and never reaches the app layer")
    func wrongCode() async throws {
        let (hostLink, deviceLink) = makeLinks()
        let device = THPDeviceResponder(link: deviceLink, completionState: 0x00)
        Task { try? await device.run(channel: 0x0008) }

        let pairing = TrezorTHPPairingHandler(hostName: "h", appName: "a") {
            let code = await device.waitForCode()
            return code == "000000" ? "000001" : "000000"
        }
        let session = TrezorTHPSession(link: hostLink, pairing: pairing)
        await #expect(throws: TrezorError.self) { try await session.open() }
        #expect(await session.pairedThisSession == false)
    }

    @Test("An unpaired Trezor without a pairing handler needs pairing")
    func pairingRequired() async throws {
        let (hostLink, deviceLink) = makeLinks()
        Task { try? await THPDeviceResponder(link: deviceLink, completionState: 0x00).run(channel: 0x0009) }
        let session = TrezorTHPSession(link: hostLink)
        await #expect(throws: TrezorError.pairingRequired) { try await session.open() }
    }

    @Test("Device properties are parsed for pairing methods")
    func deviceProperties() async throws {
        let (hostLink, deviceLink) = makeLinks()
        async let deviceRun: Void = THPDeviceResponder(link: deviceLink, completionState: 0x01).run(channel: 0x000A)
        let session = TrezorTHPSession(link: hostLink)
        try await session.open()
        #expect(await session.pairingMethods == [2])
        _ = try await session.exchange(TrezorMessage(type: 313, payload: Data()))
        try await deviceRun
    }
}

func makeLinks() -> (host: PairedPacketLink, device: PairedPacketLink) {
    let hostToDevice = PacketPipe()
    let deviceToHost = PacketPipe()
    return (PairedPacketLink(inbound: deviceToHost, outbound: hostToDevice),
            PairedPacketLink(inbound: hostToDevice, outbound: deviceToHost))
}

actor MemoryCredentialStore: TrezorTHPCredentialStore {
    private var stored: [TrezorTHPCredential] = []
    func credentials() async -> [TrezorTHPCredential] { stored }
    func save(_ credential: TrezorTHPCredential) async { stored.append(credential) }
}

actor Counter {
    private(set) var value = 0
    func increment() { value += 1 }
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

/// The device side of THP, following Trezor's `docs/common/thp/specification.md`: channel
/// allocation with `ThpDeviceProperties`, the Noise XX responder with those properties as prologue,
/// Code Entry pairing (with a ButtonRequest on the pairing request), credential issuance, the end of
/// the pairing phase, `ThpCreateNewSession`, then one echoed application message.
///
/// Simplification: the responder presents its static key unmasked; the host treats the device key
/// as opaque except for credential lookup, which this responder doesn't exercise.
actor THPDeviceResponder {
    private let link: PairedPacketLink
    private var channel: UInt16 = 0
    private var deviceSeq = 0
    private var sendCipher: NoiseCipherState?
    private var recvCipher: NoiseCipherState?
    private var handshakeHash = Data()

    private let staticKey: Curve25519.KeyAgreement.PrivateKey
    private let completionState: UInt8
    static let properties: Data = {
        var w = ProtobufWriter()
        w.string(1, "T3W1")
        w.varint(3, 2)
        w.varint(4, 0)
        w.varint(5, 2)   // CodeEntry
        return w.data
    }()

    private(set) var code: String?
    private var codeWaiters: [CheckedContinuation<String, Never>] = []
    private(set) var pairingRequestNames: [String] = []
    private(set) var issuedCredential = Data((0..<24).map { _ in UInt8.random(in: 0...255) })
    private(set) var createdSession: UInt8?
    private(set) var createdWithCardano = false

    var staticPublicKey: Data { staticKey.publicKey.rawRepresentation }

    init(link: PairedPacketLink, staticKey: Curve25519.KeyAgreement.PrivateKey = .init(), completionState: UInt8 = 0x00) {
        self.link = link
        self.staticKey = staticKey
        self.completionState = completionState
    }

    /// The code the device "displays" — what the user would type into the host.
    func waitForCode() async -> String {
        if let code { return code }
        return await withCheckedContinuation { codeWaiters.append($0) }
    }

    func run(channel cid: UInt16) async throws {
        channel = cid
        try await allocateChannel()
        try await handshake()
        if completionState == 0x00 { try await pair() }
        try await endPairingPhase()
        try await createSession()
        try await echoOneAppMessage()
    }

    private func allocateChannel() async throws {
        let (control, _, nonce) = try await readMessage()
        #expect(control == TrezorTHP.Control.channelAllocationRequest)
        var payload = Data(nonce.prefix(8))
        payload.append(UInt8(channel >> 8)); payload.append(UInt8(channel & 0xff))
        payload.append(Self.properties)
        try await writePackets(TrezorTHP.packets(control: TrezorTHP.Control.channelAllocationResponse, channel: TrezorTHP.broadcastChannel, payload: payload))
    }

    private func handshake() async throws {
        let noise = NoiseXXHandshake(role: .responder, staticKey: staticKey, prologue: Self.properties)
        _ = try noise.readMessage1(try await readData().payload)                  // -> e
        try await sendData(control: TrezorTHP.Control.handshakeInitResponse, payload: try noise.writeMessage2(payload: Data()))  // <- e, ee, s, es
        let (_, send, receive) = try noise.readMessage3(try await readData().payload)  // -> s, se
        handshakeHash = noise.handshakeHash
        sendCipher = send
        recvCipher = receive
        var s = send
        let stateCiphertext = try s.encrypt(plaintext: Data([completionState]))
        sendCipher = s
        try await sendData(control: TrezorTHP.Control.handshakeCompletionResponse, payload: stateCiphertext)
    }

    private func pair() async throws {
        // TP0: pairing request → ButtonRequest/ButtonAck → approved.
        var (_, type, payload) = try await receiveApp()
        #expect(type == TrezorMessageType.thpPairingRequest)
        let request = try ProtobufReader(payload)
        pairingRequestNames = [request.string(1) ?? "", request.string(2) ?? ""]
        try await sendApp(0, TrezorMessageType.buttonRequest, Data())
        (_, type, _) = try await receiveApp()
        #expect(type == TrezorMessageType.buttonAck)
        try await sendApp(0, TrezorMessageType.thpPairingRequestApproved, Data())

        // TP1 → selected CodeEntry: commitment.
        (_, type, payload) = try await receiveApp()
        #expect(type == TrezorMessageType.thpSelectMethod)
        #expect(try ProtobufReader(payload).varint(1) == 2)
        let secret = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        var w = ProtobufWriter(); w.bytes(1, Data(SHA256.hash(data: secret)))
        try await sendApp(0, TrezorMessageType.thpCodeEntryCommitment, w.data)

        // TP2: challenge → code + CPace public key.
        (_, type, payload) = try await receiveApp()
        #expect(type == TrezorMessageType.thpCodeEntryChallenge)
        let challenge = try #require(try ProtobufReader(payload).bytes(1))
        let shown = TrezorTHPPairing.codeString(TrezorTHPPairing.code(handshakeHash: handshakeHash, secret: secret, challenge: Data(challenge)))
        code = shown
        codeWaiters.forEach { $0.resume(returning: shown) }
        codeWaiters = []
        let cpacePrivate = Curve25519.KeyAgreement.PrivateKey()
        let generator = try TrezorTHPPairing.generator(code: shown, handshakeHash: handshakeHash)
        w = ProtobufWriter(); w.bytes(1, try TrezorTHPPairing.x25519(cpacePrivate, generator))
        try await sendApp(0, TrezorMessageType.thpCodeEntryCpaceTrezor, w.data)

        // TP3a: host tag → secret, or Failure on a wrong code.
        (_, type, payload) = try await receiveApp()
        #expect(type == TrezorMessageType.thpCodeEntryCpaceHostTag)
        let hostTag = try ProtobufReader(payload)
        let hostPublic = try #require(hostTag.bytes(1))
        let shared = try TrezorTHPPairing.x25519(cpacePrivate, Data(hostPublic))
        guard hostTag.bytes(2).map(Data.init) == Data(SHA256.hash(data: shared)) else {
            var f = ProtobufWriter(); f.varint(1, 99); f.string(2, "Unexpected tag")
            try await sendApp(0, TrezorMessageType.failure, f.data)
            throw TrezorError.pairingFailed("device: wrong tag")
        }
        w = ProtobufWriter(); w.bytes(1, secret)
        try await sendApp(0, TrezorMessageType.thpCodeEntrySecret, w.data)

        // TC1: credential request → response.
        (_, type, payload) = try await receiveApp()
        #expect(type == TrezorMessageType.thpCredentialRequest)
        #expect(try ProtobufReader(payload).bytes(1)?.count == 32)
        w = ProtobufWriter(); w.bytes(1, staticPublicKey); w.bytes(2, issuedCredential)
        try await sendApp(0, TrezorMessageType.thpCredentialResponse, w.data)
    }

    private func endPairingPhase() async throws {
        let (session, type, _) = try await receiveApp()
        #expect(session == 0)
        #expect(type == TrezorMessageType.thpEndRequest)
        try await sendApp(0, TrezorMessageType.thpEndResponse, Data())
    }

    private func createSession() async throws {
        let (session, type, payload) = try await receiveApp()
        #expect(type == TrezorMessageType.thpCreateNewSession)
        createdSession = session
        createdWithCardano = try ProtobufReader(payload).varint(3) == 1
        try await sendApp(session, TrezorMessageType.success, Data())
    }

    private func echoOneAppMessage() async throws {
        let (session, _, payload) = try await receiveApp()
        try await sendApp(session, 999, payload)
    }

    // App layer over the encrypted channel.
    private func receiveApp() async throws -> (session: UInt8, type: UInt16, payload: Data) {
        guard var recv = recvCipher else { throw TrezorError.transport("no channel") }
        let app = try recv.decrypt(ciphertext: try await readData().payload)
        recvCipher = recv
        let b = Array(app)
        return (b[0], (UInt16(b[1]) << 8) | UInt16(b[2]), Data(b[3...]))
    }

    private func sendApp(_ session: UInt8, _ type: UInt16, _ payload: Data) async throws {
        guard var send = sendCipher else { throw TrezorError.transport("no channel") }
        var app = Data([session, UInt8(type >> 8), UInt8(type & 0xff)])
        app.append(payload)
        let ciphertext = try send.encrypt(plaintext: app)
        sendCipher = send
        try await sendData(control: TrezorTHP.Control.encryptedTransport, payload: ciphertext)
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
