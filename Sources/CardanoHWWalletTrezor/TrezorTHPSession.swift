import Foundation
import Crypto
import CardanoHWKit

/// The host side of a Trezor **THP v2** secure channel, exposed as a ``TrezorTransport`` so the
/// Cardano dialogue in ``TrezorSignSession`` runs over it unchanged. ``open()`` runs the whole
/// connection process from Trezor's `docs/common/thp/specification.md`:
///
/// 1. **Channel allocation** — request a channel id on the broadcast channel; the response carries
///    the device properties, which seed the handshake (Noise prologue).
/// 2. **Noise XX handshake** (`Noise_XX_25519_AESGCM_SHA256`) with the Alternating Bit Protocol.
///    When a ``TrezorTHPCredentialStore`` holds a credential for this Trezor, the host presents it
///    (with the host static key it was issued for) so pairing is skipped.
/// 3. **Pairing** (unpaired devices only) by **Code Entry**: the Trezor shows a 6-digit code, the
///    app asks the user for it through ``TrezorTHPPairingHandler``, and CPace proves both sides saw
///    the same code. This is what protects the channel against a man in the middle.
/// 4. **Credential phase** — after pairing, ask the Trezor for a credential and save it, then end.
/// 5. **Session** — `ThpCreateNewSession { derive_cardano = true }` on ``sessionId``.
///
/// Application messages are framed `session_id ‖ msg_type ‖ protobuf`, AEAD-encrypted, packetized,
/// and ABP-sequenced. Device `ButtonRequest`s are answered with `ButtonAck` (and reported through
/// `onButtonRequest`) while the user confirms on the device.
///
/// **Device authentication.** ``deviceAuthenticated`` is `true` after Code Entry pairing, after a
/// handshake that matched a stored credential, or when a ``DeviceKeyVerifier`` accepted the device
/// key. A verifier makes ``open()`` fail closed before any application message on a mismatch.
public actor TrezorTHPSession: TrezorTransport {
    /// Decides whether the device static key presented in handshake message 2 is acceptable.
    public struct DeviceKeyVerifier: Sendable {
        /// Called with `(maskedStaticKey, deviceEphemeralKey)`, both 32-byte X25519 public keys.
        public let accepts: @Sendable (_ maskedStaticKey: Data, _ deviceEphemeralKey: Data) -> Bool

        public init(_ accepts: @escaping @Sendable (_ maskedStaticKey: Data, _ deviceEphemeralKey: Data) -> Bool) {
            self.accepts = accepts
        }

        /// Accepts only the device whose (unmasked) THP static public key is `deviceStaticKey`.
        /// The device sends `X25519(SHA-256(static ‖ ephemeral), static)`; this recomputes that
        /// mask from the pinned key and the handshake's device ephemeral key and compares.
        public static func pinned(_ deviceStaticKey: Data) -> DeviceKeyVerifier {
            DeviceKeyVerifier { masked, ephemeral in
                guard let expected = try? TrezorTHPSession.maskedStaticKey(deviceStaticKey, deviceEphemeralKey: ephemeral) else {
                    return false
                }
                return expected == masked
            }
        }
    }

    /// `X25519(SHA-256(staticKey ‖ ephemeralKey), staticKey)` — the masked device static key THP sends.
    public static func maskedStaticKey(_ staticKey: Data, deviceEphemeralKey: Data) throws -> Data {
        let scalar = Data(SHA256.hash(data: staticKey + deviceEphemeralKey))
        return try NoiseCrypto.dh(try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: scalar), staticKey)
    }

    private let link: HardwarePacketLink
    private var hostStatic: Curve25519.KeyAgreement.PrivateKey
    private let sessionId: UInt8
    private let deviceKeyVerifier: DeviceKeyVerifier?
    private let credentialStore: TrezorTHPCredentialStore?
    private let pairing: TrezorTHPPairingHandler?
    private let deriveCardano: Bool
    private let onButtonRequest: (@Sendable () -> Void)?

    /// `true` once the device is authenticated (paired by code, matched a stored credential, or
    /// accepted by a ``DeviceKeyVerifier``).
    public private(set) var deviceAuthenticated = false
    /// The decrypted handshake-completion state byte from the device (0 unpaired, 1 paired,
    /// 2 paired with autoconnect), or `nil` before ``open()``.
    public private(set) var handshakeState: UInt8?
    /// The `ThpDeviceProperties` bytes from channel allocation.
    public private(set) var deviceProperties = Data()
    /// `true` when this connection went through Code Entry pairing.
    public private(set) var pairedThisSession = false

    private var channel: UInt16 = 0
    private var handshakeHash = Data()
    private var sendCipher: NoiseCipherState?
    private var recvCipher: NoiseCipherState?
    private var hostSeq = 0
    private var opened = false

    /// - Parameters:
    ///   - sessionId: The THP session the Cardano messages run on (created during ``open()``).
    ///   - hostStaticKey: The host's Noise static key for new pairings. A stored credential brings its
    ///     own key.
    ///   - deviceKeyVerifier: When set, ``open()`` throws unless it accepts the device static key.
    ///   - credentialStore: Supplies credentials for known Trezors and saves new ones after pairing.
    ///   - pairing: Asks the user for the pairing code. Without it, an unpaired Trezor makes ``open()``
    ///     throw ``TrezorError/pairingRequired``.
    ///   - deriveCardano: Ask the device to derive Cardano keys for the session (needed for Cardano).
    ///   - onButtonRequest: Called each time the device waits for the user to confirm on screen.
    public init(
        link: HardwarePacketLink,
        sessionId: UInt8 = 1,
        hostStaticKey: Curve25519.KeyAgreement.PrivateKey = Curve25519.KeyAgreement.PrivateKey(),
        deviceKeyVerifier: DeviceKeyVerifier? = nil,
        credentialStore: TrezorTHPCredentialStore? = nil,
        pairing: TrezorTHPPairingHandler? = nil,
        deriveCardano: Bool = true,
        onButtonRequest: (@Sendable () -> Void)? = nil
    ) {
        self.link = link
        self.hostStatic = hostStaticKey
        self.sessionId = sessionId
        self.deviceKeyVerifier = deviceKeyVerifier
        self.credentialStore = credentialStore
        self.pairing = pairing
        self.deriveCardano = deriveCardano
        self.onButtonRequest = onButtonRequest
    }

    /// The pairing methods the device advertised (``TrezorTHPPairing/Method`` raw values).
    public var pairingMethods: [UInt8] {
        guard let reader = try? ProtobufReader(deviceProperties) else { return [] }
        return reader.repeatedVarint(5).compactMap { UInt8(exactly: $0) }
    }

    // MARK: - TrezorTransport

    public func open() async throws {
        guard !opened else { return }
        try await link.open()
        try await allocateChannel()
        try await handshake()
        try await establish()
        opened = true
    }

    public func exchange(_ message: TrezorMessage) async throws -> (type: UInt16, payload: Data) {
        if !opened { try await open() }
        return try await call(message.type, message.payload, session: sessionId)
    }

    // MARK: - Pairing, credential and session phases

    private func establish() async throws {
        if handshakeState == 0 {
            guard let pairing else { throw TrezorError.pairingRequired }
            try await pairByCodeEntry(pairing)
            if let credentialStore { try await requestCredential(into: credentialStore) }
        }
        // Leave the pairing/credential phase; a paired Trezor may ask the user to allow the
        // connection here, which `call` answers through the ButtonRequest loop.
        try await expect(call(TrezorMessageType.thpEndRequest, Data(), session: 0), TrezorMessageType.thpEndResponse)

        var create = ProtobufWriter()
        if deriveCardano { create.bool(3, true) }
        try await expect(call(TrezorMessageType.thpCreateNewSession, create.data, session: sessionId), TrezorMessageType.success)
    }

    private func pairByCodeEntry(_ handler: TrezorTHPPairingHandler) async throws {
        let methods = pairingMethods
        guard methods.isEmpty || methods.contains(TrezorTHPPairing.Method.codeEntry.rawValue) else {
            throw TrezorError.pairingFailed("This Trezor doesn't offer code-entry pairing.")
        }

        var request = ProtobufWriter()
        request.string(1, handler.hostName)
        request.string(2, handler.appName)
        try await expect(call(TrezorMessageType.thpPairingRequest, request.data, session: 0), TrezorMessageType.thpPairingRequestApproved)

        var select = ProtobufWriter()
        select.varint(1, UInt64(TrezorTHPPairing.Method.codeEntry.rawValue))
        let commitmentMessage = try await call(TrezorMessageType.thpSelectMethod, select.data, session: 0)
        try expect(commitmentMessage, TrezorMessageType.thpCodeEntryCommitment)
        guard let commitment = try ProtobufReader(commitmentMessage.payload).bytes(1), commitment.count == 32 else {
            throw TrezorError.malformedResponse("THP code-entry commitment is missing.")
        }

        let challenge = Data((0..<16).map { _ in UInt8.random(in: 0...255) })
        var challengeMessage = ProtobufWriter()
        challengeMessage.bytes(1, challenge)
        let cpace = try await call(TrezorMessageType.thpCodeEntryChallenge, challengeMessage.data, session: 0)
        try expect(cpace, TrezorMessageType.thpCodeEntryCpaceTrezor)
        guard let trezorPublicKey = try ProtobufReader(cpace.payload).bytes(1), trezorPublicKey.count == 32 else {
            throw TrezorError.malformedResponse("THP CPace public key is missing.")
        }

        let code = try await handler.requestCode().trimmingCharacters(in: .whitespacesAndNewlines)
        let host = try TrezorTHPPairing.hostTag(code: code, handshakeHash: handshakeHash, trezorPublicKey: Data(trezorPublicKey))
        var tagMessage = ProtobufWriter()
        tagMessage.bytes(1, host.publicKey)
        tagMessage.bytes(2, host.tag)
        let secretMessage = try await call(TrezorMessageType.thpCodeEntryCpaceHostTag, tagMessage.data, session: 0)
        try expect(secretMessage, TrezorMessageType.thpCodeEntrySecret)
        guard let secret = try ProtobufReader(secretMessage.payload).bytes(1) else {
            throw TrezorError.malformedResponse("THP pairing secret is missing.")
        }
        try TrezorTHPPairing.verify(secret: Data(secret), commitment: Data(commitment), handshakeHash: handshakeHash,
                                    challenge: challenge, enteredCode: code)
        deviceAuthenticated = true
        pairedThisSession = true
    }

    private func requestCredential(into store: TrezorTHPCredentialStore) async throws {
        var request = ProtobufWriter()
        request.bytes(1, hostStatic.publicKey.rawRepresentation)
        let response = try await call(TrezorMessageType.thpCredentialRequest, request.data, session: 0)
        try expect(response, TrezorMessageType.thpCredentialResponse)
        let reader = try ProtobufReader(response.payload)
        guard let trezorStatic = reader.bytes(1), trezorStatic.count == 32, let credential = reader.bytes(2) else {
            throw TrezorError.malformedResponse("THP credential response is incomplete.")
        }
        await store.save(TrezorTHPCredential(
            trezorStaticPublicKey: Data(trezorStatic),
            hostStaticPrivateKey: hostStatic.rawRepresentation,
            credential: Data(credential)
        ))
    }

    private func expect(_ response: (type: UInt16, payload: Data), _ type: UInt16) throws {
        guard response.type == type else { throw TrezorError.unexpectedMessage(type: response.type) }
    }

    /// One encrypted request/response on `session`, answering `ButtonRequest`s and surfacing `Failure`s.
    private func call(_ type: UInt16, _ payload: Data, session: UInt8) async throws -> (type: UInt16, payload: Data) {
        var response = try await roundTrip(type, payload, session: session)
        while response.type == TrezorMessageType.buttonRequest {
            onButtonRequest?()
            response = try await roundTrip(TrezorMessageType.buttonAck, Data(), session: session)
        }
        if response.type == TrezorMessageType.failure {
            throw try TrezorError.fromFailurePayload(response.payload)
        }
        return response
    }

    private func roundTrip(_ type: UInt16, _ payload: Data, session: UInt8) async throws -> (type: UInt16, payload: Data) {
        guard var send = sendCipher, var recv = recvCipher else {
            throw TrezorError.transport("THP secure channel is not established.")
        }
        // Application layer: session_id ‖ message_type (BE) ‖ protobuf.
        var app = Data([session, UInt8(type >> 8), UInt8(type & 0xff)])
        app.append(payload)

        let ciphertext = try send.encrypt(plaintext: app)
        sendCipher = send
        try await sendData(control: TrezorTHP.Control.encryptedTransport, payload: ciphertext)

        let (_, responseCiphertext) = try await readData()
        let plaintext = try recv.decrypt(ciphertext: responseCiphertext)
        recvCipher = recv

        guard plaintext.count >= 3 else { throw TrezorError.malformedResponse("Short THP application message.") }
        let bytes = Array(plaintext)
        return ((UInt16(bytes[1]) << 8) | UInt16(bytes[2]), Data(bytes[3...]))
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
        deviceProperties = Data(b[10...])
    }

    // MARK: - Noise XX handshake

    private func handshake() async throws {
        // The device properties are the Noise prologue: h = SHA-256(protocol_name ‖ device_properties).
        let noise = NoiseXXHandshake(role: .initiator, staticKey: hostStatic, prologue: deviceProperties)

        // -> e   (try_to_unlock = 0)
        try await sendData(control: TrezorTHP.Control.handshakeInitRequest, payload: try noise.writeMessage1(payload: Data([0x00])))
        // <- e, ee, s, es
        _ = try noise.readMessage2(try await readData().payload)
        guard let masked = noise.remoteStaticKey, let ephemeral = noise.remoteEphemeralKey else {
            throw TrezorError.malformedResponse("THP handshake is missing the device keys.")
        }
        if let deviceKeyVerifier {
            guard deviceKeyVerifier.accepts(masked, ephemeral) else {
                throw TrezorError.transport("THP device static key does not match the expected Trezor.")
            }
            deviceAuthenticated = true
        }

        // A stored credential for this Trezor lets it skip pairing; it must be presented with the
        // host static key it was issued for.
        var credential: Data?
        if let credentialStore {
            for stored in await credentialStore.credentials() {
                guard (try? Self.maskedStaticKey(stored.trezorStaticPublicKey, deviceEphemeralKey: ephemeral)) == masked,
                      let key = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: stored.hostStaticPrivateKey) else { continue }
                hostStatic = key
                noise.setLocalStatic(key)
                credential = stored.credential
                deviceAuthenticated = true
                break
            }
        }

        // -> s, se   payload = ThpHandshakeCompletionReqNoisePayload { host_pairing_credential }
        var noisePayload = ProtobufWriter()
        if let credential { noisePayload.bytes(1, credential) }
        let (msg3, send, receive) = try noise.writeMessage3(payload: noisePayload.data)
        handshakeHash = noise.handshakeHash
        try await sendData(control: TrezorTHP.Control.handshakeCompletionRequest, payload: msg3)
        sendCipher = send
        recvCipher = receive

        // Handshake completion response: encrypted trezor state, decrypted with the receive cipher.
        var r = receive
        let state = try r.decrypt(ciphertext: try await readData().payload)
        recvCipher = r
        handshakeState = state.first
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
            if let message = try reassembler.push(try await link.read()) {
                if message.control == TrezorTHP.Control.transportError {
                    throw TrezorError.thpTransportError(code: message.payload.first ?? 0)
                }
                return message
            }
        }
    }
}
