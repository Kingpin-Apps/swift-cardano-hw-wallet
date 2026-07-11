// Keystone support is iOS-only: its URRegistryFFI XCFramework ships no macOS slice.
#if canImport(KeystoneSDK)
import Foundation
import CardanoHWKit
import KeystoneSDK
import URKit

/// The Keystone air-gapped signing session: presents the sign request as animated-QR frames and
/// accumulates the device's multi-part signature response. `@MainActor` — the UR encoder/decoder are
/// not `Sendable`, and the app drives this from the camera / QR display.
@MainActor
public final class KeystoneQRSession: HardwareSignSession {
    public nonisolated let deviceKind: HardwareDeviceKind = .keystone

    private let encoder: UREncoder
    private let sdk = KeystoneSDK()          // owns the multi-part URDecoder for the inbound response
    private let expectedRequestId: String
    private(set) public var progress: Int = 0

    /// The number of fountain frames in the outbound sign request (informational; the encoder cycles
    /// indefinitely for animated display).
    public var outboundFrameCount: Int { encoder.seqLen }

    public init(request: HardwareSignRequest) throws {
        self.encoder = try KeystoneSignRequestCodec.encoder(for: request)
        self.expectedRequestId = request.requestId
    }

    /// The next outbound animated-QR frame. Call on a timer to animate the request QR.
    public func nextFrame() -> String {
        encoder.nextPart()
    }

    /// Feed a scanned response frame. Returns `.needMore` until the multipart signature UR is whole,
    /// then `.complete` with the witness-set CBOR hex ready for ``WitnessMerge``.
    public func ingest(scanned: String) throws -> SignIngestResult {
        let result: DecodeResult
        do {
            result = try sdk.decodeQR(qrCode: scanned)
        } catch {
            throw HardwareWalletError.witnessDecodeFailed("Could not decode the scanned QR frame: \(error)")
        }
        progress = result.progress
        guard let ur = result.ur else { return .needMore }
        let witnessSetHex = try KeystoneSignatureCodec.witnessSetHex(from: ur, expectedRequestId: expectedRequestId)
        return .complete(witnessSetHex: witnessSetHex)
    }

    /// Discard any partially-scanned response (e.g. the user restarts the scan).
    public func resetScan() {
        sdk.resetQRDecoder()
        progress = 0
    }
}
#endif
