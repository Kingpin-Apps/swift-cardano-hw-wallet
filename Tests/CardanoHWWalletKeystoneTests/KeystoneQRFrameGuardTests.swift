import Testing
import Foundation
@testable import CardanoHWWalletKeystone

/// Regression tests for the 2026-11-07 security audit: multi-part UR frames whose fountain header
/// would trap inside URKit are rejected before they reach the decoder. Runs on every platform; the
/// guard itself has no KeystoneSDK dependency.
@Suite("Keystone QR frame guard")
struct KeystoneQRFrameGuardTests {
    @Test("Crafted fountain headers are rejected", arguments: [
        "ur:crypto-multi-accounts/1-1/lpadadcsieaefpaeckieglmd",                 // messageLen beyond the fragments
        "ur:crypto-multi-accounts/4294967296-2/lpcwaeaeaeadaeaeaeaeaoadaefpaefllpjedt",  // seqNum > UInt32.max
        "ur:crypto-multi-accounts/1-2/lpadaoadcwaeaeaeadaeaeaeaefpaebavdiazs",   // checksum > UInt32.max
        "ur:crypto-multi-accounts/1-2/lpadcwlaaeaeaeaeaeaeaeadaefpaegobdsrcf",   // huge seqLen
    ])
    func rejectsCraftedFrames(frame: String) {
        #expect(throws: KeystoneQRFrameGuard.RejectedFrame.self) { try KeystoneQRFrameGuard.validate(frame) }
    }

    @Test("A well-formed fountain frame and non-multipart strings pass through")
    func acceptsValidFrames() {
        #expect(throws: Never.self) { try KeystoneQRFrameGuard.validate("ur:crypto-multi-accounts/1-2/lpadaoaoaefpaereredwcl") }
        #expect(throws: Never.self) { try KeystoneQRFrameGuard.validate("ur:crypto-multi-accounts/not-a-ur") }
        #expect(throws: Never.self) { try KeystoneQRFrameGuard.validate("hello") }
    }

    @Test("Bad Bytewords and mismatched sequence components are rejected")
    func rejectsBadEncoding() {
        #expect(throws: KeystoneQRFrameGuard.RejectedFrame.self) { try KeystoneQRFrameGuard.validate("ur:x/1-2/zzzzzzzzzzzzzzzz") }
        // Same body as the valid frame, but the URI says 2-2.
        #expect(throws: KeystoneQRFrameGuard.RejectedFrame.self) { try KeystoneQRFrameGuard.validate("ur:crypto-multi-accounts/2-2/lpadaoaoaefpaereredwcl") }
    }
}
