import Foundation

/// Screens a scanned Keystone QR frame before it reaches the UR fountain decoder.
///
/// URKit trusts the fountain-part header of a multi-part UR (`ur:<type>/<n>-<m>/<body>`): it narrows
/// the header's 64-bit numbers with trapping conversions and assumes the message length fits the
/// fragments, so one crafted frame on camera can crash the app. This guard decodes the header itself
/// (Bytewords minimal style, then the 5-element CBOR array `[seqNum, seqLen, messageLen, checksum,
/// fragment]`) and rejects any frame whose values are out of range, so only well-formed headers reach
/// the decoder. Single-part URs skip the fountain decoder and pass through unchanged.
enum KeystoneQRFrameGuard {
    /// The most fragments a Keystone frame may announce. Real Keystone signature and account-export
    /// QRs use a handful; the cap also bounds the decoder's per-part allocations.
    static let maxSequenceLength: UInt64 = 1024

    struct RejectedFrame: Error, CustomStringConvertible {
        let reason: String
        var description: String { "Rejected QR frame: \(reason)" }
    }

    static func validate(_ scanned: String) throws {
        let lowered = scanned.lowercased()
        guard lowered.hasPrefix("ur:") else { return }   // not a UR; the SDK rejects it
        let components = lowered.dropFirst(3).split(separator: "/").map(String.init)
        guard components.count == 3 else { return }      // single-part or malformed; no fountain header
        let sequence = components[1].split(separator: "-", omittingEmptySubsequences: false)
        guard sequence.count == 2, let uriNum = UInt64(sequence[0]), let uriLen = UInt64(sequence[1]) else {
            throw RejectedFrame(reason: "bad sequence component")
        }
        var reader = CBORHeaderReader(bytes: try decodeMinimalBytewords(components[2]))
        guard try reader.arrayCount() == 5 else { throw RejectedFrame(reason: "fountain part is not a 5-element array") }
        let seqNum = try reader.unsigned()
        let seqLen = try reader.unsigned()
        let messageLen = try reader.unsigned()
        let checksum = try reader.unsigned()
        let fragmentLen = UInt64(try reader.byteStringLength())

        guard seqNum >= 1, seqNum <= UInt64(UInt32.max), checksum <= UInt64(UInt32.max) else {
            throw RejectedFrame(reason: "sequence number or checksum out of range")
        }
        guard seqLen >= 1, seqLen <= maxSequenceLength else {
            throw RejectedFrame(reason: "sequence length out of range")
        }
        guard fragmentLen >= 1 else { throw RejectedFrame(reason: "empty fragment") }
        // The encoder splits a message into seqLen fragments of fragmentLen bytes, padding only the last.
        guard messageLen > (seqLen - 1) * fragmentLen, messageLen <= seqLen * fragmentLen else {
            throw RejectedFrame(reason: "message length does not match the fragments")
        }
        guard uriNum == seqNum, uriLen == seqLen else {
            throw RejectedFrame(reason: "sequence component does not match the fountain header")
        }
    }

    // MARK: - Bytewords (minimal style: first and last letter of each word)

    private static let minimalIndex: [String: UInt8] = {
        let chars = Array(words)
        var index: [String: UInt8] = [:]
        for i in 0..<256 { index[String([chars[i * 4], chars[i * 4 + 3]])] = UInt8(i) }
        return index
    }()

    /// Decodes minimal Bytewords and drops the trailing 4-byte CRC (URKit verifies it later).
    static func decodeMinimalBytewords(_ body: String) throws -> [UInt8] {
        let chars = Array(body)
        guard chars.count % 2 == 0, chars.count >= 10 else { throw RejectedFrame(reason: "bad Bytewords length") }
        var bytes: [UInt8] = []
        bytes.reserveCapacity(chars.count / 2)
        var i = 0
        while i < chars.count {
            guard let value = minimalIndex[String(chars[i...i + 1])] else { throw RejectedFrame(reason: "invalid Bytewords") }
            bytes.append(value)
            i += 2
        }
        return Array(bytes.dropLast(4))
    }

    /// The 256 Bytewords (BCR-2020-012), four letters each, in byte order.
    private static let words =
        "ableacidalsoapexaquaarchatomauntawayaxisbackbaldbarnbeltbetabias" +
        "bluebodybragbrewbulbbuzzcalmcashcatschefcityclawcodecolacookcost" +
        "cruxcurlcuspcyandarkdatadaysdelidicedietdoordowndrawdropdrumdull" +
        "dutyeacheasyechoedgeepicevenexamexiteyesfactfairfernfigsfilmfish" +
        "fizzflapflewfluxfoxyfreefrogfuelfundgalagamegeargemsgiftgirlglow" +
        "goodgraygrimgurugushgyrohalfhanghardhawkheathelphighhillholyhope" +
        "hornhutsicedideaidleinchinkyintoirisironitemjadejazzjoinjoltjowl" +
        "judojugsjumpjunkjurykeepkenokeptkeyskickkilnkingkitekiwiknoblamb" +
        "lavalazyleaflegsliarlimplionlistlogoloudloveluaulucklungmainmany" +
        "mathmazememomenumeowmildmintmissmonknailnavyneednewsnextnoonnote" +
        "numbobeyoboeomitonyxopenovalowlspaidpartpeckplaypluspoempoolpose" +
        "puffpumapurrquadquizraceramprealredorichroadrockroofrubyruinruns" +
        "rustsafesagascarsetssilkskewslotsoapsolosongstubsurfswantacotask" +
        "taxitenttiedtimetinytoiltombtoystriptunatwinuglyundouniturgeuser" +
        "vastveryvetovialvibeviewvisavoidvowswallwandwarmwaspwavewaxywebs" +
        "whatwhenwhizwolfworkyankyawnyellyogayurtzapszerozestzinczonezoom"

    // MARK: - Minimal CBOR header reader

    private struct CBORHeaderReader {
        let bytes: [UInt8]
        var index = 0

        private mutating func head(majorType: UInt8) throws -> UInt64 {
            guard index < bytes.count else { throw RejectedFrame(reason: "truncated CBOR") }
            let initial = bytes[index]; index += 1
            guard initial >> 5 == majorType else { throw RejectedFrame(reason: "unexpected CBOR type") }
            let info = initial & 0x1f
            let width: Int
            switch info {
            case 0..<24: return UInt64(info)
            case 24: width = 1
            case 25: width = 2
            case 26: width = 4
            case 27: width = 8
            default: throw RejectedFrame(reason: "unsupported CBOR length")
            }
            guard bytes.count - index >= width else { throw RejectedFrame(reason: "truncated CBOR") }
            var value: UInt64 = 0
            for _ in 0..<width { value = value << 8 | UInt64(bytes[index]); index += 1 }
            return value
        }

        mutating func arrayCount() throws -> UInt64 { try head(majorType: 4) }
        mutating func unsigned() throws -> UInt64 { try head(majorType: 0) }

        mutating func byteStringLength() throws -> Int {
            let length = try head(majorType: 2)
            guard length <= UInt64(bytes.count - index) else { throw RejectedFrame(reason: "fragment overruns the frame") }
            return Int(length)
        }
    }
}
