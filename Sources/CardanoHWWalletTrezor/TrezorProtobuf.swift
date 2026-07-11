import Foundation

/// A minimal protobuf (proto2) wire codec — just the field kinds the Trezor Cardano messages use
/// (varint, length-delimited bytes/string, unpacked repeated uint32). Self-contained, so the Trezor
/// module needs no protoc/codegen toolchain. Wire types: 0 = varint, 2 = length-delimited.
enum ProtobufWire {
    static let varint = 0
    static let lengthDelimited = 2
}

/// Serializes protobuf fields in call order.
struct ProtobufWriter {
    private(set) var data = Data()

    private mutating func tag(_ field: Int, _ wire: Int) {
        appendVarint(UInt64(field << 3 | wire))
    }

    private mutating func appendVarint(_ value: UInt64) {
        var v = value
        repeat {
            var byte = UInt8(v & 0x7f)
            v >>= 7
            if v != 0 { byte |= 0x80 }
            data.append(byte)
        } while v != 0
    }

    mutating func varint(_ field: Int, _ value: UInt64) {
        tag(field, ProtobufWire.varint)
        appendVarint(value)
    }

    mutating func bool(_ field: Int, _ value: Bool) {
        varint(field, value ? 1 : 0)
    }

    mutating func bytes(_ field: Int, _ value: Data) {
        tag(field, ProtobufWire.lengthDelimited)
        appendVarint(UInt64(value.count))
        data.append(value)
    }

    mutating func string(_ field: Int, _ value: String) {
        bytes(field, Data(value.utf8))
    }

    /// proto2 unpacked repeated uint32 — one varint field per element.
    mutating func repeatedUInt32(_ field: Int, _ values: [UInt32]) {
        for v in values { varint(field, UInt64(v)) }
    }
}

/// Parses the response messages we care about: pulls the raw value for a given field number.
struct ProtobufReader {
    private struct Field { let number: Int; let wire: Int; let varint: UInt64; let bytes: Data }
    private var fields: [Field] = []

    init(_ data: Data) throws {
        var idx = data.startIndex
        func readVarint() throws -> UInt64 {
            var result: UInt64 = 0
            var shift: UInt64 = 0
            while true {
                guard idx < data.endIndex else { throw TrezorError.malformedResponse("Truncated protobuf varint.") }
                let byte = data[idx]; idx = data.index(after: idx)
                result |= UInt64(byte & 0x7f) << shift
                if byte & 0x80 == 0 { break }
                shift += 7
                if shift > 63 { throw TrezorError.malformedResponse("Protobuf varint too long.") }
            }
            return result
        }
        while idx < data.endIndex {
            let key = try readVarint()
            let number = Int(key >> 3)
            let wire = Int(key & 0x7)
            switch wire {
            case ProtobufWire.varint:
                fields.append(Field(number: number, wire: wire, varint: try readVarint(), bytes: Data()))
            case ProtobufWire.lengthDelimited:
                let len = Int(try readVarint())
                guard data.distance(from: idx, to: data.endIndex) >= len else {
                    throw TrezorError.malformedResponse("Protobuf length-delimited field overruns the buffer.")
                }
                let end = data.index(idx, offsetBy: len)
                fields.append(Field(number: number, wire: wire, varint: 0, bytes: data[idx..<end]))
                idx = end
            case 5: idx = data.index(idx, offsetBy: 4)   // fixed32 (skip; unused)
            case 1: idx = data.index(idx, offsetBy: 8)   // fixed64 (skip; unused)
            default:
                throw TrezorError.malformedResponse("Unsupported protobuf wire type \(wire).")
            }
        }
    }

    func varint(_ field: Int) -> UInt64? { fields.first { $0.number == field }?.varint }
    func bytes(_ field: Int) -> Data? { fields.first { $0.number == field && $0.wire == ProtobufWire.lengthDelimited }?.bytes }
    func string(_ field: Int) -> String? { bytes(field).flatMap { String(data: $0, encoding: .utf8) } }
}
