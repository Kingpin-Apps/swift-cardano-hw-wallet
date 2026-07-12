import Foundation
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#endif
import CardanoHWKit
@testable import CardanoHWWalletLedger

/// A ``LedgerTransport`` that speaks to the **Speculos emulator** (real Ledger `app-cardano`) over its
/// raw-APDU TCP server (`:9999`), auto-approving on-device review flows via the REST button API
/// (`:5001`). Test-only; the Ledger counterpart of `TrezorEmulatorBridge`. See `Tools/emulator-ledger/`.
///
/// TCP framing: `[u32 BE payload-len][apdu]` out, `[u32 BE payload-len][payload][2-byte SW]` back (the
/// status word is not counted in the length). `exchange` strips + checks the SW, per the
/// ``LedgerTransport`` contract.
final class LedgerSpeculosTransport: LedgerTransport, @unchecked Sendable {
    private let host: String
    private let apduPort: UInt16
    private let apiBase: String
    private var fd: Int32 = -1
    private let lock = NSLock()

    init(host: String = "127.0.0.1", apduPort: UInt16 = 9999, apiBase: String = "http://127.0.0.1:5001") {
        self.host = host
        self.apduPort = apduPort
        self.apiBase = apiBase
    }

    func exchange(_ apdu: Data) async throws -> Data {
        try connectIfNeeded()
        try sendFramed(apdu)

        // The recv blocks until the app answers — which for review flows means after we approve. Run
        // the blocking read off the cooperative pool and drive button approval concurrently.
        let readTask = Task.detached(priority: .userInitiated) { [weak self] () throws -> Data in
            guard let self else { throw LedgerError.transport("transport gone") }
            return try self.recvFramedBlocking()
        }
        let navTask = Task.detached(priority: .utility) { [weak self] in
            await self?.autoApproveUntilCancelled()
        }
        defer { navTask.cancel() }

        let raw = try await readTask.value           // payload ‖ 2-byte SW
        navTask.cancel()
        return try LedgerStatus.payload(raw)         // strips + verifies SW == 0x9000
    }

    func close() {
        lock.lock(); defer { lock.unlock() }
        if fd >= 0 { Darwin.close(fd); fd = -1 }
    }

    // MARK: - Socket

    private func connectIfNeeded() throws {
        lock.lock(); defer { lock.unlock() }
        if fd >= 0 { return }
        let sock = socket(AF_INET, SOCK_STREAM, 0)
        guard sock >= 0 else { throw LedgerError.transport("socket() failed") }
        var addr = sockaddr_in()
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = apduPort.bigEndian
        guard inet_pton(AF_INET, host, &addr.sin_addr) == 1 else {
            Darwin.close(sock); throw LedgerError.transport("bad host \(host)")
        }
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(sock, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard rc == 0 else {
            Darwin.close(sock); throw LedgerError.transport("connect to \(host):\(apduPort) failed — is Speculos up?")
        }
        fd = sock
    }

    private func sendFramed(_ apdu: Data) throws {
        var frame = Data()
        let len = UInt32(apdu.count)
        frame.append(contentsOf: [UInt8((len >> 24) & 0xff), UInt8((len >> 16) & 0xff), UInt8((len >> 8) & 0xff), UInt8(len & 0xff)])
        frame.append(apdu)
        try writeAll(frame)
    }

    private func writeAll(_ data: Data) throws {
        lock.lock(); defer { lock.unlock() }
        try data.withUnsafeBytes { (buf: UnsafeRawBufferPointer) in
            var sent = 0
            let base = buf.baseAddress!
            while sent < data.count {
                let n = Darwin.send(fd, base + sent, data.count - sent, 0)
                guard n > 0 else { throw LedgerError.transport("send() failed") }
                sent += n
            }
        }
    }

    /// Blocking read of one framed response: 4-byte length, then `length + 2` bytes (payload + SW).
    private func recvFramedBlocking() throws -> Data {
        let header = try readExactly(4)
        let n = (Int(header[0]) << 24) | (Int(header[1]) << 16) | (Int(header[2]) << 8) | Int(header[3])
        return try readExactly(n + 2)
    }

    private func readExactly(_ count: Int) throws -> Data {
        var out = Data(); out.reserveCapacity(count)
        var buf = [UInt8](repeating: 0, count: max(count, 1))
        while out.count < count {
            let want = count - out.count
            let n = buf.withUnsafeMutableBytes { Darwin.recv(fd, $0.baseAddress, want, 0) }
            guard n > 0 else { throw LedgerError.transport("recv() failed / connection closed") }
            out.append(contentsOf: buf[0..<n])
        }
        return out
    }

    // MARK: - REST button approval

    /// Loop until cancelled: read the current screen and press the buttons that advance a review to
    /// approval. A first delay lets non-blocking APDUs (no prompt) answer before we ever press.
    private func autoApproveUntilCancelled() async {
        var firstDelay = true
        while !Task.isCancelled {
            try? await Task.sleep(nanoseconds: firstDelay ? 500_000_000 : 250_000_000)
            firstDelay = false
            if Task.isCancelled { return }
            let screen = readScreen().lowercased()
            if screen.isEmpty { continue }
            if screen.contains("reject") && !approveWord(in: screen) {
                // On a reject-only page, step forward rather than confirming it.
                pressButton("right")
            } else if approveWord(in: screen) {
                pressButton("both")
            } else {
                pressButton("right")
            }
        }
    }

    private func approveWord(in screen: String) -> Bool {
        for word in ["approve", "confirm", "accept", "sign", "hold", "allow", "yes", "continue"] {
            if screen.contains(word) { return true }
        }
        return false
    }

    private func readScreen() -> String {
        guard let url = URL(string: "\(apiBase)/events?currentscreenonly=true"),
              let data = try? Data(contentsOf: url),
              let json = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              let events = json["events"] as? [[String: Any]] else { return "" }
        return events.compactMap { $0["text"] as? String }.joined(separator: " | ")
    }

    private func pressButton(_ button: String) {
        guard let url = URL(string: "\(apiBase)/button/\(button)") else { return }
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = Data(#"{"action":"press-and-release"}"#.utf8)
        let sem = DispatchSemaphore(value: 0)
        URLSession.shared.dataTask(with: req) { _, _, _ in sem.signal() }.resume()
        _ = sem.wait(timeout: .now() + 3)
    }
}
