import CardanoHWWalletLedger
import CardanoHWWalletTrezor
import Foundation

/// Asks a USB Ledger (Cardano app open) for the app version, or a Trezor One
/// for its features — requests that need no confirmation on the device.
@main
struct SandboxProbe {
    static func main() async {
        let sandboxed = ProcessInfo.processInfo.environment["APP_SANDBOX_CONTAINER_ID"] != nil
        print("App Sandbox: \(sandboxed ? "on" : "off")")
        let target = CommandLine.arguments.dropFirst().first ?? "ledger"
        do {
            switch target {
            case "ledger":
                let transport = HidLedgerTransport()
                defer { transport.close() }
                let apdu = LedgerAPDU.command(ins: LedgerAPDU.INS.getVersion, p1: 0, p2: 0, data: Data())
                let version = try await transport.exchange(apdu)
                print("Ledger Cardano app version: \(version.map { String($0) }.joined(separator: "."))")
            case "trezor":
                let link = TrezorHIDPacketLink()
                try await link.open()
                // Initialize (0) is answered with Features (17).
                for report in TrezorProtocolV1.encode(messageType: 0, payload: Data()) {
                    try await link.write(report)
                }
                var decoder = TrezorProtocolV1.Decoder()
                while true {
                    if let (type, payload) = try decoder.push(try await link.read()) {
                        print("Trezor replied with message type \(type) (\(payload.count) bytes); 17 is Features.")
                        break
                    }
                }
                await link.close()
            default:
                print("usage: SandboxProbe [ledger|trezor]")
                exit(2)
            }
        } catch {
            print("Failed: \(error)")
            exit(1)
        }
    }
}
