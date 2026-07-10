import Testing
@testable import CardanoHWKit

@Suite("Hardware device kind")
struct HardwareDeviceKindTests {
    @Test("Every device has a display name and a stable raw value")
    func deviceKinds() {
        #expect(HardwareDeviceKind.keystone.displayName == "Keystone")
        #expect(HardwareDeviceKind.allCases.count == 3)
        #expect(HardwareDeviceKind(rawValue: "ledger") == .ledger)
    }
}
