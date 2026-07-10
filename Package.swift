// swift-tools-version: 6.0
import PackageDescription

// swift-cardano-hw-wallet — native Cardano hardware-wallet signing for Apple platforms.
//
// Device-agnostic core (`CardanoHWKit`) + per-device modules. First device: Keystone (air-gapped
// animated QR, `CardanoHWWalletKeystone`, added in a later phase). Ledger (BLE / USB-HID) and
// Trezor (USB) slot in behind the same `HardwareSignSession` seam.
//
// Platforms match the swift-cardano-* graph MansAmana resolves (iOS 18 / macOS 15). The Keystone
// SDK floor (iOS 15 / macOS 13) is lower, so no conflict when it's added.
let package = Package(
    name: "swift-cardano-hw-wallet",
    platforms: [
        .iOS(.v18),
        .macOS(.v15),
    ],
    products: [
        .library(name: "CardanoHWKit", targets: ["CardanoHWKit"]),
    ],
    dependencies: [
        // Pinned to the same lines MansAmana resolves, so a single version of each package resolves
        // across the whole app graph.
        .package(url: "https://github.com/Kingpin-Apps/swift-cardano-core.git", from: "0.5.0"),
        .package(url: "https://github.com/Kingpin-Apps/swift-cardano-chain.git", from: "0.7.1"),
        .package(url: "https://github.com/Kingpin-Apps/swift-cardano-txbuilder.git", from: "1.0.3"),
    ],
    targets: [
        .target(
            name: "CardanoHWKit",
            dependencies: [
                .product(name: "SwiftCardanoCore", package: "swift-cardano-core"),
                .product(name: "SwiftCardanoChain", package: "swift-cardano-chain"),
                .product(name: "SwiftCardanoTxBuilder", package: "swift-cardano-txbuilder"),
            ]
        ),
        .testTarget(
            name: "CardanoHWKitTests",
            dependencies: ["CardanoHWKit"]
        ),
    ],
    swiftLanguageModes: [.v6]
)
