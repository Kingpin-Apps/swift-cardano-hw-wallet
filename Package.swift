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
        .library(name: "CardanoHWWalletKeystone", targets: ["CardanoHWWalletKeystone"]),
        .library(name: "CardanoHWWalletLedger", targets: ["CardanoHWWalletLedger"]),
        .library(name: "CardanoHWWalletTrezor", targets: ["CardanoHWWalletTrezor"]),
    ],
    dependencies: [
        // Pinned to the same lines MansAmana resolves, so a single version of each package resolves
        // across the whole app graph.
        .package(url: "https://github.com/Kingpin-Apps/swift-cardano-core.git", from: "0.5.0"),
        .package(url: "https://github.com/Kingpin-Apps/swift-cardano-chain.git", from: "0.7.1"),
        .package(url: "https://github.com/Kingpin-Apps/swift-cardano-txbuilder.git", from: "1.0.3"),
        // Keystone's official iOS SDK: Cardano UR sign-request / signature types + URKit + the
        // URRegistryFFI binary target. Powers the air-gapped QR flow.
        .package(url: "https://github.com/KeystoneHQ/keystone-sdk-ios.git", from: "0.8.0"),
        // Dependency-graph pin: Keystone → URKit → BCSwiftDCBOR depends on wolfmcnally's
        // `SwiftSortedCollections`, which vends a target literally named `SortedCollections` — the
        // same name Apple's swift-collections added in 1.2. Two same-named targets in one graph is a
        // hard SPM error, so hold swift-collections on the 1.1.x line (no `SortedCollections` target).
        .package(url: "https://github.com/apple/swift-collections.git", "1.1.0" ..< "1.2.0"),
        // Ledger's official BLE transport (from Ledger Live). Zero transitive SPM deps, iOS 13 /
        // macOS 12. Its `exchange(apdu:)` owns the `0x05`-tag BLE chunking, so the Ledger module only
        // builds APDUs. Powers `BleLedgerTransport` (iOS + macOS).
        .package(url: "https://github.com/LedgerHQ/hw-transport-ios-ble.git", from: "1.0.0"),
        // Trezor speaks protobuf; there is no vendor Swift SDK, so we generate + commit the Cardano
        // message types and serialize them with SwiftProtobuf.
        .package(url: "https://github.com/apple/swift-protobuf.git", from: "1.28.0"),
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
        .target(
            name: "CardanoHWWalletKeystone",
            dependencies: [
                "CardanoHWKit",
                // Keystone's `URRegistryFFI` XCFramework ships **iOS-only** slices (no macOS), so the
                // Keystone transport is iOS-only. Link the SDK on iOS only; the module's sources are
                // `#if canImport(KeystoneSDK)`-guarded and compile to an empty module elsewhere.
                .product(name: "KeystoneSDK", package: "keystone-sdk-ios", condition: .when(platforms: [.iOS])),
            ]
        ),
        .testTarget(
            name: "CardanoHWKitTests",
            dependencies: [
                "CardanoHWKit",
                .product(name: "SwiftCardanoCore", package: "swift-cardano-core"),
            ]
        ),
        .testTarget(
            name: "CardanoHWWalletKeystoneTests",
            dependencies: [
                "CardanoHWWalletKeystone",
                .product(name: "SwiftCardanoCore", package: "swift-cardano-core"),
            ]
        ),
        .target(
            name: "CardanoHWWalletLedger",
            dependencies: [
                "CardanoHWKit",
                // BleTransport is available on iOS + macOS; the USB (`HidLedgerTransport`) path is
                // `#if os(macOS)`-guarded inside the source.
                .product(name: "BleTransport", package: "hw-transport-ios-ble"),
            ]
        ),
        .target(
            name: "CardanoHWWalletTrezor",
            dependencies: [
                "CardanoHWKit",
                .product(name: "SwiftProtobuf", package: "swift-protobuf"),
            ]
        ),
        .testTarget(
            name: "CardanoHWWalletLedgerTests",
            dependencies: [
                "CardanoHWWalletLedger",
                .product(name: "SwiftCardanoCore", package: "swift-cardano-core"),
            ]
        ),
        .testTarget(
            name: "CardanoHWWalletTrezorTests",
            dependencies: [
                "CardanoHWWalletTrezor",
                .product(name: "SwiftCardanoCore", package: "swift-cardano-core"),
            ]
        ),
    ],
    swiftLanguageModes: [.v6]
)
