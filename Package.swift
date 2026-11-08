// swift-tools-version: 6.0
import PackageDescription

// swift-cardano-hw-wallet — native Cardano hardware-wallet signing for Apple platforms.
//
// Device-agnostic core (`CardanoHWKit`) + per-device modules. First device: Keystone (air-gapped
// animated QR, `CardanoHWWalletKeystone`, added in a later phase). Ledger (BLE / USB-HID) and
// Trezor (USB) slot in behind the same `HardwareSignSession` seam.
//
// Platforms match the swift-cardano-* stack (iOS 18 / macOS 15). The Keystone
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
        // Pinned to the same lines the swift-cardano-* stack resolves, so a single version of each package resolves
        // across the whole app graph.
        .package(url: "https://github.com/Kingpin-Apps/swift-cardano-core.git", from: "0.11.0"),
        .package(url: "https://github.com/Kingpin-Apps/swift-cardano-chain.git", from: "0.17.0"),
        .package(url: "https://github.com/Kingpin-Apps/swift-cardano-txbuilder.git", from: "2.0.5"),
        .package(url: "https://github.com/attaswift/BigInt.git", "5.7.0"..<"7.0.0"),
        // Keystone's official iOS SDK: Cardano UR sign-request / signature types + URKit + the
        // URRegistryFFI binary target. Powers the air-gapped QR flow.
        .package(url: "https://github.com/KeystoneHQ/keystone-sdk-ios.git", from: "0.8.0"),
        // Dependency-graph pin: Keystone → URKit → BCSwiftDCBOR depends on wolfmcnally's
        // `SwiftSortedCollections`, which vends a target literally named `SortedCollections` — the
        // same name Apple's swift-collections added in 1.2. Two same-named targets in one graph is a
        // hard SPM error, so hold swift-collections on the 1.1.x line (no `SortedCollections` target).
        .package(url: "https://github.com/apple/swift-collections.git", "1.1.0" ..< "1.2.0"),
        // Noise_XX_25519_AESGCM_SHA256 handshake for Trezor's THP (v2) secure channel. Already in the
        // graph (transitive via swift-cardano-core); pinned to the same 4.x line.
        .package(url: "https://github.com/apple/swift-crypto.git", "3.0.0" ..< "5.0.0"),
    ],
    targets: [
        .target(
            name: "CardanoHWKit",
            dependencies: [
                .product(name: "SwiftCardanoCore", package: "swift-cardano-core"),
                .product(name: "SwiftCardanoChain", package: "swift-cardano-chain"),
                .product(name: "SwiftCardanoTxBuilder", package: "swift-cardano-txbuilder"),
                "BigInt",
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
        // Ledger's BLE transport, vendored from LedgerHQ/hw-transport-ios-ble 1.0.1 (MIT, see
        // Sources/LedgerBLETransport/LICENSE) with checked frame reassembly, MTU validation and
        // single-shot exchange callbacks. The upstream SDK trapped on malformed notifications.
        .target(
            name: "LedgerBLETransport",
            exclude: ["LICENSE"],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .target(
            name: "CardanoHWWalletLedger",
            dependencies: [
                "CardanoHWKit",
                // BleTransport is available on iOS + macOS; the USB (`HidLedgerTransport`) path is
                // `#if os(macOS)`-guarded inside the source.
                "LedgerBLETransport",
            ]
        ),
        .target(
            name: "CardanoHWWalletTrezor",
            dependencies: [
                // No SwiftProtobuf: the Trezor Cardano messages are encoded with a small self-contained
                // proto2 wire codec (`TrezorProtobuf`), so there's no protoc/codegen toolchain.
                "CardanoHWKit",
                // Noise XX handshake crypto for THP (v2).
                .product(name: "Crypto", package: "swift-crypto"),
            ]
        ),
        .testTarget(
            name: "CardanoHWWalletLedgerTests",
            dependencies: [
                "CardanoHWWalletLedger",
                "LedgerBLETransport",
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
