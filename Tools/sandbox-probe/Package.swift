// swift-tools-version: 6.0
import PackageDescription

// A command-line probe that talks to a USB Ledger or Trezor One from inside the
// App Sandbox, to confirm the USB entitlement is all the transports need.
// `run.sh` builds it, signs it with `probe.entitlements` and runs it.
let package = Package(
    name: "SandboxProbe",
    platforms: [.macOS(.v15)],
    dependencies: [
        .package(path: "../.."),
        // The Keystone SDK's graph needs swift-collections held below 1.2; see
        // the note in the root package. Every consumer has to repeat the pin.
        .package(url: "https://github.com/apple/swift-collections.git", "1.1.0" ..< "1.2.0"),
    ],
    targets: [
        .executableTarget(
            name: "SandboxProbe",
            dependencies: [
                .product(name: "CardanoHWWalletLedger", package: "swift-cardano-hw-wallet"),
                .product(name: "CardanoHWWalletTrezor", package: "swift-cardano-hw-wallet"),
            ],
            // A sandboxed command-line tool needs a bundle identifier, which it
            // carries in an embedded Info.plist.
            linkerSettings: [
                .unsafeFlags(["-Xlinker", "-sectcreate", "-Xlinker", "__TEXT", "-Xlinker", "__info_plist", "-Xlinker", "Info.plist"]),
            ]
        ),
    ],
    swiftLanguageModes: [.v6]
)
