# swift-cardano-hw-wallet

Native, Apple-platform Cardano **hardware-wallet signing** — Keystone, Ledger, and Trezor behind one
keyless, device-agnostic core. No CLI, no bundled Node bridge, no FFI to a vendor daemon: the wallet
holds only public keys, the device signs off-line, and the returned witness is merged into a
submittable transaction.

[![Swift 6](https://img.shields.io/badge/Swift-6.0%2B-orange.svg)](https://swift.org)
[![Platforms](https://img.shields.io/badge/Platforms-iOS%20%7C%20macOS-blue.svg)](Package.swift)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## Why

Cardano hardware support has historically meant shelling out to the `cardano-hw-cli` Node binary — it
traps on iOS and can't ship in a sandboxed Mac App Store app. This package is the native replacement:
a device-agnostic core (`CardanoHWKit`) with a per-vendor adapter for each device family, built so the
wallet never touches a private key.

- **Keyless by construction.** Addresses are derived from a device-exported **account xpub** using
  BIP32-Ed25519 public (non-hardened) derivation (`PublicHDDerivation`). Transactions are built
  keyless (`UnsignedTxBuilder`) and the device-returned witness is injected with `WitnessMerge`. The
  gating test proves the public derivation reproduces the SDK's private-key derivation byte-for-byte.
- **Three device families, one seam.** Every vendor implements the same `HardwareSigner`
  (`importAccount` / `sign`) or `HardwarePacketLink` (duplex byte link) seam, so the wallet code above
  is identical regardless of device.
- **Validated against real device code.** The Trezor, Ledger, and Keystone signing paths are each
  checked against their vendor's actual firmware/emulator — see [Verification](#verification).
- **Pure Swift + vendor SDKs only.** Built on
  [swift-cardano-core](https://github.com/Kingpin-Apps/swift-cardano-core),
  [swift-cardano-chain](https://github.com/Kingpin-Apps/swift-cardano-chain), and
  [swift-cardano-txbuilder](https://github.com/Kingpin-Apps/swift-cardano-txbuilder); Ledger BLE uses
  Ledger's official `hw-transport-ios-ble`, Keystone uses `keystone-sdk-ios`. Strict-concurrency clean.

## Platform matrix

| Device       | Transport(s)                              | Platforms                    |
|--------------|-------------------------------------------|------------------------------|
| **Keystone** | air-gapped animated QR (UR)               | iOS                          |
| **Ledger**   | BLE (official SDK) + USB-HID (IOKit)      | iOS (BLE) · macOS (BLE + USB) |
| **Trezor**   | USB-HID + protobuf (Codec-v1 / THP v2)    | macOS                        |

Keystone is air-gapped (QR only). Ledger signs over BLE on iOS and over BLE or USB on macOS. Trezor is
USB-only, so macOS-only (no USB on iOS). The USB transport is HID, which covers the **Trezor One**; the
Model T and Safe family expose a WebUSB bulk interface instead and need an `IOUSBHost` transport that
is not written yet.

## Installation

Swift Package Manager:

```swift
.package(url: "https://github.com/Kingpin-Apps/swift-cardano-hw-wallet.git", from: "0.1.0")
```

Then add the products you need:

```swift
.target(name: "YourApp", dependencies: [
    .product(name: "CardanoHWKit", package: "swift-cardano-hw-wallet"),
    .product(name: "CardanoHWWalletLedger", package: "swift-cardano-hw-wallet"),   // iOS + macOS
    .product(name: "CardanoHWWalletTrezor", package: "swift-cardano-hw-wallet"),   // macOS
    .product(name: "CardanoHWWalletKeystone", package: "swift-cardano-hw-wallet"), // iOS
])
```

Keystone's SDK depends on a package that declares a target named `SortedCollections`, as
swift-collections does from 1.2 on. Two targets of one name cannot share a package graph, and this
package's own pin does not carry over to yours, so hold swift-collections below 1.2 in your package or
app as well:

```swift
.package(url: "https://github.com/apple/swift-collections.git", "1.1.0" ..< "1.2.0"),
```

### Sandboxed apps

A sandboxed macOS app needs `com.apple.security.device.usb` for Ledger and Trezor over USB, and
`com.apple.security.device.bluetooth` plus an `NSBluetoothAlwaysUsageDescription` for Ledger over BLE.
An iOS app needs the Bluetooth usage description for Ledger and `NSCameraUsageDescription` for
Keystone's QR scan. `Tools/sandbox-probe` checks a USB device from inside the App Sandbox:

```sh
Tools/sandbox-probe/run.sh ledger   # Ledger over USB, Cardano app open
Tools/sandbox-probe/run.sh trezor   # Trezor One over USB
```

## Modules

- **`CardanoHWKit`** — device-agnostic core (iOS + macOS), no camera or vendor SDK, fully
  unit-testable. `PublicHDDerivation`, `UnsignedTxBuilder`, `WitnessMerge`, `HardwareAccountModel`,
  `HardwareSignRequest`, and the `HardwareSigner` / `HardwarePacketLink` / `HardwareSignSession` seams.
- **`CardanoHWWalletLedger`** — Ledger over the real `app-cardano` per-field staged APDU protocol.
  `LedgerSignSession` (a `HardwareSigner`), `LedgerAccountImport`, `BleLedgerTransport` (official
  `hw-transport-ios-ble`), and `HidLedgerTransport` (IOKit HID, macOS).
- **`CardanoHWWalletTrezor`** — Trezor over a self-contained proto2 codec. `TrezorSignSession`,
  `TrezorAccountImport`, `TrezorHIDPacketLink` (IOKit HID, macOS), plus the encrypted **THP** (v2 /
  Noise) channel (`TrezorTHPSession`).
- **`CardanoHWWalletKeystone`** — air-gapped animated-QR (UR) adapter over Keystone's official
  `KeystoneSDK` (iOS). `KeystoneQRSession` (sign) and `KeystoneAccountImportSession` (import).

## Usage

### 1. Import an account (get the xpub, keyless from there on)

```swift
import CardanoHWKit
import CardanoHWWalletLedger

let transport = BleLedgerTransport()   // or HidLedgerTransport() on macOS
let session = LedgerSignSession(transport: transport, network: .mainnet)
let account = try await session.importAccount(network: .mainnet, accountIndex: 0)
// account.accountXPub  → 64-byte account extended public key
// account.accountPath  → "m/1852'/1815'/0'"
```

### 2. Derive addresses — no device, no private key

```swift
let derivation = try PublicHDDerivation(
    accountXPub: account.accountXPub,
    accountPath: account.accountPath,
    network: .mainnet
)
let receive = try derivation.address(role: 0, index: 0)      // external address, bech32
let change  = try derivation.address(role: 1, index: 0)      // change address
let table   = try derivation.deriveAddressTable(gapLimit: 20) // [bech32 address: path]
```

### 3. Build an unsigned transaction (keyless, over any `ChainContext`)

```swift
let build = try await UnsignedTxBuilder.buildUnsigned(
    context: chainContext,               // swift-cardano-chain ChainContext
    candidateUTxOs: accountUTxOs,         // UTxOs across the derived address window
    outputs: [TransactionOutput(address: recipient, amount: Value(coin: 2_000_000))],
    changeAddress: try Address.fromBech32(change)
)
```

### 4. Sign on the device and merge

```swift
let request = HardwareSignRequest(
    requestId: UUID().uuidString,
    unsigned: build.transaction,
    spentUTxOs: build.spentUTxOs,
    addressPaths: table,                        // maps each spent address → its derivation path
    masterFingerprint: account.masterFingerprint,
    origin: "My Wallet"
)

let witnessSetHex = try await session.sign(request)          // device shows + confirms, returns witness
let signedTxHex   = try WitnessMerge.mergedCBORHex(
    unsigned: build.transaction,
    witnessSetHex: witnessSetHex
)
// submit signedTxHex via your ChainContext
```

`LedgerSignSession.sign` derives each witness public key locally (Ledger returns signatures only) and
integrity-guards the device's tx hash against `body.hash()`, failing loudly on any serialization
mismatch.

### Trezor

Same `HardwareSigner` shape over a USB packet link, or the encrypted THP channel:

```swift
import CardanoHWWalletTrezor

let link = TrezorHIDPacketLink()                             // IOKit HID, macOS
let trezor = TrezorSignSession(link: link, network: .mainnet)
let account = try await trezor.importAccount(network: .mainnet, accountIndex: 0)
let witnessSetHex = try await trezor.sign(request)

// Newest firmware negotiates THP (v2 / Noise):
let thp = TrezorSignSession(transport: TrezorTHPSession(link: link), network: .mainnet)
```

Trezor returns pub_key + signature, so witnesses come straight from the device.

### Keystone (air-gapped QR)

Keystone has no wired link — the wallet renders an animated QR the device scans, then scans the
device's signature QR back. `KeystoneQRSession` drives the frame pump:

```swift
import CardanoHWWalletKeystone

// Import: scan the device's account-export QR frames until an account resolves.
let importer = KeystoneAccountImportSession(network: .mainnet)
if let account = try importer.ingest(scanned: scannedURString) { /* … */ }

// Sign: render request frames, then scan the signature frames.
let qr = try KeystoneQRSession(request: request)
let frame = qr.nextFrame()                                   // display as an animated QR
switch try qr.ingest(scanned: scannedURString) {             // feed camera scans
case .witnessSet(let hex): let signedTxHex = try WitnessMerge.mergedCBORHex(unsigned: request.unsigned, witnessSetHex: hex)
case .incomplete: break
}
```

### Staking, governance, and native assets

`HardwareSignRequest` carries device-neutral `certificates` and `withdrawals`, and
`UnsignedTxBuilder` accepts `certificates` / `withdrawals` — so stake delegation, Conway
registration/deregistration, vote delegation, reward withdrawals, and native-asset (token) sends work
across all three device families through the same request.

## Verification

Unit-tested with no device (`swift test`): the public-xpub → address vector (public == private
derivation), witness-set CBOR merge round-trip, keyless build, per-device framing/serialization
layouts, and — for Ledger and Trezor — a real cryptographic end-to-end where a scripted mock transport
replays a signature over `body.hash()` and the assembled witness both verifies and merges.

Each signing path is additionally validated against the **vendor's real device code**:

- **Trezor** — the full `CardanoSignTx` dialogue runs against the **trezor-user-env** emulator (real
  firmware); confirmed `tagCborSets = false` and a verifying witness.
- **Ledger** — the staged APDU dialogue runs against **Speculos** with the real `app-cardano` (7.3.1);
  confirmed the staged protocol, `tagCborSets = false`, and a verifying witness.
- **Keystone** — the UR codecs run Keystone's real `ur-registry` Rust (iOS FFI), and signing is
  validated against Keystone's open-source firmware Rust (`app_cardano`) run as an offline oracle.

Harnesses live under `Tools/`. Physical BLE/USB pairing, animated-QR camera scan, and a preprod submit
remain the only device-gated steps.

## License

[MIT](LICENSE) © Kingpin Apps
