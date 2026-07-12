# ``CardanoHWWalletKeystone``

Keystone support for `swift-cardano-hw-wallet` — air-gapped signing over animated QR (Uniform
Resources / UR), on iOS.

## Overview

Keystone is air-gapped: there is no wired link. The wallet renders an animated QR the device scans,
and scans the device's response QR back. This module wraps Keystone's official `KeystoneSDK` and the
standard Cardano UR types behind two small drivers.

> Important: This module is **iOS-only**. Keystone's `URRegistryFFI` XCFramework ships iOS slices
> only, so the sources are `#if canImport(KeystoneSDK)`-guarded and compile to an empty module on
> other platforms.

**Account import** — `KeystoneAccountImportSession` ingests the device's account-export QR frames
until a `HardwareAccountModel` (account xpub) resolves:

```swift
let importer = KeystoneAccountImportSession(network: .mainnet)
if let account = try importer.ingest(scanned: scannedURString) {
    // account.accountXPub → derive addresses with CardanoHWKit.PublicHDDerivation
}
```

**Signing** — `KeystoneQRSession` is a `HardwareSignSession`: it emits the request as animated-QR
frames and ingests the device's signature frames, yielding a witness set to merge with
`CardanoHWKit.WitnessMerge`:

```swift
let qr = try KeystoneQRSession(request: request)
let frame = qr.nextFrame()                       // render this as an animated QR; call repeatedly
switch try qr.ingest(scanned: scannedURString) { // feed camera scans back
case .witnessSet(let hex):
    let signedTxHex = try WitnessMerge.mergedCBORHex(unsigned: request.unsigned, witnessSetHex: hex)
case .incomplete:
    break                                        // keep scanning
}
```

The three UR codecs (sign-request, signature, account-export) run Keystone's real `ur-registry` Rust
through the SDK's FFI, and the signing path is cross-validated against Keystone's open-source firmware
Rust — see `Tools/emulator-keystone/`.
