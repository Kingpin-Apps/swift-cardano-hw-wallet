# ``CardanoHWWalletLedger``

Ledger support for `swift-cardano-hw-wallet` — the real `app-cardano` per-field staged APDU protocol
over BLE or macOS USB-HID.

## Overview

``LedgerSignSession`` is a ``CardanoHWKit/HardwareSigner``: it imports the account xpub
(`getExtendedPublicKey`) and drives the staged `CardanoSignTx` dialogue — INIT → each input → each
output (basic → asset groups/tokens → confirm) → fee → ttl → certificates → withdrawals → validity →
a tx-confirm that returns the body hash → one witness request per path. Ledger returns **signatures
only** (no public keys), so the session derives each witness key locally via
``CardanoHWKit/PublicHDDerivation`` and integrity-guards the device tx hash against `body.hash()`.

The APDU stream is produced by ``LedgerCardanoSerializer`` and verified against the real Ledger
`app-cardano` (v7.3.1) in the Speculos emulator — see `Tools/emulator-ledger/`.

Choose a transport:

- ``BleLedgerTransport`` — Ledger's official `hw-transport-ios-ble` SDK (iOS + macOS).
- ``HidLedgerTransport`` — IOKit HID + `0x05`/channel framing (macOS).

```swift
let session = LedgerSignSession(transport: BleLedgerTransport(), network: .mainnet)
let account = try await session.importAccount(network: .mainnet, accountIndex: 0)
let witnessSetHex = try await session.sign(request)   // request built with the derivation
```

## Topics

### Signing

- ``LedgerSignSession``
- ``LedgerAccountImport``
- ``LedgerNetwork``
- ``LedgerSigningOptions``

### Transports

- ``LedgerTransport``
- ``BleLedgerTransport``
- ``HidLedgerTransport``

### Wire protocol

- ``LedgerCardanoSerializer``
- ``LedgerAPDU``
- ``LedgerBIP32Path``
- ``LedgerError``
