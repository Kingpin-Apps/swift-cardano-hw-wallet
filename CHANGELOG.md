## 0.2.0 (2026-09-26)

### Fix

- **usb**: open the wire interface by usage page, not the FIDO one

## 0.1.0 (2026-07-12)

### Feat

- **hw**: THP v2 session — channel + handshake + encrypted ABP transport
- **hw**: Trezor THP (v2) crypto core — Noise XX + transport framing (FU-D)
- **hw**: staking + governance certificates (FU-A core)
- **hw**: Phase 4 — physical transports (BLE + macOS USB-HID)
- **hw**: Phase 3 — Trezor Cardano protobuf protocol + sign session
- **hw**: Phase 2 — Ledger v8 APDU protocol + sign session
- **hw**: Phase 1 — Ledger/Trezor transport seams + framing codecs
- **keystone**: KeystoneAccountImportSession (multi-part account-export decode)
- **keystone**: CardanoHWWalletKeystone — air-gapped QR codecs (iOS)
- **core**: CardanoHWKit — public HD derivation, keyless build, witness merge

### Fix

- **ledger**: rewrite SignTx to the real staged APDU protocol, verified vs Speculos
