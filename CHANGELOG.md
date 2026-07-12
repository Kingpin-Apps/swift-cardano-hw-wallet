## 0.1.0 (2026-07-11)

### Feat

- **CardanoHWKit** — device-agnostic, keyless core: `PublicHDDerivation` (account-xpub → address, no private key), `UnsignedTxBuilder`, `WitnessMerge`, and the `HardwareSigner` / `HardwarePacketLink` / `HardwareSignSession` seams.
- **CardanoHWWalletKeystone** — air-gapped animated-QR (UR) adapter over Keystone's official SDK (iOS).
- **CardanoHWWalletLedger** — Ledger over the real per-field staged APDU protocol; BLE (official `hw-transport-ios-ble`) + macOS USB-HID transports.
- **CardanoHWWalletTrezor** — Trezor over a self-contained protobuf codec; legacy Codec-v1 and encrypted THP (v2 / Noise) transports; macOS USB-HID.
- Staking + governance certificates, native-asset sends, withdrawals, and multi-address HD across all device families.
- Validated against real device firmware/code: Trezor (trezor-user-env), Ledger (Speculos), Keystone (firmware Rust oracle).
