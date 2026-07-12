# Keystone device-Rust oracle harness

Keystone is **air-gapped (QR/UR only)** — there is no wired protocol and therefore no scriptable
device emulator like trezor-user-env or Speculos. So Keystone is validated differently from Trezor and
Ledger, at two levels:

1. **UR codecs** — our `CardanoHWWalletKeystone` sign-request / signature / account-import codecs run
   Keystone's **real `ur-registry` Rust** via `keystone-sdk-ios` → `URRegistryFFI` (iOS). So the QR
   encode/decode layer already executes the device's own code.
2. **Signing** — the only device-side piece not covered by the FFI is the actual signing. That logic
   is open-source Rust in Keystone's firmware (`keystone3-firmware/rust/apps/cardano`), so we run it as
   an **offline oracle**: `keystone_oracle.rs` calls `app_cardano::transaction::sign_tx_hash` (the exact
   BIP32-Ed25519 derive+sign the device performs) over a transaction body hash + witness path, and
   prints the `CardanoTxWitnessSet` CBOR the device would return.

The Swift side (`Tests/CardanoHWKitTests/`) pins the results:
- `KeystoneDeviceVectorsTests` — authentic vectors lifted from the firmware crate's own unit tests
  (`address.rs`, `transaction.rs`): our `PublicHDDerivation` reproduces the firmware address, and the
  firmware's returned witness set verifies over its body hash.
- `KeystoneOracleVectorsTests` — feeds the oracle our self-send's body hash, then confirms the device's
  returned witness verifies against our locally derived key and merges via `WitnessMerge`.

## Reproduce the oracle

Needs the pinned Rust nightly (`nightly-2025-07-01`) the firmware workspace uses.

```sh
./run.sh <bodyHashHex>     # clones keystone3-firmware next to this repo if needed, then runs the oracle
```

`run.sh` copies `keystone_oracle.rs` into the cloned `keystone3-firmware/rust/apps/cardano/examples/`
and runs it under the pinned toolchain. The body hash is printed by
`KeystoneOracleVectorsTests` (`KEYSTONE-ORACLE bodyHash=…`).

Toolchain gotcha: a Homebrew Rust install shadows the rustup toolchain in `PATH`; invoke the pinned
nightly's `cargo` binary directly (`~/.rustup/toolchains/nightly-2025-07-01-*/bin/cargo`), not the
`PATH` `cargo`.
