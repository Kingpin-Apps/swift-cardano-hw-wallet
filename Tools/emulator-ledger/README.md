# Ledger Speculos emulator harness

Validates the `CardanoHWWalletLedger` code against the **real Ledger Cardano app**
(`LedgerHQ/app-cardano`) running in [Speculos](https://speculos.ledger.com/), Ledger's official
emulator — the Ledger counterpart to the Trezor `Tools/emulator/` harness.

Speculos exposes two endpoints the Swift tests drive:

- **Raw APDU server** on TCP `:9999` — frames are `[u32 BE payload-len][apdu]` out, and
  `[u32 BE payload-len][payload][2-byte SW]` back (the status word is **not** counted in the length).
  This is what `LedgerSpeculosTransport` (in the test target) speaks.
- **REST API** on `:5000` (mapped to host `:5001` here, since macOS ControlCenter/AirPlay owns 5000) —
  `POST /apdu`, `POST /button/{left,right,both}` with body `{"action":"press-and-release"}`, and
  `GET /events?currentscreenonly=true` to read the current screen. The transport uses the button +
  events endpoints to auto-approve on-device review flows.

## Setup

Requires Docker. The Speculos image (`ghcr.io/ledgerhq/speculos`) ships **no app binaries**, so the
Cardano app ELF must be built first with `ledger-app-builder`.

```sh
# 1. Clone the app source (sibling of this repo) and build the Nano S+ ELF (DEVEL build).
./build-app.sh          # → ../../app-cardano/bin/app.elf

# 2. Run Speculos with the ELF (APDU :9999, REST :5001).
./run.sh                # docker container `speculos-cardano`
```

The default `--seed` is the classic 24-word Ledger test seed
(`glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact
monster seven myth punch hobby comfort wild raise skin`), model `nanosp`.

## Tests

The Swift integration tests are gated on `LEDGER_EMULATOR=1` (so a normal `swift test` skips them
when the emulator is down):

```sh
LEDGER_EMULATOR=1 swift test --filter LedgerSpeculos
```

Their captured firmware bytes are pinned as device-free regressions in `LedgerSpeculosVectorsTests`.

## Golden vectors (seed above, `m/1852'/1815'/0'`, mainnet)

- **account xpub**: `78d137231e6346f17b1d442bace1f7ba1d54a88ef8509464e2e786a854bd4815acafe34e34bf401b4b0164607ee506c4aac63a0828f1dc20ab73ec39f2fe11f3`
- **device base address** (`m/1852'/1815'/0'/0/0` + stake `…/2/0`) raw bytes:
  `016dfa09426959db1023639e8d1f07bb1e478e722c6ebc1d57ba8703b9db219ee5ce9a74f98fdadc2de13efced5a154ef8d4d41929d5bf9ff6`

The app is **Cardano ADA 7.3.1**; its authoritative APDU spec is
`app-cardano/tests/application_client/command_builder.py`.
