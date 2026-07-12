#!/usr/bin/env bash
# Run Keystone's actual device Cardano signer (app_cardano::sign_tx_hash) over a tx body hash and
# print the CardanoTxWitnessSet CBOR it returns. Clones keystone3-firmware next to this repo if needed
# and builds with the pinned nightly. Usage: ./run.sh <bodyHashHex> [entropyHex] [account]
set -euo pipefail

BODY_HASH="${1:?usage: run.sh <bodyHashHex> [entropyHex] [account]}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
FW="$(cd "$REPO_ROOT/.." && pwd)/keystone3-firmware"
TOOLCHAIN="nightly-2025-07-01"

if [ ! -d "$FW" ]; then
  echo "Cloning KeystoneHQ/keystone3-firmware into $FW"
  git clone --depth 1 https://github.com/KeystoneHQ/keystone3-firmware.git "$FW"
fi

# Drop our oracle example into the cardano crate (idempotent) and run it under the pinned toolchain.
mkdir -p "$FW/rust/apps/cardano/examples"
cp "$(dirname "${BASH_SOURCE[0]}")/keystone_oracle.rs" "$FW/rust/apps/cardano/examples/keystone_oracle.rs"

rustup toolchain list | grep -q "$TOOLCHAIN" || rustup toolchain install "$TOOLCHAIN" --profile minimal
TC_BIN="$HOME/.rustup/toolchains/${TOOLCHAIN}-$(uname -m)-apple-darwin/bin"

cd "$FW/rust"
# A Homebrew Rust in PATH shadows rustup, so call the toolchain's cargo binary directly.
env PATH="$TC_BIN:$PATH" RUSTC="$TC_BIN/rustc" RUSTUP_TOOLCHAIN="$TOOLCHAIN" \
  "$TC_BIN/cargo" run --quiet -p app_cardano --example keystone_oracle -- "$BODY_HASH" "${2:-}" "${3:-}"
