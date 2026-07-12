#!/usr/bin/env bash
# Build the Ledger Cardano app ELF for Nano S+ via ledger-app-builder (DEVEL build). The Speculos
# image ships no app binaries, so this ELF is what `run.sh` loads. Clones LedgerHQ/app-cardano as a
# sibling of the swift-cardano-hw-wallet repo if not already present.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
APP_DIR="$(cd "$REPO_ROOT/.." && pwd)/app-cardano"
BUILDER="ghcr.io/ledgerhq/ledger-app-builder/ledger-app-builder-lite:latest"

if [ ! -d "$APP_DIR" ]; then
  echo "Cloning LedgerHQ/app-cardano into $APP_DIR"
  git clone --depth 1 https://github.com/LedgerHQ/app-cardano.git "$APP_DIR"
fi

echo "Building Nano S+ ELF (DEVEL=1) …"
docker run --rm -v "$APP_DIR":/app "$BUILDER" bash -c "make -j DEVEL=1"

ls -la "$APP_DIR/bin/app.elf"
echo "Done → $APP_DIR/bin/app.elf"
