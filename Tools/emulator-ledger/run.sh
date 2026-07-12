#!/usr/bin/env bash
# Run Speculos with the built Cardano app ELF. APDU server on :9999, REST API on host :5001
# (container :5000). Re-creates the `speculos-cardano` container each run.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BIN_DIR="$(cd "$REPO_ROOT/.." && pwd)/app-cardano/bin"
SEED="glory promote mansion idle axis finger extra february uncover one trip resource lawn turtle enact monster seven myth punch hobby comfort wild raise skin"

if [ ! -f "$BIN_DIR/app.elf" ]; then
  echo "No app.elf in $BIN_DIR — run ./build-app.sh first." >&2
  exit 1
fi

docker rm -f speculos-cardano >/dev/null 2>&1 || true
docker run -d --name speculos-cardano \
  -v "$BIN_DIR":/app \
  -p 5001:5000 -p 9999:9999 \
  ghcr.io/ledgerhq/speculos \
  --model nanosp --display headless \
  --apdu-port 9999 --api-port 5000 \
  --seed "$SEED" \
  /app/app.elf

sleep 4
docker logs speculos-cardano 2>&1 | tail -6
echo "Speculos up: APDU tcp://127.0.0.1:9999, REST http://127.0.0.1:5001"
