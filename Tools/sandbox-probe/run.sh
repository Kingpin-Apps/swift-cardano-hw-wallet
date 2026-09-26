#!/bin/sh
# Build the probe, sign it into the App Sandbox with the USB entitlement, and
# ask the device for something harmless.
#   ./run.sh ledger          # Ledger over USB, Cardano app open
#   ./run.sh trezor          # Trezor One over USB
#   ENTITLEMENTS=no-usb.entitlements ./run.sh ledger   # the same, without the USB entitlement
set -e
cd "$(dirname "$0")"
swift build -c release --product SandboxProbe
BIN=.build/release/SandboxProbe
codesign --force --sign - --entitlements "${ENTITLEMENTS:-probe.entitlements}" "$BIN"
"$BIN" "${1:-ledger}"
