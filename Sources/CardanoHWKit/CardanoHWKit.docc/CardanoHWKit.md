# ``CardanoHWKit``

The device-agnostic, **keyless** core of `swift-cardano-hw-wallet`: derive addresses from a
device-exported account xpub, build unsigned transactions, and merge a device-returned witness — all
without ever touching a private key.

## Overview

`CardanoHWKit` is the vendor-neutral foundation every device adapter (Keystone, Ledger, Trezor) builds
on. It never holds secret material: a hardware wallet exports its **account extended public key** once,
and from that everything the wallet needs is derived publicly.

The signing lifecycle is three keyless steps plus one on-device step:

1. **Import** — a device returns a ``HardwareAccountModel`` (account xpub + path).
2. **Derive** — ``PublicHDDerivation`` turns the xpub into receive / change / stake addresses using
   BIP32-Ed25519 *public, non-hardened* derivation. The gating test proves this reproduces the SDK's
   private-key derivation byte-for-byte.
3. **Build** — ``UnsignedTxBuilder`` assembles an unsigned ``SwiftCardanoCore/Transaction`` over any
   `ChainContext`, returning an ``UnsignedBuildResult``.
4. **Sign + merge** — the device signs a ``HardwareSignRequest`` (off-line); ``WitnessMerge`` injects
   the returned `TransactionWitnessSet` into the unsigned transaction to produce a submittable signed
   tx. No private key is involved on the host at any point.

### The device seam

Two protocols let every vendor plug in behind one interface:

- ``HardwareSigner`` — an async one-shot `importAccount` / `sign` for interactive byte-protocol
  devices (Ledger, Trezor).
- ``HardwarePacketLink`` — a duplex 64-byte packet link for raw USB/BLE transports.

Air-gapped devices (Keystone) instead drive a UI frame-pump via ``HardwareSignSession``.

### Staking, governance, and native assets

``HardwareSignRequest`` carries device-neutral ``HardwareCertificate`` and ``HardwareWithdrawal``
descriptions (stake delegation, Conway registration/deregistration, vote delegation to a
``HardwareDRepKind``, reward withdrawals), and ``UnsignedTxBuilder`` accepts certificates and
withdrawals — so staking, governance, and native-asset (token) sends flow through the same request
across all device families.

## Topics

### Keyless derivation & build

- ``PublicHDDerivation``
- ``UnsignedTxBuilder``
- ``UnsignedBuildResult``
- ``WitnessMerge``

### The device model & request

- ``HardwareAccountModel``
- ``HardwareDeviceKind``
- ``HardwareSignRequest``
- ``HardwareCertificate``
- ``HardwareWithdrawal``
- ``HardwareDRepKind``

### Device seams

- ``HardwareSigner``
- ``HardwarePacketLink``
- ``HardwareSignSession``

### Errors

- ``HardwareWalletError``
