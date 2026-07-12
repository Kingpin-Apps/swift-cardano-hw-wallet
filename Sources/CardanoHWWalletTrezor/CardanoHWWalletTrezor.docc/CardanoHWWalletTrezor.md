# ``CardanoHWWalletTrezor``

Trezor support for `swift-cardano-hw-wallet` — the Cardano protobuf dialogue over USB-HID, with both
legacy Codec-v1 and the encrypted THP (v2 / Noise) transport.

## Overview

``TrezorSignSession`` is a ``CardanoHWKit/HardwareSigner``. It imports the account xpub
(`CardanoGetPublicKey`) and drives the `CardanoSignTx` dialogue — Init → body items (inputs, outputs,
asset groups/tokens, certificates, withdrawals) → per-path witness requests → body-hash verify →
finished. Trezor returns **pub_key + signature** per witness, so the witness set is assembled directly
from device responses.

The protobuf is a self-contained proto2 wire codec (no SwiftProtobuf / `protoc`) in
``TrezorCardanoSerializer``, verified against real firmware in the trezor-user-env emulator — see
`Tools/emulator/`.

The session runs over a ``TrezorTransport``:

- ``TrezorV1Transport`` — legacy `##`+type+len framing over 64-byte HID reports on a
  ``CardanoHWKit/HardwarePacketLink`` (``TrezorHIDPacketLink`` on macOS).
- ``TrezorTHPSession`` — the encrypted **THP** v2 channel (`Noise_XX_25519_AESGCM_SHA256`), for newest
  firmware.

```swift
// Legacy Codec-v1 over USB-HID:
let session = TrezorSignSession(link: TrezorHIDPacketLink(), network: .mainnet)
// Or the encrypted THP channel:
let thp = TrezorSignSession(transport: TrezorTHPSession(link: TrezorHIDPacketLink()), network: .mainnet)

let account = try await session.importAccount(network: .mainnet, accountIndex: 0)
let witnessSetHex = try await session.sign(request)
```

## Topics

### Signing

- ``TrezorSignSession``
- ``TrezorAccountImport``
- ``TrezorNetwork``
- ``TrezorSigningOptions``
- ``TrezorDerivationType``

### Transports

- ``TrezorTransport``
- ``TrezorV1Transport``
- ``TrezorTHPSession``
- ``TrezorHIDPacketLink``

### Wire protocol

- ``TrezorCardanoSerializer``
- ``TrezorProtocolV1``
- ``TrezorBIP32Path``
- ``TrezorError``
