// Capture golden vectors from the emulator (seed "all all …"): the CardanoGetPublicKey request bytes,
// the account xpub, and the device's own base address for m/1852'/1815'/0'/0/0 (mainnet). These pin
// the Swift Trezor serializer/parser + PublicHDDerivation against real firmware.
import { bridge, MSG, pbRepeatedUint32, pbUint, pbBytes } from "./control.mjs";
const H = 0x80000000;
const acct = [1852 + H, 1815 + H, 0 + H];
const asciiHexToString = (hex) => Buffer.from(hex, "hex").toString("ascii");

const devices = await bridge.enumerate();
const acq = await bridge.acquire(devices[0].path, devices[0].session ?? "null");
await bridge.call(acq.session, MSG.Initialize, pbUint(3, 1)); // derive_cardano

// --- CardanoGetPublicKey ---
const getPubReq = pbRepeatedUint32(1, acct) + pbUint(3, 2); // derivation_type ICARUS_TREZOR
let r = await bridge.call(acq.session, MSG.CardanoGetPublicKey, getPubReq);
const xpub = asciiHexToString(field(r.payloadHex, 1)); // field 1 = xpub (ascii hex string)

// --- CardanoGetAddress (BASE, m/1852'/1815'/0'/0/0 + staking /2/0, mainnet) ---
const params =
  pbUint(1, 0) +                                            // address_type BASE
  pbRepeatedUint32(2, [...acct, 0, 0]) +                    // address_n (spending)
  pbRepeatedUint32(3, [...acct, 2, 0]);                     // address_n_staking
const getAddrReq =
  pbUint(3, 764824073) + pbUint(4, 1) + pbBytes(5, params) + pbUint(6, 2); // magic, net, params, derivation
r = await bridge.call(acq.session, 307 /* CardanoGetAddress */, getAddrReq);
const address = asciiHexToString(field(r.payloadHex, 1)); // field 1 = address string? (see below)

await bridge.release(acq.session);

console.log(JSON.stringify({
  getPublicKeyRequestHex: getPubReq,
  accountPath: "m/1852'/1815'/0'",
  xpubHex: xpub,
  address,
}, null, 2));

// Read the first occurrence of `field` (wire 2, length-delimited) and return its bytes as hex.
function field(hex, wantField) {
  const b = Buffer.from(hex, "hex");
  let i = 0;
  while (i < b.length) {
    const tag = b[i++], f = tag >> 3, wire = tag & 7;
    if (wire === 2) {
      let len = 0, shift = 0, x;
      do { x = b[i++]; len |= (x & 0x7f) << shift; shift += 7; } while (x & 0x80);
      const val = b.slice(i, i + len); i += len;
      if (f === wantField) return val.toString("hex");
    } else if (wire === 0) { while (b[i] & 0x80) i++; i++; }
    else break;
  }
  return "";
}
