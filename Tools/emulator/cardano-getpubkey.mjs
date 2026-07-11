// Acquire the running emulator via the bridge and fetch the Cardano account public key
// (m/1852'/1815'/0', ICARUS_TREZOR derivation) — the reference to validate the Swift derivation.
// Assumes the emulator + bridge are already up + seeded (run bootstrap.mjs first).
import { Controller, bridge, MSG, pbRepeatedUint32, pbUint } from "./control.mjs";
const requestHex = (path, dt) => pbRepeatedUint32(1, path) + pbUint(3, dt);

const H = 0x80000000;
const account0 = [1852 + H, 1815 + H, 0 + H];   // m/1852'/1815'/0'

const c = new Controller();
await c.connect();

const devices = await bridge.enumerate();
if (!devices.length) { console.log("✗ no device — run bootstrap.mjs first"); process.exit(1); }
const acq = await bridge.acquire(devices[0].path, devices[0].session ?? "null");
console.log("● session", acq.session);

// Initialize { derive_cardano = true } to enable Cardano key derivation for the session.
let res = await bridge.call(acq.session, MSG.Initialize, pbUint(3, 1));
console.log("● Initialize(derive_cardano) →", res.type === MSG.Features ? "Features" : `type ${res.type}`);

// CardanoGetPublicKey { address_n=account0 (field 1), derivation_type=ICARUS_TREZOR=2 (field 3) }
const payload = requestHex(account0, 2);
console.log("● request payload =", payload);
res = await bridge.call(acq.session, MSG.CardanoGetPublicKey, payload);

// If the device asks for a button, approve it and read again.
if (res.type === MSG.ButtonRequest) {
  await c.send("emulator-press-yes");
  res = await bridge.call(acq.session, MSG.ButtonAck, "");
}

if (res.type !== MSG.CardanoPublicKey) {
  console.log("✗ unexpected response type", res.type, res.payloadHex);
  await bridge.release(acq.session); process.exit(1);
}

// CardanoPublicKey { xpub = field 1 (string) }. Parse the first length-delimited field-1.
const xpubHex = parseField1String(res.payloadHex);
console.log("● CardanoPublicKey.xpub =", xpubHex);
console.log("  (32-byte pubkey ‖ 32-byte chain code)");

await bridge.release(acq.session);
c.close();

function parseField1String(hex) {
  // field 1, wire 2 → tag 0x0a, then length varint, then bytes (ascii hex of the xpub).
  const bytes = Buffer.from(hex, "hex");
  let i = 0;
  while (i < bytes.length) {
    const tag = bytes[i++];
    const field = tag >> 3, wire = tag & 7;
    if (wire === 2) {
      let len = 0, shift = 0, b;
      do { b = bytes[i++]; len |= (b & 0x7f) << shift; shift += 7; } while (b & 0x80);
      const val = bytes.slice(i, i + len); i += len;
      if (field === 1) return val.toString("ascii"); // xpub is an ascii hex string
    } else if (wire === 0) {
      while (bytes[i] & 0x80) i++; i++;
    } else break;
  }
  return null;
}
