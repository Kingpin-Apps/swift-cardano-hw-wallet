// Start + seed the emulator, then prove the bridge pipeline (enumerate → acquire → Initialize).
// Usage: node Tools/emulator/bootstrap.mjs
import { Controller, bridge, MSG, TEST_MNEMONIC } from "./control.mjs";

const log = (...a) => console.log(...a);

const c = new Controller();
await c.connect();
log("● connected to controller");

let bg = await c.send("background-check");
log("● background-check:", JSON.stringify(bg.response ?? bg));

if (!(bg.response?.emulator_status)) {
  log("● starting emulator (T2T1)…");
  const started = await c.send("emulator-start", { model: "T2T1", wipe: true });
  log("  →", JSON.stringify(started.response ?? started));
}

log("● setting up seed…");
const setup = await c.send("emulator-setup", { mnemonic: TEST_MNEMONIC, pin: "", passphrase_protection: false, label: "MansAmana-Emu" });
log("  →", JSON.stringify(setup.response ?? setup));

try {
  const unsafe = await c.send("emulator-allow-unsafe-paths");
  log("● allow-unsafe-paths:", JSON.stringify(unsafe.response ?? unsafe));
} catch (e) { log("● allow-unsafe-paths skipped:", e.message); }

log("● starting bridge…");
try {
  const b = await c.send("bridge-start");
  log("  →", JSON.stringify(b.response ?? b));
} catch (e) { log("  bridge-start:", e.message); }

bg = await c.send("background-check");
log("● background-check:", JSON.stringify(bg.response ?? bg));

log("● bridge enumerate…");
const devices = await bridge.enumerate();
log("  →", JSON.stringify(devices));
if (!devices.length) { log("✗ no devices on the bridge"); c.close(); process.exit(1); }

const path = devices[0].path;
const acq = await bridge.acquire(path, devices[0].session ?? "null");
log("● acquired session:", acq.session);

const features = await bridge.call(acq.session, MSG.Initialize, "");
log("● Initialize → message type", features.type, features.type === MSG.Features ? "(Features)" : "");
// Minimal parse: pull a couple of human-readable fields out of the Features protobuf.
log("  Features payload (first 80 bytes hex):", features.payloadHex.slice(0, 160));

await bridge.release(acq.session);
log("● released. Pipeline OK.");
c.close();
