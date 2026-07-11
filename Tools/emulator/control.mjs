// trezor-user-env driver: WebSocket controller (:9001) + trezord bridge (:9002-hosted, :21325).
// Node 22+ (global WebSocket + fetch). No external deps.

const WS_URL = process.env.TREZOR_WS ?? "ws://localhost:9001";
// The node-bridge's HTTP API is on 21328 (21325 is the emulator's UDP debug port). Use IPv4 loopback
// so the Host header is `127.0.0.1:21328`, which the bridge's no-Origin allow-list accepts.
const BRIDGE = process.env.TREZOR_BRIDGE ?? "http://127.0.0.1:21328";
const ORIGIN = "https://user-env.trezor.io";

// ---- WebSocket controller ----

export class Controller {
  constructor() {
    this.ws = null;
    this.nextId = 1;
    this.pending = new Map();
  }

  connect() {
    return new Promise((resolve, reject) => {
      const ws = new WebSocket(WS_URL);
      ws.addEventListener("open", () => { this.ws = ws; resolve(); });
      ws.addEventListener("error", (e) => reject(new Error("WS error: " + (e.message ?? e))));
      ws.addEventListener("message", (ev) => {
        let msg;
        try { msg = JSON.parse(ev.data); } catch { return; }
        // The very first message after connect is a welcome/version blob with no id.
        if (msg.id != null && this.pending.has(msg.id)) {
          const { resolve } = this.pending.get(msg.id);
          this.pending.delete(msg.id);
          resolve(msg);
        }
      });
    });
  }

  send(type, args = {}, timeoutMs = 120000) {
    const id = this.nextId++;
    const payload = JSON.stringify({ id, type, ...args });
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => {
        this.pending.delete(id);
        reject(new Error(`timeout waiting for '${type}'`));
      }, timeoutMs);
      this.pending.set(id, { resolve: (m) => { clearTimeout(timer); resolve(m); } });
      this.ws.send(payload);
    });
  }

  close() { this.ws?.close(); }
}

// ---- trezord bridge ----

async function bridgePost(path, bodyText) {
  // No Origin header → the bridge accepts based on the Host being 127.0.0.1:<port>.
  const res = await fetch(`${BRIDGE}${path}`, { method: "POST", body: bodyText ?? "" });
  const text = await res.text();
  if (!res.ok) throw new Error(`bridge ${path} -> ${res.status}: ${text}`);
  return text;
}

/// Minimal protobuf encoders (proto2, the fields THP/Cardano messages use).
export function pbVarint(n) {
  let out = "";
  let v = BigInt(n);
  do {
    let byte = Number(v & 0x7fn);
    v >>= 7n;
    if (v !== 0n) byte |= 0x80;
    out += byte.toString(16).padStart(2, "0");
  } while (v !== 0n);
  return out;
}
export function pbTag(field, wire) { return pbVarint((field << 3) | wire); }
export function pbRepeatedUint32(field, values) { return values.map((v) => pbTag(field, 0) + pbVarint(v)).join(""); }
export function pbUint(field, value) { return pbTag(field, 0) + pbVarint(value); }
export function pbBytes(field, hex) { return pbTag(field, 2) + pbVarint(hex.length / 2) + hex; }

export const bridge = {
  async enumerate() { return JSON.parse(await bridgePost("/enumerate")); },
  async acquire(path, prev = "null") { return JSON.parse(await bridgePost(`/acquire/${path}/${prev}`)); },
  async release(session) { return await bridgePost(`/release/${session}`); },
  // call: send one message, get one response. The node-bridge body is JSON `{data, protocol}` where
  // `data` = hex of `msgType(2 BE) ‖ length(4 BE) ‖ protobuf`. `protocol` is "v1" (Codec v1) or "v2".
  async call(session, type, payloadHex = "", protocol = "bridge") {
    const data = be16(type) + be32(payloadHex.length / 2) + payloadHex;
    const respText = await bridgePost(`/call/${session}`, JSON.stringify({ data, protocol }));
    const json = JSON.parse(respText);
    return parseMessage(json.data);
  },
};

// ---- helpers ----

export function be16(n) { return n.toString(16).padStart(4, "0"); }
export function be32(n) { return n.toString(16).padStart(8, "0"); }

export function parseMessage(hex) {
  const type = parseInt(hex.slice(0, 4), 16);
  const len = parseInt(hex.slice(4, 12), 16);
  const payloadHex = hex.slice(12, 12 + len * 2);
  return { type, payloadHex };
}

// The standard Trezor test mnemonic (a.k.a. "all all …"), used across trezor-firmware Cardano tests.
export const TEST_MNEMONIC =
  "all all all all all all all all all all all all";

export const MSG = {
  Initialize: 0, Features: 17, Failure: 3, ButtonRequest: 26, ButtonAck: 27,
  CardanoGetPublicKey: 305, CardanoPublicKey: 306,
};
