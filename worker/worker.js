import { connect } from "cloudflare:sockets";

const DEFAULT_PATH = "/api/v1/stream";
const DNS_PATH = "/api/v1/dns";
const DOH_URL = "https://1.1.1.1/dns-query";
const USER_AGENT_PROTO = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)";

const CF_NETS = [
  ["173.245.48.0", 20],
  ["103.21.244.0", 22],
  ["103.22.200.0", 22],
  ["103.31.4.0", 22],
  ["141.101.64.0", 18],
  ["108.162.192.0", 18],
  ["190.93.240.0", 20],
  ["188.114.96.0", 20],
  ["197.234.240.0", 22],
  ["198.41.128.0", 17],
  ["162.158.0.0", 15],
  ["104.16.0.0", 13],
  ["104.24.0.0", 14],
  ["172.64.0.0", 13],
  ["131.0.72.0", 22],
];

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);

    if (url.pathname === DNS_PATH && request.method === "POST") {
      return handleDoh(request);
    }

    const upgrade = (request.headers.get("Upgrade") || "").toLowerCase();
    const wsPath = env.WS_PATH || DEFAULT_PATH;
    if (upgrade === "websocket" && url.pathname === wsPath) {
      return handleVless(request, env);
    }

    return handleDecoy(request, env, ctx);
  },
};

function handleVless(request, env) {
  const subprotocol = request.headers.get("Sec-WebSocket-Protocol");
  const pair = new WebSocketPair();
  const [client, server] = Object.values(pair);
  server.accept();

  const session = new VlessSession(server, env);

  if (subprotocol) {
    try {
      session.feed(base64UrlDecode(subprotocol));
    } catch {
      // некорректный early-data — ждём обычный первый фрейм
    }
  }

  const headers = new Headers();
  if (subprotocol) {
    headers.set("Sec-WebSocket-Protocol", subprotocol);
  }

  return new Response(null, { status: 101, webSocket: client, headers });
}

class VlessSession {
  constructor(ws, env) {
    this.ws = ws;
    this.env = env;
    this.buffer = new Uint8Array(0);
    this.header = null;
    this.writer = null;
    this.queue = [];
    this.closed = false;

    ws.addEventListener("message", (event) => this.onMessage(event.data));
    ws.addEventListener("close", () => this.close());
    ws.addEventListener("error", () => this.close());
  }

  onMessage(data) {
    if (this.closed) return;
    const bytes = toUint8(data);

    if (!this.header) {
      this.buffer = concat(this.buffer, bytes);
      this.tryParseHeader();
      return;
    }

    if (this.header.cmd === 2) {
      this.handleUdp(bytes);
      return;
    }

    if (this.writer) {
      this.writer.write(bytes).catch(() => this.close());
    } else {
      this.queue.push(bytes);
    }
  }

  feed(bytes) {
    this.onMessage(bytes);
  }

  tryParseHeader() {
    const b = this.buffer;
    if (b.length < 18) return;

    if (b[0] !== 0) {
      this.close();
      return;
    }

    const uuid = b.slice(1, 17);
    const addonsLen = b[17];
    const headerLen = 18 + addonsLen + 1 + 2 + 1;
    if (b.length < headerLen) return;

    const cmd = b[18 + addonsLen];
    const port = (b[19 + addonsLen] << 8) | b[20 + addonsLen];
    const atyp = b[21 + addonsLen];
    let offset = 22 + addonsLen;
    let host = null;

    if (atyp === 1) {
      if (b.length < offset + 4) return;
      host = `${b[offset]}.${b[offset + 1]}.${b[offset + 2]}.${b[offset + 3]}`;
      offset += 4;
    } else if (atyp === 2) {
      if (b.length < offset + 1) return;
      const len = b[offset];
      offset += 1;
      if (b.length < offset + len) return;
      host = new TextDecoder().decode(b.slice(offset, offset + len));
      offset += len;
    } else if (atyp === 3) {
      if (b.length < offset + 16) return;
      const parts = [];
      for (let i = 0; i < 16; i += 2) {
        parts.push(((b[offset + i] << 8) | b[offset + i + 1]).toString(16));
      }
      host = parts.join(":");
      offset += 16;
    } else {
      this.close();
      return;
    }

    if (!uuidAllowed(uuid, this.env)) {
      this.close();
      return;
    }

    const payload = b.slice(offset);
    this.buffer = new Uint8Array(0);
    this.header = { cmd, port, host };

    if (cmd === 1) {
      this.startTcp(host, port, payload);
    } else if (cmd === 2) {
      this.startUdp(payload);
    } else {
      this.close();
    }
  }

  async startTcp(host, port, initial) {
    try {
      const socket = await this.openTcp(host, port);
      this.writer = socket.writable.getWriter();

      socket.readable
        .pipeTo(
          new WritableStream({
            write: (chunk) => {
              try {
                this.ws.send(chunk);
              } catch {
                this.close();
              }
            },
            close: () => this.close(),
            abort: () => this.close(),
          }),
        )
        .catch(() => this.close());

      if (initial.length > 0) {
        await this.writer.write(initial);
      }
      for (const chunk of this.queue) {
        await this.writer.write(chunk);
      }
      this.queue = [];
    } catch {
      this.close();
    }
  }

  async openTcp(host, port) {
    if (!isCloudflareIp(host)) {
      try {
        return connect({ hostname: host, port });
      } catch {
        // ниже — PROXYIP fallback
      }
    }

    const proxy = this.env.PROXYIP;
    if (!proxy) {
      throw new Error("цель недоступна напрямую и PROXYIP не задан");
    }

    const [proxyHost, proxyPort] = parseProxy(proxy, port);
    const socket = connect({ hostname: proxyHost, port: proxyPort });
    const writer = socket.writable.getWriter();
    const header = `PROXY TCP4 ${host} ${proxyHost} 0 ${port}\r\n`;
    await writer.write(new TextEncoder().encode(header));
    writer.releaseLock();
    return socket;
  }

  async startUdp(initial) {
    this.header.cmd = 2;
    await this.handleUdp(initial);
  }

  async handleUdp(data) {
    try {
      let offset = 0;
      const responses = [];

      while (offset + 2 <= data.length) {
        const len = (data[offset] << 8) | data[offset + 1];
        offset += 2;
        if (offset + len > data.length) break;
        const query = data.slice(offset, offset + len);
        offset += len;

        const answer = await doh(query);
        const frame = new Uint8Array(2 + answer.length);
        frame[0] = (answer.length >> 8) & 0xff;
        frame[1] = answer.length & 0xff;
        frame.set(answer, 2);
        responses.push(frame);
      }

      if (responses.length > 0) {
        this.ws.send(concatAll(responses));
      }
    } catch {
      this.close();
    }
  }

  close() {
    if (this.closed) return;
    this.closed = true;

    if (this.writer) {
      this.writer.close().catch(() => {});
    }
    try {
      this.ws.close();
    } catch {
      // уже закрыт
    }
  }
}

async function handleDoh(request) {
  try {
    const query = new Uint8Array(await request.arrayBuffer());
    const response = await doh(query);
    return new Response(response, {
      status: 200,
      headers: {
        "content-type": "application/dns-message",
        "cache-control": "no-store",
      },
    });
  } catch {
    return new Response("Bad Gateway", { status: 502 });
  }
}

async function doh(query) {
  const response = await fetch(DOH_URL, {
    method: "POST",
    headers: {
      "content-type": "application/dns-message",
      accept: "application/dns-message",
      "user-agent": USER_AGENT_PROTO,
    },
    body: query,
  });
  if (!response.ok) {
    throw new Error(`DoH ${response.status}`);
  }
  return new Uint8Array(await response.arrayBuffer());
}

async function handleDecoy(request, env, ctx) {
  const decoy = new URL(request.url);
  decoy.protocol = "https:";
  decoy.hostname = env.DECOY_HOST || "www.cloudflare.com";
  decoy.pathname = "/";
  decoy.search = "";

  const cache = caches.default;
  const cacheKey = new Request(decoy.toString(), { method: "GET" });
  const cached = await cache.match(cacheKey);
  if (cached) return cached;

  let response;
  try {
    response = await fetch(decoy.toString(), {
      headers: { "user-agent": USER_AGENT_PROTO },
    });
  } catch {
    return new Response("Not Found", { status: 404 });
  }

  const out = new Response(response.body, response);
  out.headers.set("cache-control", "public, max-age=3600");
  ctx.waitUntil(cache.put(cacheKey, out.clone()));
  return out;
}

function uuidAllowed(uuid, env) {
  const configured = (env.UUID || "")
    .split(",")
    .map((item) => item.trim())
    .filter(Boolean);

  let matched = 0;
  for (const item of configured) {
    const candidate = parseUuid(item);
    if (!candidate) continue;
    let diff = 0;
    for (let i = 0; i < 16; i += 1) {
      diff |= uuid[i] ^ candidate[i];
    }
    matched |= diff === 0 ? 1 : 0;
  }
  return matched === 1;
}

function parseUuid(value) {
  const hex = value.replaceAll("-", "");
  if (hex.length !== 32) return null;
  const bytes = new Uint8Array(16);
  for (let i = 0; i < 16; i += 1) {
    const byte = Number.parseInt(hex.slice(i * 2, i * 2 + 2), 16);
    if (Number.isNaN(byte)) return null;
    bytes[i] = byte;
  }
  return bytes;
}

function base64UrlDecode(value) {
  let text = value.replaceAll("-", "+").replaceAll("_", "/");
  while (text.length % 4 !== 0) text += "=";
  const binary = atob(text);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i += 1) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

function toUint8(data) {
  if (data instanceof ArrayBuffer) return new Uint8Array(data);
  if (ArrayBuffer.isView(data)) {
    return new Uint8Array(data.buffer, data.byteOffset, data.byteLength);
  }
  if (typeof data === "string") return new TextEncoder().encode(data);
  return new Uint8Array(data);
}

function concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a, 0);
  out.set(b, a.length);
  return out;
}

function concatAll(chunks) {
  let total = 0;
  for (const chunk of chunks) total += chunk.length;
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

function parseProxy(value, defaultPort) {
  if (value.startsWith("[")) {
    const end = value.indexOf("]");
    const host = value.slice(1, end);
    const rest = value.slice(end + 1);
    const port = rest.startsWith(":") ? Number.parseInt(rest.slice(1), 10) : defaultPort;
    return [host, port];
  }
  const index = value.lastIndexOf(":");
  if (index > 0 && /^\d+$/.test(value.slice(index + 1))) {
    return [value.slice(0, index), Number.parseInt(value.slice(index + 1), 10)];
  }
  return [value, defaultPort];
}

function isCloudflareIp(host) {
  const ip = parseIpv4(host);
  if (ip === null) return false;
  return CF_NETS.some(([network, bits]) => {
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return (ip & mask) === (parseIpv4(network) & mask);
  });
}

function parseIpv4(value) {
  const parts = value.split(".");
  if (parts.length !== 4) return null;
  let result = 0;
  for (const part of parts) {
    if (!/^\d+$/.test(part)) return null;
    const byte = Number.parseInt(part, 10);
    if (byte < 0 || byte > 255) return null;
    result = ((result << 8) | byte) >>> 0;
  }
  return result;
}

export { VlessSession, uuidAllowed, base64UrlDecode, parseUuid, isCloudflareIp };
