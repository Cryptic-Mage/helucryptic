// helucryptic signaling server - Cloudflare Worker + Durable Object.
//
// A 1:1 port of server.py. The wire protocol is identical, so the desktop
// client connects unchanged at:
//   wss://helucryptic-signaling.<your-subdomain>.workers.dev/ws/<username>?room=<room>
//
// All connections are routed to ONE Durable Object instance ("global") so they
// share state. The DO uses the WebSocket Hibernation API; per-socket identity
// (username, room) is stored as a serialized attachment + tags so it survives
// hibernation. Media never touches this server - it only relays the handshake.

const OPEN = 1; // WebSocket.OPEN
const SERVER_TYPES = new Set([
  "peer_joined", "peer_left", "room_state", "error",
  "session_token", "presence", "hub_capability", "call_active",
]);
const ROOM_MAX = 4;

export default {
  async fetch(request, env) {
    // TURN credentials are a plain HTTP request - they need no hub state, so
    // they never touch the Durable Object.
    if (new URL(request.url).pathname === "/turn") {
      return handleTurn(request, env);
    }
    // Route every connection to the same hub instance.
    const id = env.SIGNAL_HUB.idFromName("global");
    const stub = env.SIGNAL_HUB.get(id);
    return stub.fetch(request);
  },
};

// ---------------------------------------------------------------------------
// TURN credential minting (1:1 port of turn_provider.py - keep both in sync).
//
// Peers behind CGNAT / symmetric NAT have no direct UDP path to each other, so
// a relay is the only way media and file transfer cross the WAN. The secret
// that mints relay credentials lives in Worker secrets, never in the shipped
// desktop client, and what the client receives expires within a day.
//
// Provider is chosen by whichever secrets are set (first match wins):
//   cloudflare - CF_TURN_KEY_ID + CF_TURN_API_TOKEN   (Cloudflare Realtime TURN)
//   hmac       - TURN_URL + TURN_STATIC_SECRET        (coturn use-auth-secret)
//   static     - TURN_URL + TURN_PASSWORD             (hosted provider creds)
// ---------------------------------------------------------------------------
const TURN_TTL_SECONDS = 24 * 3600;

function turnProviderMode(env) {
  if (env.CF_TURN_KEY_ID && env.CF_TURN_API_TOKEN) return "cloudflare";
  if (env.TURN_URL && env.TURN_STATIC_SECRET) return "hmac";
  if (env.TURN_URL && env.TURN_PASSWORD) return "static";
  return "none";
}

function turnUrlList(raw) {
  return String(raw || "").split(",").map((u) => u.trim()).filter(Boolean);
}

// coturn REST API: username is "<expiry>:<label>", password is
// base64(HMAC-SHA1(secret, username)).
async function hmacCredentials(secret, ttl, label) {
  const username = `${Math.floor(Date.now() / 1000) + ttl}:${label}`;
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-1" }, false, ["sign"],
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(username));
  const credential = btoa(String.fromCharCode(...new Uint8Array(sig)));
  return { username, credential };
}

async function cloudflareIceServers(env, ttl) {
  const resp = await fetch(
    `https://rtc.live.cloudflare.com/v1/turn/keys/${env.CF_TURN_KEY_ID}/credentials/generate-ice-servers`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${env.CF_TURN_API_TOKEN}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ ttl }),
    },
  );
  if (!resp.ok) throw new Error(`cloudflare turn ${resp.status}`);
  const payload = await resp.json();
  // The API has returned both a bare object and a list across versions.
  let servers = payload.iceServers;
  if (servers && !Array.isArray(servers)) servers = [servers];
  if (!Array.isArray(servers) || servers.length === 0) {
    throw new Error("cloudflare turn: no iceServers");
  }
  const out = [];
  for (const s of servers) {
    let urls = s.urls || s.url;
    if (typeof urls === "string") urls = [urls];
    if (!urls || urls.length === 0) continue;
    const entry = { urls };
    if (s.username) entry.username = s.username;
    if (s.credential) entry.credential = s.credential;
    out.push(entry);
  }
  if (out.length === 0) throw new Error("cloudflare turn: no usable URLs");
  return out;
}

async function handleTurn(request, env) {
  const url = new URL(request.url);
  const expected = env.SERVER_PASSWORD || "";
  if (expected && (url.searchParams.get("password") || "") !== expected) {
    return new Response("Invalid server access password.", { status: 403 });
  }
  const ttl = TURN_TTL_SECONDS;
  const mode = turnProviderMode(env);
  let iceServers = [];
  try {
    if (mode === "cloudflare") {
      iceServers = await cloudflareIceServers(env, ttl);
    } else if (mode === "hmac") {
      const { username, credential } = await hmacCredentials(
        env.TURN_STATIC_SECRET, ttl, "helucryptic");
      iceServers = [{ urls: turnUrlList(env.TURN_URL), username, credential }];
    } else if (mode === "static") {
      iceServers = [{
        urls: turnUrlList(env.TURN_URL),
        username: env.TURN_USERNAME || "",
        credential: env.TURN_PASSWORD || "",
      }];
    }
  } catch (err) {
    return new Response("TURN provider unavailable.", { status: 503 });
  }
  return new Response(JSON.stringify({ iceServers, ttl, provider: mode }), {
    headers: {
      "Content-Type": "application/json",
      // Credentials are per-deployment, not per-user, but they expire - let a
      // proxy hold them only for a fraction of their lifetime.
      "Cache-Control": `private, max-age=${Math.max(60, Math.floor(ttl / 4))}`,
    },
  });
}

// Sliding-window rate limiting constants (mirrors server.py).
const MSG_WINDOW_MS = 10_000;  // 10 s
const MSG_MAX = 100;     // max signaling messages per user per window
const CONN_WINDOW_MS = 60_000; // 60 s
const CONN_MAX = 20;     // max new connections per IP per window
const BYTE_WINDOW_MS = 10_000; // 10 s
const BYTE_MAX = 655360; // 640 KiB per 10 s (~64 KiB/s sustained, 256 KiB burst)
const RELAY_FRAME_MAX_BYTES = 24576; // 24 KiB wire cap for relay frames
const SERVER_CAPABILITIES = ["relay_e2ee_v1", "signaling_hello_v1"];

export class SignalHub {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this._sessionTokens = new Map(); // username → session token (prevents impersonation)
    this._msgTimes = new Map(); // username → number[] (message timestamps, ms)
    this._connTimes = new Map(); // ip → number[] (connection timestamps, ms)
    this._byteTimes = new Map(); // username → [timestamp, byteCount][]
  }

  // ---- helpers -----------------------------------------------------------

  _msgRateOk(username) {
    const now = Date.now();
    let times = this._msgTimes.get(username);
    if (!times) { times = []; this._msgTimes.set(username, times); }
    // Evict entries outside the window.
    const cutoff = now - MSG_WINDOW_MS;
    while (times.length && times[0] < cutoff) times.shift();
    if (times.length >= MSG_MAX) return false;
    times.push(now);
    return true;
  }

  // Per-IP connection rate limit (mirrors server.py _conn_rate_ok). These
  // timestamps live only in memory; if the Durable Object hibernates the
  // window simply resets, which is harmless (Cloudflare's edge also shields us).
  _connRateOk(ip) {
    const now = Date.now();
    let times = this._connTimes.get(ip);
    if (!times) { times = []; this._connTimes.set(ip, times); }
    const cutoff = now - CONN_WINDOW_MS;
    while (times.length && times[0] < cutoff) times.shift();
    if (times.length >= CONN_MAX) return false;
    times.push(now);
    return true;
  }

  _byteRateOk(username, byteCount) {
    const now = Date.now();
    let times = this._byteTimes.get(username);
    if (!times) { times = []; this._byteTimes.set(username, times); }
    const cutoff = now - BYTE_WINDOW_MS;
    while (times.length && times[0][0] < cutoff) times.shift();
    const currentTotal = times.reduce((acc, t) => acc + t[1], 0);
    if (currentTotal + byteCount > BYTE_MAX) return false;
    times.push([now, byteCount]);
    return true;
  }

  _msgRateCleanup(username) {
    this._msgTimes.delete(username);
    this._byteTimes.delete(username);
  }

  _attach(ws) {
    try {
      return ws.deserializeAttachment() || {};
    } catch {
      return {};
    }
  }

  _roomMembers(room) {
    const out = [];
    for (const ws of this.state.getWebSockets()) {
      const a = this._attach(ws);
      if (a.room === room && ws.readyState === OPEN) out.push(a.username);
    }
    return out;
  }

  _findUser(username) {
    for (const ws of this.state.getWebSockets(`user:${username}`)) {
      if (ws.readyState === OPEN) return ws;
    }
    return null;
  }

  _rejectWS(message) {
    // Accept then immediately send an error + close, so the client sees why.
    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    server.accept();
    try {
      server.send(JSON.stringify({ sender: "system", type: "error", data: message }));
    } catch { }
    server.close(1008, "rejected");
    return new Response(null, { status: 101, webSocket: client });
  }

  _generateToken() {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  // Workers expose timingSafeEqual on crypto.subtle (a non-standard CF
  // extension) - NOT on crypto itself. `crypto.timingSafeEqual(...)` throws a
  // TypeError, which turned a CORRECT password into an HTTP 500 on connect
  // (wrong-length passwords short-circuited earlier and were politely
  // rejected). Falls back to a manual constant-time comparison for safety.
  _timingSafeEqual(a, b) {
    if (a.byteLength !== b.byteLength) return false;
    try {
      if (crypto.subtle && typeof crypto.subtle.timingSafeEqual === "function") {
        return crypto.subtle.timingSafeEqual(a, b);
      }
    } catch { /* fall through to the manual comparison */ }
    let diff = 0;
    for (let i = 0; i < a.byteLength; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  _passwordOk(supplied) {
    // Mirrors server.py: when a password is configured (Cloudflare secret
    // HELUCRYPTIC_SERVER_PASSWORD), the client must send a matching `?password=`.
    // Empty config = open server (LAN/back-compat). Constant-time comparison.
    const expected = this.env?.HELUCRYPTIC_SERVER_PASSWORD || "";
    if (!expected) return true;
    const a = new TextEncoder().encode(supplied || "");
    const b = new TextEncoder().encode(expected);
    return this._timingSafeEqual(a, b);
  }

  _parseUrlParams(request) {
    const url = new URL(request.url);
    const parts = url.pathname.split("/").filter(Boolean); // ["ws", "<username>"]
    const username = decodeURIComponent(parts[1] || "");
    const room = url.searchParams.get("room") || "";
    const password = url.searchParams.get("password") || "";
    const sessionToken = url.searchParams.get("session_token") || "";
    return { username, room, password, sessionToken };
  }

  _evictOrRejectExisting(username, sessionToken) {
    const existingSockets = this.state.getWebSockets(`user:${username}`);
    if (existingSockets.length === 0) return null;
    // The in-memory token map is lost if the Durable Object hibernates while the
    // sockets survive - that would wrongly reject a legitimate reconnect. The
    // token is also serialized into each socket's attachment, which DOES survive
    // hibernation, so fall back to it when the map has been cleared.
    let expectedToken = this._sessionTokens.get(username) || "";
    if (!expectedToken) {
      for (const old of existingSockets) {
        const t = this._attach(old).token;
        if (t) { expectedToken = t; break; }
      }
    }
    const enc = new TextEncoder();
    const a = enc.encode(sessionToken);
    const b = enc.encode(expectedToken);
    const tokenOk = expectedToken.length > 0 && this._timingSafeEqual(a, b);
    if (!tokenOk) return this._rejectWS("Username already in use by an active session.");
    for (const old of existingSockets) {
      try { old.close(1000, "replaced"); } catch { }
    }
    this._sessionTokens.delete(username);
    return null;
  }

  _isRoomFull(room, username) {
    if (!room) return false;
    const others = new Set(this._roomMembers(room).filter((u) => u !== username));
    return others.size >= ROOM_MAX;
  }

  _notifyRoomJoin(room, username, server) {
    if (!room) return;
    const existing = this._roomMembers(room).filter((u) => u !== username);
    // Notify existing members that a new peer joined.
    for (const ws of this.state.getWebSockets()) {
      const a = this._attach(ws);
      if (a.room === room && a.username !== username && ws.readyState === OPEN) {
        ws.send(JSON.stringify({ type: "peer_joined", sender: username }));
      }
    }
    // Tell the joiner who is already here.
    server.send(JSON.stringify({ type: "room_state", peers: existing }));
  }

  // ---- connection handling ----------------------------------------------

  async fetch(request) {
    // Never let an exception escape as a bare 500: log it (visible via
    // `wrangler tail`) and return a readable error instead.
    try {
      return await this._handleUpgrade(request);
    } catch (err) {
      console.error("signaling fetch failed:", (err && err.stack) || err);
      return new Response("internal signaling error", { status: 500 });
    }
  }

  async _handleUpgrade(request) {
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("expected websocket", { status: 426 });
    }

    // Per-IP connection rate limit (mirrors server.py). CF-Connecting-IP is the
    // client's real IP as seen by Cloudflare.
    const clientIp = request.headers.get("CF-Connecting-IP") || "unknown";
    if (!this._connRateOk(clientIp)) {
      return new Response("Too many connection attempts - slow down.", { status: 429 });
    }

    const { username, room, password, sessionToken } = this._parseUrlParams(request);

    // Security: validate Origin header if allowlist is configured (mirrors server.py).
    // Env var HELUCRYPTIC_ALLOWED_ORIGINS is a comma-separated list. Empty Origin
    // (native clients) is allowed intentionally - same as Python server.
    const allowedOriginsRaw = this.env?.HELUCRYPTIC_ALLOWED_ORIGINS || "";
    if (allowedOriginsRaw.trim()) {
      const allowedOrigins = new Set(allowedOriginsRaw.split(",").map(s => s.trim().toLowerCase()).filter(Boolean));
      const origin = (request.headers.get("Origin") || "").toLowerCase();
      if (origin && !allowedOrigins.has(origin)) {
        console.warn(`Rejected connection from disallowed origin '${origin}' for user '${username}'`);
        return new Response("Origin not allowed.", { status: 403 });
      }
    }

    if (!username) return new Response("missing username", { status: 400 });
    // Mirror server.py: constrain usernames (routing keys + display identity)
    // and reserve "system" so server-generated messages can't be impersonated.
    if (!/^[A-Za-z0-9 _.\-]{1,32}$/.test(username) ||
      username.trim().toLowerCase() === "system") {
      return new Response("invalid username", { status: 400 });
    }
    if (!this._passwordOk(password)) return this._rejectWS("Invalid server access password.");

    const evictionError = this._evictOrRejectExisting(username, sessionToken);
    if (evictionError) return evictionError;

    if (this._isRoomFull(room, username)) return this._rejectWS("Room is full (max 4 participants).");

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];

    const tags = [`user:${username}`];
    if (room) tags.push(`room:${room}`);
    this.state.acceptWebSocket(server, tags);

    const newToken = this._generateToken();
    this._sessionTokens.set(username, newToken);
    server.serializeAttachment({ username, room, token: newToken });
    // CF-Connecting-IP is the client's real IP as seen by Cloudflare.
    // Port is not accessible in Workers (CF terminates TLS as a proxy).
    const reflectedHost = request.headers.get("CF-Connecting-IP") || null;
    server.send(JSON.stringify({
      type: "session_token",
      data: {
        token: newToken,
        reflected_host: reflectedHost,
        reflected_port: null,
        capabilities: SERVER_CAPABILITIES,
      },
    }));

    this._notifyRoomJoin(room, username, server);

    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws, message) {
    // Security: reject oversized payloads to prevent memory DoS (mirrors server.py - byte length)
    if (typeof message === "string" && new TextEncoder().encode(message).length > 65536) return;
    let payload;
    try {
      payload = JSON.parse(typeof message === "string" ? message : "");
    } catch {
      return;
    }

    const me = this._attach(ws);
    if (me.username && !this._msgRateOk(me.username)) {
      // Drop the packet silently - same behaviour as server.py.
      return;
    }

    const target = payload.target;
    const type = payload.type;

    // --- Presence query (directed at the server, not a peer) ---
    // The client sends the usernames it cares about (its local contacts)
    // and we reply with the subset that currently hold a live connection.
    if (type === "presence") {
      const wanted = payload.data?.usernames || [];
      const online = wanted.filter((u) => this._findUser(u) !== null);
      ws.send(JSON.stringify({
        sender: "system",
        type: "presence",
        data: { online },
      }));
      return;
    }

    if (!target || !type) return;
    if (SERVER_TYPES.has(type)) return; // never relay server-generated types

    // Room isolation: sender in a room may only signal peers in that same room.
    // Exception: "room_invite" exists to reach a contact who is NOT in the room
    // yet - blocking it here broke the invite-contacts feature (see server.py).
    if (me.room && type !== "room_invite") {
      const targetWsForRoom = this._findUser(target);
      if (targetWsForRoom) {
        const ta = this._attach(targetWsForRoom);
        if (ta.room !== me.room) {
          ws.send(JSON.stringify({ sender: "system", type: "error", data: `User '${target}' is not in your room.` }));
          return;
        }
      }
    }

    // Relay-specific quota & size checks to prevent signaling server abuse (mirrors server.py)
    // ``p2p_relay`` is retained for older clients, so it needs the same abuse
    // controls as the current relay message type.
    if (type === "relay_e2ee" || type === "p2p_relay") {
      const rawData = String(payload.data || "");
      const dataLen = new TextEncoder().encode(rawData).length;
      if (dataLen > RELAY_FRAME_MAX_BYTES) {
        ws.send(JSON.stringify({
          sender: "system",
          type: "error",
          data: `Relay payload too large (${dataLen} bytes, max ${RELAY_FRAME_MAX_BYTES}).`,
        }));
        return;
      }
      if (me.username && !this._byteRateOk(me.username, dataLen)) {
        ws.send(JSON.stringify({
          sender: "system",
          type: "error",
          data: "Relay bandwidth quota exceeded (slow down).",
        }));
        return;
      }
    }

    const targetWs = this._findUser(target);
    if (!targetWs) {
      ws.send(JSON.stringify({ sender: "system", type: "error", data: `User '${target}' is offline.` }));
      return;
    }
    targetWs.send(JSON.stringify({ sender: me.username, type, data: payload.data ?? null }));
  }

  async webSocketClose(ws, code, reason) {
    const a = this._attach(ws);
    try { ws.close(code, reason); } catch { }
    // Only clean up if this socket's token is still the current one - a
    // replacement socket may have already installed a new token.
    if (a.username && a.token && a.token === this._sessionTokens.get(a.username)) {
      this._sessionTokens.delete(a.username);
      this._msgRateCleanup(a.username);
    }
    if (!a.room) return;
    // If this user still has another live socket (e.g. we just replaced a stale
    // one with a fresh reconnect), don't announce them as having left.
    const stillHere = this.state
      .getWebSockets(`user:${a.username}`)
      .some((s) => s !== ws && s.readyState === OPEN);
    if (stillHere) return;
    for (const s of this.state.getWebSockets()) {
      const b = this._attach(s);
      if (b.room === a.room && b.username !== a.username && s.readyState === OPEN) {
        s.send(JSON.stringify({ type: "peer_left", sender: a.username }));
      }
    }
  }

  async webSocketError(ws) {
    // Treat an errored socket like a close for room bookkeeping.
    await this.webSocketClose(ws, 1011, "error");
  }
}
