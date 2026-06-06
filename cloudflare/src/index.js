// helucryptic signaling server — Cloudflare Worker + Durable Object.
//
// A 1:1 port of server.py. The wire protocol is identical, so the desktop
// client connects unchanged at:
//   wss://helucryptic-signaling.<your-subdomain>.workers.dev/ws/<username>?room=<room>
//
// All connections are routed to ONE Durable Object instance ("global") so they
// share state. The DO uses the WebSocket Hibernation API; per-socket identity
// (username, room) is stored as a serialized attachment + tags so it survives
// hibernation. Media never touches this server — it only relays the handshake.

const OPEN = 1; // WebSocket.OPEN
const SERVER_TYPES = new Set(["peer_joined", "peer_left", "room_state", "error"]);
const ROOM_MAX = 4;

export default {
  async fetch(request, env) {
    // Route every connection to the same hub instance.
    const id = env.SIGNAL_HUB.idFromName("global");
    const stub = env.SIGNAL_HUB.get(id);
    return stub.fetch(request);
  },
};

export class SignalHub {
  constructor(state, env) {
    this.state = state;
    this.env = env;
    this._sessionTokens = new Map(); // username → session token (prevents impersonation)
  }

  // ---- helpers -----------------------------------------------------------

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
    } catch {}
    server.close(1008, "rejected");
    return new Response(null, { status: 101, webSocket: client });
  }

  _generateToken() {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
  }

  _passwordOk(supplied) {
    // Mirrors server.py: when a password is configured (Cloudflare secret
    // HELUCRYPTIC_SERVER_PASSWORD), the client must send a matching `?password=`.
    // Empty config = open server (LAN/back-compat). Constant-time comparison.
    const expected = (this.env && this.env.HELUCRYPTIC_SERVER_PASSWORD) || "";
    if (!expected) return true;
    const a = new TextEncoder().encode(supplied || "");
    const b = new TextEncoder().encode(expected);
    if (a.byteLength !== b.byteLength) return false;
    return crypto.subtle.timingSafeEqual(a, b);
  }

  // ---- connection handling ----------------------------------------------

  async fetch(request) {
    if (request.headers.get("Upgrade") !== "websocket") {
      return new Response("expected websocket", { status: 426 });
    }

    const url = new URL(request.url);
    const parts = url.pathname.split("/").filter(Boolean); // ["ws", "<username>"]
    const username = decodeURIComponent(parts[1] || "");
    const room = url.searchParams.get("room") || "";
    const password = url.searchParams.get("password") || "";
    const sessionToken = url.searchParams.get("session_token") || "";

    if (!username) return new Response("missing username", { status: 400 });

    // --- Access control --- (reject before touching any existing sockets)
    if (!this._passwordOk(password)) {
      return this._rejectWS("Invalid server access password.");
    }

    // Username uniqueness: only allow eviction if the reconnecting client proves
    // ownership via the session token issued at their last connect. This prevents
    // any holder of the server password from impersonating an active user.
    const existingSockets = this.state.getWebSockets(`user:${username}`);
    if (existingSockets.length > 0) {
      const expectedToken = this._sessionTokens.get(username) || "";
      const enc = new TextEncoder();
      const a = enc.encode(sessionToken);
      const b = enc.encode(expectedToken);
      const tokenOk =
        expectedToken.length > 0 &&
        a.byteLength === b.byteLength &&
        crypto.subtle.timingSafeEqual(a, b);
      if (!tokenOk) {
        return this._rejectWS("Username already in use by an active session.");
      }
      for (const old of existingSockets) {
        try { old.close(1000, "replaced"); } catch {}
      }
      this._sessionTokens.delete(username);
    }

    // Room capacity (max 4) — count only OTHER usernames so a reconnecting
    // member doesn't count against the limit.
    if (room) {
      const others = new Set(this._roomMembers(room).filter((u) => u !== username));
      if (others.size >= ROOM_MAX) {
        return this._rejectWS("Room is full (max 4 participants).");
      }
    }

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];

    const tags = [`user:${username}`];
    if (room) tags.push(`room:${room}`);
    this.state.acceptWebSocket(server, tags);

    // Issue a new session token so the client can prove ownership on reconnect.
    const newToken = this._generateToken();
    this._sessionTokens.set(username, newToken);
    // Store the token in the attachment so webSocketClose can guard against
    // clobbering a replacement socket's state (reconnect race condition).
    server.serializeAttachment({ username, room, token: newToken });
    server.send(JSON.stringify({ type: "session_token", data: { token: newToken } }));

    if (room) {
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

    return new Response(null, { status: 101, webSocket: client });
  }

  async webSocketMessage(ws, message) {
    let payload;
    try {
      payload = JSON.parse(typeof message === "string" ? message : "");
    } catch {
      return;
    }
    const target = payload.target;
    const type = payload.type;

    // --- Presence query (directed at the server, not a peer) ---
    // The client sends the usernames it cares about (its local contacts)
    // and we reply with the subset that currently hold a live connection.
    if (type === "presence") {
      const wanted = (payload.data || {}).usernames || [];
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

    const me = this._attach(ws);
    const targetWs = this._findUser(target);
    if (!targetWs) {
      ws.send(JSON.stringify({ sender: "system", type: "error", data: `User '${target}' is offline.` }));
      return;
    }
    targetWs.send(JSON.stringify({ sender: me.username, type, data: payload.data ?? null }));
  }

  async webSocketClose(ws, code, reason) {
    const a = this._attach(ws);
    try { ws.close(code, reason); } catch {}
    // Only clean up if this socket's token is still the current one — a
    // replacement socket may have already installed a new token.
    if (a.username && a.token && a.token === this._sessionTokens.get(a.username)) {
      this._sessionTokens.delete(a.username);
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
