# helucryptic

> **Your conversations. Nobody else's hardware.**
> A peer-to-peer, end-to-end encrypted desktop messenger where the server forgets you the moment you've shaken hands.

Most "encrypted" chat apps still funnel every word through someone else's cloud. helucryptic doesn't. A tiny signaling server plays matchmaker for the first few seconds — just long enough for two computers to find each other — and then **bows out completely**. From that point on, every message, file, voice packet, and pixel of your screen flows **straight from your machine to theirs**, encrypted end to end.

```
   Alice's PC ─────  signaling server  ───── Bob's PC
                     (introductions only)

   …handshake done, server steps away…

   Alice's PC ═══════════════════════════════ Bob's PC
                  direct · encrypted · private
```

No message ever touches a server. No file is ever parked in a bucket. There's nothing to subpoena, leak, or mine — because it was never there.

---

## ✨ What it does

- **💬 Chat — 1-to-1 or in a group of up to 4** over an encrypted WebRTC data channel.
- **🎙️ Voice calls & 🖥️ screen sharing**, peer-to-peer and software-encoded. In a group, media is relayed through whichever participant is most reachable, so the call still connects even when everyone else is stuck behind tough NATs.
- **📎 File transfer** with SHA-256 integrity checks and disk-streaming backpressure — send a 4 GB file without your RAM noticing.
- **🔐 Real cryptography, not vibes** — **forward-secret** X25519 ECDH with a fresh ephemeral key every session → HKDF-SHA256 session keys, Ed25519-signed identities, and PASETO v4 (XChaCha20-Poly1305) message tokens.
- **🧬 Fingerprint verification** that *watches its own back* — if a verified contact's key ever changes, helucryptic un-verifies them and warns you of a possible impostor.
- **🗄️ Encrypted local history** (SQLite in WAL mode) with a retention policy you control.
- **🌍 Punches through NATs** with STUN, optional TURN relays, and automatic NAT-PMP port forwarding (great with VPN P2P port forwarding).
- **🪶 Runs on a potato** — purpose-built to stay smooth on old, weak hardware (details below).

## 🔒 The crypto stack

| Purpose | Primitive |
|---|---|
| Key agreement | Ephemeral X25519 ECDH (fresh per session, signed by your identity) → HKDF-SHA256 |
| Identity / signing | Ed25519 via PASETO v4.public |
| Message encryption | PASETO v4.local (XChaCha20-Poly1305) |
| History at rest | PASETO v4.local, keyed from your Ed25519 identity |
| Identity keys at rest | Wrapped with the OS keystore (Windows DPAPI) |

## 🗺️ Project layout

| File / Folder | Role |
|---|---|
| `main.py` | Entry point (`flet` app) |
| `client.py` | Flet UI + signaling client + app wiring |
| `webrtc_engine.py` | WebRTC engine: peers, media tracks, encryption, file transfer, group relay |
| `server.py` | FastAPI signaling server (relays SDP/ICE only) |
| `natpmp.py` | NAT-PMP port-forward discovery & renewal (VPN/router reachability) |
| `crypto.py` | Keys, HKDF, PASETO, fingerprints |
| `contacts.py` / `history.py` / `settings.py` | Local persistence |
| `sounds.py` | Notification/call sound cues (av + sounddevice) |
| `config.py` | Environment-driven configuration |
| `build.py` | One-command executable build (PyInstaller) |
| `tests/` | Unit and integration test suite |

## ⚙️ Configuration

Everything deployment-specific lives in the environment (or a `.env` file) — nothing is baked into the source. Copy the template and make it yours:

```bash
cp .env.example .env
```

The knobs that matter most:
- `HELUCRYPTIC_SIGNALING_URL` — WebSocket URL of the signaling server
- `HELUCRYPTIC_SERVER_PASSWORD` — Shared access token (validated **server-side**)
- `HELUCRYPTIC_LOW_PERF_MODE` — `true` lowers screen-share resolution/FPS defaults
- `HELUCRYPTIC_TURN_URL` / `_USERNAME` / `_PASSWORD` — TURN relay configuration

### A fully-loaded `.env`

```ini
# --- Signaling server ---
HELUCRYPTIC_SIGNALING_URL=ws://127.0.0.1:8000
HELUCRYPTIC_SERVER_PASSWORD=MySecureAccessPassword123

# --- Performance (tune for old/weak PCs) ---
# Set to true to drop default capture resolution and limit image rendering rates
HELUCRYPTIC_LOW_PERF_MODE=true
HELUCRYPTIC_SCREEN_MAX_WIDTH=960
HELUCRYPTIC_SCREEN_MAX_HEIGHT=540
HELUCRYPTIC_SCREEN_FPS=10

# --- TURN relay (rescues connections behind strict/cellular NATs) ---
HELUCRYPTIC_TURN_URL=turn:your-turn-server-domain.com:3478?transport=udp
HELUCRYPTIC_TURN_USERNAME=my-turn-username
HELUCRYPTIC_TURN_PASSWORD=my-turn-password-456
```

---

## 📡 When direct P2P won't connect: setting up a TURN relay

Sometimes two peers simply can't reach each other directly — typically when one or both sit behind a **symmetric NAT** (the norm on cellular data, public hotspots, and strict office firewalls). A TURN (Traversal Using Relays around NAT) server is the safety net: WebRTC reroutes the **still-encrypted** media through it so the call survives. The relay sees ciphertext, never your content.

### Option A — Managed cloud TURN (easiest)
Grab credentials from a hosted service and paste them into your `.env`:
* **Metered.ca** — free tier with 50 GB/month of TURN bandwidth.
* **Twilio Network Traversal** — pay-as-you-go TURN/STUN.
* **Xirsys** — developer-friendly free tiers.

### Option B — Self-host `coturn` on a VPS (Linux)
`coturn` is the de-facto open-source TURN/STUN server.

1. **Install it** on your Ubuntu/Debian VPS:
   ```bash
   sudo apt update
   sudo apt install coturn -y
   ```

2. **Configure** `/etc/turnserver.conf`:
   ```bash
   sudo nano /etc/turnserver.conf
   ```
   Uncomment and set:
   ```ini
   # Listen port for STUN/TURN requests
   listening-port=3478

   # Fingerprint signatures in messages (mandatory for WebRTC)
   fingerprint

   # Use long-term credential mechanism
   lt-cred-mech

   # Define a static user account (username:password)
   user=my-turn-username:my-turn-password-456

   # Set server domain / IP
   realm=your-turn-server-domain.com
   ```

3. **Open the firewall** (TCP/UDP):
   ```bash
   sudo ufw allow 3478/tcp
   sudo ufw allow 3478/udp
   sudo ufw allow 49152:65535/udp
   ```

4. **Enable and start it**:
   ```bash
   sudo systemctl enable coturn
   sudo systemctl restart coturn
   ```

---

## 🚀 Quick start (local / LAN)

```bash
pip install -r requirements.txt

# 1. start the signaling server
uvicorn server:app --host 127.0.0.1 --port 8000

# 2. launch the client (in another terminal)
python main.py
```

Want a friend on the call? Spin up a second client, point it at the same signaling URL, create a room, and share the code.

For VPS/HTTPS deployment and a full feature walkthrough, see **`GUIDE.md`**.
For WebSocket hosting troubleshooting, see **`DEPLOY-WEBSOCKETS.md`**.

## 📦 Building a standalone executable

```bash
python build.py
```

This bundles `tracks/`, `icon.ico`, and (if present) your `.env` into `dist/Helucryptic`. Heads-up: bundling `.env` embeds its contents in the binary — the server password is a real gate only because the **server** validates it.

## 🪶 Built for the underdog (low-end PC optimisations)

helucryptic is engineered to stay buttery on hardware everyone else gave up on:

- Outbound screen capture is **downscaled** (default ≤720p) before the software encoder ever sees it, and runs at a capped frame rate.
- Incoming video repaints **only the affected image control**, not the whole UI — and is rate-limited per sender.
- File transfers **stream from disk** with send-buffer backpressure (no slurping whole files into RAM).
- Audio playback uses a chunk queue that sidesteps per-frame buffer reallocation.
- SQLite runs in **WAL mode with indices**, so history scrollback doesn't stall on slow disks.

Flip `HELUCRYPTIC_LOW_PERF_MODE=true` to bias every default even lower.

## 🛡️ Security model & honest limitations

We'd rather tell you the sharp edges than hide them:

- The signaling server only ever sees **usernames and SDP/ICE handshake data** — never message content, files, keys, or media.
- **Verify fingerprints out-of-band.** If a contact's key changes after you've verified them, helucryptic strips the verification and warns you.
- In a group call, media is decrypted at the **relay peer** so it can forward it — chat and files stay end-to-end encrypted, but treat the relay host as trusted for media (the app tells you who it is).
- **Forward secrecy** — every session derives its key from fresh **ephemeral** X25519 keys, signed by your long-term identity. A stolen identity key can't decrypt sessions you've already had, and the signed handshake stops a tampered server from swapping keys mid-introduction.
- Your identity keys live in `~/.helucryptic/keys.json`, **wrapped with the OS keystore (Windows DPAPI)** so a raw copy of the file is useless on another account or machine. Back them up with **Export Keys** — backups carry the plaintext identity (protected by your backup passphrase) and are re-wrapped on restore, so they stay portable across machines.
