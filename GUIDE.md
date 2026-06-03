# helucryptic — User Guide & Server Setup

---

## What is helucryptic?

helucryptic is a **peer-to-peer encrypted desktop messenger**. Once two people connect, all messages, calls, files, and screen share travel **directly between their computers** — nothing passes through any server. The server is only needed for the first few seconds of a connection to help the two computers find each other (this is called signaling).

```
Alice's PC ──── signaling server ──── Bob's PC
                (handshake only)

After handshake:
Alice's PC ══════════════════════════ Bob's PC
              (direct, encrypted)
```

---

## How it works — step by step

### 1. Startup
When you launch `client.py`, the app:
- Generates your X25519 + Ed25519 keypairs on first run, saved to `~/.helucryptic/keys.json`
- Loads your contacts from `~/.helucryptic/contacts.json`
- Opens your chat history from `~/.helucryptic/history.db`
- Runs any expired-message cleanup based on your retention policy

### 2. Connecting to the signaling server
You type your username and click **Connect**. The app opens a WebSocket to the signaling server at the URL in Settings (default: `ws://127.0.0.1:8000`). The server does nothing except remember you are online and forward handshake packets.

### 3. Establishing a P2P pipe
You select a contact and click **Call** (or the contact calls you). Here is what happens behind the scenes:

```
Caller                    Server                    Callee
  │── SDP Offer ──────────►│── SDP Offer ───────────►│
  │                         │                         │
  │◄─ SDP Answer ──────────│◄── SDP Answer ──────────│
  │                         │                         │
  │── ICE candidates ──────►│── ICE candidates ───────►│
  │◄─ ICE candidates ──────│◄── ICE candidates ───────│
  │                         │                         │
  │◄══════ WebRTC P2P connection open ══════════════►│
                    (server exits the path)
```

**SDP** = Session Description Protocol — describes what codecs and capabilities each side supports.  
**ICE** = Interactive Connectivity Establishment — finds the best network path between two computers (including through NATs/firewalls using STUN).

### 4. Hello handshake (E2EE mode)
Once the DataChannel opens, both sides immediately exchange a **PASETO v4.public** token — a signed identity packet containing their username and public keys. Each side:
1. Extracts the peer's Ed25519 public key from the token
2. Verifies the token's signature using that key
3. Derives a shared AES session key via **X25519 ECDH → HKDF-SHA256**

All subsequent messages are wrapped in **PASETO v4.local** tokens (XChaCha20-Poly1305) using this shared key. The server never sees decrypted content.

### 5. Chat, files, calls, screen share
Everything travels over the encrypted WebRTC DataChannel or audio/video tracks:

| Feature | How it works |
|---|---|
| **Text chat** | PASETO-encrypted JSON frames over DataChannel |
| **File transfer** | Metadata frame + raw binary chunks + checksum frame |
| **Voice call** | Microphone audio track (48kHz, mono, Opus) |
| **Screen share** | 15fps video track from your primary monitor |
| **History** | Stored locally in SQLite, content encrypted with HKDF key derived from your Ed25519 private key |

---

## Installation

### Requirements
- Python 3.11 or newer
- Windows, macOS, or Linux

### Install dependencies
```bash
cd helucryptic
pip install -r requirements.txt
```

> **Note:** `sounddevice` requires PortAudio. On Windows this is bundled automatically. On Linux: `sudo apt install portaudio19-dev`. On macOS: `brew install portaudio`.

---

## Running locally (both people on the same machine or LAN)

### Step 1: Start the signaling server
Open a terminal and run:
```bash
uvicorn server:app --host 127.0.0.1 --port 8000
```
You should see:
```
INFO:     Application startup complete.
INFO:     Uvicorn running on http://127.0.0.1:8000
```
Leave this terminal running. The server uses almost no CPU or memory — it only forwards a few packets during connection setup.

### Step 2: Launch the client
Open a second terminal:
```bash
python client.py
```
Open a third terminal on the same or another machine and run the same command again.

### Step 3: Connect
1. Each user types their **username** in the sidebar and clicks **Connect**
2. The status dot turns yellow — you are registered with the signaling server
3. One user selects the other from the contacts panel (or adds them with **+ Add Contact**)
4. Click the **Call** button (phone icon) to start a voice call, which also opens the DataChannel
5. The status dot turns green — you are connected directly

---

## Deploying the server on a VPS / cloud

To let people connect from different networks (different houses, offices, countries), the signaling server needs to be on a machine with a **public IP address**.

### Option A — Any VPS (DigitalOcean, Linode, Hetzner, AWS, etc.)

**1. Upload server.py and requirements.txt to your server**
```bash
scp server.py requirements.txt user@your-server-ip:/opt/helucryptic/
```

**2. Install Python dependencies on the server**
```bash
ssh user@your-server-ip
cd /opt/helucryptic
pip install fastapi uvicorn websockets
```
(Only these three are needed on the server — the server has no crypto, no UI, no WebRTC.)

**3. Run the server**
```bash
uvicorn server:app --host 0.0.0.0 --port 8000
```
`--host 0.0.0.0` makes it listen on all network interfaces (required for public access).

**4. Open the firewall port**
On your VPS control panel or with ufw:
```bash
sudo ufw allow 8000/tcp
```

**5. Configure clients to use your server**
In the helucryptic **Settings** dialog (gear icon), change **Signaling URL** to:
```
ws://your-server-ip:8000
```

### Option B — HTTPS/WSS with a domain name (recommended for production)

If you have a domain name and want secure WebSocket (`wss://`), put **nginx** in front of uvicorn:

**nginx config snippet** (`/etc/nginx/sites-available/helucryptic`):
```nginx
server {
    listen 443 ssl;
    server_name signal.yourdomain.com;

    ssl_certificate     /etc/letsencrypt/live/signal.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/signal.yourdomain.com/privkey.pem;

    location / {
        proxy_pass         http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header   Upgrade $http_upgrade;
        proxy_set_header   Connection "upgrade";
        proxy_set_header   Host $host;
    }
}
```

Get a free SSL certificate with Let's Encrypt:
```bash
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d signal.yourdomain.com
```

Then in helucryptic Settings set:
```
wss://signal.yourdomain.com
```

### Option C — Keep it running with systemd (Linux auto-restart)

Create `/etc/systemd/system/helucryptic-signal.service`:
```ini
[Unit]
Description=helucryptic Signaling Server
After=network.target

[Service]
Type=simple
User=www-data
WorkingDirectory=/opt/helucryptic
ExecStart=uvicorn server:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable helucryptic-signal
sudo systemctl start helucryptic-signal
sudo systemctl status helucryptic-signal
```

---

## Using the app

### Security modes
Open **Settings** (gear icon, bottom-right) to choose:

| Mode | What it means |
|---|---|
| **DTLS-only** | Messages are encrypted by WebRTC's built-in transport layer. Simple and fast. No key fingerprints. |
| **E2EE + Signing** | Every message is additionally encrypted with a PASETO token using a key derived from your X25519 keypair. Messages are also signed with Ed25519 so you can verify who sent them. |

> **Recommendation:** Use E2EE + Signing for sensitive conversations. Use DTLS-only for casual use where you trust the network.

### Verifying a contact's identity
In E2EE mode, a yellow **⚠** badge means you have not yet verified the contact's key fingerprint. To verify:

1. Long-press the contact in the sidebar
2. Select **View Fingerprint**
3. Compare the displayed 64-character hex fingerprint with your contact **out-of-band** (phone call, in person, Signal, etc.)
4. If they match, click **Mark Verified** — the badge changes to green **✓**

This protects against a man-in-the-middle who might intercept the hello handshake.

### Message history & retention
All messages are stored locally and encrypted. To configure how long they are kept:
- Open **Settings → Message retention**
- Options: Never delete / 7 days / 30 days / 90 days / Custom
- The policy runs on startup and every 24 hours automatically

### Key management
In **Settings** you can:
- **Export Keys** — save your keypair to a file (back it up securely)
- **Import Keys** — restore a previously exported keypair
- **Regenerate Keys** — generate a new keypair (all contacts will need to re-verify)

Your keys live at `~/.helucryptic/keys.json`. Keep this file private.

### File transfer
Click the **paperclip** icon to send a file. The receiver sees a save dialog when the transfer completes. A SHA-256 integrity check runs automatically — a ⚠ warning appears if the file was corrupted in transit.

### Screen share
Click the **screen share** icon. A viewer window opens on the receiver's side showing your primary monitor at 15fps. Audio is included. Click the **X** button on the viewer to stop.

### Voice calls
Click the **phone** icon to start a voice-only call. The receiver sees an "Incoming call" dialog with Accept/Reject options. Click the **red phone** icon to hang up.

---

## NAT Traversal, Port Forwarding & Hub-Election

helucryptic features a state-of-the-art traversal engine designed to enable direct P2P connections under difficult network conditions.

### 1. Automatic NAT-PMP Port Forwarding
When **Port Forwarding** is enabled in Settings, the client:
- Automatically discovers the local network gateway (using NAT-PMP) or VPN tunnel.
- Allocates and requests a mapped port pool.
- Binds the local WebRTC engine's ICE agent socket to bind directly to this forwarded port.
- Publishes the mapped port(s) to the signaling server, which other peers fetch to connect directly without intermediate relay server latency.

**Crucially, only one of the two peers needs to have an open/forwarded port (or public IP) for a direct P2P connection to succeed.** The peer behind a strict symmetric NAT can connect directly to the forwarded port of the reachable peer, bypassing the need for a TURN relay. This means that if you are behind a strict firewall/NAT, as long as the contact you are calling has port forwarding enabled and working (or is on a public IP), you will still establish a direct, low-latency P2P connection.


### 2. Hub-Election (Group Call Relay)
In group calls (rooms), establishing a mesh of voice/video feeds between all participants is extremely heavy. helucryptic solves this using a dynamic **Hub-Election algorithm**:
- **Capability Announcement**: Every peer monitors their own reachability (e.g. public IP, port-forwarded, behind strict symmetric NAT).
- **Announcements**: Peers broadcast their capability tier (0 to 3) and epoch sequence number to all room members.
- **Election**: The client automatically elects the host with the highest reachability tier (i.e. the one with a port forward or public IP) as the **Media Relay Hub**.
- **Media Fan-out**: All audio/video streams are sent *only* to the elected Hub, which then duplicates and forwards (relays) them to the other participants.
- **E2EE Integrity**: While media is decrypted at the hub for forwarding (requiring trust in the elected hub), text chat and files remain fully end-to-end encrypted with the room's group key. The signaling server is still excluded from the media path.

---

## Data stored on your computer

| File | Contents |
|---|---|
| `~/.helucryptic/keys.json` | Your X25519 + Ed25519 private keys. **Keep this private.** |
| `~/.helucryptic/contacts.json` | Contact list with their public keys and verification status |
| `~/.helucryptic/history.db` | Chat history (message content encrypted in E2EE mode) |
| `~/.helucryptic/settings.json` | Your preferences |

None of this is ever uploaded anywhere. The signaling server only ever sees your username and SDP/ICE packets — it never sees messages, files, keys, or audio.

---

## Building a standalone .exe (Windows)

To distribute helucryptic as a single executable that doesn't require Python to be installed:

```bash
pip install nuitka
nuitka --standalone --onefile \
       --include-package=aiortc \
       --include-package=av \
       --include-package=flet \
       --include-package=cryptography \
       --include-package=pyseto \
       --include-package=sounddevice \
       --include-package=mss \
       --windows-disable-console \
       client.py
```

This produces `client.exe`. Copy it to any Windows machine and run it directly.

> **Note:** If audio doesn't work in the compiled exe, add `--include-data-files=<path-to-portaudio.dll>=.` to the Nuitka command.

---

## Troubleshooting

| Problem | Likely cause | Fix |
|---|---|---|
| Status stuck on SIGNALING | Target user is not connected | Ask them to connect first |
| Status stuck on CONNECTING | NAT/firewall blocking P2P | Ensure STUN is not blocked; both sides need internet access |
| No audio | PortAudio missing | Install PortAudio for your OS |
| Messages not decrypting | Security mode mismatch | Both sides must use the same mode |
| History shows "[decryption failed]" | Keys regenerated after messages saved | Old messages encrypted with previous key — they cannot be recovered |
| Can't connect to signaling | Wrong URL or firewall | Check Settings URL; check port 8000 is open on server |
