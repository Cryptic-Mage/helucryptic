# Getting WebSockets (wss://) working for the signaling server

## Why it's currently failing

`wss://kelu.namanskshetty.in/ws/<user>` returns **HTTP 404** because the server
is running behind **Passenger in WSGI mode** (`passenger_wsgi.py`). WSGI has no
concept of a WebSocket — the upgrade request is converted to a plain HTTP GET,
and since `server.py` only defines an ASGI WebSocket route
(`@app.websocket("/ws/{username}")`), FastAPI returns 404.

**WSGI can never carry WebSockets.** The app + URL are correct; only the
hosting bridge is wrong. The server must run in **ASGI** mode AND the web server
must allow the WebSocket upgrade to pass through.

---

## What to check / ask your host (cPanel + LiteSpeed/Passenger)

Ask your hosting support (or check the control panel) these three questions:

1. **"Do you allow WebSocket (persistent `Upgrade: websocket`) connections on
   my domain?"** Many shared hosts block long-lived upgrade connections
   entirely. If the answer is no, this host can't run the signaling server —
   use a VPS or a PaaS (Render/Railway/Fly) instead.

2. **"Does your Passenger support running Python apps in ASGI mode (Passenger
   ≥ 6.0), and can I set my app type to ASGI?"** cPanel's "Setup Python App"
   defaults to WSGI (`passenger_wsgi.py`). ASGI needs a different app type.

3. **"Can I set `PassengerAppType asgi` and a custom startup file for my Python
   app?"** (Some shared hosts lock this down.)

If all three are **yes**, do the ASGI switch below. If any is **no**, this host
cannot do it — deploy on a WebSocket-capable host instead.

---

## ASGI switch (if the host supports it)

1. Upload `passenger_asgi.py` (in this repo) next to `server.py` on the host.
   It exposes the ASGI app:
   ```python
   from server import app as application
   ```

2. Tell Passenger to run it in ASGI mode. Depending on the panel, either:
   - In cPanel "Setup Python App", set the **Application startup file** to
     `passenger_asgi.py` and the **app type** to ASGI (if the UI offers it), or
   - Add to the app's `.htaccess` (LiteSpeed/Apache + Passenger):
     ```
     PassengerAppType asgi
     PassengerStartupFile passenger_asgi.py
     ```

3. Remove/disable the old `passenger_wsgi.py` so Passenger doesn't pick WSGI.

4. Restart the Python app (cPanel: "Restart" button, or `touch tmp/restart.txt`).

---

## Confirm it works

From any machine:
```bash
# Should now complete a 101 Switching Protocols handshake (not 404):
curl -i -H "Connection: Upgrade" -H "Upgrade: websocket" \
     -H "Sec-WebSocket-Version: 13" \
     -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
     https://kelu.namanskshetty.in/ws/test
```
- **HTTP/1.1 101 Switching Protocols** → WebSockets work; the messenger will connect.
- **HTTP/1.1 404** (Connection: Keep-Alive) → still WSGI / no upgrade; ASGI not active.
- **HTTP/1.1 426 / 400** → upgrade reached an ASGI handler but headers off; close — retry from the app.

---

## Fallback if the host can't do WebSockets

Run the signaling server on a WebSocket-capable host (the server is tiny — it
only relays SDP/ICE during handshake; all media is P2P):

**VPS (most control):**
```bash
pip install fastapi uvicorn websockets
uvicorn server:app --host 0.0.0.0 --port 8000
```
Put nginx in front with the `wss` upgrade block from `GUIDE.md` and point the
app at `wss://yourdomain`.

**PaaS (easiest):** Render / Railway / Fly.io — deploy `server.py` with start
command `uvicorn server:app --host 0.0.0.0 --port $PORT`. These support `wss://`
out of the box. Then set the app's server URL to `wss://<your-app-url>`.
