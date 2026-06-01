# helucryptic signaling on Cloudflare Workers

Serverless, always-on signaling server (port of `server.py`) running on a
Cloudflare Worker + Durable Object. WebSockets work out of the box — no VPS, no
Passenger/WSGI, free tier.

The desktop client needs **no changes** — you just point it at the deployed
`workers.dev` URL.

## Deploy (you run these)

```bash
cd helucryptic/cloudflare
npm install -g wrangler        # if not already installed
wrangler login                 # opens browser, authorize your Cloudflare account
wrangler deploy
```

`wrangler deploy` prints a URL like:

```
https://helucryptic-signaling.<your-subdomain>.workers.dev
```

## Point the app at it

In the helucryptic desktop app's startup screen, choose **Custom server** and
enter that URL (https or wss both work — the client converts to `wss://`):

```
https://helucryptic-signaling.<your-subdomain>.workers.dev
```

The client will connect to
`wss://helucryptic-signaling.<your-subdomain>.workers.dev/ws/<username>?room=<room>`.

## Verify

```bash
curl -i -H "Connection: Upgrade" -H "Upgrade: websocket" \
     -H "Sec-WebSocket-Version: 13" \
     -H "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==" \
     https://helucryptic-signaling.<your-subdomain>.workers.dev/ws/test
```

Expect **HTTP/1.1 101 Switching Protocols** (not 404). Then two app instances
can connect, add each other / join a room, and chat/call/screen-share.

## Notes

- One global Durable Object instance holds all live connections + room
  membership. Fine for a personal/small messenger; media is always P2P so the
  hub only carries tiny SDP/ICE handshake messages.
- Uses the WebSocket Hibernation API, so idle periods don't burn compute and it
  stays within the free plan.
- Protocol is identical to `server.py`: client sends
  `{target, type, data}`; server forwards `{sender, type, data}` and emits
  `peer_joined` / `peer_left` / `room_state` / `error`. Room cap = 4.
