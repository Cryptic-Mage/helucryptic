# Nuitka compile:
# nuitka --standalone --onefile --include-package=aiortc --include-package=av
#        --include-package=flet --include-package=cryptography --include-package=pyseto
#        --include-package=sounddevice --include-package=mss --windows-disable-console
#        client.py

import asyncio
import base64
import json
import re as _re
import secrets
import shutil
import string
import time
import urllib.parse
from io import BytesIO
from pathlib import Path

import flet as ft
import numpy as np
import websockets
from PIL import Image

import config
from contacts import (
    delete_contact,
    get_contact,
    load_contacts,
    rename_contact,
    set_verified,
    upsert_contact,
)
from crypto import derive_history_key, generate_and_save_keys, load_or_create_keys
import backup
import identity
import paths
from history import init_db, read_messages, read_room_messages, run_retention_policy, write_message
from settings import PROFILES, apply_profile, load_settings, save_settings
from sounds import manager as sounds
from natpmp import (
    PROTON_GATEWAY,
    PortForwardManager,
    discover_gateway,
    local_ip_for,
    request_mapping_over_socket,
)
from webrtc_engine import (
    WebRTCEngine,
    clear_forwarded_port,
    set_forwarded_port,
    set_forwarded_ports,
)

# ---------------------------------------------------------------------------
# Deployment config comes from the environment / .env (see config.py), never
# hardcoded here. Override via HELUCRYPTIC_SIGNALING_URL / _SERVER_PASSWORD.
# ---------------------------------------------------------------------------
HELUCRYPTIC_SERVER_URL      = config.DEFAULT_SIGNALING_URL
HELUCRYPTIC_SERVER_PASSWORD = config.SERVER_PASSWORD


def generate_room_code() -> str:
    chars = string.ascii_uppercase + string.digits
    return "ROOM-" + "".join(secrets.choice(chars) for _ in range(4))


def _to_ws_url(base: str) -> str:
    """Normalize a server URL to a WebSocket scheme.

    WebSockets-over-TLS uses wss:// (not https://). Accept http(s)/ws(s) and a
    bare host, and always return a ws:// or wss:// base with no trailing slash.
    """
    base = (base or "").strip().rstrip("/")
    if base.startswith("https://"):
        base = "wss://" + base[len("https://"):]
    elif base.startswith("http://"):
        base = "ws://" + base[len("http://"):]
    elif base.startswith(("ws://", "wss://")):
        pass
    else:
        # bare host (e.g. "example.com" or "127.0.0.1:8000") — default to ws://
        base = "ws://" + base
    return base


# ---------------------------------------------------------------------------
# Main app
# ---------------------------------------------------------------------------

class HelucrypticApp:
    def __init__(self, page: ft.Page):
        self.page         = page
        self.settings     = load_settings()
        self.keys         = load_or_create_keys()
        self.history_key  = derive_history_key(self.keys["ed25519_private"])
        self.ws           = None
        self.engine       = WebRTCEngine(
            my_username="",
            settings=self.settings,
            keys=self.keys,
        )
        self._active_contact:  str            = ""
        self._history_offset:  int            = 0
        self._screen_img:      ft.Image | None = None
        self._room_id:         str            = ""
        self._room_peers:      dict[str, str] = {}   # username → connection state
        self._video_tiles:     dict[str, ft.Image] = {}
        self._tile_row:        ft.Row | None   = None
        self._pending_invites: set[str]        = set()
        self._muted:           bool            = False
        self._in_voice_call:   bool            = False
        self._in_screen_share: bool            = False
        self._room_call_active: bool           = False
        self._ringing:         bool            = False
        self._ring_timeout_task = None
        self._diag_open:       bool            = False
        # Contacts the user allowed for THIS session despite Verified-Only mode.
        self._session_allowed: set[str]        = set()
        # Shared access token sent to the signaling server (validated server-side).
        self._server_password: str             = HELUCRYPTIC_SERVER_PASSWORD
        # Incoming-video render throttle (per sender) + encode quality. Lower in
        # low-perf mode so old PCs aren't swamped by JPEG re-encode + repaint.
        self._last_tile_render: dict[str, float] = {}
        self._update_perf_parameters()

        self._pf_manager = None  # PortForwardManager when port-forwarding is on

        init_db()
        run_retention_policy(self.settings.retention_days)
        self._build_ui()
        self._wire_engine_callbacks()
        asyncio.ensure_future(self._retention_background_loop())
        self._apply_port_forward()

    def _apply_port_forward(self) -> None:
        """(Re)start or stop the forwarded-port manager from current settings."""
        if self._pf_manager is not None:
            asyncio.ensure_future(self._pf_manager.stop())
            self._pf_manager = None
        clear_forwarded_port()
        if self.settings.port_forward_enabled:
            asyncio.ensure_future(self._start_port_forward())

    async def _start_port_forward(self) -> None:
        gw = await asyncio.to_thread(discover_gateway) or PROTON_GATEWAY
        ip = await asyncio.to_thread(local_ip_for, gw)

        async def request_fn(gateway: str):
            # Prefer a live NAT-PMP mapping; fall back to the manually typed
            # port (e.g. a router forward with no NAT-PMP).
            port = await asyncio.to_thread(request_mapping_over_socket, gateway)
            if port is None:
                port = self.settings.forwarded_port or None
            return port

        self._pf_manager = PortForwardManager(
            gateway=gw, local_ip=ip,
            request_fn=request_fn,
            publish_fn=self._publish_forwarded_port,
            clear_fn=clear_forwarded_port,
            pool_size=3,
        )
        self._pf_manager.start()

    def _publish_forwarded_port(self, ip: str, ports) -> None:
        # PortForwardManager now publishes a LIST of mapped ports (one per peer
        # for a relay hub). Bind the whole pool; persist the first for the UI.
        port_list = list(ports) if isinstance(ports, (list, tuple)) else [ports]
        set_forwarded_ports(ip, port_list)
        first = port_list[0] if port_list else 0
        if first and self.settings.forwarded_port != first:
            self.settings.forwarded_port = first
            try:
                save_settings(self.settings)
            except Exception:
                pass
        # Caveat #2: our reachability tier may have changed — re-announce + re-elect.
        if self._room_id and self.ws:
            asyncio.ensure_future(self._on_topology_changed())

    def _update_perf_parameters(self) -> None:
        # Drive the incoming-video render throttle + JPEG quality from the active
        # performance profile (settings). Call after settings change to apply.
        self._tile_render_interval = 1.0 / max(1, getattr(self.settings, "tile_render_fps", 10))
        self._jpeg_quality = int(getattr(self.settings, "jpeg_quality", 55))

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        # --- Sidebar controls ---
        self.contact_list     = ft.Column(scroll=ft.ScrollMode.AUTO, expand=True, spacing=2)
        self.btn_add_contact  = ft.TextButton("+ Add Contact", on_click=self._show_add_contact)
        self.btn_import_id    = ft.TextButton("Import from code", on_click=self._show_import_identity)
        self.username_input   = ft.TextField(
            label="Your username", width=200, dense=True,
            border_color="#40444b", focused_border_color="#5865f2", color="#dcddde",
        )
        self.btn_connect      = ft.FilledButton("Connect", on_click=self._connect_signaling, width=200)
        self.status_dot       = ft.Container(width=12, height=12, border_radius=6, bgcolor="#72767d")
        self.status_label     = ft.Text("IDLE", size=11, color="#72767d")

        # Room controls
        self.btn_create_room  = ft.FilledButton(
            "Create", icon=ft.Icons.ADD,
            on_click=self._create_room, width=97,
            style=ft.ButtonStyle(padding=ft.Padding.all(0)),
        )
        self.btn_join_room    = ft.FilledButton(
            "Join", icon=ft.Icons.LOGIN,
            on_click=self._show_join_room, width=97,
            style=ft.ButtonStyle(padding=ft.Padding.all(0)),
        )

        def _copy_room_code(e):
            if self._room_id:
                # Flet 0.85: clipboard is a service accessed via page.clipboard.set()
                self.page.clipboard.set(self._room_id)
                self._log(f"Room code {self._room_id} copied.")

        self.room_code_label  = ft.Text("", size=12, color="#b9bbbe", selectable=True)
        self.hub_banner       = ft.Text("", size=11, color="#faa61a", visible=False)
        self.btn_copy_room    = ft.IconButton(
            ft.Icons.COPY_ALL, on_click=_copy_room_code,
            tooltip="Copy room code", visible=False, icon_size=16,
        )
        self.btn_invite       = ft.IconButton(
            ft.Icons.PERSON_ADD, on_click=lambda e: self._show_invite_contacts(),
            tooltip="Invite contacts", visible=False,
        )
        self.participant_list = ft.Column(spacing=2)

        sidebar = ft.Container(
            width=220, bgcolor="#202225",
            padding=ft.Padding.all(10),
            content=ft.Column([
                self.username_input,
                self.btn_connect,
                ft.Row([self.status_dot, self.status_label], spacing=6),
                ft.Divider(color="#40444b"),
                ft.Row([self.btn_create_room, self.btn_join_room], spacing=6),
                ft.Row([self.room_code_label, self.btn_copy_room, self.btn_invite], spacing=4),
                self.hub_banner,
                self.participant_list,
                ft.Divider(color="#40444b"),
                self.contact_list,
                self.btn_add_contact,
                self.btn_import_id,
            ], spacing=8),
        )

        # --- Chat panel ---
        self._tile_row    = ft.Row(spacing=4, wrap=True, visible=False)
        self.chat_log     = ft.ListView(expand=True, spacing=4, auto_scroll=True)
        self.msg_input    = ft.TextField(
            hint_text="Message...", expand=True, dense=True,
            on_submit=self._send_chat, disabled=True,
            border_color="#40444b", focused_border_color="#5865f2", color="#dcddde",
        )
        self.file_progress = ft.ProgressBar(value=0, visible=False, color="#5865f2", bgcolor="#40444b")

        self.btn_call     = ft.IconButton(ft.Icons.CALL,         on_click=self._start_call,   disabled=True, icon_color="#57f287", tooltip="Voice call")
        self.btn_screen   = ft.IconButton(ft.Icons.SCREEN_SHARE, on_click=self._start_screen, disabled=True, tooltip="Share screen")
        self.btn_file     = ft.IconButton(ft.Icons.ATTACH_FILE,  on_click=self._send_file,    disabled=True, tooltip="Send file")
        self.btn_mute     = ft.IconButton(ft.Icons.MIC,          on_click=self._toggle_mute,  disabled=True, tooltip="Mute mic")
        self.btn_hangup   = ft.IconButton(ft.Icons.CALL_END,     on_click=self._hangup,       disabled=True, icon_color="#ed4245", tooltip="Hang up")
        self.btn_join_call = ft.FilledButton(
            "Join call", icon=ft.Icons.CALL, on_click=self._start_call,
            visible=False, bgcolor="#57f287", color="#1e1f22",
        )
        self.btn_diag     = ft.IconButton(ft.Icons.INFO_OUTLINE, on_click=self._show_diagnostics, tooltip="Connection diagnostics")
        self.btn_settings = ft.IconButton(ft.Icons.SETTINGS,     on_click=self._show_settings, tooltip="Settings")

        # Persistent banner shown while the mic is muted during a call
        self.mute_banner = ft.Container(
            visible=False,
            bgcolor="#ed4245",
            border_radius=4,
            padding=ft.Padding.symmetric(horizontal=10, vertical=4),
            content=ft.Row(
                [ft.Icon(ft.Icons.MIC_OFF, color="#ffffff", size=16),
                 ft.Text("Microphone muted", color="#ffffff", size=12, weight=ft.FontWeight.BOLD)],
                spacing=6, tight=True,
            ),
        )

        chat_panel = ft.Container(
            expand=True, bgcolor="#36393f", padding=ft.Padding.all(10),
            content=ft.Column([
                self._tile_row,
                self.mute_banner,
                self.chat_log,
                self.file_progress,
                ft.Row([self.msg_input]),
                ft.Row([self.btn_call, self.btn_screen, self.btn_file, self.btn_mute,
                        self.btn_hangup, self.btn_join_call, ft.Container(expand=True),
                        self.btn_diag, self.btn_settings]),
            ]),
        )

        self.page.add(ft.Row(
            [sidebar, ft.VerticalDivider(width=1, color="#202225"), chat_panel],
            expand=True,
        ))

    # ------------------------------------------------------------------
    # Engine callbacks
    # ------------------------------------------------------------------

    def _wire_engine_callbacks(self) -> None:
        def on_state(peer: str, state: str):
            colors = {
                "connected":    ("#57f287", "CONNECTED"),
                "connecting":   ("#fee75c", "CONNECTING"),
                "failed":       ("#ed4245", "FAILED"),
                "disconnected": ("#ed4245", "DISCONNECTED"),
                "closed":       ("#72767d", "CLOSED"),
            }
            color, label = colors.get(state, ("#72767d", state.upper()))
            self._update_status(label, color)
            if peer in self._room_peers:
                self._room_peers[peer] = state
                self._refresh_participant_list()
            if state == "connected":
                self.msg_input.disabled  = False
                self.btn_call.disabled   = False
                self.btn_screen.disabled = False
                self.btn_file.disabled   = False
                self.page.update()
            elif state in ("failed", "disconnected", "closed"):
                if not any(s == "connected" for s in self._room_peers.values()):
                    self.msg_input.disabled  = True
                    self.btn_call.disabled   = True
                    self.btn_screen.disabled = True
                    self.btn_file.disabled   = True
                    self.btn_mute.disabled   = True
                    self.btn_hangup.disabled = True
                self.page.update()

        def on_message(sender: str, text: str, verified: bool):
            # The per-message `verified` flag from the wire is not trustworthy;
            # derive it from whether we've verified this contact's key fingerprint.
            c = get_contact(sender)
            verified = bool(c and c.verified) if self.settings.security_mode == "e2ee" else False
            contact = self._room_id if self._room_id else sender
            write_message(
                contact, "received", "chat", text,
                self.history_key, self.settings.security_mode,
                verified=verified,
                room_id=self._room_id or None,
                sender=sender,
            )
            if self._room_id or sender == self._active_contact:
                self._append_to_log("received", text, verified, label=sender)
                self.page.update()
            sounds.play("message")

        def on_call_incoming(sender: str):
            if self._room_id:
                # Group room: no per-peer ringing. Show Join-call button instead.
                self._room_call_active = True
                self._refresh_call_controls()
                return
            sounds.play_loop("incoming")
            self._ringing = True

            def _stop_ring():
                self._ringing = False
                sounds.stop_loop()
                if self._ring_timeout_task is not None:
                    self._ring_timeout_task.cancel()
                    self._ring_timeout_task = None

            def accept(e):
                if not self._is_allowed(sender):
                    _stop_ring()
                    self.engine.reject_call(sender)
                    self._close_dialog(dlg)
                    self._block_unverified(sender)
                    return
                _stop_ring()
                self.engine.accept_call(sender)
                sounds.play("call_start")
                self.btn_hangup.disabled = False
                self.btn_mute.disabled   = False
                self._close_dialog(dlg)
                self.page.update()

            def reject(e):
                _stop_ring()
                self.engine.reject_call(sender)
                self._close_dialog(dlg)

            async def _auto_decline():
                try:
                    await asyncio.sleep(25)
                except asyncio.CancelledError:
                    return
                if self._ringing:
                    _stop_ring()
                    self.engine.reject_call(sender)
                    self._close_dialog(dlg)
                    self._log(f"Missed call from {sender} (timed out).")
                    self.page.update()

            dlg = ft.AlertDialog(
                title=ft.Text(f"Incoming call from {sender}"),
                content=ft.Text("Accept or reject the call."),
                actions=[
                    ft.TextButton("Accept", on_click=accept),
                    ft.TextButton("Reject", on_click=reject),
                ],
            )
            self._show_dialog(dlg)
            self._ring_timeout_task = asyncio.ensure_future(_auto_decline())

        def on_call_accepted():
            # Caller side: the peer accepted our call.
            sounds.play("call_start")
            self.btn_hangup.disabled = False
            self.btn_mute.disabled   = False
            self.page.update()

        def on_file_chunk(fname: str, received: int, total):
            if total is not None and total > 0:
                self.file_progress.value   = received / total
                self.file_progress.visible = True
                self.page.update()

        def on_file_complete(fname: str, tmp_path: str, ok: bool):
            self.file_progress.visible = False
            self._log(f"[File received] {fname} {'✓' if ok else '⚠ integrity failed'}")
            self.page.update()
            asyncio.ensure_future(self._save_received_file(fname, tmp_path, ok))

        def on_hangup(peer=None):
            sounds.stop_loop()
            sounds.play("call_end")
            self._in_voice_call   = False
            self._in_screen_share = False
            self.btn_hangup.disabled = True
            self.btn_mute.disabled   = True
            self._set_mute_banner(False)
            self._remove_video_tile(peer) if peer else None
            self._log("[Call ended]")
            self._refresh_call_controls()
            self.page.update()

        def on_video_frame(sender: str, img):
            # Coalesce to a UI-friendly rate so a fast sender can't pile up
            # per-frame work on a weak receiver, then update ONLY the affected
            # image control instead of repainting the whole page tree.
            now  = time.monotonic()
            last = self._last_tile_render.get(sender, 0.0)
            if now - last < self._tile_render_interval:
                return
            self._last_tile_render[sender] = now
            try:
                # img is BGR (bgr24); flip to RGB for Pillow, then JPEG-encode.
                rgb = np.ascontiguousarray(img[:, :, ::-1])
                bio = BytesIO()
                Image.fromarray(rgb).save(bio, format="JPEG", quality=self._jpeg_quality)
                b64 = base64.b64encode(bio.getvalue()).decode()
                if sender not in self._video_tiles:
                    self._add_video_tile(sender)
                tile = self._video_tiles[sender]
                tile.src = "data:image/jpeg;base64," + b64
                tile.update()
            except Exception:
                pass

        def on_key_change(peer: str):
            # The contact's identity key changed after we had verified it —
            # surface a loud warning. The contact is already auto-unverified.
            # A changed key also revokes any temporary "allow for this session".
            self._session_allowed.discard(peer)
            self._refresh_contact_list()
            self._refresh_participant_list()
            display = peer
            c = get_contact(peer)
            if c and c.nickname:
                display = c.nickname
            self._log(f"⚠ SECURITY: {display}'s identity key changed — verification removed. "
                      f"Re-verify their fingerprint out-of-band before trusting.")
            dlg = ft.AlertDialog(
                title=ft.Text("⚠ Contact key changed"),
                content=ft.Text(
                    f"{display}'s encryption key is different from the one you "
                    f"previously verified.\n\nThis can happen if they reinstalled or "
                    f"regenerated keys — but it can also indicate an impersonation "
                    f"or man-in-the-middle attempt.\n\nVerification has been removed. "
                    f"Confirm their new fingerprint out-of-band before trusting it."
                ),
                actions=[ft.TextButton("Understood", on_click=lambda e: self._close_dialog(dlg))],
            )
            self._show_dialog(dlg)
            self.page.update()

        self.engine.on_state_change   = on_state
        self.engine.on_key_change     = on_key_change
        self.engine.on_message        = on_message
        self.engine.on_call_incoming  = on_call_incoming
        self.engine.on_call_accepted  = on_call_accepted
        self.engine.on_file_chunk     = on_file_chunk
        self.engine.on_file_complete  = on_file_complete
        self.engine.on_hangup         = on_hangup
        self.engine.on_video_frame    = on_video_frame

    # ------------------------------------------------------------------
    # Signaling
    # ------------------------------------------------------------------

    async def _connect_signaling(self, e, room: str = "") -> None:
        uname = self.username_input.value.strip()
        print(f"[connect] clicked. username={uname!r} room={room!r} url_base={self.settings.signaling_url!r}", flush=True)
        if not uname:
            self._log("[Error] Enter a username first.")
            print("[connect] aborted: empty username", flush=True)
            return
        self.engine.my_username = uname
        params = {}
        if room:
            params["room"] = room
        if self._server_password:
            params["password"] = self._server_password
        suffix = ("?" + urllib.parse.urlencode(params)) if params else ""
        base   = _to_ws_url(self.settings.signaling_url)
        url    = f"{base}/ws/{urllib.parse.quote(uname, safe='')}{suffix}"
        
        # Redact password in printed logs
        safe_params = dict(params)
        if "password" in safe_params:
            safe_params["password"] = "<redacted>"
        safe_suffix = ("?" + urllib.parse.urlencode(safe_params)) if safe_params else ""
        safe_url = f"{base}/ws/{urllib.parse.quote(uname, safe='')}{safe_suffix}"
        
        print(f"[connect] dialing {safe_url}", flush=True)
        if self.ws:
            try:
                await self.ws.close()
            except Exception:
                pass
        try:
            self.ws = await websockets.connect(url)
            self._update_status("SIGNALING", "#fee75c")
            self._log(f"Connected as '{uname}'" + (f" in {room}" if room else "") + ".")
            print(f"[connect] websocket OPEN to {safe_url}", flush=True)
            sounds.play("reactivated")
            asyncio.ensure_future(self._signaling_listener())
        except Exception as ex:
            self.engine.last_error = f"signaling: {type(ex).__name__}"
            self._log(f"[Error] Cannot reach server: {ex}")
            print(f"[connect] FAILED: {type(ex).__name__}: {ex}", flush=True)

    async def _signaling_listener(self) -> None:
        async def ws_send(payload: dict):
            await self.ws.send(json.dumps(payload))

        try:
            async for raw in self.ws:
                try:
                    msg = json.loads(raw)
                except Exception:
                    continue
                t      = msg.get("type")
                sender = msg.get("sender", "")
                data   = msg.get("data") or {}

                try:
                    if t == "offer":
                        await self.engine.handle_offer(sender, data, ws_send)

                    elif t == "answer":
                        await self.engine.handle_answer(data, sender=sender)

                    elif t == "ice-candidate":
                        await self.engine.handle_ice(data, sender=sender)

                    elif t == "connect_request":
                        # A contact wants to start a 1-to-1 conversation with us.
                        upsert_contact(sender)
                        self._refresh_contact_list()
                        if not self._active_contact:
                            self.engine.target_peer = sender
                        await self.engine.add_peer(sender, ws_send)

                    elif t == "peer_joined":
                        self._room_peers[sender] = "connecting"
                        self._refresh_participant_list()
                        await self._broadcast_capability(ws_send)
                        await self.engine.reconcile_room_connections(list(self._room_peers.keys()), ws_send)
                        await self._apply_active_call_to_hub()
                        self._refresh_hub_indicator()
                        if self._in_voice_call or self._in_screen_share:
                            await self._broadcast_call_active(ws_send)

                    elif t == "peer_left":
                        self._room_peers.pop(sender, None)
                        self._refresh_participant_list()
                        await self.engine.remove_peer(sender)
                        await self.engine.reconcile_room_connections(list(self._room_peers.keys()), ws_send)
                        self._remove_video_tile(sender)
                        await self._apply_active_call_to_hub()
                        self._refresh_hub_indicator()

                    elif t == "room_state":
                        # Server sends `peers` at the top level of the message
                        # (like `sender` for peer_joined), NOT nested under `data`.
                        for peer in msg.get("peers", []):
                            self._room_peers[peer] = "connecting"
                        self._refresh_participant_list()
                        await self._broadcast_capability(ws_send)
                        await self.engine.reconcile_room_connections(list(self._room_peers.keys()), ws_send)
                        await self._apply_active_call_to_hub()
                        self._refresh_hub_indicator()

                    elif t == "hub_capability":
                        self.engine.record_capability(sender, data.get("tier", 0), data.get("epoch", 0))
                        if data.get("creator"):
                            self.engine.set_room_creator(sender)
                        await self.engine.reconcile_room_connections(list(self._room_peers.keys()), ws_send)
                        await self._apply_active_call_to_hub()
                        self._refresh_hub_indicator()

                    elif t == "call_active":
                        self._room_call_active = True
                        self._log("📞 A call is active in the room — click 'Join call' to join.")
                        self._refresh_call_controls()

                    elif t == "room_invite":
                        room_id = data.get("room_id", "")
                        inviter = data.get("inviter", sender)
                        self._show_room_invite_dialog(inviter, room_id)

                    elif t == "error":
                        msg_text = data if isinstance(data, str) else msg.get("error", str(data))
                        match = _re.search(r"User '(.+?)' is offline", msg_text)
                        if match and match.group(1) in self._pending_invites:
                            username = match.group(1)
                            self._pending_invites.discard(username)
                            self._log(f"Could not invite {username} — they are offline")
                        else:
                            self._log(f"[Server] {msg_text}")
                except Exception as inner_ex:
                    print(f"[signaling] Error handling message {t} from {sender}: {inner_ex}", flush=True)

        except Exception as ex:
            self._log(f"[Disconnected] {ex}")
            self._update_status("IDLE", "#72767d")

    # ------------------------------------------------------------------
    # Room management
    # ------------------------------------------------------------------

    async def _create_room(self, e) -> None:
        print("[create_room] clicked", flush=True)
        uname = self.username_input.value.strip()
        if not uname:
            self._log("[Error] Enter a username first.")
            print("[create_room] aborted: empty username", flush=True)
            return
        # _join_room connects to signaling (with the room) itself, so a prior
        # plain Connect is not required.
        code = generate_room_code()
        print(f"[create_room] generated {code}, joining…", flush=True)
        await self._join_room(code, is_creator=True)
        self._show_invite_contacts()

    def _show_join_room(self, e) -> None:
        field = ft.TextField(label="Room code (e.g. ROOM-AB12)", autofocus=True, dense=True)

        async def do_join(ev):
            code = field.value.strip().upper()
            if not code.startswith("ROOM-") or len(code) != 9:
                field.error_text = "Invalid room code"
                self.page.update()
                return
            self._close_dialog(dlg)
            await self._join_room(code, is_creator=False)

        dlg = ft.AlertDialog(
            title=ft.Text("Join Room"),
            content=field,
            actions=[
                ft.TextButton("Join",   on_click=do_join),
                ft.TextButton("Cancel", on_click=lambda ev: self._close_dialog(dlg)),
            ],
        )
        self._show_dialog(dlg)

    async def _join_room(self, code: str, is_creator: bool) -> None:
        uname = self.username_input.value.strip()
        if not uname:
            return
        self._room_id = code
        # Fresh room session: clear any stale call state from a prior room so the
        # "Join call" button doesn't appear for a call that isn't happening here.
        self._room_call_active = False
        self._in_voice_call = False
        self._in_screen_share = False
        self.engine.set_room(code, is_creator=is_creator)
        self.room_code_label.value    = f"Room: {code}"
        self.btn_invite.visible       = True
        self.btn_copy_room.visible    = True
        self.page.update()
        self._refresh_hub_indicator()
        await self._connect_signaling(None, room=code)

    def _show_room_invite_dialog(self, inviter: str, room_id: str) -> None:
        async def do_join(e):
            self._close_dialog(dlg)
            await self._join_room(room_id, is_creator=False)

        dlg = ft.AlertDialog(
            title=ft.Text(f"Room invite from {inviter}"),
            content=ft.Text(f"{inviter} is inviting you to {room_id}"),
            actions=[
                ft.TextButton("Join",    on_click=do_join),
                ft.TextButton("Decline", on_click=lambda e: self._close_dialog(dlg)),
            ],
        )
        self._show_dialog(dlg)

    def _show_invite_contacts(self) -> None:
        contacts    = load_contacts()
        checkboxes  = []

        for c in contacts:
            display = c.nickname or c.username
            in_room = c.username in self._room_peers
            label   = display + (" (already in room)" if in_room else "")
            cb      = ft.Checkbox(label=label, value=False, disabled=in_room)
            checkboxes.append((cb, c.username))

        async def send_invites(e):
            for cb, username in checkboxes:
                if cb.value and self.ws:
                    self._pending_invites.add(username)
                    await self.ws.send(json.dumps({
                        "target": username,
                        "type":   "room_invite",
                        "data":   {"room_id": self._room_id, "inviter": self.engine.my_username},
                    }))
            self._close_dialog(dlg)

        dlg = ft.AlertDialog(
            title=ft.Text("Invite Contacts"),
            content=ft.Column(
                [cb for cb, _ in checkboxes] or [ft.Text("No contacts yet.", color="#72767d")],
                scroll=ft.ScrollMode.AUTO,
                height=200,
            ),
            actions=[
                ft.TextButton("Send Invites", on_click=send_invites),
                ft.TextButton("Cancel",       on_click=lambda e: self._close_dialog(dlg)),
            ],
        )
        self._show_dialog(dlg)

    # ------------------------------------------------------------------
    # Hub-election helpers
    # ------------------------------------------------------------------

    async def _ws_send(self, payload: dict) -> None:
        if self.ws:
            await self.ws.send(json.dumps(payload))

    async def _on_topology_changed(self) -> None:
        """Re-announce capability, re-elect/reconnect to the hub, and (Caveat #3)
        re-apply any active call to the (possibly new) hub."""
        if not self._room_id:
            return
        await self._broadcast_capability(self._ws_send)
        await self.engine.reconcile_room_connections(list(self._room_peers.keys()), self._ws_send)
        await self._apply_active_call_to_hub()
        self._refresh_hub_indicator()

    async def _apply_active_call_to_hub(self) -> None:
        if not self._room_id or not (self._in_voice_call or self._in_screen_share):
            return
        hub = self.engine.current_hub()
        if hub == self.engine.my_username:
            targets = [p for p in self.engine.pcs if self.engine.pcs[p].connectionState == "connected"]
        elif hub and self.engine.pcs.get(hub):
            targets = [hub]
        else:
            targets = []
        for peer in targets:
            if self._in_voice_call:
                await self.engine.start_voice_call(peer)
            if self._in_screen_share:
                await self.engine.start_screen_share(peer)

    async def _broadcast_capability(self, ws_send) -> None:
        """Send our hub-election capability to every known room peer."""
        if not self._room_id:
            return
        payload = self.engine.capability_payload()
        for peer in list(self._room_peers.keys()):
            await ws_send({"target": peer, "type": "hub_capability", "data": payload})

    async def _broadcast_call_active(self, ws_send) -> None:
        """Tell every room peer that a call is currently active in this room."""
        if not self._room_id:
            return
        for peer in list(self._room_peers.keys()):
            await ws_send({"target": peer, "type": "call_active", "data": {}})

    def _refresh_call_controls(self) -> None:
        """Show/hide the Join-call button based on room + call state."""
        in_call = self._in_voice_call or self._in_screen_share
        self.btn_join_call.visible = bool(self._room_id and self._room_call_active and not in_call)
        try:
            self.page.update()
        except Exception:
            pass

    def _refresh_hub_indicator(self) -> None:
        if not self._room_id or not self._room_peers:
            self.hub_banner.value = ""
            self.hub_banner.visible = False
        else:
            hub = self.engine.current_hub()
            if hub == self.engine.my_username:
                self.hub_banner.value = "🛰 You are the relay — others' audio/video pass through you"
            else:
                self.hub_banner.value = f"🛰 Relayed by {hub} — media passes through them"
            self.hub_banner.visible = True
        try:
            self.page.update()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Participant list
    # ------------------------------------------------------------------

    def _refresh_participant_list(self) -> None:
        self.participant_list.controls.clear()
        for username, state in self._room_peers.items():
            dot_color = "#57f287" if state == "connected" else "#fee75c"
            c         = get_contact(username)
            display   = (c.nickname if c and c.nickname else username)
            badge     = (" ✓" if c and c.verified else " ⚠") if self.settings.security_mode == "e2ee" else ""
            self.participant_list.controls.append(
                ft.ListTile(
                    leading=ft.Container(width=10, height=10, border_radius=5, bgcolor=dot_color),
                    title=ft.Text(f"👤 {display}{badge}", size=12, color="#dcddde"),
                    dense=True,
                    on_long_press=lambda ev, u=username: self._show_contact_menu(u),
                )
            )
        self.page.update()

    # ------------------------------------------------------------------
    # Contact list
    # ------------------------------------------------------------------

    def _refresh_contact_list(self) -> None:
        self.contact_list.controls.clear()
        for c in load_contacts():
            display   = c.nickname or c.username
            dot_color = "#57f287" if c.username == self._connected_peer() else "#72767d"
            badge     = (" ✓" if c.verified else " ⚠") if self.settings.security_mode == "e2ee" else ""
            tile = ft.ListTile(
                leading=ft.Container(width=10, height=10, border_radius=5, bgcolor=dot_color),
                title=ft.Text(f"{display}{badge}", size=13, color="#dcddde"),
                on_click=lambda e, u=c.username: self._select_contact(u),
                on_long_press=lambda e, u=c.username: self._show_contact_menu(u),
                dense=True,
            )
            self.contact_list.controls.append(tile)
        self.page.update()

    def _show_contact_menu(self, username: str) -> None:
        c = get_contact(username)
        if not c:
            return

        def do_rename(e):
            self._close_dialog(menu)
            field = ft.TextField(label="Nickname", value=c.nickname, autofocus=True)
            def save_rename(ev):
                rename_contact(username, field.value.strip())
                self._refresh_contact_list()
                self._refresh_participant_list()
                self._close_dialog(rename_dlg)
            rename_dlg = ft.AlertDialog(
                title=ft.Text("Rename contact"), content=field,
                actions=[
                    ft.TextButton("Save",   on_click=save_rename),
                    ft.TextButton("Cancel", on_click=lambda ev: self._close_dialog(rename_dlg)),
                ],
            )
            self._show_dialog(rename_dlg)

        def do_fingerprint(e):
            self._close_dialog(menu)
            fp = c.fingerprint or "(no key exchanged yet)"
            def mark_verified(ev):
                set_verified(username, True)
                self._refresh_contact_list()
                self._refresh_participant_list()
                self._close_dialog(fp_dlg)
            fp_dlg = ft.AlertDialog(
                title=ft.Text(f"Fingerprint — {c.nickname or username}"),
                content=ft.Column([
                    ft.Text(fp, font_family="monospace", size=13, color="#dcddde"),
                    ft.Text("Confirm with your contact out-of-band.", size=11, color="#72767d"),
                ], tight=True, spacing=6),
                actions=[
                    ft.TextButton("Mark Verified", on_click=mark_verified),
                    ft.TextButton("Close",         on_click=lambda ev: self._close_dialog(fp_dlg)),
                ],
            )
            self._show_dialog(fp_dlg)

        def do_remove(e):
            delete_contact(username)
            if self._active_contact == username:
                self._active_contact = ""
                self.chat_log.controls.clear()
            self._refresh_contact_list()
            self._close_dialog(menu)

        menu = ft.AlertDialog(
            title=ft.Text(c.nickname or username),
            content=ft.Column([
                ft.TextButton("Rename",           on_click=do_rename),
                ft.TextButton("View Fingerprint", on_click=do_fingerprint),
                ft.TextButton("Remove Contact",   on_click=do_remove),
            ], tight=True, spacing=0),
        )
        self._show_dialog(menu)

    def _select_contact(self, username: str) -> None:
        self._active_contact = username
        self.engine.target_peer = username   # 1-to-1 sends/answers route to this peer
        self._history_offset = 0
        self.chat_log.controls.clear()
        self._load_more_history()
        self.page.update()
        # In 1-to-1 mode, selecting an online contact establishes the P2P link
        # (data channel) so you can chat/call without a separate step.
        if self.ws and not self._room_id and username not in self.engine.pcs:
            asyncio.ensure_future(self._connect_to_contact(username))

    async def _connect_to_contact(self, username: str) -> None:
        async def ws_send(payload: dict):
            await self.ws.send(json.dumps(payload))
        # Tell the peer we want to connect (they'll add_peer us too), then add
        # them on our side. add_peer's alphabetical tie-break decides who offers.
        try:
            await self.ws.send(json.dumps({"target": username, "type": "connect_request"}))
        except Exception as ex:
            self._log(f"[Error] {ex}")
            return
        await self.engine.add_peer(username, ws_send)

    def _load_more_history(self) -> None:
        msgs = read_messages(
            self._active_contact, self.history_key,
            self.settings.security_mode, limit=100, offset=self._history_offset,
        )
        for m in msgs:
            self._append_to_log(m["direction"], m["content"], bool(m["verified"]))
        self._history_offset += len(msgs)
        if len(msgs) == 100:
            def load_more(e):
                self._load_more_history()
                self.page.update()
            self.chat_log.controls.insert(0, ft.TextButton("Load more…", on_click=load_more))

    def _select_room(self) -> None:
        if not self._room_id:
            return
        self._active_contact = ""
        self._history_offset = 0
        self.chat_log.controls.clear()
        self._load_more_room_history()
        self.page.update()

    def _load_more_room_history(self) -> None:
        msgs = read_room_messages(
            self._room_id, self.history_key,
            self.settings.security_mode, limit=100, offset=self._history_offset,
        )
        for m in msgs:
            self._append_to_log(
                m["direction"], m["content"], bool(m["verified"]),
                label=m.get("sender") or "You",
            )
        self._history_offset += len(msgs)
        if len(msgs) == 100:
            def load_more(e):
                self._load_more_room_history()
                self.page.update()
            self.chat_log.controls.insert(0, ft.TextButton("Load more…", on_click=load_more))

    # ------------------------------------------------------------------
    # Chat
    # ------------------------------------------------------------------

    async def _send_chat(self, e) -> None:
        text = self.msg_input.value.strip()
        if not text:
            return
        # Verified-Only gate (1-to-1 only; leaves the text in the box so the
        # user can re-send after verifying / allowing).
        if not self._room_id and not self._is_allowed(self._active_contact):
            self._block_unverified(self._active_contact)
            return
        await self.engine.send_chat(text)
        contact = self._room_id if self._room_id else self._active_contact
        if contact:
            write_message(
                contact, "sent", "chat", text,
                self.history_key, self.settings.security_mode,
                room_id=self._room_id or None,
                sender=None,
            )
        self._append_to_log("sent", text, False)
        self.msg_input.value = ""
        self.page.update()

    # ------------------------------------------------------------------
    # File transfer
    # ------------------------------------------------------------------

    async def _send_file(self, e) -> None:
        # Files are always 1-to-1. In a room with more than one connected peer,
        # ask which peer to send to so the destination is never ambiguous.
        peer = await self._choose_file_target()
        if peer is None:
            return
        if not self._is_allowed(peer):
            self._block_unverified(peer)
            return
        # Flet 0.85: FilePicker is a service; pick_files() is async and returns the files.
        picker = ft.FilePicker()
        self.page.services.append(picker)
        self.page.update()
        files = await picker.pick_files()
        if not files:
            return
        self.file_progress.visible = True
        self.file_progress.value   = 0
        self.page.update()
        await self.engine.send_file(files[0].path, target=peer)
        self.file_progress.visible = False
        self.page.update()

    async def _choose_file_target(self):
        """Return the peer username to send a file to, or None if cancelled."""
        connected = [p for p, pc in self.engine.pcs.items() if pc.connectionState == "connected"]
        if not self._room_id:
            return self._active_contact or self.engine.target_peer or (connected[0] if connected else None)
        if not connected:
            self._log("[File] No connected peers to send to.")
            return None
        if len(connected) == 1:
            return connected[0]
        # Multiple peers — present a chooser
        fut: asyncio.Future = asyncio.get_event_loop().create_future()

        def pick(username):
            if not fut.done():
                fut.set_result(username)
            self._close_dialog(dlg)

        dlg = ft.AlertDialog(
            title=ft.Text("Send file to…"),
            content=ft.Column(
                [ft.TextButton(p, on_click=lambda e, u=p: pick(u)) for p in connected],
                tight=True, spacing=0,
            ),
            actions=[ft.TextButton("Cancel", on_click=lambda e: (pick(None)))],
        )
        self._show_dialog(dlg)
        return await fut

    async def _save_received_file(self, fname: str, tmp_path: str, ok: bool = True) -> None:
        if not ok:
            try:
                Path(tmp_path).unlink()
            except OSError:
                pass
            return
        picker = ft.FilePicker()
        self.page.services.append(picker)
        self.page.update()
        dest = await picker.save_file(file_name=fname)
        if dest:
            shutil.copyfile(tmp_path, dest)
        try:
            Path(tmp_path).unlink()
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Calls & screen share
    # ------------------------------------------------------------------

    async def _start_call(self, e) -> None:
        if not self.ws:
            return

        async def ws_send(payload: dict):
            await self.ws.send(json.dumps(payload))

        if self._room_id:
            hub = self.engine.current_hub()
            if hub == self.engine.my_username:
                # We are the hub: send our mic to every connected member.
                for peer in list(self.engine.pcs.keys()):
                    if self.engine.pcs[peer].connectionState == "connected":
                        await self.engine.start_voice_call(peer)
            elif hub and self.engine.pcs.get(hub):
                # Non-hub: send our mic only to the hub; it fans out to the others.
                await self.engine.start_voice_call(hub)
        else:
            if not self._active_contact:
                return
            if not self._is_allowed(self._active_contact):
                self._block_unverified(self._active_contact)
                return
            if not self.engine.pcs.get(self._active_contact):
                await self.engine.create_offer(self._active_contact, ws_send)
            await self.engine.start_voice_call(self._active_contact)

        self._in_voice_call = True
        if self._room_id:
            self._room_call_active = True
            await self._broadcast_call_active(ws_send)
        self._refresh_call_controls()
        self.btn_hangup.disabled = False
        self.btn_mute.disabled   = False
        self.page.update()

    async def _start_screen(self, e) -> None:
        if not self.ws:
            return

        async def ws_send(payload: dict):
            await self.ws.send(json.dumps(payload))

        if self._room_id:
            hub = self.engine.current_hub()
            if hub == self.engine.my_username:
                for peer in list(self.engine.pcs.keys()):
                    if self.engine.pcs[peer].connectionState == "connected":
                        await self.engine.start_screen_share(peer)
            elif hub and self.engine.pcs.get(hub):
                await self.engine.start_screen_share(hub)
        else:
            if not self._active_contact:
                return
            if not self._is_allowed(self._active_contact):
                self._block_unverified(self._active_contact)
                return
            if not self.engine.pcs.get(self._active_contact):
                await self.engine.create_offer(self._active_contact, ws_send)
            await self.engine.start_screen_share(self._active_contact)

        self._in_screen_share = True
        if self._room_id:
            self._room_call_active = True
            await self._broadcast_call_active(ws_send)
        self._refresh_call_controls()
        self.btn_hangup.disabled = False
        self.btn_mute.disabled   = False
        self._log("[Screen sharing started]")
        self.page.update()

    def _toggle_mute(self, e) -> None:
        self._muted = not self._muted
        self.engine.set_mic_muted(self._muted)
        self.btn_mute.icon       = ft.Icons.MIC_OFF if self._muted else ft.Icons.MIC
        self.btn_mute.icon_color = "#ed4245" if self._muted else None
        self.btn_mute.tooltip    = "Unmute mic" if self._muted else "Mute mic"
        self._set_mute_banner(self._muted)
        self.page.update()

    def _set_mute_banner(self, muted: bool) -> None:
        self.mute_banner.visible = muted
        self.page.update()

    async def _hangup(self, e) -> None:
        self.engine.hangup()
        sounds.stop_loop()
        sounds.play("call_end")
        self._muted = False
        self._in_voice_call   = False
        self._in_screen_share = False
        self.btn_mute.icon       = ft.Icons.MIC
        self.btn_mute.icon_color = None
        self._set_mute_banner(False)
        self.btn_hangup.disabled = True
        self.btn_mute.disabled   = True
        self.btn_call.disabled   = True
        self.btn_screen.disabled = True
        self._log("[Hung up]")
        self._refresh_call_controls()
        self.page.update()

    # ------------------------------------------------------------------
    # Video tiles
    # ------------------------------------------------------------------

    def _add_video_tile(self, sender: str) -> ft.Image:
        img  = ft.Image(
            src="", width=240, height=135,
            fit=ft.ImageFit.CONTAIN, gapless_playback=True,
            border_radius=ft.border_radius.all(6),
        )
        tile = ft.Container(
            content=ft.Stack([
                img,
                ft.Container(
                    content=ft.Text(sender, size=10, color="#ffffff"),
                    bgcolor="#00000066", padding=ft.Padding.all(4),
                    border_radius=ft.border_radius.all(4),
                    alignment=ft.alignment.bottom_left,
                ),
            ]),
            width=244, height=139, bgcolor="#2b2d31",
            border_radius=ft.border_radius.all(6),
            data=sender,
        )
        self._video_tiles[sender] = img
        self._tile_row.controls.append(tile)
        self._tile_row.visible = True
        self.page.update()
        return img

    def _remove_video_tile(self, sender: str) -> None:
        self._video_tiles.pop(sender, None)
        self._tile_row.controls = [
            c for c in self._tile_row.controls
            if getattr(c, "data", None) != sender
        ]
        if not self._tile_row.controls:
            self._tile_row.visible = False
        self.page.update()

    # ------------------------------------------------------------------
    # Settings dialog
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Identity QR / verification code
    # ------------------------------------------------------------------

    def _show_my_identity(self, e=None) -> None:
        uname = (self.engine.my_username or self.username_input.value or "").strip()
        if not uname:
            # A bare _log() here is invisible when this is triggered from the
            # Settings dialog (the chat log is painted behind it), so surface a
            # real dialog instead — the username is part of the identity code.
            warn = ft.AlertDialog(
                title=ft.Text("Set a username first"),
                content=ft.Text("Enter your username in the sidebar before showing "
                                "your identity code — it's part of the code you share."),
                actions=[ft.TextButton("OK", on_click=lambda ev: self._close_dialog(warn))],
            )
            self._show_dialog(warn)
            return
        code = identity.encode_identity(
            uname, self.keys["x25519_public"], self.keys["ed25519_public"])
        controls = []
        try:
            # Flet 0.85 dropped Image.src_base64 — base64 must go through src as
            # a data URI.
            controls.append(ft.Image(
                src="data:image/png;base64," + identity.qr_png_base64(code),
                width=220, height=220))
        except Exception:
            pass  # QR optional; the text code below is the source of truth
        controls += [
            ft.Text("Your verification code (share with a contact):",
                    size=12, color="#72767d"),
            ft.TextField(value=code, read_only=True, multiline=True, min_lines=2,
                         max_lines=4, width=360, text_size=11),
            ft.Text("They paste this into 'Import from code'. Compare the "
                    "fingerprint out-of-band before trusting.", size=11, color="#72767d"),
        ]
        dlg = ft.AlertDialog(
            title=ft.Text("My identity"),
            content=ft.Column(controls, tight=True, spacing=8,
                              horizontal_alignment=ft.CrossAxisAlignment.CENTER,
                              scroll=ft.ScrollMode.AUTO),
            actions=[ft.TextButton("Close", on_click=lambda ev: self._close_dialog(dlg))],
        )
        self._show_dialog(dlg)

    def _show_import_identity(self, e=None) -> None:
        field = ft.TextField(label="Paste verification code (HELU1:…)",
                             autofocus=True, multiline=True, min_lines=2, max_lines=4, width=360)
        error = ft.Text("", color="#ed4245", size=11, visible=False)

        def do_import(ev):
            try:
                info = identity.decode_identity(field.value)
            except ValueError as ex:
                error.value = str(ex); error.visible = True; self.page.update(); return
            self._close_dialog(dlg)
            self._confirm_import(info)

        dlg = ft.AlertDialog(
            title=ft.Text("Import contact from code"),
            content=ft.Column([field, error], tight=True, spacing=6),
            actions=[
                ft.TextButton("Import", on_click=do_import),
                ft.TextButton("Cancel", on_click=lambda ev: self._close_dialog(dlg)),
            ],
        )
        self._show_dialog(dlg)

    def _confirm_import(self, info: dict) -> None:
        # Never auto-verify: the user must explicitly confirm this identity.
        def confirm(ev):
            upsert_contact(info["username"],
                           x25519_pub=info["x25519_pub"], ed25519_pub=info["ed25519_pub"])
            set_verified(info["username"], True)
            self._refresh_contact_list()
            self._refresh_participant_list()
            self._session_allowed.discard(info["username"])
            self._close_dialog(dlg)
            self._log(f"Imported and verified {info['username']}.")

        dlg = ft.AlertDialog(
            title=ft.Text(f"Verify {info['username']}?"),
            content=ft.Column([
                ft.Text("Confirm this fingerprint matches what your contact shows "
                        "you out-of-band:", size=12, color="#b9bbbe"),
                ft.Text(info["fingerprint"], font_family="monospace", size=12, color="#dcddde",
                        selectable=True),
            ], tight=True, spacing=8),
            actions=[
                ft.TextButton("Add & mark verified", on_click=confirm),
                ft.TextButton("Cancel", on_click=lambda ev: self._close_dialog(dlg)),
            ],
        )
        self._show_dialog(dlg)

    # ------------------------------------------------------------------
    # Encrypted backup / restore / emergency wipe
    # ------------------------------------------------------------------

    def _show_backup(self, e=None) -> None:
        pw1 = ft.TextField(label="Backup passphrase", password=True,
                           can_reveal_password=True, width=280, dense=True)
        pw2 = ft.TextField(label="Confirm passphrase", password=True,
                           width=280, dense=True)
        incl = ft.Checkbox(label="Include message history", value=False)
        err = ft.Text("", color="#ed4245", size=11, visible=False)

        async def do_backup(ev):
            if not pw1.value:
                err.value = "Enter a passphrase"; err.visible = True; self.page.update(); return
            if pw1.value != pw2.value:
                err.value = "Passphrases do not match"; err.visible = True; self.page.update(); return
            blob = backup.export_backup(pw1.value, include_history=incl.value)
            self._close_dialog(dlg)
            picker = ft.FilePicker()
            self.page.services.append(picker)
            self.page.update()
            await picker.save_file(file_name="helucryptic-backup.helu", src_bytes=blob)
            self._log("Encrypted backup saved.")

        dlg = ft.AlertDialog(
            title=ft.Text("Backup profile"),
            content=ft.Column([
                ft.Text("Encrypts keys, contacts and settings with your passphrase.",
                        size=11, color="#72767d"),
                pw1, pw2, incl, err,
            ], tight=True, spacing=8),
            actions=[
                ft.TextButton("Create backup", on_click=do_backup),
                ft.TextButton("Cancel", on_click=lambda ev: self._close_dialog(dlg)),
            ],
        )
        self._show_dialog(dlg)

    def _show_restore(self, e=None) -> None:
        pw = ft.TextField(label="Backup passphrase", password=True,
                          can_reveal_password=True, width=280, dense=True)
        err = ft.Text("", color="#ed4245", size=11, visible=False)

        async def do_restore(ev):
            if not pw.value:
                err.value = "Enter the passphrase"; err.visible = True; self.page.update(); return
            picker = ft.FilePicker()
            self.page.services.append(picker)
            self.page.update()
            files = await picker.pick_files(allowed_extensions=["helu"])
            if not files:
                return
            try:
                data = Path(files[0].path).read_bytes()
                restored = backup.import_backup(data, pw.value)
            except ValueError as ex:
                err.value = str(ex); err.visible = True; self.page.update(); return
            # Reload everything from the restored files.
            self.keys        = load_or_create_keys()
            self.history_key = derive_history_key(self.keys["ed25519_private"])
            self.engine.keys = self.keys
            self.settings    = load_settings()
            self.engine.settings = self.settings
            self._update_perf_parameters()
            self._refresh_contact_list()
            self._close_dialog(dlg)
            self._log(f"Restored: {', '.join(restored)}. Previous files saved as .bak")

        dlg = ft.AlertDialog(
            title=ft.Text("Restore profile"),
            content=ft.Column([
                ft.Text("Choose a .helu backup. Existing files are saved as .bak first.",
                        size=11, color="#72767d"),
                pw, err,
            ], tight=True, spacing=8),
            actions=[
                ft.TextButton("Choose file & restore", on_click=do_restore),
                ft.TextButton("Cancel", on_click=lambda ev: self._close_dialog(dlg)),
            ],
        )
        self._show_dialog(dlg)

    def _show_wipe(self, e=None) -> None:
        phrase = ft.TextField(label='Type WIPE to confirm', width=280, dense=True, autofocus=True)
        err = ft.Text("", color="#ed4245", size=11, visible=False)

        async def do_wipe(ev):
            if phrase.value.strip() != "WIPE":
                err.value = 'Type WIPE exactly to confirm'; err.visible = True; self.page.update(); return
            # Close active connections first, then delete local data.
            if self.ws:
                try:
                    await self.ws.close()
                except Exception:
                    pass
            for p in list(self.engine.pcs.keys()):
                try:
                    await self.engine.remove_peer(p)
                except Exception:
                    pass
            removed = backup.emergency_wipe()
            self._close_dialog(dlg)
            self.page.controls.clear()
            self.page.add(ft.Container(
                padding=ft.Padding.all(40),
                content=ft.Column([
                    ft.Icon(ft.Icons.DELETE_FOREVER, color="#ed4245", size=40),
                    ft.Text("Local profile wiped", size=20, weight=ft.FontWeight.BOLD, color="#ffffff"),
                    ft.Text(f"Removed: {', '.join(removed) or '(nothing)'}", size=12, color="#b9bbbe"),
                    ft.Text("Please restart helucryptic. A new identity will be created; "
                            "contacts will need to re-verify you.", size=12, color="#72767d"),
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=10),
            ))
            self.page.update()

        dlg = ft.AlertDialog(
            title=ft.Text("⚠ Emergency wipe"),
            content=ft.Column([
                ft.Text("This permanently deletes your identity keys, contacts, settings "
                        "and message history from this device. It cannot be undone, and "
                        "contacts will need to re-verify you.", color="#dcddde", size=12),
                phrase, err,
            ], tight=True, spacing=8),
            actions=[
                ft.TextButton("Wipe everything", on_click=do_wipe),
                ft.TextButton("Cancel", on_click=lambda ev: self._close_dialog(dlg)),
            ],
        )
        self._show_dialog(dlg)

    # ------------------------------------------------------------------
    # Verified-Only gating
    # ------------------------------------------------------------------

    def _is_allowed(self, contact: str) -> bool:
        if not self.settings.verified_only:
            return True
        if not contact:
            return True  # room/group actions are not gated here
        c = get_contact(contact)
        if c and c.verified:
            return True
        return contact in self._session_allowed

    def _block_unverified(self, contact: str) -> None:
        c = get_contact(contact)
        name = (c.nickname if c and c.nickname else contact)

        def allow(ev):
            self._session_allowed.add(contact)
            self._close_dialog(dlg)
            self._log(f"Allowed {name} for this session. Re-try the action.")

        def verify(ev):
            self._close_dialog(dlg)
            self._show_contact_menu(contact)

        dlg = ft.AlertDialog(
            title=ft.Text("Contact not verified"),
            content=ft.Text(
                f"Verified-Only mode is on and {name} isn't verified.\n\n"
                f"Verify their fingerprint (View Fingerprint or Import from code), "
                f"or allow them just for this session."),
            actions=[
                ft.TextButton("Verify…", on_click=verify),
                ft.TextButton("Allow this session", on_click=allow),
                ft.TextButton("Cancel", on_click=lambda ev: self._close_dialog(dlg)),
            ],
        )
        self._show_dialog(dlg)

    def _show_diagnostics(self, e) -> None:
        body = ft.Text("", size=12, color="#dcddde", selectable=True, font_family="monospace")
        self._diag_open = True

        def render() -> str:
            d = self.engine.get_diagnostics()
            lines = [
                f"Signaling : {d['signaling']}",
                f"TURN      : {'configured' if d['turn_configured'] else 'not configured'}",
                f"Last error: {d['last_error'] or '(none)'}",
                "Peers:",
            ]
            if not d["peers"]:
                lines.append("  (none)")
            for p in d["peers"]:
                lines.append(f"  {p['peer']}: conn={p['connection']} ice={p['ice']}")
            return "\n".join(lines)

        body.value = render()

        async def refresh_loop():
            while self._diag_open:
                body.value = render()
                try:
                    body.update()
                except Exception:
                    break
                await asyncio.sleep(1)

        def copy_safe(ev):
            self.page.clipboard.set(render())
            self._log("Safe diagnostics copied.")

        def close(ev):
            self._diag_open = False
            self._close_dialog(dlg)

        dlg = ft.AlertDialog(
            title=ft.Text("Connection diagnostics"),
            content=ft.Column([body], width=420, height=260, scroll=ft.ScrollMode.AUTO),
            actions=[
                ft.TextButton("Copy safe diagnostics", on_click=copy_safe),
                ft.TextButton("Close", on_click=close),
            ],
        )
        self._show_dialog(dlg)
        asyncio.ensure_future(refresh_loop())

    def _show_settings(self, e) -> None:
        mode_radio    = ft.RadioGroup(
            value=self.settings.security_mode,
            content=ft.Row([
                ft.Radio(value="dtls", label="DTLS-only"),
                ft.Radio(value="e2ee",  label="E2EE + Signing"),
            ]),
        )
        preset_value  = (
            str(self.settings.retention_days)
            if self.settings.retention_days in (0, 7, 30, 90)
            else "custom"
        )
        custom_days   = ft.TextField(
            label="Days", width=100, dense=True,
            visible=(preset_value == "custom"),
            value=str(self.settings.retention_days) if preset_value == "custom" else "1",
        )
        custom_error  = ft.Text("", color="#ed4245", size=11, visible=False)
        retention_dd  = ft.Dropdown(
            value=preset_value, width=160,
            options=[
                ft.dropdown.Option("0",      "Never"),
                ft.dropdown.Option("7",      "7 days"),
                ft.dropdown.Option("30",     "30 days"),
                ft.dropdown.Option("90",     "90 days"),
                ft.dropdown.Option("custom", "Custom…"),
            ],
        )
        def on_retention_change(ev):
            custom_days.visible  = retention_dd.value == "custom"
            custom_error.visible = False
            self.page.update()
        retention_dd.on_change = on_retention_change

        url_field = ft.TextField(
            value=self.settings.signaling_url, label="Signaling URL", width=280, dense=True,
        )
        # --- Trust ---
        verified_only_cb = ft.Checkbox(
            label="Verified-Only mode (block actions with unverified contacts)",
            value=self.settings.verified_only,
        )
        btn_show_identity = ft.TextButton("Show My Identity (QR / code)",
                                          on_click=self._show_my_identity)
        # --- Performance profile ---
        _profile_labels = {
            "old_pc": "Old PC (480p/5fps)", "balanced": "Balanced (720p/10fps)",
            "quality": "Quality (1080p/30fps)", "overclock": "Overclock (2K/60fps)",
        }
        profile_opts = [ft.dropdown.Option(k, _profile_labels[k]) for k in PROFILES]
        if self.settings.performance_profile not in PROFILES:
            profile_opts.append(ft.dropdown.Option("custom", "Custom (from .env)"))
        profile_dd = ft.Dropdown(
            value=self.settings.performance_profile, width=240, options=profile_opts,
        )
        overclock_warn = ft.Text(
            "⚠ Overclock (2K/60) is very CPU/bandwidth heavy and may not reach "
            "60 FPS with software encoding.",
            size=11, color="#faa61a", visible=self.settings.performance_profile == "overclock",
        )
        def on_profile_change(ev):
            overclock_warn.visible = profile_dd.value == "overclock"
            self.page.update()
        profile_dd.on_change = on_profile_change

        # --- TURN relay ---
        turn_url_f  = ft.TextField(label="TURN URL (turn:host:port)", value=self.settings.turn_url,
                                   width=280, dense=True)
        turn_user_f = ft.TextField(label="TURN username", value=self.settings.turn_username,
                                   width=280, dense=True)
        turn_pass_f = ft.TextField(label="TURN password", value=self.settings.turn_password,
                                   width=280, dense=True, password=True, can_reveal_password=True)
        turn_result = ft.Text("", size=11)
        async def do_test_turn(ev):
            from webrtc_engine import test_turn
            turn_result.value = "Testing…"; turn_result.color = "#b9bbbe"; self.page.update()
            ok, msg = await test_turn(turn_url_f.value.strip(), turn_user_f.value.strip(), turn_pass_f.value)
            turn_result.value = msg; turn_result.color = "#57f287" if ok else "#ed4245"; self.page.update()
        btn_test_turn = ft.TextButton("Test TURN", on_click=do_test_turn)

        # --- Port forwarding (advanced) ---
        pf_enabled_cb = ft.Checkbox(
            label="I'm port-forwarding (VPN/router)",
            value=self.settings.port_forward_enabled,
        )
        pf_port_f = ft.TextField(
            label="Forwarded port", value=str(self.settings.forwarded_port or ""),
            width=280, dense=True,
        )
        pf_result = ft.Text("", size=11)

        async def do_pf_autodetect(ev):
            pf_result.value = "Detecting…"; pf_result.color = "#b9bbbe"; self.page.update()
            gw   = await asyncio.to_thread(discover_gateway) or PROTON_GATEWAY
            ip   = await asyncio.to_thread(local_ip_for, gw)
            port = await asyncio.to_thread(request_mapping_over_socket, gw)
            if port and ip:
                pf_port_f.value = str(port)
                pf_result.value = f"Got port {port} on {ip}"; pf_result.color = "#57f287"
            else:
                pf_result.value = "No NAT-PMP mapping — enter the port manually"
                pf_result.color = "#ed4245"
            self.page.update()
        btn_pf_detect = ft.TextButton("Auto-detect (NAT-PMP)", on_click=do_pf_autodetect)

        async def do_pf_test(ev):
            from webrtc_engine import test_forwarded_port
            try:
                port = int(pf_port_f.value or 0)
            except ValueError:
                port = 0
            if not (1024 <= port <= 65535):
                pf_result.value = "Enter a valid port (1024–65535)"; pf_result.color = "#ed4245"
                self.page.update(); return
            pf_result.value = "Testing…"; pf_result.color = "#b9bbbe"; self.page.update()
            gw = await asyncio.to_thread(discover_gateway) or PROTON_GATEWAY
            ip = await asyncio.to_thread(local_ip_for, gw)
            if not ip:
                pf_result.value = "Could not determine local IP"; pf_result.color = "#ed4245"
                self.page.update(); return
            ok, msg = await asyncio.to_thread(test_forwarded_port, ip, port)
            pf_result.value = msg; pf_result.color = "#57f287" if ok else "#ed4245"
            self.page.update()
        btn_pf_test = ft.TextButton("Test", on_click=do_pf_test)

        pf_caption = ft.Text(
            "Needs full-tunnel VPN; applies to one peer at a time.",
            size=11, color="#72767d",
        )

        async def export_keys(ev):
            data   = (paths.DATA_DIR / "keys.json").read_bytes()
            picker = ft.FilePicker()
            self.page.services.append(picker)
            self.page.update()
            await picker.save_file(file_name="helucryptic-keys.json", src_bytes=data)

        async def import_keys(ev):
            picker = ft.FilePicker()
            self.page.services.append(picker)
            self.page.update()
            files = await picker.pick_files(allowed_extensions=["json"])
            if files:
                paths.DATA_DIR.mkdir(parents=True, exist_ok=True)
                paths.write_private_text(
                    paths.DATA_DIR / "keys.json",
                    Path(files[0].path).read_text(encoding="utf-8"),
                )
                self.keys        = load_or_create_keys()
                self.history_key = derive_history_key(self.keys["ed25519_private"])
                self.engine.keys = self.keys

        def regen_keys(ev):
            def confirm_regen(cev):
                from contacts import load_contacts as lc, save_contacts as sc
                generate_and_save_keys()
                self.keys        = load_or_create_keys()
                self.history_key = derive_history_key(self.keys["ed25519_private"])
                self.engine.keys = self.keys
                contacts = lc()
                for c in contacts:
                    c.verified = False
                sc(contacts)
                self._refresh_contact_list()
                self._close_dialog(confirm_dlg)
            confirm_dlg = ft.AlertDialog(
                title=ft.Text("Regenerate keys?"),
                content=ft.Text("All contacts must re-verify. Cannot be undone."),
                actions=[
                    ft.TextButton("Regenerate", on_click=confirm_regen),
                    ft.TextButton("Cancel",     on_click=lambda cev: self._close_dialog(confirm_dlg)),
                ],
            )
            self._show_dialog(confirm_dlg)

        def save_settings_cb(ev):
            if retention_dd.value == "custom":
                try:
                    days = int(custom_days.value)
                    if days <= 0:
                        raise ValueError
                except ValueError:
                    custom_error.value   = "Enter a positive number of days"
                    custom_error.visible = True
                    self.page.update()
                    return
                self.settings.retention_days = days
            else:
                self.settings.retention_days = int(retention_dd.value)
            self.settings.security_mode = mode_radio.value
            self.settings.signaling_url = url_field.value
            # Applying a profile sets the 5 concrete knobs + label; "custom"
            # leaves the existing concrete values untouched.
            if profile_dd.value in PROFILES:
                apply_profile(self.settings, profile_dd.value)
            self.settings.turn_url      = turn_url_f.value.strip()
            self.settings.turn_username = turn_user_f.value.strip()
            self.settings.turn_password = turn_pass_f.value
            self.settings.verified_only = verified_only_cb.value
            self.settings.port_forward_enabled = pf_enabled_cb.value
            try:
                self.settings.forwarded_port = int(pf_port_f.value or 0)
            except ValueError:
                self.settings.forwarded_port = 0
            save_settings(self.settings)
            self._update_perf_parameters()  # apply jpeg/tile knobs live
            self._apply_port_forward()      # (re)start/stop the forward manager
            self._close_dialog(dlg)

        dlg = ft.AlertDialog(
            title=ft.Text("Settings"),
            content=ft.Column([
                ft.Text("Security mode", size=12, color="#72767d"),
                mode_radio,
                ft.Text("Message retention", size=12, color="#72767d"),
                ft.Row([retention_dd, custom_days]),
                custom_error,
                url_field,
                ft.Divider(color="#40444b"),
                ft.Text("Performance profile", size=12, color="#72767d"),
                profile_dd,
                overclock_warn,
                ft.Divider(color="#40444b"),
                ft.Text("TURN relay (optional — fixes strict-NAT connections)", size=12, color="#72767d"),
                turn_url_f,
                turn_user_f,
                turn_pass_f,
                ft.Row([btn_test_turn, turn_result]),
                ft.Divider(color="#40444b"),
                ft.Text("Port forwarding (advanced — direct connect via a forwarded port)",
                        size=12, color="#72767d"),
                pf_enabled_cb,
                pf_port_f,
                ft.Row([btn_pf_detect, btn_pf_test]),
                pf_result,
                pf_caption,
                ft.Divider(color="#40444b"),
                ft.Text("Trust & verification", size=12, color="#72767d"),
                verified_only_cb,
                btn_show_identity,
                ft.Divider(color="#40444b"),
                ft.Row([
                    ft.FilledButton("Export Keys",     on_click=export_keys),
                    ft.FilledButton("Import Keys",     on_click=import_keys),
                    ft.FilledButton("Regenerate Keys", on_click=regen_keys),
                ], wrap=True, spacing=6),
                ft.Divider(color="#40444b"),
                ft.Text("Data & backup", size=12, color="#72767d"),
                ft.Text(f"Data folder: {paths.DATA_DIR}"
                        + ("  (portable)" if paths.is_portable() else ""),
                        size=11, color="#b9bbbe", selectable=True),
                ft.Row([
                    ft.FilledButton("Backup Profile…",  on_click=self._show_backup),
                    ft.FilledButton("Restore Profile…", on_click=self._show_restore),
                ], wrap=True, spacing=6),
                ft.TextButton("⚠ Emergency Wipe…", on_click=self._show_wipe,
                              style=ft.ButtonStyle(color="#ed4245")),
            ], tight=True, spacing=10, scroll=ft.ScrollMode.AUTO),
            actions=[
                ft.TextButton("Save",   on_click=save_settings_cb),
                ft.TextButton("Cancel", on_click=lambda ev: self._close_dialog(dlg)),
            ],
        )
        self._show_dialog(dlg)

    # ------------------------------------------------------------------
    # Add contact
    # ------------------------------------------------------------------

    def _show_add_contact(self, e) -> None:
        field = ft.TextField(label="Username", autofocus=True, dense=True)
        def add(ev):
            name = field.value.strip()
            if name:
                upsert_contact(name)
                self._refresh_contact_list()
            self._close_dialog(dlg)
        dlg = ft.AlertDialog(
            title=ft.Text("Add Contact"),
            content=field,
            actions=[
                ft.TextButton("Add",    on_click=add),
                ft.TextButton("Cancel", on_click=lambda ev: self._close_dialog(dlg)),
            ],
        )
        self._show_dialog(dlg)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _show_dialog(self, dlg) -> None:
        # Flet 0.85: dialogs are shown/dismissed via show_dialog()/pop_dialog(),
        # NOT the old `page.dialog = dlg; dlg.open = True` pattern (which is a
        # silent no-op in this version).
        self.page.show_dialog(dlg)

    def _close_dialog(self, dlg=None) -> None:
        # pop_dialog() dismisses the current (top) dialog; the arg is ignored.
        self.page.pop_dialog()

    async def _retention_background_loop(self) -> None:
        while True:
            await asyncio.sleep(86400)
            run_retention_policy(self.settings.retention_days)

    def _connected_peer(self) -> str:
        if self.engine.pc and self.engine.pc.connectionState == "connected":
            return self.engine.target_peer
        return ""

    def _update_status(self, label: str, color: str) -> None:
        self.status_dot.bgcolor   = color
        self.status_label.value   = label
        self.status_label.color   = color
        self.engine.signaling_status = label.lower()
        self.page.update()

    def _append_to_log(self, direction: str, text: str, verified: bool, label: str = "") -> None:
        is_sent = direction == "sent"
        prefix  = "You" if is_sent else (label or self._active_contact or "Peer")
        color   = "#5865f2" if is_sent else "#b9bbbe"
        badge   = " ✓" if verified else ""
        self.chat_log.controls.append(
            ft.Text(spans=[
                ft.TextSpan(f"[{prefix}]{badge}: ",
                            style=ft.TextStyle(weight=ft.FontWeight.BOLD, color=color)),
                ft.TextSpan(text, style=ft.TextStyle(color="#dcddde")),
            ])
        )

    def _log(self, text: str) -> None:
        self.chat_log.controls.append(ft.Text(text, color="#72767d", size=11, italic=True))
        self.page.update()


# ---------------------------------------------------------------------------
# Startup screen
# ---------------------------------------------------------------------------

class StartupScreen:
    def __init__(self, page: ft.Page, on_done):
        self.page      = page
        self.on_done   = on_done
        self._selected = "a"
        self._build()

    def _build(self) -> None:
        self._pw_field  = ft.TextField(
            label="Password", password=True, can_reveal_password=True,
            width=280, dense=True,
            border_color="#40444b", focused_border_color="#5865f2", color="#dcddde",
        )
        self._pw_error  = ft.Text("", color="#ed4245", size=11, visible=False)
        self._url_field = ft.TextField(
            label="Server URL", value="ws://", width=280, dense=True,
            hint_text="ws://your-server-ip:8000",
            border_color="#40444b", focused_border_color="#5865f2", color="#dcddde",
        )
        self._custom_pw_field = ft.TextField(
            label="Server password (optional)", password=True, can_reveal_password=True,
            width=280, dense=True,
            border_color="#40444b", focused_border_color="#5865f2", color="#dcddde",
        )
        self._url_error = ft.Text("", color="#ed4245", size=11, visible=False)

        card_a = ft.Container(
            border=ft.Border.all(2, "#5865f2"), border_radius=8,
            padding=ft.Padding.all(16), bgcolor="#2b2d31",
            content=ft.Column([
                ft.Row([ft.Icon(ft.Icons.PUBLIC, color="#5865f2"),
                        ft.Text("helucryptic server", weight=ft.FontWeight.BOLD, color="#dcddde")], spacing=8),
                ft.Text("Connect to the official server.\nRequires access password.", size=12, color="#b9bbbe"),
                self._pw_field,
                self._pw_error,
            ], spacing=8, tight=True),
        )
        card_b = ft.Container(
            border=ft.Border.all(1, "#40444b"), border_radius=8,
            padding=ft.Padding.all(16), bgcolor="#2b2d31",
            content=ft.Column([
                ft.Row([ft.Icon(ft.Icons.DNS, color="#72767d"),
                        ft.Text("Custom server", weight=ft.FontWeight.BOLD, color="#dcddde")], spacing=8),
                ft.Text("Connect to your own self-hosted server.", size=12, color="#b9bbbe"),
                self._url_field,
                self._custom_pw_field,
                self._url_error,
            ], spacing=8, tight=True),
        )
        self._card_a = card_a
        self._card_b = card_b

        radio_group = ft.RadioGroup(
            value="a",
            content=ft.Column([
                ft.Radio(value="a", label=""),
                ft.Radio(value="b", label=""),
            ], spacing=52),
        )
        radio_group.on_change = self._on_radio_change

        def connect(e):
            if self._selected == "a":
                pw = self._pw_field.value or ""
                if not pw:
                    self._pw_error.value   = "Enter the server access password"
                    self._pw_error.visible = True
                    self.page.update()
                    return
                sounds.play("authorized")
                self.on_done(HELUCRYPTIC_SERVER_URL, pw)
            else:
                url = self._url_field.value.strip()
                if not url.startswith(("ws://", "wss://", "http://", "https://")):
                    self._url_error.value   = "Use ws://, wss://, http:// or https://"
                    self._url_error.visible = True
                    self.page.update()
                    return
                # Store normalized to a WebSocket scheme (https -> wss, http -> ws)
                self.on_done(_to_ws_url(url), self._custom_pw_field.value or "")

        self.page.add(
            ft.Column([
                ft.Container(height=40),
                ft.Row([
                    ft.Icon(ft.Icons.LOCK, color="#5865f2", size=28),
                    ft.Text("helucryptic", size=26, weight=ft.FontWeight.BOLD, color="#ffffff"),
                ], alignment=ft.MainAxisAlignment.CENTER, spacing=10),
                ft.Text("Choose how to connect", size=13, color="#72767d",
                        text_align=ft.TextAlign.CENTER),
                ft.Container(height=20),
                ft.Row(
                    [radio_group, ft.Column([card_a, card_b], spacing=12)],
                    alignment=ft.MainAxisAlignment.CENTER,
                    vertical_alignment=ft.CrossAxisAlignment.START,
                    spacing=8,
                ),
                ft.Container(height=24),
                ft.FilledButton(
                    "Connect", on_click=connect, width=200,
                    style=ft.ButtonStyle(bgcolor={"": "#5865f2"}, color={"": "#ffffff"}),
                ),
            ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=6),
        )

    def _on_radio_change(self, e) -> None:
        self._selected = e.control.value
        if self._selected == "a":
            self._card_a.border = ft.Border.all(2, "#5865f2")
            self._card_b.border = ft.Border.all(1, "#40444b")
        else:
            self._card_a.border = ft.Border.all(1, "#40444b")
            self._card_b.border = ft.Border.all(2, "#5865f2")
        self._pw_error.visible  = False
        self._url_error.visible = False
        self.page.update()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main(page: ft.Page) -> None:
    page.title         = "helucryptic"
    page.theme_mode    = ft.ThemeMode.DARK
    page.theme         = ft.Theme(color_scheme_seed="#5865f2")
    page.window.width  = 1100
    page.window.height = 700
    page.bgcolor       = "#2f3136"

    import sys
    from pathlib import Path
    if hasattr(sys, "_MEIPASS"):
        page.window.icon = str(Path(sys._MEIPASS) / "icon.ico")
    else:
        page.window.icon = str(Path(__file__).parent / "icon.ico")

    def launch_app(signaling_url: str, password: str = "") -> None:
        page.controls.clear()
        page.update()
        s = load_settings()
        s.signaling_url = signaling_url
        save_settings(s)
        app = HelucrypticApp(page)
        # Thread the access token through so the app sends it to the server.
        app._server_password = password or config.SERVER_PASSWORD
        app._refresh_contact_list()

    StartupScreen(page, on_done=launch_app)


if __name__ == "__main__":
    ft.app(target=main)
