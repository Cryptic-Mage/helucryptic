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
from pathlib import Path

import cv2
import flet as ft
import websockets

from contacts import (
    delete_contact,
    get_contact,
    load_contacts,
    rename_contact,
    set_verified,
    upsert_contact,
)
from crypto import derive_history_key, generate_and_save_keys, load_or_create_keys
from history import init_db, read_messages, read_room_messages, run_retention_policy, write_message
from settings import load_settings, save_settings
from sounds import manager as sounds
from webrtc_engine import WebRTCEngine

# ---------------------------------------------------------------------------
# Change this to your deployed server URL when you go public
# ---------------------------------------------------------------------------
HELUCRYPTIC_SERVER_URL      = "https://helucryptic-signaling.crypticmage00.workers.dev/"
HELUCRYPTIC_SERVER_PASSWORD = "CrypticKodu"


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
        self._ringing:         bool            = False
        self._ring_timeout_task = None

        init_db()
        run_retention_policy(self.settings.retention_days)
        self._build_ui()
        self._wire_engine_callbacks()
        asyncio.ensure_future(self._retention_background_loop())

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        # --- Sidebar controls ---
        self.contact_list     = ft.Column(scroll=ft.ScrollMode.AUTO, expand=True, spacing=2)
        self.btn_add_contact  = ft.TextButton("+ Add Contact", on_click=self._show_add_contact)
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
                self.participant_list,
                ft.Divider(color="#40444b"),
                self.contact_list,
                self.btn_add_contact,
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
                        self.btn_hangup, ft.Container(expand=True), self.btn_settings]),
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
            verified = bool(c and c.verified)
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
            sounds.play_loop("incoming")
            self._ringing = True

            def _stop_ring():
                self._ringing = False
                sounds.stop_loop()
                if self._ring_timeout_task is not None:
                    self._ring_timeout_task.cancel()
                    self._ring_timeout_task = None

            def accept(e):
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

        def on_file_complete(fname: str, data: bytes, ok: bool):
            self.file_progress.visible = False
            self._log(f"[File received] {fname} {'✓' if ok else '⚠ integrity failed'}")
            self.page.update()
            asyncio.ensure_future(self._save_received_file(fname, data))

        def on_hangup(peer=None):
            sounds.stop_loop()
            sounds.play("call_end")
            self.btn_hangup.disabled = True
            self.btn_mute.disabled   = True
            self._set_mute_banner(False)
            self._remove_video_tile(peer) if peer else None
            self._log("[Call ended]")
            self.page.update()

        def on_video_frame(sender: str, img):
            try:
                _, buf = cv2.imencode(".jpg", img, [cv2.IMWRITE_JPEG_QUALITY, 70])
                b64 = base64.b64encode(buf).decode()
                if sender not in self._video_tiles:
                    self._add_video_tile(sender)
                self._video_tiles[sender].src_base64 = b64
                self.page.update()
            except Exception:
                pass

        self.engine.on_state_change   = on_state
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
        suffix = f"?room={room}" if room else ""
        base   = _to_ws_url(self.settings.signaling_url)
        url    = f"{base}/ws/{uname}{suffix}"
        print(f"[connect] dialing {url}", flush=True)
        if self.ws:
            try:
                await self.ws.close()
            except Exception:
                pass
        try:
            self.ws = await websockets.connect(url)
            self._update_status("SIGNALING", "#fee75c")
            self._log(f"Connected as '{uname}'" + (f" in {room}" if room else "") + ".")
            print(f"[connect] websocket OPEN to {url}", flush=True)
            sounds.play("reactivated")
            asyncio.ensure_future(self._signaling_listener())
        except Exception as ex:
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
                    await self.engine.add_peer(sender, ws_send)

                elif t == "peer_left":
                    self._room_peers.pop(sender, None)
                    self._refresh_participant_list()
                    asyncio.ensure_future(self.engine.remove_peer(sender))
                    self._remove_video_tile(sender)

                elif t == "room_state":
                    # Server sends `peers` at the top level of the message
                    # (like `sender` for peer_joined), NOT nested under `data`.
                    for peer in msg.get("peers", []):
                        self._room_peers[peer] = "connecting"
                        await self.engine.add_peer(peer, ws_send)
                    self._refresh_participant_list()

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
        self.engine.set_room(code, is_creator=is_creator)
        self.room_code_label.value    = f"Room: {code}"
        self.btn_invite.visible       = True
        self.btn_copy_room.visible    = True
        self.page.update()
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
    # Participant list
    # ------------------------------------------------------------------

    def _refresh_participant_list(self) -> None:
        self.participant_list.controls.clear()
        for username, state in self._room_peers.items():
            dot_color = "#57f287" if state == "connected" else "#fee75c"
            c         = get_contact(username)
            display   = (c.nickname if c and c.nickname else username)
            badge     = " ✓" if (c and c.verified) else (
                " ⚠" if self.settings.security_mode == "e2ee" else ""
            )
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
            badge     = " ✓" if c.verified else (" ⚠" if self.settings.security_mode == "e2ee" else "")
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

    async def _save_received_file(self, fname: str, data: bytes) -> None:
        # Flet 0.85: save_file() is async, returns the chosen path, and can write src_bytes directly.
        picker = ft.FilePicker()
        self.page.services.append(picker)
        self.page.update()
        await picker.save_file(file_name=fname, src_bytes=data)

    # ------------------------------------------------------------------
    # Calls & screen share
    # ------------------------------------------------------------------

    async def _start_call(self, e) -> None:
        if not self.ws:
            return

        async def ws_send(payload: dict):
            await self.ws.send(json.dumps(payload))

        if self._room_id:
            for peer in list(self.engine.pcs.keys()):
                if self.engine.pcs[peer].connectionState == "connected":
                    await self.engine.start_voice_call(peer)
        else:
            if not self._active_contact:
                return
            if not self.engine.pcs.get(self._active_contact):
                await self.engine.create_offer(self._active_contact, ws_send)
            await self.engine.start_voice_call(self._active_contact)

        self.btn_hangup.disabled = False
        self.btn_mute.disabled   = False
        self.page.update()

    async def _start_screen(self, e) -> None:
        if not self.ws:
            return

        async def ws_send(payload: dict):
            await self.ws.send(json.dumps(payload))

        if self._room_id:
            for peer in list(self.engine.pcs.keys()):
                if self.engine.pcs[peer].connectionState == "connected":
                    await self.engine.start_screen_share(peer)
        else:
            if not self._active_contact:
                return
            if not self.engine.pcs.get(self._active_contact):
                await self.engine.create_offer(self._active_contact, ws_send)
            await self.engine.start_screen_share(self._active_contact)

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
        self.btn_mute.icon       = ft.Icons.MIC
        self.btn_mute.icon_color = None
        self._set_mute_banner(False)
        self.btn_hangup.disabled = True
        self.btn_mute.disabled   = True
        self.btn_call.disabled   = True
        self.btn_screen.disabled = True
        self._log("[Hung up]")
        self.page.update()

    # ------------------------------------------------------------------
    # Video tiles
    # ------------------------------------------------------------------

    def _add_video_tile(self, sender: str) -> ft.Image:
        img  = ft.Image(
            src_base64="", width=240, height=135,
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

        async def export_keys(ev):
            data   = (Path.home() / ".helucryptic" / "keys.json").read_bytes()
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
                shutil.copy(files[0].path, Path.home() / ".helucryptic" / "keys.json")
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
            save_settings(self.settings)
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
                ft.Row([
                    ft.FilledButton("Export Keys",     on_click=export_keys),
                    ft.FilledButton("Import Keys",     on_click=import_keys),
                    ft.FilledButton("Regenerate Keys", on_click=regen_keys),
                ], wrap=True, spacing=6),
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
                if self._pw_field.value != HELUCRYPTIC_SERVER_PASSWORD:
                    self._pw_error.value   = "Incorrect password"
                    self._pw_error.visible = True
                    self.page.update()
                    return
                sounds.play("authorized")
                self.on_done(HELUCRYPTIC_SERVER_URL)
            else:
                url = self._url_field.value.strip()
                if not url.startswith(("ws://", "wss://", "http://", "https://")):
                    self._url_error.value   = "Use ws://, wss://, http:// or https://"
                    self._url_error.visible = True
                    self.page.update()
                    return
                # Store normalized to a WebSocket scheme (https -> wss, http -> ws)
                self.on_done(_to_ws_url(url))

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

    def launch_app(signaling_url: str) -> None:
        page.controls.clear()
        page.update()
        s = load_settings()
        s.signaling_url = signaling_url
        save_settings(s)
        app = HelucrypticApp(page)
        app._refresh_contact_list()

    StartupScreen(page, on_done=launch_app)


if __name__ == "__main__":
    ft.app(target=main)
