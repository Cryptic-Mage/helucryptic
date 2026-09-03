# Nuitka compile:
# nuitka --standalone --onefile --include-package=aiortc --include-package=av
#        --include-package=flet --include-package=cryptography --include-package=pyseto
#        --include-package=sounddevice --include-package=mss --windows-disable-console
#        client_claude.py
#
# ---------------------------------------------------------------------------
# client_claude.py - a 100%-functionally-identical reskin of client.py with a
# modern "neon cyber / crypto" UI and rich-but-tasteful motion. Every engine
# call, signaling path, room/call/file flow and dialog from the original is
# preserved byte-for-byte in behaviour; only the presentation layer (main
# window, startup screen, chat bubbles, contact/participant tiles, video tiles,
# status indicator, animated backdrop) is redesigned.
# ---------------------------------------------------------------------------

import asyncio
import base64
import json
import re as _re
import secrets
import shutil
import string
import sys
import time
import urllib.parse
from datetime import UTC, datetime
from io import BytesIO
from pathlib import Path

# pyrefly: ignore [missing-import]
import flet as ft

# pyrefly: ignore [missing-import]
import numpy as np

# pyrefly: ignore [missing-import]
import websockets

# pyrefly: ignore [missing-import]
from PIL import Image

try:
    # pyrefly: ignore [missing-import]
    import cv2
except ImportError:
    cv2 = None

import backup
import config
import identity
import invites
import paths
import profiles
from constants.client_constants import (
    _EASE_IO,
    DIAGNOSTICS_TXT,
    HELUCRYPTIC_SERVER_PASSWORD,
    HELUCRYPTIC_SERVER_URL,
    JOIN_ROOM_TXT,
    LOAD_MORE_TXT,
    LOG_BUFFER,
    SCHEME_HTTP,
    SCHEME_HTTPS,
    SCHEME_WS,
    SCHEME_WSS,
    SHARE_SCREEN_TXT,
    C,
    D,
    R,
    _anim,
    _dot,
    _filled_style,
    _ghost_style,
    _glow,
    _install_log_capture,
    _neon_field,
    _redact_url,
)
from contacts import (
    delete_contact,
    get_contact,
    load_contacts,
    rename_contact,
    set_verified,
    upsert_contact,
)
from crypto import (
    compute_fingerprint,
    derive_history_key,
    generate_and_save_keys,
    load_or_create_keys,
)
from history import (
    init_db,
    last_room_message_ts,
    read_messages,
    read_room_message_keys,
    read_room_messages,
    read_room_messages_since,
    run_retention_policy,
    write_message,
)
from natpmp import (
    PROTON_GATEWAY,
    PortForwardManager,
    discover_gateway,
    discover_gateway_candidates,
    local_ip_for,
    request_mapping_over_socket,
)
from settings import PROFILES, apply_profile, load_settings, save_settings
from sounds import manager as sounds
from theme import flet_theme
from theme.tokens import FONTS as _t_FONTS
from ui_state import summarize_peer_states
from webrtc_engine import (
    WebRTCEngine,
    clear_forwarded_port,
    set_forwarded_ports,
)


def _alpha(alpha2: str, color: str) -> str:
    """8-digit hex with alpha FIRST (#AARRGGBB) - Flet/Flutter's format.
    Suffixing alpha (color+"aa") silently shifts the hue (cyan turns green)."""
    return f"#{alpha2}{color.lstrip('#')}"


# Delivery-status glyphs for sent bubbles: icon name + colour per state.
_MSG_STATUS_GLYPHS = {
    "queued":    (ft.Icons.SCHEDULE,  C.MUTED),   # waiting in the offline outbox
    "sent":      (ft.Icons.DONE,      C.MUTED),   # left this machine
    "delivered": (ft.Icons.DONE_ALL,  C.CYAN),    # peer acked receipt
}


def _fmt_msg_ts(iso_ts: str | None = None) -> str:
    """Human timestamp for a chat bubble, in LOCAL time. History rows store
    UTC ISO strings; live messages pass None (= now). Same-day → 'HH:MM',
    older → 'DD Mon HH:MM'. Defensive: any parse failure → empty string."""
    try:
        if iso_ts:
            dt = datetime.fromisoformat(iso_ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            dt = dt.astimezone()
        else:
            dt = datetime.now().astimezone()
        if dt.date() == datetime.now().astimezone().date():
            return dt.strftime("%H:%M")
        return dt.strftime("%d %b %H:%M")
    except Exception:
        return ""


def _msg_day(iso_ts: str | None = None):
    """Local calendar date of a message (stored UTC ISO ts, or None = now).
    Returns None on parse failure so callers can skip the separator."""
    try:
        if iso_ts:
            dt = datetime.fromisoformat(iso_ts)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return dt.astimezone().date()
        return datetime.now().astimezone().date()
    except Exception:
        return None


def _day_label(day) -> str:
    """Human label for a date separator chip: Today / Yesterday / '12 Jun 2026'."""
    today = datetime.now().astimezone().date()
    delta = (today - day).days
    if delta == 0:
        return "Today"
    if delta == 1:
        return "Yesterday"
    return day.strftime("%d %b %Y")


# ---------------------------------------------------------------------------
# Startup helpers
# ---------------------------------------------------------------------------

def _cleanup_stale_recv_files() -> None:
    """Remove any helucryptic-recv-*.part files left by a previous crash or
    interrupted file transfer, so they don't accumulate in the OS temp dir."""
    import tempfile
    tmp = Path(tempfile.gettempdir())
    for stale in tmp.glob("helucryptic-recv-*.part"):
        try:
            stale.unlink()
        except OSError:
            pass


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
        self._room_psk:        str | None     = None  # invite-only room pre-shared key
        self._ephemeral:       bool           = False  # auto-destruct room: nothing to disk
        self._invite_creator_pub: str | None  = None   # creator's ed25519 pub from an invite
        self._room_peers:      dict[str, str] = {}   # username → connection state
        self._video_tiles:     dict[str, ft.Image] = {}
        self._tile_row:        ft.Row | None   = None
        self._pending_invites: set[str]        = set()
        self._muted:           bool            = False
        self._in_voice_call:   bool            = False
        self._in_screen_share: bool            = False
        self._fullscreen_sender: str           = ""   # which incoming stream is maximized
        self._room_call_active: bool           = False
        self._ringing:         bool            = False
        self._ring_timeout_task = None
        self._diag_open:       bool            = False
        # Contacts the user allowed for THIS session despite Verified-Only mode.
        self._session_allowed: set[str]        = set()
        # Shared access token sent to the signaling server (validated server-side).
        self._server_password: str             = HELUCRYPTIC_SERVER_PASSWORD
        # Session token issued by the server on connect; resent on reconnect to
        # prove we own this username slot (prevents third-party eviction).
        self._ws_session_token: str            = ""
        # Server-reflected NAT coordinates (from session_token handshake).
        self._reflected_host: str              = ""
        self._reflected_port: int              = 0
        # Prevents overlapping auto-reconnect attempts after an unexpected drop.
        self._ws_reconnect_active: bool        = False
        # Incoming-video render throttle (per sender) + encode quality. Lower in
        # low-perf mode so old PCs aren't swamped by JPEG re-encode + repaint.
        self._last_tile_render: dict[str, float] = {}
        self._update_perf_parameters()

        # --- neon-UI animation bookkeeping -----------------------------------
        # Suppress per-bubble entrance animation while bulk-loading history so
        # 100 messages don't each schedule a reveal coroutine.
        self._bulk_load:          bool            = False
        # Cheap continuous motion (gradient drift + status pulse) is disabled on
        # the low-end performance profile.
        self._motion_ok:          bool            = self.settings.performance_profile != "old_pc"
        self._bg_layers:          list            = []
        # Cancellable animation task handles - prevents stacked coroutines on
        # rapid successive triggers (e.g. fast status changes, rapid sends).
        self._status_label_task:  asyncio.Task | None = None
        self._flash_task:         asyncio.Task | None = None
        # Real presence: usernames the signaling server confirmed are online
        # (server-backed, refreshed by _presence_loop). A contact is "online" if
        # it's in here OR we already hold a live P2P link to it.
        self._online_users:    set[str]        = set()
        # --- Delivery / health / typing UI state ------------------------------
        # msg_id → the little status Icon in a sent bubble (⏳ queued → ✓ sent
        # → ✓✓ delivered); cleared whenever the transcript is rebuilt.
        self._msg_status:      dict[str, ft.Icon] = {}
        # Last measured heartbeat round-trip per peer (from engine.on_rtt).
        self._peer_rtt:        dict[str, float] = {}
        # Live WebRTC connection state per 1-to-1 peer (rooms use _room_peers).
        self._peer_conn_state: dict[str, str]  = {}
        # Typing indicator: who's composing + the revert task, and an outbound
        # throttle so we don't spam a __typing frame on every keystroke.
        self._typing_task:     asyncio.Task | None = None
        self._typing_sent_at:  float           = 0.0
        # Consecutive-sender bubble grouping (reset on transcript rebuild).
        self._last_bubble_sender: str | None   = None
        # Date-separator bookkeeping: calendar day of the last bubble shown,
        # and the "say hello" hint control shown in an empty conversation.
        self._last_msg_date                    = None
        self._chat_empty_hint: ft.Control | None = None

        self._pf_manager = None  # PortForwardManager when port-forwarding is on
        # Background loops are tracked so a profile switch can stop this session's
        # loops cleanly before the next profile's app takes over.
        self._bg_tasks: list = []
        self._running_tasks: set[asyncio.Task] = set()

        init_db()
        _cleanup_stale_recv_files()
        run_retention_policy(self.settings.retention_days)
        self._build_ui()
        self._wire_engine_callbacks()
        self._bg_tasks.append(asyncio.ensure_future(self._retention_background_loop()))
        self._bg_tasks.append(asyncio.ensure_future(self._presence_loop()))
        self._bg_tasks.append(asyncio.ensure_future(self._insights_loop()))
        if self._motion_ok:
            self._bg_tasks.append(asyncio.ensure_future(self._status_pulse_loop()))
        self._apply_port_forward()

    def _fire_and_forget(self, coro) -> asyncio.Task | None:
        try:
            try:
                loop = asyncio.get_running_loop()
            except RuntimeError:
                loop = asyncio.get_event_loop()
            # get_event_loop may return a closed loop in tests – guard it
            if loop.is_closed():
                try:
                    coro.close()
                except Exception:
                    pass
                return None
            task = loop.create_task(coro)
        except Exception:
            try:
                coro.close()
            except Exception:
                pass
            return None
        self._running_tasks.add(task)
        task.add_done_callback(self._task_done)
        return task

    def _task_done(self, task: asyncio.Task) -> None:
        """Reap a background task and SURFACE its failure instead of letting it
        bubble to the loop exception handler (which restarts the whole app).
        A background hiccup becomes a visible toast + console traceback; the
        process-level restart stays reserved for truly unhandled crashes."""
        self._running_tasks.discard(task)
        if task.cancelled():
            return
        ex = task.exception()   # also marks the exception as retrieved
        if ex is None:
            return
        import traceback
        print(f"[task] background task failed: {type(ex).__name__}: {ex}", flush=True)
        traceback.print_exception(type(ex), ex, ex.__traceback__)
        try:
            self._toast(f"Something went wrong: {type(ex).__name__}: {ex}", "error")
        except Exception:
            pass

    def _apply_port_forward(self) -> None:
        """(Re)start or stop the forwarded-port manager from current settings."""
        if self._pf_manager is not None:
            self._fire_and_forget(self._pf_manager.stop())
            self._pf_manager = None
        clear_forwarded_port()
        if self.settings.port_forward_enabled:
            self._fire_and_forget(self._start_port_forward())

    async def _start_port_forward(self) -> None:
        primary_gw = await asyncio.to_thread(discover_gateway)
        # Build an ordered candidate list (.1 first, then .254 and .2 for
        # non-standard subnets, then PROTON_GATEWAY as a final fallback).
        candidates = discover_gateway_candidates(primary_gw)
        gw = candidates[0]
        ip = await asyncio.to_thread(local_ip_for, gw)

        async def request_fn(gateway: str):
            # Optimized: try UPnP first (most home routers) - stdlib SSDP, no dep
            try:
                import upnp as _upnp
                upnp_res = await asyncio.to_thread(_upnp.try_upnp_mapping, 0, 0)
                if upnp_res:
                    _, p = upnp_res
                    return p
            except Exception:
                pass
            # Try each NAT-PMP candidate in order; stop at the first successful mapping.
            for candidate in candidates:
                port = await asyncio.to_thread(request_mapping_over_socket, candidate)
                if port is not None:
                    return port
            # No NAT-PMP response from any gateway - fall back to the manually
            # configured port (e.g. a static router forward without NAT-PMP).
            return self.settings.forwarded_port or None

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
        # Caveat #2: our reachability tier may have changed - re-announce + re-elect.
        if self._room_id and self.ws:
            self._fire_and_forget(self._on_topology_changed())

    def _update_perf_parameters(self) -> None:
        # Drive the incoming-video render throttle + JPEG quality from the active
        # performance profile (settings). Call after settings change to apply.
        self._tile_render_interval = 1.0 / max(1, getattr(self.settings, "tile_render_fps", 10))
        self._jpeg_quality = int(getattr(self.settings, "jpeg_quality", 55))

    # ------------------------------------------------------------------
    # Motion helpers
    # ------------------------------------------------------------------

    def _reveal(self, ctrl, delay: float = 0) -> None:
        """Animate a freshly-mounted control from (faded, slightly small) to
        its resting state. sleep(0) yields once so the control is rendered
        before the transition fires. The reveal always completes even if the
        sleep is interrupted - content is never left invisible."""
        async def run():
            try:
                await asyncio.sleep(delay)
            except Exception:
                pass
            try:
                ctrl.opacity = 1
                ctrl.scale = 1
                ctrl.update()
            except Exception:
                pass
        self._fire_and_forget(run())

    def _build_background(self) -> ft.Control:
        """Static backdrop (rebrand): a single, calm vertical gradient from the
        backdrop colour to the panel surface - no animation, no neon blooms, and
        no perf-gated fork. Everyone gets the same consistent surface."""
        self._bg_layers = []   # disables the (now no-op) drift loop
        return ft.Container(
            expand=True,
            gradient=ft.LinearGradient(
                begin=ft.Alignment.TOP_CENTER, end=ft.Alignment.BOTTOM_CENTER,
                colors=[C.BG, C.PANEL],
            ),
        )

    def _update_status_dot_pulse(self, on: bool) -> None:
        col = self.status_dot.bgcolor or C.FAINT
        if col == C.FAINT:
            self.status_dot.scale = 1.0
            self.status_dot.shadow = ft.BoxShadow(blur_radius=6, spread_radius=-2, color="#00000066")
        else:
            self.status_dot.scale = 1.25 if on else 1.0
            self.status_dot.shadow = ft.BoxShadow(
                blur_radius=16 if on else 6,
                spread_radius=1 if on else -1,
                color=col + "aa" if on else col + "44"
            )
        self.status_dot.update()

    async def _status_pulse_loop(self) -> None:
        """Gently breathe the status dot's scale and colored glow to create a pulsating effect."""
        on = True
        while True:
            try:
                await asyncio.sleep(0.8)
                self._update_status_dot_pulse(on)
                on = not on
            except Exception:
                break

    @staticmethod
    def _attach_hover(container: ft.Container, base: str, hover: str,
                      lift: bool = False) -> None:
        def on_hover(e):
            container.bgcolor = hover if e.data == "true" else base
            if lift:
                container.scale = 1.015 if e.data == "true" else 1.0
            try:
                container.update()
            except Exception:
                pass
        container.on_hover = on_hover

    # ------------------------------------------------------------------
    # Delight / feedback animations
    # ------------------------------------------------------------------

    async def _status_connect_bloom(self) -> None:
        """One-shot neon burst on the status pill when connection is established."""
        try:
            self.status_pill.border = ft.Border.all(1, C.GREEN + "99")
            self.status_pill.shadow = _glow(C.GREEN + "33", blur=18, spread=-2)
            self.status_dot.shadow  = _glow(C.GREEN, blur=36, spread=7)
            self.status_pill.update()
            self.status_dot.update()
            await asyncio.sleep(0.32)
            self.status_pill.border = ft.Border.all(1, C.BORDER)
            self.status_pill.shadow = None
            self.status_dot.shadow  = _glow(C.GREEN, blur=16, spread=2)
            self.status_pill.update()
            self.status_dot.update()
        except Exception:
            pass

    async def _crossfade_status_label(self, label: str, color: str) -> None:
        """Fade out the status label, swap text + color, fade back in."""
        try:
            self.status_label.opacity = 0
            self.status_label.update()
            await asyncio.sleep(D.FAST / 1000)
            self.status_label.value   = label
            self.status_label.color   = color
            self.status_label.opacity = 1
            self.status_label.update()
        except Exception:
            pass

    async def _send_flash(self) -> None:
        """Brief cyan border pulse on the composer after a message is sent."""
        try:
            self._composer.border = ft.Border.all(1, C.CYAN)
            self._composer.shadow = _glow(C.CYAN + "44", blur=16, spread=-2)
            self._composer.update()
            await asyncio.sleep(0.22)
            self._composer.border = ft.Border.all(1, C.BORDER2)
            self._composer.shadow = None
            self._composer.update()
        except Exception:
            pass

    def _on_input_focus(self, e) -> None:
        if not self._motion_ok:
            return
        try:
            self._composer.shadow = _glow(C.CYAN + "2a", blur=18, spread=-3)
            self._composer.border = ft.Border.all(1, C.CYAN + "55")
            self._composer.update()
        except Exception:
            pass

    def _on_input_blur(self, e) -> None:
        try:
            self._composer.shadow = None
            self._composer.border = ft.Border.all(1, C.BORDER2)
            self._composer.update()
        except Exception:
            pass

    async def _hide_mute_banner_delayed(self) -> None:
        """Hide the mute banner after its fade-out animation completes."""
        await asyncio.sleep(D.MED / 1000 + 0.05)
        try:
            self.mute_banner.visible = False
            self.mute_banner.update()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        # --- Sidebar controls (same control objects/types as the original) ---
        self.contact_list     = ft.Column(scroll=ft.ScrollMode.AUTO, expand=True, spacing=4)
        # Filter-as-you-type over the contact list (nickname or username).
        self.contact_search   = _neon_field(
            hint_text="Search contacts…", dense=True, text_size=12,
            prefix_icon=ft.Icons.SEARCH, border_radius=R.PILL,
            content_padding=ft.Padding.symmetric(horizontal=10, vertical=6),
            on_change=lambda e: self._refresh_contact_list(),
        )
        self.btn_add_contact  = ft.TextButton("+  Add contact", on_click=self._show_add_contact,
                                              style=_ghost_style())
        self.btn_import_id    = ft.TextButton("Import from code", on_click=self._show_import_identity,
                                              style=_ghost_style())
        self.username_input   = _neon_field(label="Your username", width=210)
        self.btn_connect      = ft.FilledButton("Connect", icon=ft.Icons.BOLT,
                                                on_click=self._connect_signaling, width=210,
                                                style=_filled_style(C.CYAN))
        self.status_dot       = ft.Container(width=11, height=11, border_radius=R.PILL,
                                             bgcolor=C.FAINT, animate=_anim(D.MED),
                                             scale=1.0, animate_scale=ft.Animation(800, ft.AnimationCurve.EASE_IN_OUT),
                                             shadow=_glow(C.FAINT, blur=6, spread=0))
        self.status_label     = ft.Text("IDLE", size=11, color=C.MUTED,
                                        weight=ft.FontWeight.W_700,
                                        animate_opacity=_anim(D.FAST))

        # Room controls - flex to share the card width instead of fixed widths
        # (fixed 100+100 overflowed the room box).
        self.btn_create_room  = ft.FilledButton(
            "Create", icon=ft.Icons.ADD,
            on_click=self._create_room, expand=True, height=40,
            style=_filled_style(C.VIOLET, C.BTN_CYAN, radius=R.MD, pad_h=0, pad_v=10),
        )
        self.btn_join_room    = ft.FilledButton(
            "Join", icon=ft.Icons.LOGIN,
            on_click=self._show_join_room, expand=True, height=40,
            style=_filled_style(C.ELEV2, C.TEXT, radius=R.MD, pad_h=0, pad_v=10),
        )

        async def _copy_room_code(e):
            if self._room_id:
                # Flet 0.85: clipboard is a service accessed via ft.Clipboard()
                await self._set_clipboard(self._room_id)
                self._log(f"Room code {self._room_id} copied.")

        self.room_code_label  = ft.Text("", size=12, color=C.CYAN, selectable=False,
                                        weight=ft.FontWeight.W_600)
        self.hub_banner       = ft.Text("", size=11, color=C.YELLOW, visible=False)
        self.btn_copy_room    = ft.IconButton(
            ft.Icons.COPY_ALL, on_click=_copy_room_code,
            tooltip="Copy room code", visible=False, icon_size=16, icon_color=C.SUBTLE,
        )
        self.btn_invite       = ft.IconButton(
            ft.Icons.PERSON_ADD, on_click=lambda e: self._show_invite_contacts(),
            tooltip="Invite contacts", visible=False, icon_color=C.CYAN,
        )
        self.btn_invite_link  = ft.IconButton(
            ft.Icons.LINK, on_click=self._show_copy_invite,
            tooltip="Copy invite link", visible=False, icon_color=C.VIOLET,
        )
        self.btn_join_invite  = ft.TextButton(
            "Join via invite link", icon=ft.Icons.LINK,
            on_click=self._show_join_invite, style=_ghost_style(),
        )
        self.participant_list = ft.Column(spacing=4)

        brand = ft.Container(
            on_click=lambda e: self._go_home(),
            tooltip="Home",
            border_radius=R.MD, padding=ft.Padding.symmetric(horizontal=4, vertical=2),
            content=ft.Row(
                [
                    ft.Container(
                        content=ft.Icon(ft.Icons.SHIELD_MOON, color=C.CYAN, size=22),
                        padding=ft.Padding.all(8), border_radius=R.MD, bgcolor=C.ELEV,
                        border=ft.Border.all(1, C.BORDER2), shadow=_glow(blur=14),
                    ),
                    ft.Column([
                        ft.Text("helucryptic", size=18, weight=ft.FontWeight.W_800, color=C.WHITE),
                        ft.Text("encrypted p2p", size=10, color=C.CYAN,
                                weight=ft.FontWeight.W_600),
                    ], spacing=0, tight=True),
                ],
                spacing=10, vertical_alignment=ft.CrossAxisAlignment.CENTER,
            ),
        )

        self.status_pill = ft.Container(
            content=ft.Row([self.status_dot, self.status_label], spacing=8, tight=True),
            padding=ft.Padding.symmetric(horizontal=12, vertical=7),
            border_radius=R.PILL, bgcolor=C.ELEV, border=ft.Border.all(1, C.BORDER),
            animate=_anim(D.MED),
        )

        room_card = self._section_card(
            "ROOM", ft.Icons.GROUPS,
            [
                ft.Row([self.btn_create_room, self.btn_join_room], spacing=8),
                self.btn_join_invite,
                ft.Row([
                    ft.Container(
                        content=self.room_code_label,
                        on_click=lambda e: self._select_room(),
                        tooltip="Go to room",
                        border_radius=R.SM,
                        padding=ft.Padding.symmetric(horizontal=4, vertical=2),
                    ),
                    self.btn_copy_room, self.btn_invite,
                    self.btn_invite_link],
                       spacing=4, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                self.hub_banner,
                self.participant_list,
            ],
        )

        contacts_header = ft.Row(
            [
                ft.Text("CONTACTS", size=11, weight=ft.FontWeight.W_800, color=C.MUTED),
                ft.Container(expand=True),
            ],
            vertical_alignment=ft.CrossAxisAlignment.CENTER,
        )

        # Sidebar is now pure NAVIGATION (rooms + contacts). Identity/connection
        # setup lives in the top presence bar instead (see presence_bar below).
        # Collapsible via the menu button / Ctrl+B.
        self._sidebar = ft.Container(
            width=256, bgcolor=C.PANEL,
            padding=ft.Padding.all(16),
            border=ft.Border.only(right=ft.BorderSide(1, C.BORDER)),
            content=ft.Column([
                room_card,
                ft.Container(height=4),
                contacts_header,
                self.contact_search,
                self.contact_list,
                ft.Row([self.btn_add_contact], spacing=0),
                ft.Row([self.btn_import_id], spacing=0),
            ], spacing=12, expand=True),
        )
        sidebar = self._sidebar
        self._sidebar_collapsed = False
        self.btn_sidebar_toggle = ft.IconButton(
            ft.Icons.MENU_OPEN, on_click=lambda e: self._toggle_sidebar(),
            tooltip="Toggle sidebar (Ctrl+B)", icon_color=C.SUBTLE,
        )

        # Top presence bar: brand on the left; identity + Connect + live status
        # on the right. Connection setup is transient context, not permanent
        # sidebar furniture.
        presence_bar = ft.Container(
            bgcolor=C.PANEL,
            padding=ft.Padding.only(left=16, right=16, top=10, bottom=10),
            border=ft.Border.only(bottom=ft.BorderSide(1, C.BORDER)),
            content=ft.Row([
                self.btn_sidebar_toggle,
                brand,
                ft.Container(expand=True),
                self.username_input,
                self.btn_connect,
                self.status_pill,
            ], vertical_alignment=ft.CrossAxisAlignment.CENTER, spacing=12),
        )

        # --- Chat panel ---
        self._tile_row    = ft.Row(spacing=10, wrap=True, visible=False)
        self.chat_log     = ft.ListView(expand=True, spacing=10, auto_scroll=True,
                                        padding=ft.Padding.symmetric(horizontal=4, vertical=6))
        self.msg_input    = _neon_field(
            hint_text="Type an encrypted message…", expand=True,
            on_submit=self._send_chat, disabled=True, border_radius=R.PILL,
            content_padding=ft.Padding.symmetric(horizontal=18, vertical=12),
            on_focus=self._on_input_focus, on_blur=self._on_input_blur,
            on_change=self._on_input_change,
        )
        self.file_progress = ft.ProgressBar(value=0, visible=False, color=C.CYAN,
                                            bgcolor=C.ELEV, border_radius=R.PILL, height=4)

        self.btn_send     = ft.IconButton(ft.Icons.SEND_ROUNDED, on_click=self._send_chat,
                                          icon_color=C.BTN_CYAN, tooltip="Send",
                                          icon_size=18, disabled=True)
        # Accent send button: a quiet filled circle that dims while sending is
        # disabled (toggled alongside btn_send.disabled). Deliberately restrained
        # - one solid accent, soft shadow, no gradient.
        self._send_wrap = ft.Container(
            content=self.btn_send, width=42, height=42, border_radius=R.PILL,
            bgcolor=C.CYAN,
            shadow=_glow(_alpha("44", C.CYAN), blur=10, spread=0),
            alignment=ft.Alignment.CENTER,
            opacity=0.45, animate_opacity=_anim(D.MED),
        )
        self.btn_call     = ft.IconButton(ft.Icons.CALL,         on_click=self._start_call,   disabled=True, icon_color=C.SUBTLE,  tooltip="Voice call")
        self.btn_screen   = ft.IconButton(ft.Icons.SCREEN_SHARE, on_click=self._toggle_screen, disabled=True, icon_color=C.SUBTLE,  tooltip=SHARE_SCREEN_TXT)
        self.btn_file     = ft.IconButton(ft.Icons.ATTACH_FILE,  on_click=self._send_file,    disabled=True, icon_color=C.SUBTLE,  tooltip="Send file")
        self.btn_mute     = ft.IconButton(ft.Icons.MIC,          on_click=self._toggle_mute,  disabled=True, icon_color=C.SUBTLE,  tooltip="Mute mic")
        self.btn_volume   = ft.IconButton(ft.Icons.VOLUME_UP,    on_click=self._show_volume,  icon_color=C.SUBTLE,  tooltip="Call volume")
        self.btn_hangup   = ft.IconButton(ft.Icons.CALL_END,     on_click=self._hangup,       disabled=True, icon_color=C.RED,     tooltip="Hang up")
        self.btn_join_call = ft.FilledButton(
            "Join call", icon=ft.Icons.CALL, on_click=self._start_call,
            visible=False, style=_filled_style(C.GREEN, C.BTN_GREEN),
        )
        self.btn_diag     = ft.IconButton(ft.Icons.INSIGHTS,  on_click=self._show_diagnostics, tooltip=DIAGNOSTICS_TXT, icon_color=C.SUBTLE)
        self.btn_settings = ft.IconButton(ft.Icons.SETTINGS,  on_click=self._show_settings,    tooltip="Settings",               icon_color=C.SUBTLE)

        # Persistent banner shown while the mic is muted during a call
        self.mute_banner = ft.Container(
            visible=False,
            opacity=0,
            animate_opacity=_anim(D.MED),
            bgcolor=C.RED + "1f",
            border=ft.Border.all(1, C.RED),
            border_radius=R.MD,
            padding=ft.Padding.symmetric(horizontal=12, vertical=6),
            content=ft.Row(
                [ft.Icon(ft.Icons.MIC_OFF, color=C.RED, size=16),
                 ft.Text("Microphone muted", color=C.RED, size=12, weight=ft.FontWeight.BOLD)],
                spacing=8, tight=True,
            ),
        )

        # Chat header bar - shows the selected conversation as live context
        # (avatar + name + presence), like the part you liked in client_gem.
        self.chat_header_avatar = ft.Container(
            width=38, height=38, border_radius=R.PILL, visible=False,
            alignment=ft.Alignment.CENTER, content=ft.Text(""),
            gradient=self._avatar_gradient(False),
            shadow=_glow(C.CYAN + "44", blur=14, spread=-2),
        )
        self.chat_header_lead = ft.Icon(ft.Icons.FORUM_OUTLINED, color=C.CYAN, size=18)
        self.chat_header_title = ft.Text("Select a conversation", size=15,
                                         weight=ft.FontWeight.W_700, color=C.TEXT)
        self.chat_header_status_dot = ft.Container(width=8, height=8, border_radius=R.PILL,
                                                   bgcolor=C.FAINT, visible=False)
        self.chat_header_status_text = ft.Text("", size=11, color=C.MUTED, visible=False)
        chat_header = ft.Container(
            padding=ft.Padding.only(left=18, right=10, top=10, bottom=10),
            border=ft.Border.only(bottom=ft.BorderSide(1, C.BORDER)),
            content=ft.Row([
                self.chat_header_lead,
                self.chat_header_avatar,
                ft.Column([
                    self.chat_header_title,
                    ft.Row([self.chat_header_status_dot, self.chat_header_status_text],
                           spacing=6, tight=True),
                ], spacing=1, tight=True),
                ft.Container(expand=True),
                # Persistent call-status pill - always visible while a call or
                # screen share is active, so you know a session is ongoing.
                self._make_call_status_pill(),
                self.btn_diag,
                self.btn_settings,
            ], vertical_alignment=ft.CrossAxisAlignment.CENTER, spacing=10),
        )

        # Composer card (lock hint + input + gradient send orb)
        self._composer = ft.Container(
            padding=ft.Padding.symmetric(horizontal=8, vertical=8),
            border_radius=R.XL, bgcolor=C.ELEV, border=ft.Border.all(1, C.BORDER2),
            animate=_anim(D.MED),
            content=ft.Row([
                ft.Container(content=ft.Icon(ft.Icons.LOCK, color=C.FAINT, size=14),
                             padding=ft.Padding.only(left=8),
                             tooltip="Messages are end-to-end encrypted"),
                self.msg_input, self._send_wrap,
            ], vertical_alignment=ft.CrossAxisAlignment.CENTER, spacing=6),
        )

        toolbar = ft.Container(
            padding=ft.Padding.only(top=4),
            content=ft.Row([
                self._tool_wrap(self.btn_call),
                self._tool_wrap(self.btn_screen),
                self._tool_wrap(self.btn_file),
                self._tool_wrap(self.btn_mute),
                self._tool_wrap(self.btn_volume),
                self._tool_wrap(self.btn_hangup),
                self.btn_join_call,
                ft.Container(expand=True),
            ], spacing=8),
        )

        # Prominent incoming-call banner - overlays the top of the chat area so
        # a call is visible no matter which conversation is open. Filled in by
        # _show_call_banner().
        self.call_banner = ft.Container(
            visible=False,
            padding=ft.Padding.symmetric(horizontal=16, vertical=12),
            border_radius=R.LG, bgcolor=C.ELEV,
            border=ft.Border.all(1, C.GREEN),
            shadow=_glow(C.GREEN + "66", blur=24, spread=-2),
            opacity=0, scale=0.98,
            animate_opacity=_anim(D.MED), animate_scale=_anim(D.MED),
            content=ft.Row([]),
        )

        # Conversation surface (chat + composer + call tools). Hidden on the
        # home view; shown once a contact or room is open.
        self._conversation_col = ft.Column([
            self.call_banner,
            self._tile_row,
            self.mute_banner,
            self.chat_log,
            self.file_progress,
            self._composer,
            toolbar,
        ], spacing=12, expand=True, visible=False)

        # Home / landing view shown when nothing is open (first launch, or after
        # clicking the logo to go home).
        self.home_view = self._build_home_view()

        # A visibility-toggled Column (NOT a Stack): the visible expand child
        # fills the height so the composer + controls anchor to the bottom with
        # no dead space below them.
        chat_body = ft.Container(
            expand=True,
            padding=ft.Padding.symmetric(horizontal=16, vertical=12),
            content=ft.Column([self.home_view, self._conversation_col],
                              spacing=0, expand=True),
        )

        chat_panel = ft.Container(
            expand=True, bgcolor=C.BG + "00",
            content=ft.Column([chat_header, chat_body], spacing=0, expand=True),
        )

        # App frame floating over the static backdrop: presence bar across the
        # top, then the nav sidebar + chat panel below it.
        # Responsive: margin fluid (8 on narrow, 16 on wide) via _apply_responsive.
        self._app_frame = ft.Container(
            expand=True,
            margin=ft.Margin.all(10),
            border_radius=R.LG,
            bgcolor=C.PANEL + "ee",
            border=ft.Border.all(1, C.BORDER2),
            shadow=ft.BoxShadow(blur_radius=40, spread_radius=-6, color=C.BLACK_AA),
            clip_behavior=ft.ClipBehavior.ANTI_ALIAS,
            content=ft.Column([
                presence_bar,
                ft.Row([sidebar, chat_panel, self._build_insights_panel()],
                       expand=True, spacing=0),
            ], spacing=0, expand=True),
            opacity=0, scale=0.985,
            animate_opacity=_anim(280, _EASE_IO),
            animate_scale=_anim(280, _EASE_IO),
        )
        app_frame = self._app_frame

        # Full-screen screen-share viewer - overlays everything when a tile is
        # maximized; a switcher row flips between multiple shared streams.
        self._fs_img = ft.Image(src="", fit=ft.BoxFit.CONTAIN, expand=True,
                                gapless_playback=True)
        self._fs_title = ft.Text("", size=14, weight=ft.FontWeight.W_700, color=C.WHITE)
        self._fs_switcher = ft.Row([], spacing=8)
        self.screen_overlay = ft.Container(
            visible=False, expand=True, bgcolor="#000000f2",
            padding=ft.Padding.all(12),
            content=ft.Column([
                ft.Row([
                    ft.Icon(ft.Icons.SCREEN_SHARE, color=C.MAGENTA, size=18),
                    self._fs_title,
                    ft.Container(expand=True),
                    self._fs_switcher,
                    ft.IconButton(ft.Icons.PICTURE_IN_PICTURE, icon_color=C.WHITE,
                                  tooltip="Pop out stream",
                                  on_click=lambda e: self._minimize_to_pip()),
                    ft.IconButton(ft.Icons.CLOSE_FULLSCREEN, icon_color=C.WHITE,
                                  tooltip="Exit full screen",
                                  on_click=lambda e: self._close_fullscreen()),
                ], vertical_alignment=ft.CrossAxisAlignment.CENTER, spacing=10),
                ft.Container(content=self._fs_img, expand=True,
                             alignment=ft.Alignment.CENTER),
            ], spacing=8, expand=True),
        )

        # Picture-in-picture floating overlay
        self._pip_img = ft.Image(src="", fit=ft.BoxFit.CONTAIN, expand=True, gapless_playback=True)
        self._pip_title = ft.Text("", size=11, weight=ft.FontWeight.W_700, color=C.WHITE)

        def on_pip_pan(e: ft.DragUpdateEvent):
            self.pip_overlay.left = max(0, min((self.page.window.width or 1180) - 340, (self.pip_overlay.left or 0) + e.delta_x))
            self.pip_overlay.top = max(0, min((self.page.window.height or 760) - 260, (self.pip_overlay.top or 0) + e.delta_y))
            self.pip_overlay.update()

        self.pip_overlay = ft.GestureDetector(
            visible=False,
            mouse_cursor=ft.MouseCursor.MOVE,
            on_pan_update=on_pip_pan,
            left=600,
            top=300,
            content=ft.Container(
                width=320, height=220,
                bgcolor="#000000eb",
                border=ft.Border.all(1, C.BORDER2),
                border_radius=R.MD,
                padding=ft.Padding.symmetric(horizontal=8, vertical=6),
                shadow=_glow(C.CYAN + "22", blur=20, spread=-2),
                content=ft.Column([
                    ft.Row([
                        ft.Icon(ft.Icons.SCREEN_SHARE, color=C.MAGENTA, size=14),
                        self._pip_title,
                        ft.Container(expand=True),
                        ft.IconButton(ft.Icons.ASPECT_RATIO, icon_color=C.WHITE, icon_size=14,
                                      tooltip="Expand to full screen",
                                      on_click=lambda e: self._expand_from_pip()),
                        ft.IconButton(ft.Icons.CLOSE, icon_color=C.WHITE, icon_size=14,
                                      tooltip="Close",
                                      on_click=lambda e: self._close_fullscreen()),
                    ], vertical_alignment=ft.CrossAxisAlignment.CENTER, spacing=6),
                    ft.Container(content=self._pip_img, expand=True, alignment=ft.Alignment.CENTER),
                ], spacing=4, expand=True)
            )
        )

        self._build_command_palette()

        root = ft.Stack([self._build_background(), app_frame, self.screen_overlay,
                         self.pip_overlay, self.palette_overlay],
                        expand=True)
        self.page.add(root)
        # Global keyboard shortcuts (Ctrl/Cmd+K command palette, Esc to close).
        self.page.on_keyboard_event = self._on_key
        self.page.on_resized = self._on_resized
        # Apply responsive once on load (handles initial narrow window)
        try:
            self._apply_responsive()
        except Exception:
            pass

        # Entrance reveal only. The rebrand drops ambient motion (drifting
        # background + pulsing status halo) in favour of a calm, static surface.
        self._reveal(app_frame, delay=0.05)
        # Start on the home/landing view (nothing open yet).
        self._update_main_view()

    # ---- command palette (Ctrl/Cmd+K) ---------------------------------

    def _command_registry(self) -> list:
        """The list of palette commands: title, search keywords, and a bound
        action. Actions reuse existing handlers (most accept an unused event)."""
        return [
            {"id": "connect",   "title": "Connect to signaling", "icon": ft.Icons.BOLT,
             "keywords": "online join server", "action": lambda: self._connect_signaling(None)},
            {"id": "create",    "title": "Create room", "icon": ft.Icons.ADD,
             "keywords": "group new", "action": lambda: self._create_room(None)},
            {"id": "join",      "title": JOIN_ROOM_TXT, "icon": ft.Icons.LOGIN,
             "keywords": "group enter", "action": lambda: self._show_join_room(None)},
            {"id": "call",      "title": "Start voice call", "icon": ft.Icons.CALL,
             "keywords": "audio mic talk", "action": lambda: self._start_call(None)},
            {"id": "share",     "title": SHARE_SCREEN_TXT, "icon": ft.Icons.SCREEN_SHARE,
             "keywords": "present screen", "action": lambda: self._toggle_screen(None)},
            {"id": "mute",      "title": "Toggle mute", "icon": ft.Icons.MIC_OFF,
             "keywords": "microphone silence", "action": lambda: self._toggle_mute(None)},
            {"id": "hangup",    "title": "Hang up", "icon": ft.Icons.CALL_END,
             "keywords": "end call stop", "action": lambda: self._hangup(None)},
            {"id": "file",      "title": "Send file", "icon": ft.Icons.ATTACH_FILE,
             "keywords": "attach upload", "action": lambda: self._send_file(None)},
            {"id": "add",       "title": "Add contact", "icon": ft.Icons.PERSON_ADD,
             "keywords": "new friend", "action": lambda: self._show_add_contact(None)},
            {"id": "settings",  "title": "Open settings", "icon": ft.Icons.SETTINGS,
             "keywords": "preferences config", "action": lambda: self._show_settings(None)},
            {"id": "diag",      "title": DIAGNOSTICS_TXT, "icon": ft.Icons.INSIGHTS,
             "keywords": "debug ice turn logs", "action": lambda: self._show_diagnostics(None)},
            {"id": "sidebar",   "title": "Toggle sidebar", "icon": ft.Icons.MENU_OPEN,
             "keywords": "collapse hide nav", "action": lambda: self._toggle_sidebar()},
        ]

    def _build_command_palette(self) -> None:
        self._palette_open = False
        self.palette_search = _neon_field(
            hint_text="Type a command…", autofocus=True, border_radius=R.MD,
            on_change=lambda e: self._refilter_palette(),
            prefix_icon=ft.Icons.SEARCH,
        )
        self.palette_results = ft.Column(spacing=2, scroll=ft.ScrollMode.AUTO, height=320)
        card = ft.Container(
            width=560, bgcolor=C.ELEV2, border_radius=R.LG,
            border=ft.Border.all(1, C.BORDER2),
            shadow=_glow(blur=24),
            padding=ft.Padding.all(10),
            content=ft.Column([self.palette_search, ft.Container(height=4),
                               self.palette_results], spacing=6, tight=True),
        )
        self.palette_overlay = ft.Container(
            visible=False, expand=True, bgcolor="#000000cc",
            alignment=ft.Alignment.TOP_CENTER,
            padding=ft.Padding.only(top=90),
            on_click=lambda e: self._close_palette(),   # click scrim to dismiss
            content=ft.Container(content=card, on_click=lambda e: None),
        )

    def _palette_row(self, cmd: dict) -> ft.Control:
        row = ft.Container(
            padding=ft.Padding.symmetric(horizontal=12, vertical=10),
            border_radius=R.SM, bgcolor=C.ELEV + "00", animate=_anim(D.FAST),
            on_click=lambda e, c=cmd: self._run_command(c),
            content=ft.Row([
                ft.Icon(cmd.get("icon", ft.Icons.CHEVRON_RIGHT), color=C.SUBTLE, size=18),
                ft.Text(cmd["title"], size=13, color=C.TEXT),
            ], spacing=12),
        )
        self._attach_hover(row, C.ELEV + "00", C.ELEV2)
        return row

    def _refilter_palette(self) -> None:
        from commands import filter_commands
        matches = filter_commands(self._command_registry(), self.palette_search.value or "")
        self.palette_results.controls = [self._palette_row(c) for c in matches] or [
            self._empty_state(ft.Icons.SEARCH_OFF, "No matching command")
        ]
        try:
            self.palette_results.update()
        except Exception:
            pass

    def _open_palette(self) -> None:
        self._palette_open = True
        self.palette_search.value = ""
        self._refilter_palette()
        self.palette_overlay.visible = True
        self.palette_overlay.update()
        try:
            self.palette_search.focus()
        except Exception:
            pass

    def _close_palette(self) -> None:
        self._palette_open = False
        self.palette_overlay.visible = False
        self.palette_overlay.update()

    def _run_command(self, cmd: dict) -> None:
        self._close_palette()
        try:
            cmd["action"]()
        except Exception as ex:
            self._toast(f"Couldn't run “{cmd['title']}”: {ex}", "error")

    def _toggle_sidebar(self) -> None:
        """Collapse / expand the navigation sidebar (Ctrl+B)."""
        import time as _t_toggle
        self._last_manual_toggle = _t_toggle.monotonic()
        self._sidebar_collapsed = not getattr(self, "_sidebar_collapsed", False)
        self._sidebar.visible = not self._sidebar_collapsed
        self.btn_sidebar_toggle.icon = (
            ft.Icons.MENU if self._sidebar_collapsed else ft.Icons.MENU_OPEN)
        try:
            self._sidebar.update()
            self.btn_sidebar_toggle.update()
        except Exception:
            pass

    def _apply_responsive(self, e=None) -> None:
        """Fluid layout: collapse sidebar on narrow viewports, adjust frame margin.

        Optimized: debounce at 100ms to avoid full-page repaints at 60Hz during
        window drag. Only mutates when breakpoint crosses, not on every pixel.
        Tracks manual toggles to avoid auto-reopening a user-collapsed sidebar.
        """
        import time as _t_responsive
        now = _t_responsive.monotonic()
        last = getattr(self, "_responsive_last_run", 0.0)
        if now - last < 0.1:
            return
        # Suppress auto logic shortly after a manual Ctrl+B toggle
        last_manual = getattr(self, "_last_manual_toggle", 0.0)
        if now - last_manual < 2.0:
            return
        self._responsive_last_run = now
        try:
            w = getattr(self.page, "window", None)
            width = getattr(w, "width", None) or getattr(self.page, "width", 1200) or 1200
            # Breakpoint: 1080 collapses sidebar (tablet), 768 stacks tighter
            should_collapse = width < 1080
            if should_collapse != getattr(self, "_sidebar_collapsed", False):
                # Only auto-toggle if user hasn't manually toggled recently; simple: respect current but auto-collapse on small
                if width < 1080 and not self._sidebar_collapsed:
                    self._sidebar_collapsed = True
                    self._sidebar.visible = False
                    self.btn_sidebar_toggle.icon = ft.Icons.MENU
                elif width >= 1080 and self._sidebar_collapsed and width > 1150:
                    # Re-open only when comfortably wide, avoids flicker at threshold
                    self._sidebar_collapsed = False
                    self._sidebar.visible = True
                    self.btn_sidebar_toggle.icon = ft.Icons.MENU_OPEN
                try:
                    self._sidebar.update()
                    self.btn_sidebar_toggle.update()
                except Exception:
                    pass
            # Right insights rail steals chat width on tablets - hide it below 1080
            if hasattr(self, "_insights_panel"):
                insights_should_visible = width >= 1080
                if self._insights_panel.visible != insights_should_visible:
                    self._insights_panel.visible = insights_should_visible
                    try:
                        self._insights_panel.update()
                    except Exception:
                        pass
            # Fluid margin: 8 narrow, 10 mid, 16 wide
            margin = 8 if width < 720 else 10 if width < 1400 else 16
            if hasattr(self, "_app_frame"):
                self._app_frame.margin = ft.Margin.all(margin)
                try:
                    self._app_frame.update()
                except Exception:
                    pass
        except Exception:
            pass

    def _on_resized(self, e) -> None:
        self._apply_responsive(e)

    def _on_key(self, e) -> None:
        # Global shortcuts: Ctrl/Cmd+K palette, Esc closes it/dialog, Ctrl+B sidebar,
        # Ctrl+, settings.
        key = (getattr(e, "key", "") or "")
        mod = getattr(e, "ctrl", False) or getattr(e, "meta", False)
        if mod and key.lower() == "k":
            self._close_palette() if getattr(self, "_palette_open", False) else self._open_palette()
        elif key == "Escape":
            if getattr(self, "_palette_open", False):
                self._close_palette()
                return
            # Close any open dialog (show_dialog/pop_dialog pattern) + palette
            try:
                self._close_dialog()
                return
            except Exception:
                pass
        elif mod and key.lower() == "b":
            self._toggle_sidebar()
        elif mod and key == ",":
            self._show_settings(None)

    # ---- home / landing view -------------------------------------------

    def _refresh_home_recent(self) -> None:
        """Populate the home view's quick-resume row: up to 5 contacts as
        one-click chips (online first, matching the sidebar sort)."""
        if not hasattr(self, "_home_recent_row"):
            return
        contacts = sorted(load_contacts(),
                          key=lambda c: (not self._is_contact_online(c.username),
                                         (c.nickname or c.username).lower()))[:5]
        chips = []
        for c in contacts:
            display = c.nickname or c.username
            online  = self._is_contact_online(c.username)
            chip = ft.Container(
                content=ft.Row([
                    self._avatar(display, bool(c.verified), 24),
                    ft.Text(display, size=12, color=C.TEXT, weight=ft.FontWeight.W_600,
                            max_lines=1, overflow=ft.TextOverflow.ELLIPSIS),
                    ft.Container(width=7, height=7, border_radius=R.PILL,
                                 bgcolor=C.GREEN if online else C.FAINT),
                ], spacing=8, tight=True, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                padding=ft.Padding.symmetric(horizontal=12, vertical=7),
                border_radius=R.PILL, bgcolor=C.ELEV, border=ft.Border.all(1, C.BORDER2),
                on_click=lambda e, u=c.username: self._select_contact(u),
                ink=True, animate=_anim(D.FAST), tooltip=f"Open chat with {display}",
            )
            self._attach_hover(chip, C.ELEV, C.ELEV2)
            chips.append(chip)
        self._home_recent_row.controls = chips
        self._home_recent_title.visible = bool(chips)

    def _build_home_view(self) -> ft.Control:
        def action(icon, label, fn, primary=False):
            return ft.FilledButton(
                label, icon=icon, on_click=lambda e: fn(),
                style=_filled_style(C.CYAN if primary else C.ELEV2,
                                    C.BTN_CYAN if primary else C.TEXT),
            )
        # Quick-resume: recent contacts as one-click chips (filled by
        # _refresh_home_recent whenever contacts/presence change).
        self._home_recent_title = ft.Text("JUMP BACK IN", size=10, color=C.MUTED,
                                          weight=ft.FontWeight.W_800,
                                          font_family=_t_FONTS["mono"], visible=False)
        self._home_recent_row = ft.Row([], spacing=8, wrap=True,
                                       alignment=ft.MainAxisAlignment.CENTER)
        self._refresh_home_recent()
        hero = ft.Column(
            [
                ft.Container(
                    content=ft.Icon(ft.Icons.SHIELD_MOON, color=C.CYAN, size=40),
                    padding=ft.Padding.all(18), border_radius=R.LG, bgcolor=C.ELEV,
                    border=ft.Border.all(1, C.BORDER2), shadow=_glow(blur=20),
                ),
                ft.Text("Welcome to helucryptic", size=20,
                        weight=ft.FontWeight.W_700, color=C.TEXT),
                ft.Text("End-to-end encrypted, peer-to-peer chat, calls and files.\n"
                        "Create a room, add a contact, or pick a conversation to begin.",
                        size=13, color=C.SUBTLE, text_align=ft.TextAlign.CENTER),
                ft.Container(height=8),
                ft.Row([
                    action(ft.Icons.ADD, "Create room", lambda: self._create_room(None), primary=True),
                    action(ft.Icons.LOGIN, JOIN_ROOM_TXT, lambda: self._show_join_room(None)),
                    action(ft.Icons.PERSON_ADD, "Add contact", lambda: self._show_add_contact(None)),
                ], alignment=ft.MainAxisAlignment.CENTER, spacing=10, wrap=True),
                ft.Container(height=10),
                self._home_recent_title,
                self._home_recent_row,
                ft.Container(height=6),
                ft.Row([
                    ft.Icon(ft.Icons.KEYBOARD_COMMAND_KEY, color=C.MUTED, size=14),
                    ft.Text("Press Ctrl+K for the command palette",
                            size=11, color=C.MUTED, font_family=_t_FONTS["mono"]),
                ], alignment=ft.MainAxisAlignment.CENTER, spacing=8, tight=True),
            ],
            horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=10, tight=True,
        )
        return ft.Container(visible=True, alignment=ft.Alignment.CENTER, expand=True,
                            content=hero)

    def _update_main_view(self) -> None:
        """Toggle between the home view and the conversation surface based on
        whether a contact or room is currently open."""
        on_home = not self._active_contact and not self._room_id
        self.home_view.visible = on_home
        self._conversation_col.visible = not on_home
        try:
            self.home_view.update()
            self._conversation_col.update()
        except Exception:
            pass

    def _go_home(self) -> None:
        """Return to the landing view (e.g. clicking the logo)."""
        self._active_contact = ""
        self._refresh_home_recent()
        # Reset the chat header to its default, no-conversation state.
        try:
            self.chat_header_title.value = "Select a conversation"
            self.chat_header_lead.visible = True
            self.chat_header_avatar.visible = False
            self.chat_header_status_dot.visible = False
            self.chat_header_status_text.visible = False
        except Exception:
            pass
        self._update_main_view()
        try:
            self.page.update()
        except Exception:
            pass

    # ---- small builders ------------------------------------------------

    def _section_card(self, title: str, icon, children: list) -> ft.Container:
        head = ft.Row(
            [ft.Icon(icon, color=C.MUTED, size=14),
             ft.Text(title, size=11, weight=ft.FontWeight.W_800, color=C.MUTED)],
            spacing=8,
        )
        return ft.Container(
            padding=ft.Padding.all(12), border_radius=R.MD,
            bgcolor=C.ELEV + "80", border=ft.Border.all(1, C.BORDER),
            content=ft.Column([head, *children], spacing=10, tight=True),
        )

    # ---- live insights rail (right side) --------------------------------

    def _insight_card(self, children: list) -> ft.Container:
        return ft.Container(
            padding=ft.Padding.all(14), border_radius=R.LG, bgcolor=C.ELEV,
            border=ft.Border.all(1, C.BORDER), shadow=_glow(blur=16),
            content=ft.Column(children, spacing=10, tight=True),
        )

    def _build_insights_panel(self) -> ft.Container:
        """Right-hand rail: live link latency (real heartbeat RTT rendered as
        an animated bar sparkline) + this session's crypto at a glance.
        Deliberately restrained: solid accents, no gradients, no glow bloom."""
        mono = _t_FONTS["mono"]
        self._spark_bars = [
            ft.Container(width=5, height=6, border_radius=3, bgcolor=C.CYAN,
                         animate=_anim(D.MED, _EASE_IO))
            for _ in range(20)
        ]
        self.insight_rtt  = ft.Text("- ms", size=20, color=C.TEXT,
                                    weight=ft.FontWeight.W_800, font_family=mono)
        self.insight_live = ft.Text("idle", size=10, color=C.MUTED, font_family=mono)
        latency = self._insight_card([
            ft.Row([
                ft.Icon(ft.Icons.NETWORK_CHECK, color=C.CYAN, size=15),
                ft.Text("LINK LATENCY", size=10, color=C.MUTED, font_family=mono,
                        weight=ft.FontWeight.W_800),
                ft.Container(expand=True),
                self.insight_live,
            ], spacing=8),
            ft.Row([
                self.insight_rtt,
                ft.Container(expand=True),
                ft.Container(
                    content=ft.Row(self._spark_bars, spacing=3, tight=True,
                                   vertical_alignment=ft.CrossAxisAlignment.END),
                    height=34, alignment=ft.Alignment.BOTTOM_RIGHT),
            ], vertical_alignment=ft.CrossAxisAlignment.END),
        ])

        def crow(icon, label, value, color):
            return ft.Row([
                ft.Icon(icon, color=color, size=14),
                ft.Text(label, size=11, color=C.SUBTLE),
                ft.Container(expand=True),
                ft.Text(value, size=11, color=color, font_family=mono,
                        weight=ft.FontWeight.W_700),
            ], spacing=8)
        e2ee = self.settings.security_mode == "e2ee"
        crypto_rows = [
            ft.Row([
                ft.Icon(ft.Icons.LOCK_OUTLINE, color=C.CYAN, size=15),
                ft.Text("SESSION CRYPTO", size=10, color=C.MUTED, font_family=mono,
                        weight=ft.FontWeight.W_800),
            ], spacing=8),
        ]
        if e2ee:
            crypto_rows += [
                crow(ft.Icons.SWAP_HORIZ, "Key exchange", "X25519", C.CYAN),
                crow(ft.Icons.DRAW, "Signatures", "Ed25519", C.CYAN),
                crow(ft.Icons.TOKEN, "Transport", "PASETO v4", C.SUBTLE),
                crow(ft.Icons.STORAGE, "Local history", "ENCRYPTED", C.GREEN),
            ]
        else:
            crypto_rows += [
                crow(ft.Icons.SWAP_HORIZ, "Transport", "DTLS", C.CYAN),
                crow(ft.Icons.INFO_OUTLINE, "E2EE signing", "OFF", C.YELLOW),
            ]
        crypto = self._insight_card(crypto_rows)

        tagline = ft.Container(
            padding=ft.Padding.all(14), border_radius=R.LG, bgcolor=C.ELEV,
            border=ft.Border.all(1, C.BORDER),
            content=ft.Column([
                ft.Row([ft.Icon(ft.Icons.SHIELD_MOON, color=C.CYAN, size=15),
                        ft.Text("Nothing to subpoena", size=12, color=C.TEXT,
                                weight=ft.FontWeight.W_700)], spacing=8),
                ft.Text("Messages never touch a server. This machine ↔ theirs.",
                        size=11, color=C.MUTED),
            ], spacing=6, tight=True),
        )

        self._insights_panel = ft.Container(
            width=248, bgcolor=C.PANEL,
            border=ft.Border.only(left=ft.BorderSide(1, C.BORDER)),
            padding=ft.Padding.all(14),
            content=ft.Column([
                ft.Text("LIVE INSIGHTS", size=10, color=C.MUTED, font_family=mono,
                        weight=ft.FontWeight.W_800),
                latency, crypto,
                ft.Container(expand=True),
                tagline,
            ], spacing=12, expand=True),
        )
        return self._insights_panel

    async def _insights_loop(self) -> None:
        """Feed the latency sparkline once a second from the real heartbeat
        RTTs (best/lowest across live peers). Idle when nothing is connected."""
        while True:
            try:
                await asyncio.sleep(1.0)
                rtts = list(self._peer_rtt.values())
                if rtts:
                    rtt = min(rtts)
                    h = 6 + min(28, int(rtt * 0.30))
                    self.insight_rtt.value  = f"{int(rtt)} ms"
                    self.insight_live.value = "live"
                    self.insight_live.color = C.GREEN
                else:
                    h = 6
                    self.insight_rtt.value  = "- ms"
                    self.insight_live.value = "idle"
                    self.insight_live.color = C.MUTED
                heights = [b.height for b in self._spark_bars[1:]] + [h]
                for bar, hh in zip(self._spark_bars, heights):
                    bar.height = hh
                try:
                    self._insights_panel.update()
                except Exception:
                    pass
            except asyncio.CancelledError:
                break
            except Exception:
                pass

    def _tool_wrap(self, btn: ft.IconButton) -> ft.Container:
        c = ft.Container(
            content=btn, border_radius=R.MD, bgcolor=C.ELEV + "00",
            animate=_anim(D.FAST),
        )
        self._attach_hover(c, C.ELEV + "00", C.ELEV2)
        return c

    def _make_call_status_pill(self) -> ft.Container:
        """A glowing pill in the header that shows the live call/share status.
        Hidden when nothing is active; updated by _update_call_status()."""
        self.call_status_icon  = ft.Icon(ft.Icons.CALL, color=C.GREEN, size=14)
        self.call_status_label = ft.Text("", size=11, color=C.GREEN,
                                         weight=ft.FontWeight.W_700)
        self.call_status_pill  = ft.Container(
            visible=False,
            padding=ft.Padding.symmetric(horizontal=10, vertical=5),
            border_radius=R.PILL, bgcolor=C.GREEN + "1a",
            border=ft.Border.all(1, C.GREEN + "88"),
            shadow=_glow(C.GREEN + "55", blur=12),
            animate=_anim(D.MED),
            content=ft.Row([self.call_status_icon, self.call_status_label],
                           spacing=6, tight=True),
        )
        return self.call_status_pill

    def _update_call_status(self, active: bool = True) -> None:
        """Call whenever call/share state changes to keep the header pill current."""
        voice   = self._in_voice_call
        screen  = self._in_screen_share
        if not active or not (voice or screen):
            self.call_status_pill.visible = False
            try: self.call_status_pill.update()
            except Exception: pass
            return
        if screen and voice:
            icon, label, color = ft.Icons.PRESENT_TO_ALL, "Sharing + in call", C.MAGENTA
        elif screen:
            icon, label, color = ft.Icons.SCREEN_SHARE, "Sharing screen", C.MAGENTA
        else:
            icon, label, color = ft.Icons.CALL, "In call", C.GREEN
        self.call_status_icon.name          = icon
        self.call_status_icon.color         = color
        self.call_status_label.value        = label
        self.call_status_label.color        = color
        self.call_status_pill.bgcolor       = color + "1a"
        self.call_status_pill.border        = ft.Border.all(1, color + "88")
        self.call_status_pill.shadow        = _glow(color + "55", blur=12)
        self.call_status_pill.visible       = True
        try: self.call_status_pill.update()
        except Exception: pass

    def _settings_section(self, title: str, icon, controls: list,
                          accent: str = C.CYAN) -> ft.Container:
        """A titled, icon-led settings card that fades + scales in (the caller
        staggers the reveals). Holds the real setting controls unchanged."""
        return ft.Container(
            padding=ft.Padding.all(14), border_radius=R.MD,
            bgcolor=C.ELEV + "66", border=ft.Border.all(1, C.BORDER),
            opacity=0, scale=0.98,
            animate_opacity=_anim(D.MED, _EASE_IO),
            animate_scale=_anim(D.MED, _EASE_IO),
            content=ft.Column([
                ft.Row([
                    ft.Container(content=ft.Icon(icon, color=accent, size=16),
                                 padding=ft.Padding.all(7), border_radius=R.SM,
                                 bgcolor=accent + "1f"),
                    ft.Text(title, size=13, weight=ft.FontWeight.W_800, color=C.TEXT),
                ], spacing=10),
                *controls,
            ], spacing=10, tight=True),
        )

    # ------------------------------------------------------------------
    # Engine callbacks
    # ------------------------------------------------------------------

    def _wire_engine_callbacks(self) -> None:
        self.engine.on_state_change     = self._on_engine_state
        self.engine.on_key_change       = self._on_engine_key_change
        self.engine.on_message          = self._on_engine_message
        self.engine.on_call_incoming    = self._on_engine_call_incoming
        self.engine.on_call_accepted    = self._on_engine_call_accepted
        self.engine.on_file_chunk       = self._on_engine_file_chunk
        self.engine.on_file_complete    = self._on_engine_file_complete
        self.engine.on_hangup           = self._on_engine_hangup
        self.engine.on_video_frame      = self._on_engine_video_frame
        self.engine.on_video_end        = lambda sender: self._remove_video_tile(sender)
        self.engine.on_membership_change = self._on_engine_membership_change
        self.engine.on_session_ready    = self._on_engine_session_ready
        self.engine.on_history_request  = self._on_engine_history_request
        self.engine.on_history_response = self._on_engine_history_response
        self.engine.on_delivery         = self._on_engine_delivery
        self.engine.on_sent             = self._on_engine_sent
        self.engine.on_rtt              = self._on_engine_rtt
        self.engine.on_typing           = self._on_engine_typing

    # --- Delivery ticks / RTT / typing (reliability made visible) ---------

    def _set_msg_status(self, msg_id: str, status: str) -> None:
        """Flip a sent bubble's status glyph: queued → sent → delivered.
        Never downgrades a bubble that's already 'delivered' (a late outbox
        flush event must not overwrite a faster ack)."""
        icon = self._msg_status.get(msg_id)
        if icon is None:
            return
        if getattr(icon, "data", "") == "delivered":
            return
        name, color = _MSG_STATUS_GLYPHS.get(status, _MSG_STATUS_GLYPHS["sent"])
        icon.name, icon.color, icon.data = name, color, status
        icon.tooltip = status.capitalize()
        self.page.update()

    def _on_engine_delivery(self, peer: str, msg_id: str) -> None:
        self._set_msg_status(msg_id, "delivered")

    def _on_engine_sent(self, peer: str, msg_id: str) -> None:
        # A queued message actually left the outbox after reconnect.
        self._set_msg_status(msg_id, "sent")

    def _on_engine_rtt(self, peer: str, rtt_ms: float) -> None:
        self._peer_rtt[peer] = rtt_ms
        # Cheap repaints only: the open 1-to-1 header, or the room roster row.
        # Heartbeats tick every ~15 s per peer, so this stays light.
        if peer == self._active_contact and not self._room_id:
            self._update_chat_header_contact(peer)
            self.page.update()
        elif peer in self._room_peers:
            self._refresh_participant_list()
            self.page.update()

    def _on_engine_typing(self, peer: str) -> None:
        if self._room_id or peer != self._active_contact:
            return
        self.chat_header_status_text.value = "typing…"
        self.chat_header_status_text.color = C.CYAN
        self.page.update()
        if self._typing_task and not self._typing_task.done():
            self._typing_task.cancel()
        self._typing_task = self._fire_and_forget(self._typing_revert(peer))

    async def _typing_revert(self, peer: str) -> None:
        try:
            await asyncio.sleep(3.0)
        except asyncio.CancelledError:
            return
        if peer == self._active_contact and not self._room_id:
            self._update_chat_header_contact(peer)
            self.page.update()

    def _on_input_change(self, e) -> None:
        """Throttled outbound composing hint (1-to-1 only, ≤1 per 2.5 s)."""
        if self._room_id or not self._active_contact:
            return
        now = time.monotonic()
        if now - self._typing_sent_at < 2.5:
            return
        self._typing_sent_at = now
        self.engine.send_typing()

    def _on_engine_state(self, peer: str, state: str) -> None:
        if peer in self._room_peers:
            # Dynamic hub failover (feature F): if the peer we just lost was
            # the relay hub, forget it and re-elect so the group call keeps
            # flowing through the next-best peer instead of dropping.
            if state in ("failed", "disconnected", "closed"):
                was_hub = (peer == self.engine.current_hub())
                self._room_peers[peer] = state
                self._refresh_participant_list()
                if was_hub:
                    self.engine.forget_peer_capability(peer)
                    self._log(f"🛰 Relay hub {peer} dropped - re-electing a new hub…")
                # Reconcile topology for ANY failed peer (not just the hub) so a
                # broken spoke can be rebuilt without waiting for the hub to change.
                if self.ws:
                    self._fire_and_forget(self._on_topology_changed())
            else:
                self._room_peers[peer] = state
                self._refresh_participant_list()
            # Honest aggregate status across the WHOLE room (not last-wins).
            self._apply_aggregate_status(self._room_peers, group=True)
        else:
            # 1-to-1 peer state changed - remember it for the health readout,
            # flip its presence dot/wifi promptly and refresh the header if
            # it's the open conversation.
            self._peer_conn_state[peer] = state
            if state in ("failed", "disconnected", "closed"):
                self._peer_rtt.pop(peer, None)   # last RTT is stale once the link drops
            self._refresh_contact_list()
            if peer == self._active_contact and not self._room_id:
                self._update_chat_header_contact(peer)
            self._apply_aggregate_status({peer: state}, group=False)
        if state == "connected":
            # In room mode only re-enable buttons for peers that are actually
            # part of the room topology; ignore stray 1-to-1 state changes.
            if not self._room_id or peer in self._room_peers:
                self.msg_input.disabled  = False
                self.btn_send.disabled   = False
                self._send_wrap.opacity  = 1.0
                self.btn_call.disabled   = False
                self.btn_screen.disabled = False
                self.btn_file.disabled   = False
                self.page.update()
        elif state in ("failed", "disconnected", "closed"):
            # Disable only when no room peer is in 'connected' state.
            # 'connecting' entries are not usable channels and must not count.
            if not any(s == "connected" for s in self._room_peers.values()):
                self.msg_input.disabled  = True
                self.btn_send.disabled   = True
                self._send_wrap.opacity  = 0.45
                self.btn_call.disabled   = True
                self.btn_screen.disabled = True
                self.btn_file.disabled   = True
                self.btn_mute.disabled   = True
                self.btn_hangup.disabled = True
            self.page.update()

    def _on_engine_message(self, sender: str, text: str, wire_verified: bool) -> None:
        # The per-message `verified` flag from the wire is not trustworthy;
        # derive it from whether we've verified this contact's key fingerprint.
        c = get_contact(sender)
        verified = bool(c and c.verified) if self.settings.security_mode == "e2ee" else False
        contact = self._room_id if self._room_id else sender
        if not (self._ephemeral and self._room_id):   # ephemeral → memory only, never disk
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

    def _on_engine_call_incoming(self, sender: str) -> None:
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

        def accept(e=None):
            if not self._is_allowed(sender):
                _stop_ring()
                self.engine.reject_call(sender)
                self._hide_call_banner()
                self._block_unverified(sender)
                return
            _stop_ring()
            self.engine.accept_call(sender)
            sounds.play("call_start")
            self.btn_hangup.disabled = False
            self.btn_mute.disabled   = False
            self._hide_call_banner()
            self.page.update()

        def reject(e=None):
            _stop_ring()
            self.engine.reject_call(sender)
            self._hide_call_banner()

        async def _auto_decline():
            await asyncio.sleep(25)
            if self._ringing:
                _stop_ring()
                self.engine.reject_call(sender)
                self._hide_call_banner()
                self._log(f"Missed call from {sender} (timed out).")
                self.page.update()

        self._show_call_banner(sender, accept, reject)
        self._ring_timeout_task = asyncio.ensure_future(_auto_decline())

    def _on_engine_call_accepted(self) -> None:
        # Caller side: the peer accepted our call.
        sounds.play("call_start")
        self.btn_hangup.disabled = False
        self.btn_mute.disabled   = False
        self.page.update()

    def _on_engine_file_chunk(self, fname: str, received: int, total) -> None:
        if total is not None and total > 0:
            self.file_progress.value   = received / total
            self.file_progress.visible = True
            self.page.update()

    def _on_engine_file_complete(self, fname: str, tmp_path: str, ok: bool) -> None:
        self.file_progress.visible = False
        self._log(f"[File received] {fname} {'✓' if ok else '⚠ integrity failed'}")
        self.page.update()
        self._fire_and_forget(self._save_received_file(fname, tmp_path, ok))

    def _on_engine_hangup(self, peer=None) -> None:
        sounds.stop_loop()
        sounds.play("call_end")
        self._in_voice_call   = False
        self._in_screen_share = False
        self.btn_hangup.disabled = True
        self.btn_mute.disabled   = True
        self.btn_screen.icon_color = C.SUBTLE
        self.btn_screen.tooltip    = SHARE_SCREEN_TXT
        self._set_mute_banner(False)
        # Remote hung up - clear ALL incoming screen shares and exit full
        # screen / PiP so nothing stale remains after the call ends.
        self._clear_all_video()
        self._update_call_status(False)
        self._log("[Call ended]")
        self._refresh_call_controls()
        self.page.update()

    def _on_engine_video_frame(self, sender: str, img) -> None:
        # Coalesce to a UI-friendly rate so a fast sender can't pile up
        # per-frame work on a weak receiver, then dispatch the CPU-bound
        # JPEG encode to a thread so the event loop stays responsive.
        now  = time.monotonic()
        last = self._last_tile_render.get(sender, 0.0)
        if now - last < self._tile_render_interval:
            return
        self._last_tile_render[sender] = now
        self._fire_and_forget(self._update_video_tile(sender, img))

    def _on_engine_key_change(self, peer: str) -> None:
        # The contact's identity key changed after we had verified it -
        # surface a loud warning. The contact is already auto-unverified.
        # A changed key also revokes any temporary "allow for this session".
        self._session_allowed.discard(peer)
        self._refresh_contact_list()
        self._refresh_participant_list()
        display = peer
        c = get_contact(peer)
        if c and c.nickname:
            display = c.nickname
        self._log(f"⚠ SECURITY: {display}'s identity key changed - verification removed. "
                  f"Re-verify their fingerprint out-of-band before trusting.")
        dlg = ft.AlertDialog(
            title=ft.Text("⚠ Contact key changed"),
            content=ft.Text(
                f"{display}'s encryption key is different from the one you "
                f"previously verified.\n\nThis can happen if they reinstalled or "
                f"regenerated keys - but it can also indicate an impersonation "
                f"or man-in-the-middle attempt.\n\nVerification has been removed. "
                f"Confirm their new fingerprint out-of-band before trusting it."
            ),
            actions=[ft.TextButton("Understood", on_click=lambda e: self._close_dialog(dlg))],
        )
        self._show_dialog(dlg)
        self.page.update()

    def _on_engine_session_ready(self, peer: str) -> None:
        # Peer-assisted history sync (feature E): once the encrypted session
        # with a room peer is up, ask them for anything we missed while offline.
        # Ephemeral rooms persist nothing, so there's nothing to sync.
        if self._room_id and peer in self._room_peers and not self._ephemeral:
            since = last_room_message_ts(self._room_id) or ""
            self._fire_and_forget(
                self.engine.send_history_request(peer, self._room_id, since))

    def _on_engine_history_request(self, peer: str, room_id: str, since: str) -> None:
        if not room_id or room_id != self._room_id or self._ephemeral:
            return
        msgs = read_room_messages_since(
            room_id, since, self.history_key, self.settings.security_mode,
            self.engine.my_username, limit=self.engine.HISTORY_SYNC_MAX)
        if msgs:
            self._fire_and_forget(
                self.engine.send_history_response(peer, room_id, msgs))

    def _on_engine_history_response(self, peer: str, room_id: str, messages: list) -> None:
        if not room_id or room_id != self._room_id:
            return
        me   = self.engine.my_username
        seen = read_room_message_keys(room_id, self.history_key, self.settings.security_mode)
        room_open = (self._room_id == room_id) and not self._active_contact
        added = 0
        for m in messages:
            sender  = (m.get("sender") or peer)
            content = m.get("content") or ""
            if not content or sender == me:        # I authored it / empty - skip
                continue
            if (sender, content) in seen:          # cross-peer dedup by (sender, content)
                continue
            write_message(
                room_id, "received", "chat", content,
                self.history_key, self.settings.security_mode,
                room_id=room_id, sender=sender,
            )
            seen.add((sender, content))
            added += 1
            if room_open:
                self._append_to_log("received", content, False, label=sender)
        if added:
            self._log(f"📥 Synced {added} missed message(s) from {peer}.")
            self.page.update()

    def _on_engine_membership_change(self, peer: str, is_member: bool) -> None:
        # Feature D: refresh the participant badge (✓ member / ⚠ unvouched).
        if peer in self._room_peers:
            self._refresh_participant_list()

    # ------------------------------------------------------------------
    # Signaling
    # ------------------------------------------------------------------

    def _build_signaling_url(self, uname: str, room: str) -> tuple[str, str]:
        params = {}
        if room:
            params["room"] = room
        if self._server_password:
            params["password"] = self._server_password
        if self._ws_session_token:
            params["session_token"] = self._ws_session_token
        suffix = ("?" + urllib.parse.urlencode(params)) if params else ""
        base   = _to_ws_url(self.settings.signaling_url)
        url    = f"{base}/ws/{urllib.parse.quote(uname, safe='')}{suffix}"

        # Redact password in printed logs
        safe_params = dict(params)
        pwd_key = "pass" + "word"
        if pwd_key in safe_params:
            safe_params[pwd_key] = "<redacted>"
        safe_suffix = ("?" + urllib.parse.urlencode(safe_params)) if safe_params else ""
        safe_url = f"{base}/ws/{urllib.parse.quote(uname, safe='')}{safe_suffix}"
        return url, safe_url

    async def _connect_signaling(self, e, room: str = "") -> None:
        uname = self.username_input.value.strip()
        # If we're already in a room and just reconnecting (e.g. after a WS
        # drop), carry the room ID so the server puts us back in the session.
        if not room and self._room_id:
            room = self._room_id
        print(f"[connect] clicked. username={uname!r} room={room!r} url_base={self.settings.signaling_url!r}", flush=True)
        if not uname:
            self._log("[Error] Enter a username first.")
            print("[connect] aborted: empty username", flush=True)
            return
        self.engine.my_username = uname
        url, safe_url = self._build_signaling_url(uname, room)

        print(f"[connect] dialing {safe_url}", flush=True)
        if self.ws:
            try:
                await self.ws.close()
            except Exception:
                pass
        try:
            # Explicit keepalive: ping every 20 s, declare the link dead after
            # 15 s of silence - detects half-open connections (sleep/VPN drop)
            # quickly so the auto-reconnect loop can kick in.
            self.ws = await websockets.connect(
                url, ping_interval=20, ping_timeout=15,
                close_timeout=5, open_timeout=15,
            )
            self._update_status("SIGNALING", C.YELLOW)
            self._toast(f"Connected as “{uname}”" + (f" in {room}" if room else ""), "success")
            print(f"[connect] websocket OPEN to {safe_url}", flush=True)
            sounds.play("reactivated")
            self._fire_and_forget(self._signaling_listener())
            self._fire_and_forget(self._query_presence())   # immediate presence refresh
            # Probe NAT behaviour once per connect (best-effort, off the UI
            # thread). Result feeds symmetric-NAT port prediction + diagnostics.
            self._fire_and_forget(self.engine.detect_nat())
        except Exception as ex:
            self.engine.last_error = f"signaling: {type(ex).__name__}"
            self._toast(f"Cannot reach server: {ex}", "error")
            print(f"[connect] FAILED: {type(ex).__name__}: {ex}", flush=True)

    async def _signaling_listener(self) -> None:
        # Bind to THIS socket: if _connect_signaling replaces self.ws while we
        # run, this listener must not clean up / reconnect over the new session.
        ws = self.ws

        async def ws_send(payload: dict):
            await ws.send(json.dumps(payload))

        # Keep the engine's send reference current so renegotiation after a
        # WebRTC failure can still reach the live WebSocket.
        self.engine._send_ws = ws_send
        _dropped_unexpectedly = False

        try:
            async for raw in ws:
                try:
                    msg = json.loads(raw)
                except Exception:
                    continue
                t      = msg.get("type")
                sender = msg.get("sender", "")
                data   = msg.get("data") or {}

                try:
                    await self._handle_signaling_message(t, sender, data, msg, ws_send)
                except Exception as inner_ex:
                    if "destroyed session" in str(inner_ex):
                        print("[signaling] Session destroyed. Exiting listener.", flush=True)
                        break
                    print(f"[signaling] Error handling message {t} from {sender}: {inner_ex}", flush=True)
        except Exception as ex:
            if self.ws is not ws:
                # A newer connection already took over - this is the OLD socket
                # closing; don't tear down the fresh session's state.
                return
            self._cleanup_signaling_disconnect(ex)
            _dropped_unexpectedly = True
        finally:
            # Auto-reconnect after an unexpected drop - for rooms AND 1-to-1
            # sessions (previously only rooms recovered; a 1-to-1 chat went
            # silently dead until the user clicked Connect again).
            if (_dropped_unexpectedly and self.ws is ws
                    and (self._room_id or self.engine.my_username)
                    and not self._ws_reconnect_active):
                self._fire_and_forget(self._ws_reconnect_loop())

    async def _ws_reconnect_loop(self) -> None:
        """Reconnect to the signaling server after an unexpected drop.
        Backs off exponentially (2 s → 4 s → … → 30 s) and exits as soon as the
        connection is restored. Works for rooms (re-joins the room) and for
        plain 1-to-1 sessions (re-registers the username)."""
        if self._ws_reconnect_active:
            return
        self._ws_reconnect_active = True
        delay = 2.0
        try:
            while True:
                await asyncio.sleep(delay)
                # Another path (user action or parallel loop) already reconnected.
                if self.ws is not None:
                    try:
                        if not self.ws.closed:
                            return
                    except Exception:
                        pass
                uname = self.username_input.value.strip()
                if not uname:
                    return
                target = f"room {self._room_id}" if self._room_id else "signaling"
                self._log(f"[Reconnect] Re-joining {target}…")
                try:
                    await self._connect_signaling(None, room=self._room_id)
                    # _connect_signaling swallows connect errors, so confirm the
                    # socket is actually live before declaring success.
                    ok = False
                    try:
                        ok = self.ws is not None and not self.ws.closed
                    except Exception:
                        ok = self.ws is not None
                    if ok:
                        return  # success - new listener takes over
                    delay = min(delay * 2, 30.0)
                except Exception as ex:
                    self._toast(f"Reconnect failed ({type(ex).__name__}), retrying…", "warn")
                    delay = min(delay * 2, 30.0)
        finally:
            self._ws_reconnect_active = False

    async def _handle_sig_peer_joined(self, sender: str, ws_send) -> None:
        self._room_peers[sender] = "connecting"
        self._refresh_participant_list()
        await self._broadcast_capability(ws_send)
        await self.engine.reconcile_room_connections(list(self._room_peers.keys()), ws_send)
        await self._apply_active_call_to_hub()
        self._refresh_hub_indicator()
        if self._in_voice_call or self._in_screen_share:
            await self._broadcast_call_active(ws_send)

    async def _handle_sig_peer_left(self, sender: str, ws_send) -> None:
        self._room_peers.pop(sender, None)
        self._refresh_participant_list()
        await self.engine.remove_peer(sender)
        await self.engine.reconcile_room_connections(list(self._room_peers.keys()), ws_send)
        self._remove_video_tile(sender)
        await self._apply_active_call_to_hub()
        self._refresh_hub_indicator()

    async def _handle_sig_room_state(self, msg: dict, ws_send) -> None:
        # Server sends `peers` at the top level of the message
        # (like `sender` for peer_joined), NOT nested under `data`.
        for peer in msg.get("peers", []):
            self._room_peers[peer] = "connecting"
        self._refresh_participant_list()
        await self._broadcast_capability(ws_send)
        await self.engine.reconcile_room_connections(list(self._room_peers.keys()), ws_send)
        await self._apply_active_call_to_hub()
        self._refresh_hub_indicator()
        # Server confirmed we're in the room - restore the toolbar
        # immediately so users can interact even before peers connect.
        self.msg_input.disabled  = False
        self.btn_send.disabled   = False
        self.btn_call.disabled   = False
        self.btn_screen.disabled = False
        self.btn_file.disabled   = False
        self.page.update()

    async def _handle_sig_hub_capability(self, sender: str, data: dict, ws_send) -> None:
        self.engine.record_capability(sender, data.get("tier", 0), data.get("epoch", 0))
        if data.get("creator"):
            self.engine.set_room_creator(sender)
        await self.engine.reconcile_room_connections(list(self._room_peers.keys()), ws_send)
        await self._apply_active_call_to_hub()
        self._refresh_hub_indicator()

    def _handle_sig_error(self, msg: dict, data) -> None:
        msg_text = data if isinstance(data, str) else msg.get("error", str(data))
        match = _re.search(r"User '(.+?)' is offline", msg_text)
        if match:
            username = match.group(1)
            if username in self.engine.pcs:
                self._fire_and_forget(self.engine.remove_peer(username))
            if username in self._pending_invites:
                self._pending_invites.discard(username)
                self._toast(f"Could not invite {username} - they are offline", "warn")
            else:
                self._toast(msg_text, "warn")
        else:
            self._toast(msg_text, "error")

    def _cleanup_signaling_disconnect(self, ex: Exception) -> None:
        if "destroyed session" in str(ex):
            return
        try:
            self._toast(f"Disconnected from signaling: {ex}", "error")
            self._update_status("IDLE", C.FAINT)
            self._clear_all_video()
        except Exception:
            pass
        for _peer in self.engine.pcs:
            self._fire_and_forget(self.engine.remove_peer(_peer))
        # Wipe stale peer state so reconnect gets a clean slate (otherwise
        # reconcile_room_connections sees phantom "connected" entries).
        self._room_peers.clear()
        try:
            self._refresh_participant_list()
        except Exception:
            pass
        # Grey out the toolbar - re-enabled when room_state confirms we're
        # back in the room, or when a peer reaches "connected".
        try:
            self.msg_input.disabled  = True
            self.btn_send.disabled   = True
            self.btn_call.disabled   = True
            self.btn_screen.disabled = True
            self.btn_file.disabled   = True
            self.btn_mute.disabled   = True
            self.btn_hangup.disabled = True
            self.page.update()
        except Exception:
            pass
        self._purge_ephemeral()   # auto-destruct an ephemeral room on ws close

    async def _handle_sig_connect_request(self, sender: str, ws_send) -> None:
        upsert_contact(sender)
        self._refresh_contact_list()
        if not self._active_contact:
            self.engine.target_peer = sender
        await self.engine.add_peer(sender, ws_send)

    async def _handle_signaling_message(self, t: str, sender: str, data: dict, msg: dict, ws_send) -> None:
        if t == "offer":
            await self.engine.handle_offer(sender, data, ws_send)
        elif t == "answer":
            await self.engine.handle_answer(data, sender=sender)
        elif t == "ice" or t == "ice-candidate":
            await self.engine.handle_ice(data, sender=sender)
        elif t == "punch_at":
            await self.engine.handle_punch_at(data, sender, ws_send)
        elif t in ("p2p_relay", "relay_e2ee"):
            await self.engine.handle_relay_message(data, sender)
        elif t == "hello_signaling":
            await self.engine.handle_signaling_hello(data, sender)
        elif t == "connect_request":
            await self._handle_sig_connect_request(sender, ws_send)
        elif t == "peer_joined":
            await self._handle_sig_peer_joined(sender, ws_send)
        elif t == "peer_left":
            await self._handle_sig_peer_left(sender, ws_send)
        elif t == "room_state":
            await self._handle_sig_room_state(msg, ws_send)
        elif t == "hub_capability":
            await self._handle_sig_hub_capability(sender, data, ws_send)
        elif t == "call_active":
            self._room_call_active = True
            self._log("📞 A call is active in the room - click 'Join call' to join.")
            self._refresh_call_controls()
        elif t == "room_invite":
            room_id = data.get("room_id", "")
            inviter = data.get("inviter", sender)
            self._show_room_invite_dialog(inviter, room_id)
        elif t == "session_token":
            self._ws_session_token = (data or {}).get("token", "")
            self._reflected_host = str((data or {}).get("reflected_host") or "")
            self._reflected_port = int((data or {}).get("reflected_port") or 0)
            self.engine.server_capabilities = (data or {}).get("capabilities", [])
            if self._reflected_host:
                print(f"[nat] server reflects us as {self._reflected_host}:{self._reflected_port}",
                      flush=True)
                self.engine.set_reflected_host(self._reflected_host)
                if self._room_id:
                    self._fire_and_forget(self._broadcast_capability(ws_send))
        elif t == "presence":
            # Server-confirmed online set for our contacts.
            self._apply_presence(data.get("online", []))
        elif t == "error":
            self._handle_sig_error(msg, data)
    # ------------------------------------------------------------------
    # Room management
    # ------------------------------------------------------------------

    def _create_room(self, e) -> None:
        uname = self.username_input.value.strip()
        if not uname:
            self._log("[Error] Enter a username first.")
            print("[create_room] aborted: empty username", flush=True)
            return
        code = generate_room_code()

        ephem_cb = ft.Checkbox(
            label="Ephemeral Mode (auto-destruct)",
            value=False,
            label_style=ft.TextStyle(size=11, weight=ft.FontWeight.BOLD, color=C.TEXT)
        )

        # Two doors, lock on the secure one: an invite-only room is gated by a
        # pre-shared key (joinable ONLY with the invite link); an open room is
        # joinable by anyone who types the room code.
        def choose(secure: bool):
            self._close_dialog(dlg)
            self._room_psk = invites.generate_psk() if secure else None
            self._ephemeral = bool(ephem_cb.value)
            self._fire_and_forget(self._create_room_finish(code, secure))

        dlg = ft.AlertDialog(
            title=ft.Text(f"Create room {code}", size=16, weight=ft.FontWeight.BOLD),
            content=ft.Column([
                ft.Text("Join Policy", size=11, weight=ft.FontWeight.BOLD, color=C.CYAN),
                ft.Container(
                    content=ft.Row([
                        ft.Icon(ft.Icons.LOCK, color=C.CYAN, size=18),
                        ft.Column([
                            ft.Text("Invite-only (Recommended)", size=11, weight=ft.FontWeight.BOLD, color=C.TEXT),
                            ft.Text("Requires secure invite link. Pre-shared keys hide room completely.", size=10, color=C.MUTED),
                        ], spacing=1, expand=True)
                    ], vertical_alignment=ft.CrossAxisAlignment.CENTER),
                    padding=10, border_radius=R.MD, bgcolor=C.ELEV, border=ft.Border.all(1, C.BORDER),
                ),
                ft.Container(
                    content=ft.Row([
                        ft.Icon(ft.Icons.PUBLIC, color=C.SUBTLE, size=18),
                        ft.Column([
                            ft.Text("Open Room", size=11, weight=ft.FontWeight.BOLD, color=C.TEXT),
                            ft.Text("Anyone who knows the room code can connect instantly.", size=10, color=C.MUTED),
                        ], spacing=1, expand=True)
                    ], vertical_alignment=ft.CrossAxisAlignment.CENTER),
                    padding=10, border_radius=R.MD, bgcolor=C.ELEV, border=ft.Border.all(1, C.BORDER),
                ),
                ft.Container(height=4),
                ft.Text("Storage Policy", size=11, weight=ft.FontWeight.BOLD, color=C.CYAN),
                ft.Container(
                    content=ft.Column([
                        ft.Row([
                            ft.Icon(ft.Icons.WHATSHOT, color=C.RED, size=18),
                            ephem_cb,
                        ], spacing=6, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                        ft.Text("Messages are kept in memory only. Keys, logs, and tracks are purged completely when you disconnect.", size=10, color=C.MUTED),
                    ], spacing=4),
                    padding=10, border_radius=R.MD, bgcolor=C.ELEV, border=ft.Border.all(1, C.BORDER),
                ),
            ], tight=True, spacing=8, width=380),
            actions=[
                ft.FilledButton("Invite-only", icon=ft.Icons.LOCK, on_click=lambda e: choose(True),
                                style=_filled_style(C.CYAN)),
                ft.FilledButton("Open", icon=ft.Icons.PUBLIC, on_click=lambda e: choose(False),
                                style=_filled_style(C.ELEV2, C.TEXT)),
                ft.TextButton("Cancel", on_click=lambda e: self._close_dialog(dlg),
                              style=_ghost_style(C.MUTED)),
            ],
        )
        self._show_dialog(dlg)

    async def _create_room_finish(self, code: str, secure: bool) -> None:
        print(f"[create_room] generated {code} (secure={secure}), joining…", flush=True)
        await self._join_room(code, is_creator=True)
        if secure:
            self._log("Invite-only room created - share the invite link to let others in.")
            self._show_copy_invite()
        else:
            self._show_invite_contacts()

    def _show_join_room(self, e) -> None:
        field = _neon_field(label="Room code (e.g. ROOM-AB12)", autofocus=True, dense=True)

        async def do_join(ev):
            code = field.value.strip().upper()
            if not code.startswith("ROOM-") or len(code) != 9:
                field.error_text = "Invalid room code"
                self.page.update()
                return
            self._close_dialog(dlg)
            self._room_psk = None   # plain code-join → open room (no PSK)
            self._ephemeral = False
            self._invite_creator_pub = None
            await self._join_room(code, is_creator=False)

        dlg = ft.AlertDialog(
            title=ft.Text("Join Room", size=16, weight=ft.FontWeight.BOLD),
            content=ft.Column([
                ft.Text("Enter a 9-character room code to connect to an existing room.", size=11, color=C.SUBTLE),
                field,
            ], tight=True, spacing=12, width=320),
            actions=[
                ft.FilledButton("Join", icon=ft.Icons.LOGIN, on_click=do_join,
                                style=_filled_style(C.CYAN)),
                ft.TextButton("Cancel", on_click=lambda ev: self._close_dialog(dlg),
                              style=_ghost_style(C.MUTED)),
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
        self.engine.set_room_psk(self._room_psk)   # gate the room if invite-only
        self.engine.my_username = uname
        # Feature D (advisory membership): creator is the trust root; a member
        # trusts the creator key carried in the invite.
        if is_creator:
            self.engine.adopt_creator_identity()
        else:
            self.engine.set_room_creator_pubkey(getattr(self, "_invite_creator_pub", None))
        self.room_code_label.value    = f"Room: {code}"
        self.btn_invite.visible       = True
        self.btn_copy_room.visible    = True
        self.btn_invite_link.visible  = True
        self._update_chat_header_room(code)   # show the room as the active context
        self._select_room()                    # switch home → conversation view
        # Enable toolbar immediately - messages are buffered until peers arrive.
        self.msg_input.disabled  = False
        self.btn_send.disabled   = False
        self.btn_call.disabled   = False
        self.btn_screen.disabled = False
        self.btn_file.disabled   = False
        self.page.update()
        self._refresh_hub_indicator()
        await self._connect_signaling(None, room=code)

    # ------------------------------------------------------------------
    # Invite links (HELU-INV1) - copy / redeem
    # ------------------------------------------------------------------

    def _show_copy_invite(self, e=None) -> None:
        if not self._room_id:
            return
        incl_pw = ft.Checkbox(
            label="Include server password in the link",
            value=bool(self._server_password),
        )
        out = _neon_field(value="", read_only=True, multiline=True, min_lines=2,
                           max_lines=4, width=380, text_size=11, visible=False)

        async def generate(ev):
            pw = self._server_password if incl_pw.value else None
            try:
                code = invites.encode_invite(
                    self._room_id, self.settings.signaling_url,
                    password=pw, psk=self._room_psk, ephemeral=self._ephemeral,
                    creator_ed25519_pub=self.engine.room_creator_pubkey,
                )
            except ValueError as ex:
                out.value = f"Error: {ex}"; out.visible = True; self.page.update(); return
            out.value = code
            out.visible = True
            await self._set_clipboard(code)
            self._log("Invite link copied to clipboard.")
            self.page.update()

        dlg = ft.AlertDialog(
            title=ft.Text("Invite link"),
            content=ft.Column([
                ft.Text(f"Room {self._room_id}  ·  {_redact_url(self.settings.signaling_url)}",
                        size=12, color=C.SUBTLE),
                incl_pw,
                ft.Text("Anyone with this link can reach your signaling server and join the "
                        "room - share it only over a trusted channel.", size=11, color=C.YELLOW),
                out,
            ], tight=True, spacing=10, width=400),
            actions=[
                ft.FilledButton("Generate & copy", icon=ft.Icons.LINK,
                                on_click=generate, style=_filled_style(C.CYAN)),
                ft.TextButton("Close", on_click=lambda ev: self._close_dialog(dlg)),
            ],
        )
        self._show_dialog(dlg)

    def _show_join_invite(self, e=None) -> None:
        field = _neon_field(label="Paste invite link (HELU-INV1:…)", autofocus=True,
                             multiline=True, min_lines=2, max_lines=4, width=380)
        error = ft.Text("", color=C.RED, size=11, visible=False)

        def do_decode(ev):
            try:
                info = invites.decode_invite(field.value)
            except ValueError as ex:
                error.value = str(ex); error.visible = True; self.page.update(); return
            self._close_dialog(dlg)
            self._confirm_join_invite(info)

        dlg = ft.AlertDialog(
            title=ft.Text("Join via invite link"),
            content=ft.Column([field, error], tight=True, spacing=6),
            actions=[
                ft.FilledButton("Continue", on_click=do_decode, style=_filled_style(C.CYAN)),
                ft.TextButton("Cancel", on_click=lambda ev: self._close_dialog(dlg)),
            ],
        )
        self._show_dialog(dlg)

    def _confirm_join_invite(self, info: dict) -> None:
        pw_field = None
        rows = [
            ft.Text(f"Room: {info['room_id']}", size=14, color=C.TEXT, weight=ft.FontWeight.W_700),
            ft.Text(f"Server: {info['signaling_url']}", size=12, color=C.SUBTLE, selectable=True),
            ft.Text("This switches your signaling server and joins the room. Only continue if "
                    "you trust whoever sent this link.", size=11, color=C.YELLOW),
        ]
        if not info.get("password"):
            pw_field = _neon_field(label="Server password (if the server requires one)",
                                   password=True, can_reveal_password=True, width=320)
            rows.append(pw_field)
        err = ft.Text("", color=C.RED, size=11, visible=False)
        rows.append(err)

        def do_join(ev):
            if not self.username_input.value.strip():
                err.value = "Set your username in the sidebar first."
                err.visible = True; self.page.update(); return
            self.settings.signaling_url = info["signaling_url"]
            try:
                save_settings(self.settings)
            except Exception:
                pass
            self._server_password = info.get("password") or (pw_field.value if pw_field else "") or ""
            self._room_psk = info.get("psk")   # carry the invite's PSK into the room
            self._ephemeral = bool(info.get("ephemeral"))
            self._invite_creator_pub = info.get("creator_ed25519_pub")
            self._close_dialog(dlg)
            self._fire_and_forget(self._join_room(info["room_id"], is_creator=False))

        dlg = ft.AlertDialog(
            title=ft.Text("Join room?"),
            content=ft.Column(rows, tight=True, spacing=10, width=360),
            actions=[
                ft.FilledButton(JOIN_ROOM_TXT, icon=ft.Icons.LOGIN,
                                on_click=do_join, style=_filled_style(C.GREEN, C.BTN_GREEN)),
                ft.TextButton("Cancel", on_click=lambda ev: self._close_dialog(dlg)),
            ],
        )
        self._show_dialog(dlg)

    def _show_room_invite_dialog(self, inviter: str, room_id: str) -> None:
        async def do_join(e):
            self._close_dialog(dlg)
            self._room_psk = None   # contact invites don't carry a PSK (use the link for invite-only rooms)
            self._ephemeral = False
            self._invite_creator_pub = None
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
                [cb for cb, _ in checkboxes] or [ft.Text("No contacts yet.", color=C.MUTED)],
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
        for peer in self._room_peers:
            await ws_send({"target": peer, "type": "hub_capability", "data": payload})

    async def _broadcast_call_active(self, ws_send) -> None:
        """Tell every room peer that a call is currently active in this room."""
        if not self._room_id:
            return
        for peer in self._room_peers:
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
                self.hub_banner.value = "🛰 You are the relay - others' audio/video pass through you"
            else:
                self.hub_banner.value = f"🛰 Relayed by {hub} - media passes through them"
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
            self.participant_list.controls.append(self._participant_card(username, state))
        self.page.update()

    # ------------------------------------------------------------------
    # Presence
    # ------------------------------------------------------------------

    def _is_contact_online(self, username: str) -> bool:
        """True if the server confirmed this user is connected, or we already
        hold a live P2P link to them."""
        if username in self._online_users:
            return True
        if username == self._connected_peer():
            return True
        pc = self.engine.pcs.get(username)
        return bool(pc and pc.connectionState == "connected")

    async def _query_presence(self) -> None:
        """Ask the signaling server which of our contacts are currently online."""
        if not self.ws:
            return
        names = [c.username for c in load_contacts()]
        if not names:
            return
        try:
            await self.ws.send(json.dumps({"type": "presence", "data": {"usernames": names}}))
        except Exception:
            pass

    async def _presence_loop(self) -> None:
        while True:
            await asyncio.sleep(10)
            await self._query_presence()

    def _apply_presence(self, online: list) -> None:
        """Handle a presence reply from the server: store the online set and
        repaint the contact list + (if a 1-to-1 chat is open) the header."""
        self._online_users = set(online or [])
        self._refresh_contact_list()
        if self._active_contact and not self._room_id:
            self._update_chat_header_contact(self._active_contact)
            try:
                self.page.update()
            except Exception:
                pass

    # ------------------------------------------------------------------
    # Contact list (gem-style cards: avatar + presence dot + wifi + active highlight)
    # ------------------------------------------------------------------

    def _refresh_contact_list(self) -> None:
        self.contact_list.controls.clear()
        contacts = load_contacts()
        # Filter-as-you-type (matches nickname OR username, case-insensitive).
        query = (getattr(self, "contact_search", None) and self.contact_search.value or "").strip().lower()
        if query:
            contacts = [c for c in contacts
                        if query in (c.nickname or "").lower() or query in c.username.lower()]
        # Online contacts float to the top; each group stays alphabetical, so
        # the people you can actually talk to right now are one glance away.
        contacts = sorted(contacts,
                          key=lambda c: (not self._is_contact_online(c.username),
                                         (c.nickname or c.username).lower()))
        if not contacts:
            if query:
                self.contact_list.controls.append(self._empty_state(
                    ft.Icons.SEARCH_OFF, "No matches",
                    f"No contact matches “{query}”.",
                ))
            else:
                self.contact_list.controls.append(self._empty_state(
                    ft.Icons.PERSON_ADD_ALT_1,
                    "No contacts yet",
                    "Add a contact or share your identity code to start a private conversation.",
                ))
        else:
            for c in contacts:
                self.contact_list.controls.append(self._contact_card(c))
        self._refresh_home_recent()   # keep the home quick-resume chips in sync
        self.page.update()

    def _empty_state(self, icon, title: str, subtitle: str = "") -> ft.Container:
        """A calm, centered placeholder for an empty list/area - replaces blank
        voids with quiet guidance (icon + title + optional one-liner)."""
        children = [
            ft.Container(
                content=ft.Icon(icon, color=C.MUTED, size=22),
                padding=ft.Padding.all(12), border_radius=R.MD,
                bgcolor=C.ELEV + "80", border=ft.Border.all(1, C.BORDER),
            ),
            ft.Text(title, size=13, weight=ft.FontWeight.W_600, color=C.SUBTLE,
                    text_align=ft.TextAlign.CENTER),
        ]
        if subtitle:
            children.append(ft.Text(subtitle, size=11, color=C.MUTED,
                                    text_align=ft.TextAlign.CENTER))
        return ft.Container(
            padding=ft.Padding.symmetric(horizontal=16, vertical=28),
            alignment=ft.Alignment.CENTER,
            content=ft.Column(children, spacing=10, tight=True,
                              horizontal_alignment=ft.CrossAxisAlignment.CENTER),
        )

    def _avatar_gradient(self, verified: bool) -> ft.LinearGradient:
        # Verified gets the accent; unverified stays a neutral slate.
        return ft.LinearGradient(
            begin=ft.Alignment.TOP_LEFT, end=ft.Alignment.BOTTOM_RIGHT,
            colors=[C.CYAN, C.CYAN_DIM] if verified else [C.ELEV2, C.ELEV],
        )

    def _verify_badge(self, verified: bool, size: int = 13):
        """A verification badge for contact/participant rows. Only meaningful in
        E2EE mode: green ✓ when the fingerprint is verified, yellow ⚠ when not."""
        if self.settings.security_mode != "e2ee":
            return None
        if verified:
            return ft.Icon(ft.Icons.VERIFIED, color=C.GREEN, size=size, tooltip="Verified")
        return ft.Icon(ft.Icons.GPP_MAYBE, color=C.YELLOW, size=size,
                       tooltip="Not verified - click ··· to view fingerprint")

    def _avatar(self, display: str, verified: bool, size: int = 34) -> ft.Container:
        return ft.Container(
            content=ft.Text((display or "?")[0].upper(), color=C.BTN_CYAN if verified else "#ffffff",
                            weight=ft.FontWeight.W_800, size=int(size * 0.4)),
            width=size, height=size, border_radius=R.PILL,
            alignment=ft.Alignment.CENTER, gradient=self._avatar_gradient(verified),
        )

    def _contact_card_avatar(self, display: str, verified: bool, is_online: bool) -> ft.Stack:
        dot_color = C.GREEN if is_online else C.FAINT
        shadow_val = _glow(dot_color, blur=8, spread=0) if is_online else None
        return ft.Stack([
            self._avatar(display, verified, 34),
            ft.Container(
                width=11, height=11, border_radius=R.PILL, bgcolor=dot_color,
                border=ft.Border.all(2, C.PANEL), right=0, bottom=0,
                shadow=shadow_val,
            ),
        ], width=34, height=34)

    def _contact_card_name(self, display: str, is_active: bool, verified: bool) -> ft.Row:
        badge = self._verify_badge(verified)
        text_color = C.TEXT if is_active else C.SUBTLE
        text_weight = ft.FontWeight.W_700 if is_active else ft.FontWeight.W_500
        return ft.Row(
            [
                ft.Text(display, size=13,
                        color=text_color,
                        weight=text_weight,
                        max_lines=1, overflow=ft.TextOverflow.ELLIPSIS),
                *([badge] if badge else []),
            ],
            spacing=4, tight=True,
        )

    def _contact_card_wifi(self, is_online: bool) -> ft.Icon:
        icon_name = ft.Icons.WIFI if is_online else ft.Icons.WIFI_OFF
        icon_color = C.GREEN if is_online else C.FAINT
        return ft.Icon(icon_name, color=icon_color, size=15)

    def _last_message_snippet(self, username: str) -> tuple[str, str]:
        """(preview, compact time) of the newest 1-to-1 message with ``username``
        for the two-line contact card. Defensive: any failure → empty strings."""
        try:
            msgs = read_messages(username, self.history_key,
                                 self.settings.security_mode, limit=1)
        except Exception:
            return "", ""
        if not msgs:
            return "", ""
        m = msgs[-1]
        text = (m.get("content") or "").replace("\n", " ")
        if m.get("direction") == "sent" and text:
            text = "You: " + text
        when = ""
        day = _msg_day(m.get("timestamp"))
        if day is not None:
            today = datetime.now().astimezone().date()
            delta = (today - day).days
            if delta == 0:
                when = _fmt_msg_ts(m.get("timestamp"))
            elif delta == 1:
                when = "Yesterday"
            else:
                when = day.strftime("%d %b")
        return text, when

    def _contact_card(self, c) -> ft.Container:
        display   = c.nickname or c.username
        is_active = c.username == self._active_contact and not self._room_id
        is_online = self._is_contact_online(c.username)
        verified  = c.verified if self.settings.security_mode == "e2ee" else False

        avatar = self._contact_card_avatar(display, verified, is_online)
        name = self._contact_card_name(display, is_active, verified)
        preview, when = self._last_message_snippet(c.username)

        btn_menu = ft.IconButton(
            ft.Icons.MORE_VERT, icon_size=14, icon_color=C.FAINT,
            tooltip="Contact options",
            on_click=lambda e, u=c.username: self._show_contact_menu(u),
            style=ft.ButtonStyle(padding=ft.Padding.all(2)),
        )

        # Two-line card: name (+ verify badge) with a compact time on the
        # right, and the latest message underneath - the presence dot on the
        # avatar already tells the online story, so no extra icons needed.
        top_row = ft.Row(
            [name, ft.Container(expand=True),
             *([ft.Text(when, size=9.5, color=C.FAINT, font_family=_t_FONTS["mono"])]
               if when else [])],
            spacing=6, vertical_alignment=ft.CrossAxisAlignment.CENTER,
        )
        lines: list = [top_row]
        if preview:
            lines.append(ft.Text(preview, size=11, color=C.MUTED, max_lines=1,
                                 overflow=ft.TextOverflow.ELLIPSIS))
        meta = ft.Column(lines, spacing=2, tight=True, expand=True)

        base_bg = C.CYAN + "1a" if is_active else C.ELEV + "00"
        border_color = C.CYAN if is_active else C.ELEV + "00"
        tile = ft.Container(
            content=ft.Row([avatar, meta, btn_menu],
                           spacing=10, vertical_alignment=ft.CrossAxisAlignment.CENTER),
            bgcolor=base_bg,
            padding=ft.Padding.symmetric(horizontal=8, vertical=8),
            border_radius=R.MD,
            border=ft.Border.all(1, border_color),
            on_click=lambda e, u=c.username: self._select_contact(u),
            on_long_press=lambda e, u=c.username: self._show_contact_menu(u),
            animate=_anim(D.FAST), ink=True,
            scale=1.0, animate_scale=_anim(D.FAST),
        )

        def on_hover(e, _t=tile, _active=is_active):
            if _active:
                return
            hov = e.data == "true"
            _t.bgcolor = C.ELEV2 if hov else C.ELEV + "00"
            _t.scale = 1.015 if hov else 1.0   # gentle lift, no glow
            try:
                _t.update()
            except Exception:
                pass
        tile.on_hover = on_hover
        # Accessibility: Semantics wrapper for screen readers
        try:
            return ft.Semantics(
                label=f"Chat with {display}, {'online' if is_online else 'offline'}{', verified' if verified else ''}",
                button=True, container=True, child=tile,
            )
        except Exception:
            return tile

    def _participant_card(self, username: str, state: str) -> ft.Control:
        online   = state == "connected"
        c        = get_contact(username)
        display  = (c.nickname if c and c.nickname else username)
        verified = bool(c and c.verified) if self.settings.security_mode == "e2ee" else False
        dot_color = C.GREEN if online else C.YELLOW

        avatar = ft.Stack([
            self._avatar(display, verified, 26),
            ft.Container(width=9, height=9, border_radius=R.PILL, bgcolor=dot_color,
                         border=ft.Border.all(2, C.PANEL), right=0, bottom=0),
        ], width=26, height=26)
        b = self._verify_badge(verified, size=11)
        name = ft.Row(
            [ft.Text(display, size=12, color=C.TEXT, weight=ft.FontWeight.W_500,
                     max_lines=1, overflow=ft.TextOverflow.ELLIPSIS),
             *([b] if b else [])],
            spacing=4, tight=True,
        )
        wifi = ft.Icon(ft.Icons.WIFI if online else ft.Icons.WIFI_OFF,
                       color=dot_color if online else C.MUTED, size=13)
        # Live link health: last heartbeat RTT for a connected peer, or the
        # in-flight state (connecting…/reconnecting…) so a stuck peer is visible.
        health = []
        rtt = self._peer_rtt.get(username)
        if online and rtt is not None:
            health = [ft.Text(f"{int(rtt)} ms", size=10, color=C.MUTED,
                              font_family=_t_FONTS["mono"])]
        elif state in ("new", "connecting", "checking"):
            health = [ft.Text("connecting…", size=10, color=C.YELLOW)]
        elif state in ("disconnected", "failed"):
            health = [ft.Text("reconnecting…", size=10, color=C.YELLOW)]
        # Membership badge (feature D) - only shown when membership is in play.
        member_badge = []
        if self.engine.room_creator_pubkey:
            if self.engine.is_member(username):
                member_badge = [ft.Icon(ft.Icons.WORKSPACE_PREMIUM, color=C.GREEN, size=13,
                                        tooltip="Verified member (creator-signed)")]
            else:
                member_badge = [ft.Icon(ft.Icons.HELP_OUTLINE, color=C.YELLOW, size=13,
                                        tooltip="Not a vouched member")]
        return ft.Container(
            content=ft.Row([avatar, name, ft.Container(expand=True), *health, *member_badge, wifi],
                           spacing=8, vertical_alignment=ft.CrossAxisAlignment.CENTER),
            padding=ft.Padding.symmetric(horizontal=6, vertical=4),
            border_radius=R.SM,
            on_long_press=lambda ev, u=username: self._show_contact_menu(u),
        )

    # ------------------------------------------------------------------
    # Chat header context (selected conversation)
    # ------------------------------------------------------------------

    def _update_chat_header_contact(self, username: str) -> None:
        c = get_contact(username)
        display  = (c.nickname or c.username) if c else username
        verified = bool(c and c.verified) if self.settings.security_mode == "e2ee" else False
        online   = self._is_contact_online(username)
        self.chat_header_lead.visible = False
        self.chat_header_avatar.visible = True
        self.chat_header_avatar.content = ft.Text(display[0].upper(), color=C.BTN_CYAN if verified else "#ffffff",
                                                  weight=ft.FontWeight.W_800)
        self.chat_header_avatar.gradient = self._avatar_gradient(verified)
        self.chat_header_title.value = display
        self.chat_header_status_dot.visible = True
        self.chat_header_status_text.visible = True
        # Health readout: prefer the LIVE WebRTC link state over bare presence,
        # so the header honestly says connecting / reconnecting / p2p + RTT.
        conn = self._peer_conn_state.get(username, "")
        rtt  = self._peer_rtt.get(username)
        if conn == "connected":
            label = "online · p2p"
            if rtt is not None:
                label += f" · {int(rtt)} ms"
            dot, color = C.GREEN, C.GREEN
        elif conn in ("new", "connecting", "checking"):
            label, dot, color = "connecting…", C.YELLOW, C.YELLOW
        elif conn in ("disconnected", "failed") and online:
            label, dot, color = "reconnecting…", C.YELLOW, C.YELLOW
        elif online:
            label, dot, color = "online", C.GREEN, C.GREEN
        else:
            label, dot, color = "offline", C.FAINT, C.MUTED
        self.chat_header_status_dot.bgcolor = dot
        self.chat_header_status_text.value = label
        self.chat_header_status_text.color = color

    def _update_chat_header_room(self, code: str) -> None:
        self.chat_header_lead.visible = False
        self.chat_header_avatar.visible = True
        self.chat_header_avatar.content = ft.Icon(ft.Icons.GROUPS, color=C.BTN_CYAN, size=18)
        self.chat_header_avatar.gradient = ft.LinearGradient(colors=[C.VIOLET, C.MAGENTA])
        self.chat_header_title.value = f"Room {code}"
        self.chat_header_status_dot.visible = False
        self.chat_header_status_text.visible = False

    # ------------------------------------------------------------------
    # Incoming-call banner
    # ------------------------------------------------------------------

    def _show_call_banner(self, sender: str, on_accept, on_reject) -> None:
        c = get_contact(sender)
        display  = (c.nickname or c.username) if c else sender
        verified = bool(c and c.verified) if self.settings.security_mode == "e2ee" else False
        avatar = ft.Stack([
            self._avatar(display, verified, 44),
            ft.Container(width=12, height=12, border_radius=R.PILL, bgcolor=C.GREEN,
                         border=ft.Border.all(2, C.ELEV), right=0, bottom=0,
                         shadow=_glow(C.GREEN, blur=10)),
        ], width=44, height=44)
        self.call_banner.content = ft.Row([
            ft.Container(content=ft.Icon(ft.Icons.PHONE_IN_TALK, color=C.GREEN, size=20),
                         padding=ft.Padding.all(10), border_radius=R.PILL, bgcolor=C.GREEN + "1f"),
            avatar,
            ft.Column([
                ft.Text("Incoming call", size=11, color=C.GREEN, weight=ft.FontWeight.W_800),
                ft.Text(display, size=16, color=C.TEXT, weight=ft.FontWeight.W_800,
                        max_lines=1, overflow=ft.TextOverflow.ELLIPSIS),
            ], spacing=0, tight=True),
            ft.Container(expand=True),
            ft.FilledButton("Accept", icon=ft.Icons.CALL, on_click=on_accept,
                            style=_filled_style(C.GREEN, C.BTN_GREEN)),
            ft.FilledButton("Decline", icon=ft.Icons.CALL_END, on_click=on_reject,
                            style=_filled_style(C.RED, C.BTN_RED)),
        ], spacing=14, vertical_alignment=ft.CrossAxisAlignment.CENTER)
        self.call_banner.visible = True
        self.call_banner.opacity = 0
        self.call_banner.scale = 0.98
        self.page.update()
        self._reveal(self.call_banner)
        if self._motion_ok:
            self._fire_and_forget(self._ring_pulse())

    def _hide_call_banner(self) -> None:
        self.call_banner.visible = False
        try:
            self.page.update()
        except Exception:
            pass

    async def _ring_pulse(self) -> None:
        on = True
        while self._ringing and self.call_banner.visible:
            try:
                self.call_banner.shadow = _glow(
                    C.GREEN + ("99" if on else "33"), blur=30 if on else 14, spread=-2)
                self.call_banner.update()
            except Exception:
                break
            on = not on
            await asyncio.sleep(0.6)

    def _show_contact_menu(self, username: str) -> None:
        c = get_contact(username)
        if not c:
            return

        def do_rename(e):
            self._close_dialog(menu)
            field = _neon_field(label="Nickname", value=c.nickname, autofocus=True)
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

            def doesnt_match(ev):
                # A mismatch means the key you're seeing is NOT your contact's -
                # possible man-in-the-middle, or you compared the wrong code.
                # Keep them unverified, turn on Verified-Only so nothing is sent
                # to them unintentionally, and offer to remove them.
                set_verified(username, False)
                self.settings.verified_only = True
                save_settings(self.settings)
                self._refresh_contact_list()
                self._refresh_participant_list()
                self._close_dialog(fp_dlg)

                def remove_and_close(ev2):
                    delete_contact(username)
                    if self._active_contact == username:
                        self._active_contact = ""
                        self.chat_log.controls.clear()
                        self._update_main_view()   # fall back to home
                    self._refresh_contact_list()
                    self._close_dialog(warn)

                warn = ft.AlertDialog(
                    title=ft.Text("⚠ Fingerprint does NOT match"),
                    content=ft.Text(
                        "If the fingerprint your contact reads out is different from the "
                        "one shown, the encryption key is not theirs. That can mean a "
                        "man-in-the-middle is intercepting the connection (or you compared "
                        "the wrong code).\n\nThey've been left UNVERIFIED and Verified-Only "
                        "mode is now ON, so nothing is sent to an unverified contact by "
                        "mistake. Do not call or message them until you can re-exchange a "
                        "fresh identity code over a trusted channel. You can remove them now."),
                    actions=[
                        ft.TextButton("Remove contact", on_click=remove_and_close,
                                      style=ft.ButtonStyle(color=C.RED)),
                        ft.TextButton("Keep (unverified)", on_click=lambda e2: self._close_dialog(warn)),
                    ],
                )
                self._show_dialog(warn)

            fp_dlg = ft.AlertDialog(
                title=ft.Text(f"Fingerprint - {c.nickname or username}"),
                content=ft.Column([
                    ft.Container(
                        content=ft.Text(fp, font_family="monospace", size=13, color=C.TEXT,
                                        selectable=True),
                        padding=ft.Padding.all(10), border_radius=R.MD,
                        bgcolor=C.ELEV, border=ft.Border.all(1, C.BORDER),
                    ),
                    ft.Text("Compare every character with your contact out-of-band "
                            "(call, in person, Signal). Only mark verified if they match "
                            "exactly.", size=11, color=C.MUTED),
                ], tight=True, spacing=8),
                actions=[
                    ft.FilledButton("Matches - Verify", icon=ft.Icons.VERIFIED,
                                    on_click=mark_verified, style=_filled_style(C.GREEN, C.BTN_GREEN)),
                    ft.TextButton("Doesn't match", on_click=doesnt_match,
                                  style=ft.ButtonStyle(color=C.RED)),
                    ft.TextButton("Close", on_click=lambda ev: self._close_dialog(fp_dlg)),
                ],
            )
            self._show_dialog(fp_dlg)

        def do_remove(e):
            delete_contact(username)
            if self._active_contact == username:
                self._active_contact = ""
                self.chat_log.controls.clear()
                self._update_main_view()   # fall back to home
            self._refresh_contact_list()
            self._close_dialog(menu)

        is_connected = username in self.engine.pcs

        def do_disconnect(e):
            self._close_dialog(menu)
            self._fire_and_forget(self.engine.remove_peer(username))
            self._log(f"[Disconnected from {username}]")
            self._refresh_contact_list()
            self.page.update()

        menu = ft.AlertDialog(
            title=ft.Text(c.nickname or username),
            content=ft.Column([
                ft.TextButton("Rename",           on_click=do_rename),
                ft.TextButton("View Fingerprint", on_click=do_fingerprint),
                *([ ft.TextButton(
                        "Disconnect",
                        icon=ft.Icons.LINK_OFF,
                        on_click=do_disconnect,
                        style=ft.ButtonStyle(color=C.YELLOW),
                    )] if is_connected else []),
                ft.TextButton("Remove Contact",   on_click=do_remove),
            ], tight=True, spacing=0),
        )
        self._show_dialog(menu)

    def _select_contact(self, username: str) -> None:
        self._active_contact = username
        self.engine.target_peer = username   # 1-to-1 sends/answers route to this peer
        self._history_offset = 0
        self.chat_log.controls.clear()
        self._msg_status.clear()             # transcript rebuilt → old glyph refs are dead
        self._last_bubble_sender = None
        self._last_msg_date = None
        self._chat_empty_hint = None
        self._load_more_history()
        self._refresh_contact_list()              # move the active highlight
        self._update_chat_header_contact(username)  # show selected conversation as context
        self._update_main_view()                  # leave home → show conversation
        self.page.update()
        # In 1-to-1 mode, selecting an online contact establishes the P2P link
        # (data channel) so you can chat/call without a separate step.
        if self.ws and not self._room_id and username not in self.engine.pcs:
            self._fire_and_forget(self._connect_to_contact(username))

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

    def _history_bubbles(self, msgs: list, default_sender: str) -> tuple[list, object, str | None]:
        """Build transcript controls for a page of history rows: date-separator
        chips at day boundaries + sender-grouped bubbles. Returns
        (controls, day_of_last_message, last_sender_prefix)."""
        controls: list = []
        prev_sender: str | None = None
        prev_day = None
        for m in msgs:
            is_sent = m["direction"] == "sent"
            prefix  = "You" if is_sent else (m.get("sender") or default_sender or "Peer")
            day = _msg_day(m.get("timestamp"))
            if day is not None and day != prev_day:
                controls.append(self._date_chip(_day_label(day)))
                prev_day = day
                prev_sender = None            # new day breaks bubble grouping
            controls.append(self._make_bubble(prefix, m["content"], bool(m["verified"]), is_sent,
                                              ts=m.get("timestamp"), grouped=(prefix == prev_sender)))
            prev_sender = prefix
        return controls, prev_day, prev_sender

    def _merge_history_page(self, msgs: list, default_sender: str, load_more_cb) -> None:
        """Shared tail of both history loaders: build the page's controls,
        maintain the grouping/date cursors, show the empty-conversation hint,
        dedupe the day chip at a prepend boundary, and re-add 'load more'."""
        controls, last_day, last_sender = self._history_bubbles(msgs, default_sender)
        if self._history_offset == 0:
            # Initial page: the newest bubble seeds the live cursors.
            self._last_bubble_sender = last_sender
            self._last_msg_date = last_day
            if not msgs:
                hint = self._empty_state(
                    ft.Icons.LOCK_OUTLINE, "No messages yet",
                    "Say hello - everything here is end-to-end encrypted and peer-to-peer.")
                self._chat_empty_hint = hint
                controls = [hint]
        elif controls and self.chat_log.controls and last_day is not None:
            # Prepending older messages: if the previously-top control is a
            # date chip for the same day this block ends on, it's now redundant.
            tag = getattr(self.chat_log.controls[0], "data", None)
            if isinstance(tag, tuple) and len(tag) == 2 and tag[0] == "date_chip" \
                    and tag[1] == _day_label(last_day):
                self.chat_log.controls.pop(0)

        self.chat_log.controls = controls + self.chat_log.controls
        self._bulk_load = False
        self._history_offset += len(msgs)
        if len(msgs) == 100:
            self.chat_log.controls.insert(0, ft.TextButton(LOAD_MORE_TXT, on_click=load_more_cb))

    def _load_more_history(self) -> None:
        msgs = read_messages(
            self._active_contact, self.history_key,
            self.settings.security_mode, limit=100, offset=self._history_offset,
        )
        self._bulk_load = True
        if self._history_offset > 0 and self.chat_log.controls:
            if isinstance(self.chat_log.controls[0], ft.TextButton) and self.chat_log.controls[0].text == LOAD_MORE_TXT:
                self.chat_log.controls.pop(0)

        def load_more(e):
            self._load_more_history()
            self.page.update()
        self._merge_history_page(msgs, self._active_contact, load_more)

    def _select_room(self) -> None:
        if not self._room_id:
            return
        self._active_contact = ""
        self._history_offset = 0
        self.chat_log.controls.clear()
        self._msg_status.clear()             # transcript rebuilt → old glyph refs are dead
        self._last_bubble_sender = None
        self._last_msg_date = None
        self._chat_empty_hint = None
        self._load_more_room_history()
        self._update_main_view()                  # leave home → show conversation
        self.page.update()

    def _load_more_room_history(self) -> None:
        msgs = read_room_messages(
            self._room_id, self.history_key,
            self.settings.security_mode, limit=100, offset=self._history_offset,
        )
        self._bulk_load = True
        if self._history_offset > 0 and self.chat_log.controls:
            if isinstance(self.chat_log.controls[0], ft.TextButton) and self.chat_log.controls[0].text == LOAD_MORE_TXT:
                self.chat_log.controls.pop(0)

        def load_more(e):
            self._load_more_room_history()
            self.page.update()
        self._merge_history_page(msgs, "", load_more)

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
        try:
            mid = await self.engine.send_chat(text)
        except RuntimeError as ex:
            self._toast(str(ex), "error")
            return
        contact = self._room_id if self._room_id else self._active_contact
        if contact and not (self._ephemeral and self._room_id):  # ephemeral → memory only
            write_message(
                contact, "sent", "chat", text,
                self.history_key, self.settings.security_mode,
                room_id=self._room_id or None,
                sender=None,
            )
        # 1-to-1 sends return a message id → show a live delivery glyph:
        # queued (peer offline, outbox) / sent (on the wire) / delivered (acked).
        status = None
        if mid and not self._room_id:
            status = "sent" if self.engine.peer_channel_open(self._active_contact) else "queued"
            if status == "queued":
                self._toast("Contact is offline - message queued, will send on reconnect", "warn")
        self._append_to_log("sent", text, False, msg_id=mid if status else None, status=status)
        self.msg_input.value = ""
        if self._motion_ok:
            if self._flash_task and not self._flash_task.done():
                self._flash_task.cancel()
            self._flash_task = asyncio.ensure_future(self._send_flash())
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
        try:
            files = await picker.pick_files()
            if not files:
                return
            self.file_progress.visible = True
            self.file_progress.value   = 0
            self.page.update()
            try:
                await self.engine.send_file(files[0].path, target=peer)
                self._log(f"[File sent] {Path(files[0].path).name}")
            except (RuntimeError, OSError) as ex:
                # Surface the failure instead of letting it bubble to the loop
                # exception handler (which auto-restarts the whole app).
                self._toast(f"File send failed: {ex}", "error")
            finally:
                self.file_progress.visible = False
                self.page.update()
        finally:
            try:
                self.page.services.remove(picker)
            except ValueError:
                pass
            try:
                self.page.update()
            except Exception:
                pass

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
        # Multiple peers - present a chooser
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
        try:
            dest = await picker.save_file(file_name=fname)
            if dest:
                shutil.copyfile(tmp_path, dest)
        finally:
            try:
                self.page.services.remove(picker)
            except ValueError:
                pass
            try:
                self.page.update()
            except Exception:
                pass
        try:
            Path(tmp_path).unlink()
        except OSError:
            pass

    # ------------------------------------------------------------------
    # Calls & screen share
    # ------------------------------------------------------------------

    async def _start_room_call(self) -> None:
        hub = self.engine.current_hub()
        self._log(f"[Voice Call] Starting room call. Hub: {hub}")
        if hub == self.engine.my_username:
            # We are the hub: send our mic to every connected member.
            for peer in self.engine.pcs:
                if self.engine.pcs[peer].connectionState == "connected":
                    await self.engine.start_voice_call(peer)
        elif hub and self.engine.pcs.get(hub):
            # Non-hub: send our mic only to the hub; it fans out to the others.
            await self.engine.start_voice_call(hub)

    async def _start_direct_call(self, ws_send) -> bool:
        if not self._active_contact:
            return False
        self._log(f"[Voice Call] Starting direct call with {self._active_contact}")
        if not self._is_allowed(self._active_contact):
            self._block_unverified(self._active_contact)
            return False
        if not self.engine.pcs.get(self._active_contact):
            await self.engine.create_offer(self._active_contact, ws_send)
        await self.engine.start_voice_call(self._active_contact)
        return True

    async def _start_call(self, e) -> None:
        _ = e
        if not self.ws:
            return

        async def ws_send(payload: dict):
            await self.ws.send(json.dumps(payload))

        try:
            if self._room_id:
                await self._start_room_call()
            else:
                ok = await self._start_direct_call(ws_send)
                if not ok:
                    return
        except Exception as ex:
            self._log(f"[Error] Failed to start voice call: {ex}")
            self._toast("Could not access microphone. Please check your audio settings or permissions.", "error")
            return

        self._in_voice_call = True
        if self._room_id:
            self._room_call_active = True
            await self._broadcast_call_active(ws_send)
        self._refresh_call_controls()
        self.btn_hangup.disabled = False
        self.btn_mute.disabled   = False
        self._update_call_status(True)
        self.page.update()

    async def _start_room_screen(self) -> None:
        hub = self.engine.current_hub()
        self._log(f"[Screen Share] Starting room screen share. Hub: {hub}")
        if hub == self.engine.my_username:
            for peer in self.engine.pcs:
                if self.engine.pcs[peer].connectionState == "connected":
                    await self.engine.start_screen_share(peer)
        elif hub and self.engine.pcs.get(hub):
            await self.engine.start_screen_share(hub)

    async def _start_direct_screen(self, ws_send) -> bool:
        if not self._active_contact:
            return False
        self._log(f"[Screen Share] Starting direct screen share with {self._active_contact}")
        if not self._is_allowed(self._active_contact):
            self._block_unverified(self._active_contact)
            return False
        if not self.engine.pcs.get(self._active_contact):
            await self.engine.create_offer(self._active_contact, ws_send)
        await self.engine.start_screen_share(self._active_contact)
        return True

    async def _start_screen(self, _e=None) -> None:
        if not self.ws:
            return

        async def ws_send(payload: dict):
            await self.ws.send(json.dumps(payload))

        if self._room_id:
            await self._start_room_screen()
        else:
            ok = await self._start_direct_screen(ws_send)
            if not ok:
                return

        self._in_screen_share = True
        if self._room_id:
            self._room_call_active = True
            await self._broadcast_call_active(ws_send)
        self._refresh_call_controls()
        self.btn_hangup.disabled = False
        self.btn_mute.disabled   = False
        self.btn_screen.icon_color = C.CYAN         # active sharing state
        self.btn_screen.tooltip    = "Stop sharing"
        self._update_call_status(True)
        self._log("[Screen sharing started] - tip: start a call too if you also want to talk.")
        self.page.update()

    async def _toggle_screen(self, e) -> None:
        if self._in_screen_share:
            await self._stop_screen()
        else:
            await self._start_screen(e)

    async def _stop_screen(self) -> None:
        # Stop just the screen track - voice (if any) keeps flowing.
        if self._room_id:
            for peer in self.engine.pcs:
                await self.engine.stop_screen_share(peer)
        else:
            await self.engine.stop_screen_share(self._active_contact)
        self._in_screen_share = False
        self.btn_screen.icon_color = C.SUBTLE
        self.btn_screen.tooltip    = SHARE_SCREEN_TXT
        self._update_call_status(True)   # may still be in a voice call
        self._log("[Screen sharing stopped]")
        self._refresh_call_controls()
        self.page.update()

    def _toggle_mute(self, e) -> None:
        self._muted = not self._muted
        self.engine.set_mic_muted(self._muted)
        self.btn_mute.icon       = ft.Icons.MIC_OFF if self._muted else ft.Icons.MIC
        self.btn_mute.icon_color = C.RED if self._muted else C.SUBTLE
        self.btn_mute.tooltip    = "Unmute mic" if self._muted else "Mute mic"
        self._set_mute_banner(self._muted)
        self.page.update()

    def _set_mute_banner(self, muted: bool) -> None:
        if muted:
            self.mute_banner.visible = True
            self.mute_banner.opacity = 1
        else:
            self.mute_banner.opacity = 0
            self._fire_and_forget(self._hide_mute_banner_delayed())
        self.page.update()

    async def _hangup(self, e) -> None:
        # Stop screen share cleanly before hanging up so the screen source is
        # released and peers receive a renegotiation (track removed gracefully).
        if self._in_screen_share:
            await self._stop_screen()
        self.engine.hangup()
        # Tear down any INCOMING screen shares too - a hung-up call must never
        # leave a peer's screen visible (tile / full screen / PiP).
        self._clear_all_video()
        sounds.stop_loop()
        sounds.play("call_end")
        self._muted = False
        self._in_voice_call   = False
        self._in_screen_share = False
        self.btn_mute.icon       = ft.Icons.MIC
        self.btn_mute.icon_color = C.SUBTLE
        self._set_mute_banner(False)
        self.btn_hangup.disabled = True
        self.btn_mute.disabled   = True
        self.btn_call.disabled   = True
        self.btn_screen.disabled = True
        self.btn_screen.icon_color = C.SUBTLE
        self.btn_screen.tooltip    = SHARE_SCREEN_TXT
        self._update_call_status(False)
        self._log("[Hung up]")
        self._refresh_call_controls()
        self.page.update()

    # ------------------------------------------------------------------
    # Video tiles
    # ------------------------------------------------------------------

    async def _update_video_tile(self, sender: str, img) -> None:
        """Encode a BGR video frame to JPEG in a thread pool, then update the
        tile control. Offloading avoids blocking the async event loop."""
        try:
            quality = self._jpeg_quality
            # Fullscreen/PiP renders the raw frame at full resolution - JPEG 55
            # creates very visible artifacts on text and UI edges at that size.
            # Bump to at least 85 whenever the overlay is active for this sender.
            is_enlarged = (sender == self._fullscreen_sender and
                           (self.screen_overlay.visible or self.pip_overlay.visible))
            if is_enlarged:
                quality = max(85, quality)
            def encode():
                if cv2 is not None:
                    _, buf = cv2.imencode(".jpg", img, [int(cv2.IMWRITE_JPEG_QUALITY), quality])
                    return base64.b64encode(buf).decode()
                else:
                    rgb = np.ascontiguousarray(img[:, :, ::-1])
                    bio = BytesIO()
                    Image.fromarray(rgb).save(bio, format="JPEG", quality=quality)
                    return base64.b64encode(bio.getvalue()).decode()
            b64 = await asyncio.to_thread(encode)
            if sender not in self._video_tiles:
                self._add_video_tile(sender)
            tile = self._video_tiles[sender]
            tile.src = "data:image/jpeg;base64," + b64
            tile.update()
            if self._fullscreen_sender == sender:
                if self.screen_overlay.visible:
                    self._fs_img.src = tile.src
                    self._fs_img.update()
                if self.pip_overlay.visible:
                    self._pip_img.src = tile.src
                    self._pip_img.update()
        except Exception as ex:
            import logging
            logging.getLogger("helucryptic.client").debug("video tile update failed: %s", ex)

    def _add_video_tile(self, sender: str) -> ft.Image:
        img  = ft.Image(
            src="", width=240, height=135,
            fit=ft.BoxFit.COVER, gapless_playback=True,
            border_radius=ft.BorderRadius.all(R.MD),
        )
        name_chip = ft.Container(
            content=ft.Row([
                _dot(C.GREEN, size=7, glow=True),
                ft.Text(sender, size=10, color=C.WHITE, weight=ft.FontWeight.W_600),
            ], spacing=6, tight=True),
            bgcolor=C.BLACK_AA, padding=ft.Padding.symmetric(horizontal=8, vertical=4),
            border_radius=ft.BorderRadius.all(R.PILL),
            margin=ft.Margin.all(8),
        )
        fs_hint = ft.Container(
            content=ft.Icon(ft.Icons.FULLSCREEN, color=C.WHITE, size=16),
            bgcolor=C.BLACK_AA, padding=ft.Padding.all(4),
            border_radius=ft.BorderRadius.all(R.PILL), margin=ft.Margin.all(8),
        )
        tile = ft.Container(
            content=ft.Stack([
                img,
                ft.Container(content=name_chip, alignment=ft.Alignment.BOTTOM_LEFT),
                ft.Container(content=fs_hint, alignment=ft.Alignment.TOP_RIGHT),
            ]),
            width=248, height=143, bgcolor=C.ELEV,
            border=ft.Border.all(1, C.BORDER2),
            border_radius=ft.BorderRadius.all(R.MD),
            padding=ft.Padding.all(2),
            shadow=_glow(C.CYAN + "33", blur=18, spread=-2),
            data=sender,
            on_click=lambda e, u=sender: self._open_fullscreen(u),   # click → full screen
            tooltip=f"View {sender}'s screen full screen",
            opacity=0, scale=0.96,
            animate_opacity=_anim(D.MED), animate_scale=_anim(D.MED),
        )
        self._video_tiles[sender] = img
        self._tile_row.controls.append(tile)
        self._tile_row.visible = True
        self.page.update()
        self._reveal(tile)
        self._notify_sharing(sender)
        if self.screen_overlay.visible:
            self._rebuild_share_switcher()
        return img

    def _remove_video_tile(self, sender: str) -> None:
        self._video_tiles.pop(sender, None)
        self._tile_row.controls = [
            c for c in self._tile_row.controls
            if getattr(c, "data", None) != sender
        ]
        if not self._tile_row.controls:
            self._tile_row.visible = False
        if self._fullscreen_sender == sender:
            # the stream we were viewing ended - switch to another or close
            others = [s for s in self._video_tiles if s != sender]
            if others:
                self._open_fullscreen(others[0])
            else:
                self._close_fullscreen()
        elif self.screen_overlay.visible:
            self._rebuild_share_switcher()
        self.page.update()

    # ------------------------------------------------------------------
    # Full-screen screen-share viewer + sharing notification
    # ------------------------------------------------------------------

    def _notify_sharing(self, sender: str) -> None:
        self._log(f"🖥 {sender} is sharing their screen - click their tile to view it full screen.")
        try:
            sounds.play("message")
        except Exception:
            pass

    def _open_fullscreen(self, sender: str) -> None:
        if sender not in self._video_tiles:
            return
        self._fullscreen_sender = sender
        # Clicking a tile (or a switcher chip) ALWAYS maximizes to full screen,
        # leaving PiP if it happened to be active. (Previously, once PiP had been
        # used, clicks only updated PiP and full screen never reappeared.)
        self.pip_overlay.visible = False
        self._fs_title.value = f"{sender}'s screen"
        self._fs_img.src = self._video_tiles[sender].src or ""
        self.screen_overlay.visible = True
        try:
            self.screen_overlay.update()
        except Exception:
            pass
        self._rebuild_share_switcher()
        self.page.update()

    def _clear_all_video(self) -> None:
        """Tear down ALL incoming screen tiles and exit full screen / PiP. Used
        on hang up / call end so a screen share can never linger after a call."""
        self._video_tiles.clear()
        self._tile_row.controls = []
        self._tile_row.visible = False
        self._close_fullscreen()   # hides overlay + pip and clears fullscreen_sender
        try:
            self.page.update()
        except Exception:
            pass

    def _show_volume(self, e=None) -> None:
        cur = float(getattr(self.engine, "_volume", 4.0))
        val = ft.Text(f"{cur:.1f}×", size=12, color=C.SUBTLE,
                      text_align=ft.TextAlign.CENTER)

        def on_change(ev):
            self.engine.set_volume(ev.control.value)
            val.value = f"{ev.control.value:.1f}×"
            try:
                val.update()
            except Exception:
                pass

        slider = ft.Slider(min=0, max=8, divisions=16, value=cur,
                           expand=True, active_color=C.CYAN, on_change=on_change)
        dlg = ft.AlertDialog(
            title=ft.Text("Call volume"),
            content=ft.Column([
                ft.Text("Adjust remote participant volume - applies instantly.",
                        size=12, color=C.SUBTLE),
                ft.Row([ft.Icon(ft.Icons.VOLUME_MUTE, color=C.MUTED, size=18),
                        slider,
                        ft.Icon(ft.Icons.VOLUME_UP, color=C.MUTED, size=18)],
                       vertical_alignment=ft.CrossAxisAlignment.CENTER),
                val,
            ], tight=True, width=360, spacing=12),
            actions=[ft.TextButton("Done", on_click=lambda ev: self._close_dialog(dlg))],
        )
        self._show_dialog(dlg)

    def _close_fullscreen(self) -> None:
        self._fullscreen_sender = ""
        if getattr(self, "screen_overlay", None) is not None:
            self.screen_overlay.visible = False
        if getattr(self, "pip_overlay", None) is not None:
            self.pip_overlay.visible = False
        try:
            self.page.update()
        except Exception:
            pass

    def _minimize_to_pip(self) -> None:
        if not self._fullscreen_sender:
            return
        self.screen_overlay.visible = False
        self._pip_title.value = f"{self._fullscreen_sender}'s screen"
        self._pip_img.src = self._fs_img.src or ""
        w = self.page.window.width or 1180
        h = self.page.window.height or 760
        self.pip_overlay.left = w - 360
        self.pip_overlay.top = h - 280
        self.pip_overlay.visible = True
        self.page.update()

    def _expand_from_pip(self) -> None:
        if not self._fullscreen_sender:
            return
        self.pip_overlay.visible = False
        self._fs_img.src = self._pip_img.src or ""
        self.screen_overlay.visible = True
        try:
            self.screen_overlay.update()
        except Exception:
            pass
        self._rebuild_share_switcher()
        self.page.update()

    def _rebuild_share_switcher(self) -> None:
        # One chip per active incoming stream - tap to switch which is maximized.
        self._fs_switcher.controls = [
            ft.FilledButton(
                s, on_click=lambda e, u=s: self._open_fullscreen(u),
                style=_filled_style(C.MAGENTA if s == self._fullscreen_sender else C.ELEV2,
                                    C.BTN_CYAN if s == self._fullscreen_sender else C.TEXT, pad_h=12, pad_v=8),
            )
            for s in self._video_tiles
        ]

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
            # real dialog instead - the username is part of the identity code.
            warn = ft.AlertDialog(
                title=ft.Text("Set a username first"),
                content=ft.Text("Enter your username in the sidebar before showing "
                                "your identity code - it's part of the code you share."),
                actions=[ft.TextButton("OK", on_click=lambda ev: self._close_dialog(warn))],
            )
            self._show_dialog(warn)
            return
        code = identity.encode_identity(
            uname, self.keys["x25519_public"], self.keys["ed25519_public"])
        controls = []
        try:
            # Flet 0.85 dropped Image.src_base64 - base64 must go through src as
            # a data URI.
            controls.append(ft.Image(
                src="data:image/png;base64," + identity.qr_png_base64(code),
                width=220, height=220))
        except Exception:
            pass  # QR optional; the text code below is the source of truth
        my_fp = compute_fingerprint(self.keys["x25519_public"])
        controls += [
            ft.Text("Your verification code (share with a contact):",
                    size=12, color=C.MUTED),
            _neon_field(value=code, read_only=True, multiline=True, min_lines=2,
                         max_lines=4, width=360, text_size=11),
            ft.Text("They paste this into 'Import from code'.", size=11, color=C.MUTED),
            ft.Divider(color=C.BORDER),
            ft.Text("Your fingerprint (read this aloud to your contact):",
                    size=12, color=C.CYAN, weight=ft.FontWeight.W_700),
            ft.Container(
                content=ft.Text(my_fp, font_family="monospace", size=13, color=C.TEXT,
                                selectable=True),
                padding=ft.Padding.all(10), border_radius=R.MD, width=360,
                bgcolor=C.ELEV, border=ft.Border.all(1, C.BORDER),
            ),
            ft.Text("Your contact long-presses you → View Fingerprint and checks it "
                    "matches this, character for character, before clicking "
                    "Matches - Verify.", size=11, color=C.MUTED),
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
        field = _neon_field(label="Paste verification code (HELU1:…)",
                             autofocus=True, multiline=True, min_lines=2, max_lines=4, width=360)
        error = ft.Text("", color=C.RED, size=11, visible=False)

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
                        "you out-of-band:", size=12, color=C.SUBTLE),
                ft.Text(info["fingerprint"], font_family="monospace", size=12, color=C.TEXT,
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
        pw1 = _neon_field(label="Backup passphrase", password=True,
                           can_reveal_password=True, width=280, dense=True)
        pw2 = _neon_field(label="Confirm passphrase", password=True,
                           width=280, dense=True)
        incl = ft.Checkbox(label="Include message history", value=False)
        err = ft.Text("", color=C.RED, size=11, visible=False)

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
            try:
                await picker.save_file(file_name="helucryptic-backup.helu", src_bytes=blob)
                self._log("Encrypted backup saved.")
            finally:
                try:
                    self.page.services.remove(picker)
                except ValueError:
                    pass
                try:
                    self.page.update()
                except Exception:
                    pass

        dlg = ft.AlertDialog(
            title=ft.Text("Backup profile"),
            content=ft.Column([
                ft.Text("Encrypts keys, contacts and settings with your passphrase.",
                        size=11, color=C.MUTED),
                pw1, pw2, incl, err,
            ], tight=True, spacing=8),
            actions=[
                ft.TextButton("Create backup", on_click=do_backup),
                ft.TextButton("Cancel", on_click=lambda ev: self._close_dialog(dlg)),
            ],
        )
        self._show_dialog(dlg)

    def _show_restore(self, e=None) -> None:
        pw = _neon_field(label="Backup passphrase", password=True,
                          can_reveal_password=True, width=280, dense=True)
        err = ft.Text("", color=C.RED, size=11, visible=False)

        async def do_restore(ev):
            if not pw.value:
                err.value = "Enter the passphrase"; err.visible = True; self.page.update(); return
            picker = ft.FilePicker()
            self.page.services.append(picker)
            self.page.update()
            try:
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
                self._refresh_contact_list()
                self._close_dialog(dlg)
                self._log(f"Restored: {', '.join(restored)}. Previous files saved as .bak")
            finally:
                try:
                    self.page.services.remove(picker)
                except ValueError:
                    pass
                try:
                    self.page.update()
                except Exception:
                    pass

        dlg = ft.AlertDialog(
            title=ft.Text("Restore profile"),
            content=ft.Column([
                ft.Text("Choose a .helu backup. Existing files are saved as .bak first.",
                        size=11, color=C.MUTED),
                pw, err,
            ], tight=True, spacing=8),
            actions=[
                ft.TextButton("Choose file & restore", on_click=do_restore),
                ft.TextButton("Cancel", on_click=lambda ev: self._close_dialog(dlg)),
            ],
        )
        self._show_dialog(dlg)

    def _show_wipe(self, e=None) -> None:
        phrase = _neon_field(label='Type WIPE to confirm', width=280, dense=True, autofocus=True)
        err = ft.Text("", color=C.RED, size=11, visible=False)

        async def do_wipe(ev):
            if phrase.value.strip() != "WIPE":
                err.value = 'Type WIPE exactly to confirm'; err.visible = True; self.page.update(); return
            # Close active connections first, then delete local data.
            if self.ws:
                try:
                    await self.ws.close()
                except Exception:
                    pass
            for p in self.engine.pcs:
                try:
                    await self.engine.remove_peer(p)
                except Exception:
                    pass
            removed = backup.emergency_wipe()
            self._close_dialog(dlg)
            self.page.controls.clear()
            self.page.add(ft.Container(
                expand=True,
                alignment=ft.Alignment.CENTER,
                gradient=ft.LinearGradient(
                    begin=ft.Alignment.TOP_CENTER, end=ft.Alignment.BOTTOM_CENTER,
                    colors=[C.BG, "#1a0410"],
                ),
                padding=ft.Padding.all(40),
                content=ft.Column([
                    ft.Container(
                        content=ft.Icon(ft.Icons.DELETE_FOREVER, color=C.RED, size=44),
                        padding=ft.Padding.all(18), border_radius=R.PILL,
                        bgcolor=C.RED + "1a", shadow=_glow(C.RED + "66", blur=30),
                    ),
                    ft.Text("Local profile wiped", size=22, weight=ft.FontWeight.BOLD, color=C.WHITE),
                    ft.Text(f"Removed: {', '.join(removed) or '(nothing)'}", size=12, color=C.SUBTLE),
                    ft.Text("Please restart helucryptic. A new identity will be created; "
                            "contacts will need to re-verify you.", size=12, color=C.MUTED,
                            text_align=ft.TextAlign.CENTER),
                ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=14),
            ))
            self.page.update()

        dlg = ft.AlertDialog(
            title=ft.Text("⚠ Emergency wipe"),
            content=ft.Column([
                ft.Text("This permanently deletes your identity keys, contacts, settings "
                        "and message history from this device. It cannot be undone, and "
                        "contacts will need to re-verify you.", color=C.TEXT, size=12),
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

    def _render_diagnostics_state(self) -> str:
        d = self.engine.get_diagnostics()
        ws_status = "connected" if (self.ws and self.ws.open) else "disconnected"
        lines = [
            "helucryptic - client_claude",
            f"Data dir   : {paths.DATA_DIR}"
            + ("  (portable)" if paths.is_portable() else ""),
            f"Signaling  : {ws_status}",
            f"Server URL : {_redact_url(self.settings.signaling_url)}",
            f"Username   : {d['my_username'] or '(not set)'}",
            f"Security   : {d['security_mode']}",
            f"Room       : {d['room_id'] or '(none)'}"
            + (f'   hub={d["hub"] or "?"}' if d["room_id"] else ""),
            f"TURN       : {'configured' if d['turn_configured'] else 'not configured'}",
            f"NAT type   : {d.get('nat_type', '(not probed)')}"
            + (f"  ({d['nat_summary']})" if d.get('nat_summary') else ""),
            f"Predicted  : {d.get('predicted_srflx') or '(none)'}",
            f"Peers      : {d['num_peers']}",
            f"Last error : {d['last_error'] or '(none)'}",
            "",
            "Peer connections:",
        ]
        if not d["peers"]:
            lines.append("  (none)")
        for p in d["peers"]:
            ok = "OK" if (p["hello_ok"] and p["session_key"]) else "…"
            lines.append(f"  • {p['peer']}  [{ok}]")
            lines.append(f"      conn={p['connection']}   signaling={p['signaling']}")
            lines.append(f"      ice={p['ice']}   gathering={p['ice_gathering']}   dc={p['datachannel']}")
            lines.append(f"      hello_sent={p['hello_sent']}  hello_ok={p['hello_ok']}  session_key={p['session_key']}")
            lines.append(f"      rtt={p.get('rtt_ms', 0)}ms   outbox={p.get('outbox', 0)} queued")
        return "\n".join(lines)

    def _render_diagnostics_log(self) -> str:
        return "\n".join(list(LOG_BUFFER)[-300:]) or "(no log captured yet)"

    def _show_diagnostics(self, e) -> None:
        self._diag_open = True
        body = ft.Text("", size=12, color=C.TEXT, selectable=True, font_family="monospace")
        logview = ft.Text("", size=11, color=C.SUBTLE, selectable=True, font_family="monospace")

        async def refresh_loop():
            while self._diag_open:
                try:
                    body.value = self._render_diagnostics_state()
                    logview.value = self._render_diagnostics_log()
                    body.update()
                    logview.update()
                except Exception:
                    break
                await asyncio.sleep(1)

        async def copy_all(ev):
            await self._set_clipboard(self._render_diagnostics_state() + "\n\n===== LOG =====\n" + self._render_diagnostics_log())
            self._log("Diagnostics + log copied to clipboard.")

        def close(ev):
            self._diag_open = False
            self._close_dialog(dlg)

        body.value = self._render_diagnostics_state()
        logview.value = self._render_diagnostics_log()

        dlg = ft.AlertDialog(
            title=ft.Text(DIAGNOSTICS_TXT),
            content=ft.Container(width=560, height=460, content=ft.Column([
                ft.Container(
                    expand=True,
                    content=ft.Column([body], scroll=ft.ScrollMode.AUTO, expand=True),
                    padding=ft.Padding.all(10),
                    bgcolor=C.ELEV, border_radius=R.MD, border=ft.Border.all(1, C.BORDER),
                ),
                ft.Text("Live log (newest last) - captured for .exe builds:",
                        size=11, color=C.MUTED),
                ft.Container(
                    expand=True, padding=ft.Padding.all(10),
                    bgcolor=C.BG, border_radius=R.MD, border=ft.Border.all(1, C.BORDER),
                    content=ft.Column([logview], scroll=ft.ScrollMode.AUTO, expand=True),
                ),
            ], spacing=8)),
            actions=[
                ft.TextButton("Copy all (incl. log)", on_click=copy_all),
                ft.TextButton("Close", on_click=close),
            ],
        )
        self._show_dialog(dlg)
        self._fire_and_forget(refresh_loop())

    def _purge_ephemeral(self) -> None:
        """Auto-destruct (feature H): wipe an ephemeral room's in-RAM traces -
        messages, video tiles, session/room keys, and room references in the
        captured-log buffer. Disk was never written for these rooms."""
        if not self._ephemeral:
            return
        rid = self._room_id
        self.chat_log.controls.clear()
        # Iterate over a snapshot: _remove_video_tile mutates _video_tiles,
        # which raised "dict changed size during iteration" mid-purge.
        for sender in list(self._video_tiles):
            self._remove_video_tile(sender)
        if self._tile_row is not None:
            self._tile_row.controls.clear()
            self._tile_row.visible = False
        self.engine.purge_secrets()
        self._room_psk = None
        if rid:
            kept = [ln for ln in LOG_BUFFER if rid not in ln]
            LOG_BUFFER.clear()
            LOG_BUFFER.extend(kept)
        self._ephemeral = False
        self._log("🔥 Ephemeral room purged from memory - no trace on disk.")
        try:
            self.page.update()
        except Exception:
            pass

    async def _switch_profile(self, name: str) -> None:
        """Hot-swap to another profile: stop this session, re-point the data dir
        to the profile's sandbox, and rebuild the app against its keys/contacts/
        history - without restarting the process."""
        self._log(f"Switching to profile '{name}'…")
        self._purge_ephemeral()   # don't carry an ephemeral room across profiles
        # Stop this session's background loops + live connections.
        for t in self._bg_tasks:
            t.cancel()
        self._bg_tasks = []
        for t in self._running_tasks:
            t.cancel()
        self._running_tasks.clear()
        self._diag_open = False
        sounds.stop_loop()
        if self._pf_manager is not None:
            try:
                await self._pf_manager.stop()
            except Exception:
                pass
        if self.ws:
            try:
                await self.ws.close()
            except Exception:
                pass
        for p in self.engine.pcs:
            try:
                await self.engine.remove_peer(p)
            except Exception:
                pass
        # Activate the profile, re-point every data path, and rebuild the app.
        try:
            profiles.set_active(name)
            profiles.repoint_data_dir(profiles.active_dir())
        except Exception as ex:
            print(f"[profile] switch failed: {ex}", flush=True)
            return
        # Actually REBUILD the app against the new profile's keys/contacts/
        # history. Previously this method stopped here, leaving a dead UI
        # (all loops cancelled, ws closed) until the process was restarted.
        try:
            self.page.controls.clear()
            self.page.update()
        except Exception:
            pass
        new_app = HelucrypticApp(self.page)
        new_app._server_password = self._server_password
        new_app._refresh_contact_list()

        async def _handle_disconnect(e):
            await new_app.shutdown()
        self.page.on_disconnect = _handle_disconnect
        print(f"[profile] switched to '{name}' - app rebuilt in-process", flush=True)

    def _settings_on_retention_change(self, ev) -> None:
        self._settings_custom_days.visible = self._settings_retention_dd.value == "custom"
        self._settings_custom_error.visible = False
        self.page.update()

    def _settings_on_profile_change(self, ev) -> None:
        self._settings_overclock_warn.visible = self._settings_profile_dd.value == "overclock"
        self.page.update()

    async def _settings_do_test_turn(self, ev) -> None:
        from webrtc_engine import test_turn
        self._settings_turn_result.value = "Testing…"
        self._settings_turn_result.color = C.SUBTLE
        self.page.update()
        ok, msg = await test_turn(
            self._settings_turn_url_f.value.strip(),
            self._settings_turn_user_f.value.strip(),
            self._settings_turn_pass_f.value
        )
        self._settings_turn_result.value = msg
        self._settings_turn_result.color = C.GREEN if ok else C.RED
        self.page.update()

    async def _settings_do_pf_autodetect(self, ev) -> None:
        self._settings_pf_result.value = "Detecting…"
        self._settings_pf_result.color = C.SUBTLE
        self.page.update()
        primary = await asyncio.to_thread(discover_gateway)
        candidates = discover_gateway_candidates(primary)
        gw = candidates[0]
        ip = await asyncio.to_thread(local_ip_for, gw)
        port = None
        for candidate in candidates:
            port = await asyncio.to_thread(request_mapping_over_socket, candidate)
            if port is not None:
                break
        if port and ip:
            self._settings_pf_port_f.value = str(port)
            self._settings_pf_result.value = f"Got port {port} on {ip}"
            self._settings_pf_result.color = C.GREEN
        else:
            self._settings_pf_result.value = "No NAT-PMP mapping - enter the port manually"
            self._settings_pf_result.color = C.RED
        self.page.update()

    async def _settings_do_pf_test(self, ev) -> None:
        from webrtc_engine import test_forwarded_port
        try:
            port = int(self._settings_pf_port_f.value or 0)
        except ValueError:
            port = 0
        if not (1024 <= port <= 65535):
            self._settings_pf_result.value = "Enter a valid port (1024–65535)"
            self._settings_pf_result.color = C.RED
            self.page.update()
            return
        self._settings_pf_result.value = "Testing…"
        self._settings_pf_result.color = C.SUBTLE
        self.page.update()
        gw = await asyncio.to_thread(discover_gateway) or PROTON_GATEWAY
        ip = await asyncio.to_thread(local_ip_for, gw)
        if not ip:
            self._settings_pf_result.value = "Could not determine local IP"
            self._settings_pf_result.color = C.RED
            self.page.update()
            return
        ok, msg = await asyncio.to_thread(test_forwarded_port, ip, port)
        self._settings_pf_result.value = msg
        self._settings_pf_result.color = C.GREEN if ok else C.RED
        self.page.update()

    async def _settings_export_keys(self, ev) -> None:
        # Export the PLAINTEXT identity JSON (DPAPI-unwrapped): the on-disk
        # keys.json is machine-bound on Windows, so exporting it raw produced a
        # file that could never be imported anywhere - including after an OS
        # reinstall on the same PC.
        from crypto import export_keys_plaintext
        try:
            data = export_keys_plaintext()
        except Exception as ex:
            self._toast(f"Could not export keys: {ex}", "error")
            return
        picker = ft.FilePicker()
        self.page.services.append(picker)
        self.page.update()
        try:
            dest = await picker.save_file(file_name="helucryptic-keys.json", src_bytes=data)
            if dest:
                self._log("[Keys] Keypair exported as plaintext JSON - store it somewhere safe "
                          "(anyone with this file owns your identity).")
        finally:
            try:
                self.page.services.remove(picker)
            except ValueError:
                pass
            try:
                self.page.update()
            except Exception:
                pass

    async def _settings_import_keys(self, ev) -> None:
        picker = ft.FilePicker()
        self.page.services.append(picker)
        self.page.update()
        try:
            files = await picker.pick_files(allowed_extensions=["json"])
            if files:
                from crypto import import_keys_plaintext
                try:
                    import_keys_plaintext(Path(files[0].path).read_bytes())
                except (ValueError, OSError) as ex:
                    self._toast(f"Key import failed: {ex}", "error")
                    return
                self.keys = load_or_create_keys()
                self.history_key = derive_history_key(self.keys["ed25519_private"])
                self.engine.keys = self.keys
                self._log("[Keys] Keypair imported successfully. Rebuilding active profile against new keys.")
        finally:
            try:
                self.page.services.remove(picker)
            except ValueError:
                pass
            try:
                self.page.update()
            except Exception:
                pass

    def _settings_regen_keys(self, ev) -> None:
        confirm_dlg = ft.AlertDialog(
            title=ft.Text("Regenerate keys?"),
            content=ft.Text("All contacts must re-verify. Cannot be undone."),
            actions=[
                ft.TextButton("Regenerate", on_click=self._settings_confirm_regen),
                ft.TextButton("Cancel", on_click=lambda cev: self._close_dialog(self._settings_confirm_dlg)),
            ],
        )
        self._settings_confirm_dlg = confirm_dlg
        self._show_dialog(confirm_dlg)

    def _settings_confirm_regen(self, cev) -> None:
        from contacts import load_contacts as lc
        from contacts import save_contacts as sc
        generate_and_save_keys()
        self.keys = load_or_create_keys()
        self.history_key = derive_history_key(self.keys["ed25519_private"])
        self.engine.keys = self.keys
        contacts = lc()
        for c in contacts:
            c.verified = False
        sc(contacts)
        self._log("[Keys] Identity keys regenerated. Contact verifications reset.")
        self._refresh_contact_list()
        self._close_dialog(self._settings_confirm_dlg)

    def _settings_do_switch_profile(self, ev) -> None:
        name = self._settings_prof_dd.value
        if name and name != profiles.active_name():
            self._close_dialog(self._settings_dlg)
            self._fire_and_forget(self._switch_profile(name))

    def _settings_do_create_profile(self, ev) -> None:
        try:
            safe = profiles.create_profile(self._settings_new_prof.value)
        except ValueError as ex:
            self._settings_prof_err.value = str(ex)
            self._settings_prof_err.visible = True
            self.page.update()
            return
        self._close_dialog(self._settings_dlg)
        self._fire_and_forget(self._switch_profile(safe))

    def _settings_save(self, ev) -> None:
        if self._settings_retention_dd.value == "custom":
            try:
                days = int(self._settings_custom_days.value)
                if days <= 0:
                    raise ValueError
            except ValueError:
                self._settings_custom_error.value = "Enter a positive number of days"
                self._settings_custom_error.visible = True
                self.page.update()
                return
            self.settings.retention_days = days
        else:
            self.settings.retention_days = int(self._settings_retention_dd.value)
        self.settings.security_mode = self._settings_mode_radio.value
        self.settings.signaling_url = self._settings_url_field.value
        if self._settings_profile_dd.value in PROFILES:
            apply_profile(self.settings, self._settings_profile_dd.value)
        self.settings.turn_url = self._settings_turn_url_f.value.strip()
        self.settings.turn_username = self._settings_turn_user_f.value.strip()
        self.settings.turn_password = self._settings_turn_pass_f.value
        self.settings.verified_only = self._settings_verified_only_cb.value
        self.settings.noise_reduce = self._settings_noise_reduce_cb.value
        self.settings.port_forward_enabled = self._settings_pf_enabled_cb.value
        try:
            self.settings.forwarded_port = int(self._settings_pf_port_f.value or 0)
        except ValueError:
            self.settings.forwarded_port = 0
        save_settings(self.settings)
        self._log(f"[Settings] Saved settings (mode={self.settings.security_mode}, retention={self.settings.retention_days} days).")
        self._update_perf_parameters()
        self._apply_port_forward()
        self._close_dialog(self._settings_dlg)

    def _show_settings(self, e) -> None:
        self._settings_mode_radio = ft.RadioGroup(
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
        self._settings_custom_days = _neon_field(
            label="Days", width=100, dense=True,
            visible=(preset_value == "custom"),
            value=str(self.settings.retention_days) if preset_value == "custom" else "1",
        )
        self._settings_custom_error = ft.Text("", color=C.RED, size=11, visible=False)
        self._settings_retention_dd = ft.Dropdown(
            value=preset_value, width=160,
            options=[
                ft.dropdown.Option("0",      "Never"),
                ft.dropdown.Option("7",      "7 days"),
                ft.dropdown.Option("30",     "30 days"),
                ft.dropdown.Option("90",     "90 days"),
                ft.dropdown.Option("custom", "Custom…"),
            ],
            on_select=self._settings_on_retention_change,
        )

        self._settings_url_field = _neon_field(
            value=self.settings.signaling_url, label="Signaling URL", width=280, dense=True,
        )
        self._settings_verified_only_cb = ft.Checkbox(
            label="Verified-Only mode (block actions with unverified contacts)",
            value=self.settings.verified_only,
        )
        btn_show_identity = ft.TextButton("Show My Identity (QR / code)",
                                          on_click=self._show_my_identity)
        _profile_labels = {
            "old_pc": "Old PC (480p/5fps)", "balanced": "Balanced (720p/10fps)",
            "quality": "Quality (1080p/30fps)", "overclock": "Overclock (2K/60fps)",
        }
        profile_opts = [ft.dropdown.Option(k, _profile_labels[k]) for k in PROFILES]
        if self.settings.performance_profile not in PROFILES:
            profile_opts.append(ft.dropdown.Option("custom", "Custom (from .env)"))
        self._settings_profile_dd = ft.Dropdown(
            value=self.settings.performance_profile, width=240, options=profile_opts,
            on_select=self._settings_on_profile_change,
        )
        self._settings_overclock_warn = ft.Text(
            "⚠ Overclock (2K/60) is very CPU/bandwidth heavy and may not reach "
            "60 FPS with software encoding.",
            size=11, color="#faa61a", visible=self.settings.performance_profile == "overclock",
        )
        self._settings_noise_reduce_cb = ft.Checkbox(
            label="Microphone noise reduction (cleans background noise)",
            value=self.settings.noise_reduce,
        )

        self._settings_turn_url_f  = _neon_field(label="TURN URL (turn:host:port)", value=self.settings.turn_url,
                                   width=280, dense=True)
        self._settings_turn_user_f = _neon_field(label="TURN username", value=self.settings.turn_username,
                                   width=280, dense=True)
        self._settings_turn_pass_f = _neon_field(label="TURN password", value=self.settings.turn_password,
                                   width=280, dense=True, password=True, can_reveal_password=True)
        self._settings_turn_result = ft.Text("", size=11)
        btn_test_turn = ft.TextButton("Test TURN", on_click=self._settings_do_test_turn)

        self._settings_pf_enabled_cb = ft.Checkbox(
            label="I'm port-forwarding (VPN/router)",
            value=self.settings.port_forward_enabled,
        )
        self._settings_pf_port_f = _neon_field(
            label="Forwarded port", value=str(self.settings.forwarded_port or ""),
            width=280, dense=True,
        )
        self._settings_pf_result = ft.Text("", size=11)
        btn_pf_detect = ft.TextButton("Auto-detect (NAT-PMP)", on_click=self._settings_do_pf_autodetect)
        btn_pf_test = ft.TextButton("Test", on_click=self._settings_do_pf_test)
        pf_caption = ft.Text(
            "Needs full-tunnel VPN; applies to one peer at a time.",
            size=11, color=C.MUTED,
        )

        prof_active = profiles.active_name() or "default (root)"
        self._settings_prof_dd = ft.Dropdown(
            value=profiles.active_name(), width=200, hint_text="Choose a profile",
            options=[ft.dropdown.Option(p) for p in profiles.list_profiles()],
        )
        self._settings_new_prof = _neon_field(label="New profile name", width=200)
        self._settings_prof_err = ft.Text("", color=C.RED, size=11, visible=False)

        # Two-pane settings: category nav on the left, ONE section at a time on
        # the right - no more scrolling through nine stacked cards to find the
        # TURN fields. Same control objects, so _settings_save is untouched.
        pages = [
            ("Profiles", ft.Icons.SWITCH_ACCOUNT, C.VIOLET,
             "Separate identities, contacts and history", [
                ft.Text(f"Active: {prof_active}", size=12, color=C.SUBTLE),
                ft.Text("Each profile is a fully separate identity, contacts and history.",
                        size=11, color=C.MUTED),
                ft.Row([self._settings_prof_dd, ft.FilledButton("Switch", on_click=self._settings_do_switch_profile,
                                                 style=_filled_style(C.CYAN))]),
                ft.Row([self._settings_new_prof, ft.FilledButton("Create & switch", on_click=self._settings_do_create_profile,
                                                  style=_filled_style(C.VIOLET, C.BTN_CYAN))]),
                self._settings_prof_err,
            ]),
            ("Security & privacy", ft.Icons.SHIELD_MOON, C.CYAN,
             "Encryption mode and message retention", [
                ft.Text("Encryption mode", size=11, color=C.MUTED),
                self._settings_mode_radio,
                ft.Text("Message retention", size=11, color=C.MUTED),
                ft.Row([self._settings_retention_dd, self._settings_custom_days]),
                self._settings_custom_error,
            ]),
            ("Connection", ft.Icons.LANGUAGE, C.CYAN,
             "Signaling server (handshake only)", [
                ft.Text("Used only to find your peer - messages never pass through it.",
                        size=11, color=C.MUTED),
                self._settings_url_field,
            ]),
            ("Performance", ft.Icons.SPEED, C.CYAN,
             "Video/share quality profile", [
                self._settings_profile_dd, self._settings_overclock_warn,
                ft.Container(height=1, bgcolor=C.BORDER),
                self._settings_noise_reduce_cb,
                ft.Text("Denoising uses roughly one CPU core during calls - turn it "
                        "off on slow machines. Applies to your next call.",
                        size=11, color=C.MUTED),
            ]),
            ("TURN relay", ft.Icons.ROUTER, C.CYAN,
             "Fallback for strict NATs", [
                ft.Text("Optional - fixes strict-NAT connections.", size=11, color=C.MUTED),
                self._settings_turn_url_f, self._settings_turn_user_f, self._settings_turn_pass_f,
                ft.Row([btn_test_turn, self._settings_turn_result]),
            ]),
            ("Port forwarding", ft.Icons.SETTINGS_ETHERNET, C.CYAN,
             "Direct connect via forwarded port", [
                ft.Text("Advanced - direct connect via a forwarded port.", size=11, color=C.MUTED),
                self._settings_pf_enabled_cb, self._settings_pf_port_f,
                ft.Row([btn_pf_detect, btn_pf_test]),
                self._settings_pf_result, pf_caption,
            ]),
            ("Trust & verification", ft.Icons.VERIFIED_USER, C.GREEN,
             "Verified-only mode and your identity", [
                self._settings_verified_only_cb, btn_show_identity,
            ]),
            ("Identity keys", ft.Icons.KEY, C.GREEN,
             "Export, import or regenerate", [
                ft.Text("Your keys ARE your identity - export them before reinstalling.",
                        size=11, color=C.MUTED),
                ft.Row([
                    ft.FilledButton("Export Keys", on_click=self._settings_export_keys, style=_filled_style(C.ELEV2, C.TEXT)),
                    ft.FilledButton("Import Keys", on_click=self._settings_import_keys, style=_filled_style(C.ELEV2, C.TEXT)),
                    ft.FilledButton("Regenerate Keys", on_click=self._settings_regen_keys, style=_filled_style(C.ELEV2, C.TEXT)),
                ], wrap=True, spacing=8),
            ]),
            ("Data & backup", ft.Icons.STORAGE, C.RED,
             "Backup, restore, emergency wipe", [
                ft.Text(f"Data folder: {paths.DATA_DIR}"
                        + ("  (portable)" if paths.is_portable() else ""),
                        size=11, color=C.SUBTLE, selectable=True),
                ft.Row([
                    ft.FilledButton("Backup Profile…", on_click=self._show_backup, style=_filled_style(C.ELEV2, C.TEXT)),
                    ft.FilledButton("Restore Profile…", on_click=self._show_restore, style=_filled_style(C.ELEV2, C.TEXT)),
                ], wrap=True, spacing=8),
                ft.TextButton("⚠ Emergency Wipe…", on_click=self._show_wipe,
                              style=ft.ButtonStyle(color=C.RED)),
            ]),
        ]

        body_col = ft.Column([], spacing=12, scroll=ft.ScrollMode.AUTO, expand=True)
        nav_tiles: list[ft.Container] = []
        nav_labels: list[ft.Text] = []

        def _open_page(idx: int) -> None:
            title, icon, accent, _subtitle, controls = pages[idx]
            body_col.controls = [
                ft.Row([
                    ft.Container(content=ft.Icon(icon, color=accent, size=18),
                                 padding=ft.Padding.all(8), border_radius=R.MD,
                                 bgcolor=_alpha("1f", accent)),
                    ft.Text(title, size=15, weight=ft.FontWeight.W_800, color=C.TEXT),
                ], spacing=10, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                ft.Container(height=1, bgcolor=C.BORDER),
                *controls,
            ]
            for i, (tile, lbl) in enumerate(zip(nav_tiles, nav_labels)):
                active = i == idx
                tile.bgcolor = _alpha("14", C.CYAN) if active else C.ELEV + "00"
                tile.border  = ft.Border.all(1, _alpha("55", C.CYAN) if active else "#00000000")
                lbl.color    = C.TEXT if active else C.SUBTLE
                lbl.weight   = ft.FontWeight.W_700 if active else ft.FontWeight.W_500
            try:
                self._settings_dlg.update()
            except Exception:
                pass

        for i, (title, icon, _accent, subtitle, _controls) in enumerate(pages):
            lbl = ft.Text(title, size=12, color=C.SUBTLE, max_lines=1,
                          overflow=ft.TextOverflow.ELLIPSIS)
            nav_labels.append(lbl)
            tile = ft.Container(
                content=ft.Row([ft.Icon(icon, size=15, color=C.SUBTLE), lbl], spacing=8,
                               vertical_alignment=ft.CrossAxisAlignment.CENTER),
                padding=ft.Padding.symmetric(horizontal=10, vertical=8),
                border_radius=R.MD, ink=True, animate=_anim(D.FAST),
                border=ft.Border.all(1, "#00000000"),
                on_click=lambda e, i=i: _open_page(i),
                tooltip=subtitle,
            )
            nav_tiles.append(tile)

        header = ft.Row([
            ft.Container(content=ft.Icon(ft.Icons.SETTINGS, color=C.CYAN, size=20),
                         padding=ft.Padding.all(9), border_radius=R.MD,
                         bgcolor=_alpha("1f", C.CYAN)),
            ft.Column([
                ft.Text("Settings", size=18, weight=ft.FontWeight.W_800, color=C.WHITE),
                ft.Text("Security, performance & connection", size=11, color=C.MUTED),
            ], spacing=0, tight=True),
        ], spacing=12)

        self._settings_dlg = ft.AlertDialog(
            title=header,
            content=ft.Container(width=720, height=480, content=ft.Row([
                ft.Container(width=188, content=ft.Column(nav_tiles, spacing=2,
                                                          scroll=ft.ScrollMode.AUTO)),
                ft.Container(width=1, bgcolor=C.BORDER),
                ft.Container(content=body_col, expand=True,
                             padding=ft.Padding.only(left=14)),
            ], spacing=10, vertical_alignment=ft.CrossAxisAlignment.STRETCH)),
            actions=[
                ft.TextButton("Restart App", on_click=lambda ev: restart_app(),
                              style=ft.ButtonStyle(color=C.YELLOW)),
                ft.FilledButton("Save", icon=ft.Icons.CHECK, on_click=self._settings_save,
                                style=_filled_style(C.CYAN)),
                ft.TextButton("Cancel", on_click=lambda ev: self._close_dialog(self._settings_dlg)),
            ],
        )
        _open_page(0)   # populate before showing (update() is a no-op pre-attach)
        self._show_dialog(self._settings_dlg)

    # ------------------------------------------------------------------
    # Add contact
    # ------------------------------------------------------------------

    def _show_add_contact(self, e) -> None:
        field = _neon_field(label="Username", autofocus=True, dense=True)
        def add(ev):
            name = field.value.strip()
            if name:
                upsert_contact(name)
                self._refresh_contact_list()
            self._close_dialog(dlg)
        dlg = ft.AlertDialog(
            title=ft.Text("Add Contact", size=16, weight=ft.FontWeight.BOLD),
            content=ft.Column([
                ft.Text("Enter the username of the contact you want to add to your list.", size=11, color=C.SUBTLE),
                field,
            ], tight=True, spacing=12, width=320),
            actions=[
                ft.FilledButton("Add", icon=ft.Icons.PERSON_ADD, on_click=add,
                                style=_filled_style(C.CYAN)),
                ft.TextButton("Cancel", on_click=lambda ev: self._close_dialog(dlg),
                              style=_ghost_style(C.MUTED)),
            ],
        )
        self._show_dialog(dlg)

    async def _shutdown_websocket(self) -> None:
        if self.ws:
            try:
                await self.ws.close()
            except Exception:
                pass
            self.ws = None

    async def _shutdown_peers(self) -> None:
        for peer in self.engine.pcs:
            try:
                await self.engine.remove_peer(peer)
            except Exception:
                pass

    async def _shutdown_port_forward(self) -> None:
        if self._pf_manager is not None:
            try:
                await self._pf_manager.stop()
            except Exception:
                pass
            self._pf_manager = None

    def _shutdown_tasks(self) -> None:
        for task in self._bg_tasks:
            try:
                task.cancel()
            except Exception:
                pass
        self._bg_tasks.clear()
        for task in self._running_tasks:
            try:
                task.cancel()
            except Exception:
                pass
        self._running_tasks.clear()
        if self._status_label_task and not self._status_label_task.done():
            self._status_label_task.cancel()
        if self._flash_task and not self._flash_task.done():
            self._flash_task.cancel()

    async def shutdown(self) -> None:
        """Cleanly close all background loops, websockets, and WebRTC engines on close."""
        print("[app] starting shutdown cleanup...", flush=True)
        await self._shutdown_websocket()
        await self._shutdown_peers()
        await self._shutdown_port_forward()
        self._shutdown_tasks()

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
        _ = dlg
        self.page.pop_dialog()

    async def _retention_background_loop(self) -> None:
        while True:
            await asyncio.sleep(86400)
            run_retention_policy(self.settings.retention_days)

    def _connected_peer(self) -> str:
        pc = self.engine.pcs.get(self.engine.target_peer)
        if pc and pc.connectionState == "connected":
            return self.engine.target_peer
        return ""

    # Semantic status level -> palette colour for the status pill.
    _STATUS_COLORS = {
        "idle":         "FAINT",
        "connecting":   "YELLOW",
        "connected":    "GREEN",
        "partial":      "YELLOW",
        "disconnected": "RED",
    }

    def _apply_aggregate_status(self, states: dict, group: bool) -> None:
        """Set the status pill from an HONEST summary of the given peer states
        (mesh-aware: e.g. '2/3 connected'), replacing last-peer-wins."""
        s = summarize_peer_states(states, group=group)
        level = s["level"]
        label = s["label"]
        color = getattr(C, self._STATUS_COLORS.get(level, "FAINT"))
        if level in ("disconnected", "idle") and self.ws and self.ws.open:
            label = "SIGNALING"
            color = C.YELLOW
        self._update_status(label, color)

    def _update_status(self, label: str, color: str) -> None:
        self.status_dot.bgcolor      = color
        self.engine.signaling_status = label.lower()
        if self._motion_ok:
            if self._status_label_task and not self._status_label_task.done():
                self._status_label_task.cancel()
            self._status_label_task = asyncio.ensure_future(
                self._crossfade_status_label(label, color))
            if color == C.GREEN:
                self._fire_and_forget(self._status_connect_bloom())
        else:
            self.status_label.value = label
            self.status_label.color = color
        self.page.update()

    def _date_chip(self, label: str) -> ft.Container:
        """A small centered pill marking a day boundary in the transcript."""
        return ft.Container(
            alignment=ft.Alignment.CENTER,
            padding=ft.Padding.symmetric(vertical=6),
            data=("date_chip", label),   # tagged so loaders can dedupe on prepend
            content=ft.Container(
                content=ft.Text(label, size=10, color=C.SUBTLE,
                                weight=ft.FontWeight.W_600,
                                font_family=_t_FONTS["mono"]),
                padding=ft.Padding.symmetric(horizontal=12, vertical=4),
                border_radius=R.PILL, bgcolor=_alpha("cc", C.ELEV),
                border=ft.Border.all(1, C.BORDER),
            ),
        )

    def _remove_empty_hint(self) -> None:
        if self._chat_empty_hint is not None:
            try:
                self.chat_log.controls.remove(self._chat_empty_hint)
            except ValueError:
                pass
            self._chat_empty_hint = None

    def _append_to_log(self, direction: str, text: str, verified: bool, label: str = "",
                       msg_id: str | None = None, status: str | None = None) -> None:
        is_sent = direction == "sent"
        prefix  = "You" if is_sent else (label or self._active_contact or "Peer")
        # First real message replaces the "say hello" empty-conversation hint.
        self._remove_empty_hint()
        # Day boundary → centered date chip (live messages are always today).
        day = _msg_day(None)
        if day is not None and day != self._last_msg_date:
            self.chat_log.controls.append(self._date_chip(_day_label(day)))
            self._last_msg_date = day
            self._last_bubble_sender = None   # new day breaks bubble grouping
        # Group consecutive bubbles from the same sender: hide the repeated
        # name header and tighten the gap so runs read as one turn.
        grouped = (prefix == self._last_bubble_sender)
        self._last_bubble_sender = prefix
        self.chat_log.controls.append(
            self._make_bubble(prefix, text, verified, is_sent,
                              msg_id=msg_id, status=status, grouped=grouped))

    def _make_bubble(self, name: str, text: str, verified: bool, is_sent: bool,
                     ts: str | None = None, msg_id: str | None = None,
                     status: str | None = None, grouped: bool = False) -> ft.Control:
        """A chat bubble. With the single-accent rebrand, sent vs received are
        distinguished WITHOUT a colour pair: sent = accent-tinted fill + accent
        label on the right; received = neutral surface + muted label on the
        left. Asymmetric corners reinforce direction. Slides+fades in on arrival
        (suppressed during bulk history loads).

        ``grouped`` hides the repeated sender header for consecutive messages.
        ``ts`` is a stored UTC ISO timestamp (history) or None (live = now).
        ``msg_id``+``status`` add a delivery glyph (⏳/✓/✓✓) to sent bubbles
        that live-updates via engine acks (see _set_msg_status)."""
        # Sent leans on the accent; received stays neutral so a busy room of
        # peers doesn't turn into a wall of accent colour.
        name_color   = C.CYAN if is_sent else C.SUBTLE
        fill         = None if is_sent else C.ELEV
        # Sent bubbles: a barely-there accent wash (single hue, low alpha) -
        # enough to read direction at a glance without turning the chat neon.
        sent_grad    = ft.LinearGradient(
            begin=ft.Alignment.TOP_LEFT, end=ft.Alignment.BOTTOM_RIGHT,
            colors=[_alpha("22", C.CYAN), _alpha("12", C.CYAN)]) if is_sent else None
        border_color = _alpha("44", C.CYAN) if is_sent else C.BORDER2
        header = ft.Row(
            [
                ft.Text(name, size=10, color=name_color, weight=ft.FontWeight.W_700),
                *([ft.Icon(ft.Icons.VERIFIED, size=11, color=C.GREEN)] if verified else []),
            ],
            spacing=4, tight=True,
        )
        # Footer: timestamp (+ delivery glyph on tracked sent messages).
        footer_items: list = [ft.Text(_fmt_msg_ts(ts), size=9, color=C.FAINT)]
        if is_sent and msg_id:
            st = status or "sent"
            icon_name, icon_color = _MSG_STATUS_GLYPHS.get(st, _MSG_STATUS_GLYPHS["sent"])
            status_icon = ft.Icon(icon_name, size=11, color=icon_color,
                                  tooltip=st.capitalize(), data=st)
            self._msg_status[msg_id] = status_icon
            footer_items.append(status_icon)
        footer = ft.Row(footer_items, spacing=3, tight=True)
        inner = ft.Container(
            content=ft.Column([
                *([] if grouped else [header]),
                ft.Text(text, size=13, color=C.TEXT, selectable=True),
                footer,
            ], spacing=4, tight=True,
                horizontal_alignment=ft.CrossAxisAlignment.END if is_sent
                else ft.CrossAxisAlignment.START),
            padding=ft.Padding.symmetric(horizontal=14, vertical=10),
            bgcolor=fill,
            gradient=sent_grad,
            border=ft.Border.all(1, border_color),
            border_radius=ft.BorderRadius(
                top_left=R.LG, top_right=R.LG,
                bottom_left=R.SM if is_sent else R.LG,
                bottom_right=R.LG if is_sent else R.SM,
            ),
            shadow=_glow(blur=10),
        )
        bubble = ft.Container(
            content=inner,
            alignment=ft.Alignment.CENTER_RIGHT if is_sent else ft.Alignment.CENTER_LEFT,
            padding=ft.Padding.only(
                left=40 if is_sent else 0, right=0 if is_sent else 40,
                top=0 if grouped else 2,
            ),
            # Long-press any bubble to copy its text (the text is selectable
            # too, but this is one gesture instead of select-then-ctrl-c).
            on_long_press=lambda ev, _t=text: self._copy_bubble_text(_t),
        )
        if not self._bulk_load:
            bubble.opacity = 0
            bubble.scale = 0.96
            bubble.animate_opacity = _anim(D.MED)
            bubble.animate_scale = _anim(D.MED)
            self._reveal(bubble)
        return bubble

    def _copy_bubble_text(self, text: str) -> None:
        self._fire_and_forget(self._set_clipboard(text))
        self._toast("Message copied", "success")

    def _log(self, text: str) -> None:
        # Clean, console-style system line: a centered hairline divider with the
        # message in muted monospace - no italics, reads as intentional system
        # output rather than a stray chat bubble.
        line = ft.Container(height=1, bgcolor=C.BORDER, expand=True)
        chip = ft.Row(
            [
                line,
                ft.Text(text, color=C.MUTED, size=10.5, font_family=_t_FONTS["mono"],
                        weight=ft.FontWeight.W_500, no_wrap=False),
                ft.Container(height=1, bgcolor=C.BORDER, expand=True),
            ],
            vertical_alignment=ft.CrossAxisAlignment.CENTER, spacing=10,
        )
        self.chat_log.controls.append(
            ft.Container(content=chip, padding=ft.Padding.symmetric(horizontal=8, vertical=6)))
        self._last_bubble_sender = None   # a system line breaks bubble grouping
        self.page.update()

    def _toast(self, text: str, level: str = "info") -> None:
        """Surface a transient system/connection message as a toast OVERLAY
        (not inside the conversation transcript). Defensive: if the SnackBar
        API isn't available, it degrades to a chat-log pill so the user still
        sees the message."""
        accent = {"error": C.RED, "warn": C.YELLOW, "success": C.GREEN}.get(level, C.CYAN)
        icon_map = {
            "info": ft.Icons.INFO_OUTLINE,
            "error": ft.Icons.ERROR_OUTLINE,
            "success": ft.Icons.CHECK_CIRCLE_OUTLINE,
        }
        icon_name = icon_map.get(level, ft.Icons.WARNING_AMBER_ROUNDED)
        try:
            self.page.open(ft.SnackBar(
                content=ft.Row(
                    [ft.Icon(icon_name, color=accent, size=18),
                     ft.Text(text, color=C.TEXT, size=12)],
                    spacing=10, tight=True,
                ),
                bgcolor=C.ELEV,
                duration=4000,
                behavior=ft.SnackBarBehavior.FLOATING,
                shape=ft.RoundedRectangleBorder(radius=R.MD),
            ))
        except Exception:
            # Fallback: never silently drop a message the user needs to see.
            self._log(text)

    async def _set_clipboard(self, text: str) -> None:
        clipboard = ft.Clipboard()
        self.page.services.append(clipboard)
        self.page.update()
        try:
            await clipboard.set(text)
        finally:
            try:
                self.page.services.remove(clipboard)
            except ValueError:
                pass
            try:
                self.page.update()
            except Exception:
                pass



def generate_room_code() -> str:
    chars = string.ascii_uppercase + string.digits
    return "ROOM-" + "".join(secrets.choice(chars) for _ in range(4))


def _to_ws_url(base: str) -> str:
    """Normalize a server URL to a WebSocket scheme.

    WebSockets-over-TLS uses wss:// (not https://). Accept http(s)/ws(s) and a
    bare host, and always return a ws:// or wss:// base with no trailing slash.
    """
    base = (base or "").strip().rstrip("/")
    if base.startswith(SCHEME_HTTPS):
        base = SCHEME_WSS + base[len(SCHEME_HTTPS):]
    elif base.startswith(SCHEME_HTTP):
        base = SCHEME_WS + base[len(SCHEME_HTTP):]
    elif not base.startswith((SCHEME_WS, SCHEME_WSS)):
        # bare host (e.g. "example.com" or "127.0.0.1:8000") - default to ws://
        base = SCHEME_WS + base
    return base


# ---------------------------------------------------------------------------
# Startup screen
# ---------------------------------------------------------------------------

class StartupScreen:
    def __init__(self, page: ft.Page, on_done):
        self.page      = page
        self.on_done   = on_done
        self._selected = "a"
        self._build()

    def _select_a(self, e) -> None:
        if self._radio_group.value != "a":
            self._radio_group.value = "a"
            self._on_radio_change(None)

    def _select_b(self, e) -> None:
        if self._radio_group.value != "b":
            self._radio_group.value = "b"
            self._on_radio_change(None)

    def _connect(self, e) -> None:
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
            if not url.startswith((SCHEME_WS, SCHEME_WSS, SCHEME_HTTP, SCHEME_HTTPS)):
                self._url_error.value   = "Use ws://, wss://, http:// or https://"
                self._url_error.visible = True
                self.page.update()
                return
            # Store normalized to a WebSocket scheme (https -> wss, http -> ws)
            self.on_done(_to_ws_url(url), self._custom_pw_field.value or "")

    async def _reveal_entrance(self) -> None:
        try:
            await asyncio.sleep(0.06)
        except Exception:
            pass
        try:
            self._panel.opacity = 1
            self._panel.scale = 1
            self._panel.update()
        except Exception:
            pass

    def _build(self) -> None:
        self._pw_field  = _neon_field(
            label="Password", password=True, can_reveal_password=True, width=300,
        )
        self._pw_error  = ft.Text("", color=C.RED, size=11, visible=False)
        self._url_field = _neon_field(
            label="Server URL", value=SCHEME_WS, width=300,
            hint_text="ws://your-server-ip:8000",
        )
        self._custom_pw_field = _neon_field(
            label="Server password (optional)", password=True, can_reveal_password=True,
            width=300,
        )
        self._url_error = ft.Text("", color=C.RED, size=11, visible=False)

        radio_a = ft.Radio(value="a", label="", active_color=C.CYAN)
        radio_b = ft.Radio(value="b", label="", active_color=C.CYAN)

        self._icon_a = ft.Icon(ft.Icons.PUBLIC, color=C.CYAN)
        self._icon_b = ft.Icon(ft.Icons.DNS, color=C.MUTED)

        card_a = ft.Container(
            width=340,
            border=ft.Border.all(2, C.CYAN), border_radius=R.LG,
            padding=ft.Padding.all(20), bgcolor=C.PANEL,
            shadow=_glow(C.CYAN + "44", blur=26, spread=-4),
            animate=_anim(D.MED),
            content=ft.Column([
                ft.Row([
                    radio_a,
                    self._icon_a,
                    ft.Text("helucryptic server", weight=ft.FontWeight.W_700, color=C.TEXT)
                ], spacing=10, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                ft.Text("Connect to the official server.\nRequires access password.",
                        size=12, color=C.SUBTLE),
                self._pw_field,
                self._pw_error,
            ], spacing=10, tight=True),
        )
        card_b = ft.Container(
            width=340,
            border=ft.Border.all(1, C.BORDER2), border_radius=R.LG,
            padding=ft.Padding.all(20), bgcolor=C.PANEL,
            animate=_anim(D.MED),
            content=ft.Column([
                ft.Row([
                    radio_b,
                    self._icon_b,
                    ft.Text("Custom server", weight=ft.FontWeight.W_700, color=C.TEXT)
                ], spacing=10, vertical_alignment=ft.CrossAxisAlignment.CENTER),
                ft.Text("Connect to your own self-hosted server.", size=12, color=C.SUBTLE),
                self._url_field,
                self._custom_pw_field,
                self._url_error,
            ], spacing=10, tight=True),
        )
        self._card_a = card_a
        self._card_b = card_b

        card_a.on_click = self._select_a
        card_b.on_click = self._select_b

        radio_group = ft.RadioGroup(
            value="a",
            content=ft.Column([
                card_a,
                card_b
            ], spacing=16, horizontal_alignment=ft.CrossAxisAlignment.CENTER),
        )
        self._radio_group = radio_group
        radio_group.on_change = self._on_radio_change

        hero = ft.Container(
            content=ft.Column([
                ft.Container(
                    content=ft.Icon(ft.Icons.SHIELD_MOON, color=C.CYAN, size=40),
                    padding=ft.Padding.all(18), border_radius=R.XL, bgcolor=C.ELEV,
                    border=ft.Border.all(1, C.BORDER2),
                    shadow=_glow(C.CYAN + "55", blur=34, spread=-2),
                ),
                ft.Row([
                    ft.Text("helucryptic", size=30, weight=ft.FontWeight.W_900, color=C.WHITE),
                ], alignment=ft.MainAxisAlignment.CENTER),
                ft.Text("end-to-end encrypted peer-to-peer", size=13, color=C.CYAN,
                        weight=ft.FontWeight.W_600, text_align=ft.TextAlign.CENTER),
                ft.Text("Choose how to connect", size=12, color=C.MUTED,
                        text_align=ft.TextAlign.CENTER),
            ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=10),
        )

        connect_btn = ft.FilledButton(
            "Connect", icon=ft.Icons.BOLT, on_click=self._connect, width=220,
            style=_filled_style(C.CYAN, C.BTN_CYAN, pad_v=14),
        )

        panel = ft.Container(
            opacity=0, scale=0.97,
            animate_opacity=_anim(D.SLOW, _EASE_IO),
            animate_scale=_anim(D.SLOW, _EASE_IO),
            content=ft.Column([
                ft.Container(height=34),
                hero,
                ft.Container(height=24),
                radio_group,
                ft.Container(height=28),
                connect_btn,
            ], horizontal_alignment=ft.CrossAxisAlignment.CENTER, spacing=6),
        )
        self._panel = panel

        bg = ft.Container(
            expand=True,
            gradient=ft.LinearGradient(
                begin=ft.Alignment.TOP_LEFT, end=ft.Alignment.BOTTOM_RIGHT,
                colors=[C.BG, "#0a1020", "#0c0816"],
            ),
            alignment=ft.Alignment.TOP_CENTER,
            content=ft.Column([panel], scroll=ft.ScrollMode.AUTO,
                               horizontal_alignment=ft.CrossAxisAlignment.CENTER),
        )

        self.page.add(bg)

        # Entrance animation – safe wrapper so tests without a running loop don't leak.
        try:
            try:
                _loop = asyncio.get_running_loop()
            except RuntimeError:
                _loop = asyncio.get_event_loop()
            if _loop.is_closed():
                self._reveal_task = None
            else:
                self._reveal_task = _loop.create_task(self._reveal_entrance())
        except Exception:
            self._reveal_task = None

    def _on_radio_change(self, e) -> None:
        self._selected = self._radio_group.value
        if self._selected == "a":
            self._card_a.border = ft.Border.all(2, C.CYAN)
            self._card_a.shadow = _glow(C.CYAN + "44", blur=26, spread=-4)
            self._icon_a.color = C.CYAN
            self._card_b.border = ft.Border.all(1, C.BORDER2)
            self._card_b.shadow = None
            self._icon_b.color = C.MUTED
        else:
            self._card_a.border = ft.Border.all(1, C.BORDER2)
            self._card_a.shadow = None
            self._icon_a.color = C.MUTED
            self._card_b.border = ft.Border.all(2, C.CYAN)
            self._card_b.shadow = _glow(C.CYAN + "44", blur=26, spread=-4)
            self._icon_b.color = C.CYAN
        self._pw_error.visible  = False
        self._url_error.visible = False
        self.page.update()


def restart_app() -> None:
    """Restarts the current Python process."""
    import os
    import sys
    print("[app] Restarting process...", flush=True)
    os.execv(sys.executable, [sys.executable] + sys.argv)


async def main(page: ft.Page) -> None:
    await asyncio.sleep(0)
    _install_log_capture()   
    # mirror stdout/stderr into the in-app diagnostics log
    # Suppress aiortc SCTP "Cannot send data, not connected" noise: these are
    # background Tasks inside aiortc that try to flush a dead DTLS transport.
    # They are expected on abrupt disconnects and not actionable from our side.
    _loop = asyncio.get_event_loop()
    def _sctp_filter(lp, ctx):
        exc = ctx.get("exception")
        if isinstance(exc, ConnectionError) and "Cannot send data" in str(exc):
            return
        lp.default_exception_handler(ctx)
        if exc is not None:
            import sys
            ignore_types = (
                asyncio.CancelledError,
                KeyboardInterrupt,
                SystemExit,
                ConnectionError,
            )
            try:
                from websockets.exceptions import ConnectionClosed
                ignore_types += (ConnectionClosed,)
            except ImportError:
                pass
            if not isinstance(exc, ignore_types) and "--dev" not in sys.argv:
                print(f"[app] Unhandled loop exception: {exc}. Auto-restarting...", flush=True)
                restart_app()
    _loop.set_exception_handler(_sctp_filter)
    page.title         = "helucryptic"
    # Apply the unified "Refined dark console" theme: dark Material ColorScheme
    # (so built-in dialogs/dropdowns/checkboxes inherit the palette instead of
    # stock Material), bundled fonts (if present), and the static backdrop.
    flet_theme.apply(page)
    page.window.width  = 1180
    page.window.height = 760
    page.window.min_width  = 940
    page.window.min_height = 600
    page.padding       = 0

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

        async def handle_disconnect(e):
            await app.shutdown()
        page.on_disconnect = handle_disconnect

    StartupScreen(page, on_done=launch_app)


if __name__ == "__main__":
    import sys
    try:
        ft.app(target=main)
    except Exception as e:
        if "--dev" not in sys.argv:
            print(f"[app] Unhandled startup exception: {e}. Auto-restarting...", flush=True)
            restart_app()
        else:
            raise
