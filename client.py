# Nuitka compile:
# nuitka --standalone --onefile --include-package=aiortc --include-package=av
#        --include-package=flet --include-package=cryptography --include-package=pyseto
#        --include-package=sounddevice --include-package=mss --windows-disable-console
#        client_claude.py
#
# ---------------------------------------------------------------------------
# client_claude.py — a 100%-functionally-identical reskin of client.py with a
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
from collections import deque
import urllib.parse
from io import BytesIO
from pathlib import Path

import flet as ft
import numpy as np
import websockets
from PIL import Image

try:
    import cv2
except ImportError:
    cv2 = None

import config
from theme import flet_theme
from theme.tokens import PALETTE as _P
from theme.tokens import RADIUS as _t_RADIUS
from theme.tokens import MOTION as _t_MOTION
from theme.tokens import FONTS as _t_FONTS
from ui_state import summarize_peer_states
from contacts import (
    delete_contact,
    get_contact,
    load_contacts,
    rename_contact,
    set_verified,
    upsert_contact,
)
from crypto import compute_fingerprint, derive_history_key, generate_and_save_keys, load_or_create_keys
import backup
import identity
import invites
import paths
import profiles
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


# ===========================================================================
# In-app log capture — mirror everything printed to stdout/stderr into a ring
# buffer so the Diagnostics dialog can show it even in a windowed .exe build
# (built with --windows-disable-console), where there is no console to read.
# ===========================================================================
LOG_BUFFER: "deque[str]" = deque(maxlen=1500)


class _LogTee:
    """Writes through to the original stream (if any) and keeps the last N
    non-blank lines, timestamped, in LOG_BUFFER for the diagnostics view."""

    def __init__(self, original):
        self._orig = original

    def write(self, s):
        if self._orig is not None:
            try:
                self._orig.write(s)
            except Exception:
                pass
        try:
            for line in str(s).splitlines():
                if line.strip():
                    LOG_BUFFER.append(time.strftime("%H:%M:%S ") + line)
        except Exception:
            pass
        return len(s) if s else 0

    def flush(self):
        if self._orig is not None:
            try:
                self._orig.flush()
            except Exception:
                pass

    def isatty(self):
        return False


def _install_log_capture() -> None:
    if not isinstance(sys.stdout, _LogTee):
        sys.stdout = _LogTee(sys.stdout)
    if not isinstance(sys.stderr, _LogTee):
        sys.stderr = _LogTee(sys.stderr)


def _redact_url(u: str) -> str:
    return _re.sub(r"(password=)[^&\s]*", r"\1<redacted>", u or "")


# ===========================================================================
# Neon design system — tokens, easing curves and small UI factories. Kept at
# module scope so the file stays single-file and drop-in next to client.py.
# ===========================================================================

class C:
    """Legacy palette names, now sourced from the unified design tokens
    (theme.tokens.PALETTE) — the "Refined dark console" rebrand. Attribute
    names are preserved so every existing call site re-skins unchanged.

    Note: the rebrand collapses the old multi-accent scheme (cyan/magenta/
    violet) onto a SINGLE cool accent; semantic state colours map to
    success/warning/danger. Differentiation that previously relied on hue
    (e.g. sent vs received bubbles) now leans on alignment, shape and labels.
    """
    BG       = _P.bg               # page backdrop (static)
    BG2      = _P.surface
    PANEL    = _P.surface          # primary panel
    ELEV     = _P.surface_raised   # elevated surface (inputs, tiles)
    ELEV2    = _P.surface_overlay  # hover / overlay surface
    BORDER   = _P.border_subtle    # hairline border
    BORDER2  = _P.border           # stronger border

    CYAN     = _P.accent           # the single accent (you / sent / connect)
    CYAN_DIM = _P.accent_subtle
    MAGENTA  = _P.accent           # collapsed onto the single accent
    VIOLET   = _P.accent           # collapsed onto the single accent

    GREEN    = _P.success          # online / connected / verified
    YELLOW   = _P.warning          # connecting / warning
    RED      = _P.danger           # failed / danger

    TEXT     = _P.text_primary     # primary text
    SUBTLE   = _P.text_secondary   # secondary text
    MUTED    = _P.text_muted       # tertiary text
    FAINT    = _P.text_faint       # idle dot / faint lines
    WHITE    = "#ffffff"

    # Button foreground tokens — on-colour for each filled surface.
    BTN_CYAN  = _P.on_accent
    BTN_GREEN = _P.on_success
    BTN_RED   = _P.on_danger


class R:
    """Corner radii — tightened for a precise, console-grade feel (from
    theme.tokens.RADIUS). Names preserved for drop-in compatibility."""
    SM = _t_RADIUS["sm"]    # 6
    MD = _t_RADIUS["md"]    # 8
    LG = _t_RADIUS["lg"]    # 12
    XL = _t_RADIUS["lg"]    # collapsed to lg — no oversized corners
    PILL = _t_RADIUS["pill"]


class D:
    """Animation durations (ms) — functional, short (from theme.tokens.MOTION)."""
    FAST  = _t_MOTION["fast"]   # 120
    PULSE = _t_MOTION["base"]   # 180
    MED   = _t_MOTION["base"]   # 180
    SLOW  = _t_MOTION["slow"]   # 260
    BG    = _t_MOTION["slow"]   # background is static now; kept for compatibility


_EASE     = ft.AnimationCurve.EASE_OUT
_EASE_IO  = ft.AnimationCurve.EASE_IN_OUT


def _anim(ms: int, curve=_EASE) -> ft.Animation:
    return ft.Animation(ms, curve)


def _glow(color: str = "", blur: int = 18, spread: float = 1.0) -> ft.BoxShadow:
    """Rebrand: depth now comes from a neutral elevation shadow, not coloured
    neon halos. Signature is kept for drop-in compatibility — the ``color`` and
    ``spread`` arguments are intentionally ignored so every existing call site
    works unchanged while the look becomes calm and console-grade."""
    b = max(2, min(int(blur), 24))
    return ft.BoxShadow(
        blur_radius=b, spread_radius=-2,
        offset=ft.Offset(0, max(1, b // 6)), color="#00000066",
    )


def _dot(color: str, size: int = 11, glow: bool = True) -> ft.Container:
    """A glowing presence/status dot."""
    return ft.Container(
        width=size, height=size, border_radius=R.PILL, bgcolor=color,
        shadow=_glow(color, blur=12, spread=1) if glow else None,
        animate=_anim(D.MED),
    )


def _filled_style(bg: str = C.CYAN, fg: str = C.BTN_CYAN, radius: int = R.MD,
                  pad_h: int = 16, pad_v: int = 12) -> ft.ButtonStyle:
    return ft.ButtonStyle(
        bgcolor={"": bg},
        color={"": fg},
        shape=ft.RoundedRectangleBorder(radius=radius),
        padding=ft.Padding.symmetric(horizontal=pad_h, vertical=pad_v),
    )


def _ghost_style(color: str = C.SUBTLE, radius: int = R.SM) -> ft.ButtonStyle:
    return ft.ButtonStyle(
        color={"": color},
        shape=ft.RoundedRectangleBorder(radius=radius),
        padding=ft.Padding.symmetric(horizontal=10, vertical=8),
    )


def _neon_field(**kwargs) -> ft.TextField:
    """A TextField styled for the neon theme. Accepts/overrides any TextField kwarg."""
    base = dict(
        dense=True,
        border_color=C.BORDER2,
        focused_border_color=C.CYAN,
        cursor_color=C.CYAN,
        color=C.TEXT,
        bgcolor=C.ELEV,
        border_radius=R.MD,
        text_size=13,
        content_padding=ft.Padding.symmetric(horizontal=12, vertical=10),
        focused_border_width=2,
        label_style=ft.TextStyle(color=C.MUTED, size=12),
        hint_style=ft.TextStyle(color=C.FAINT, size=12),
    )
    base.update(kwargs)
    return ft.TextField(**base)


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
        # Cancellable animation task handles — prevents stacked coroutines on
        # rapid successive triggers (e.g. fast status changes, rapid sends).
        self._status_label_task:  "asyncio.Task | None" = None
        self._flash_task:         "asyncio.Task | None" = None
        # Real presence: usernames the signaling server confirmed are online
        # (server-backed, refreshed by _presence_loop). A contact is "online" if
        # it's in here OR we already hold a live P2P link to it.
        self._online_users:    set[str]        = set()

        self._pf_manager = None  # PortForwardManager when port-forwarding is on
        # Background loops are tracked so a profile switch can stop this session's
        # loops cleanly before the next profile's app takes over.
        self._bg_tasks: list = []

        init_db()
        run_retention_policy(self.settings.retention_days)
        self._build_ui()
        self._wire_engine_callbacks()
        self._bg_tasks.append(asyncio.ensure_future(self._retention_background_loop()))
        self._bg_tasks.append(asyncio.ensure_future(self._presence_loop()))
        if self._motion_ok:
            self._bg_tasks.append(asyncio.ensure_future(self._status_pulse_loop()))
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
    # Motion helpers
    # ------------------------------------------------------------------

    def _reveal(self, ctrl, delay: float = 0) -> None:
        """Animate a freshly-mounted control from (faded, slightly small) to
        its resting state. sleep(0) yields once so the control is rendered
        before the transition fires. The reveal always completes even if the
        sleep is interrupted — content is never left invisible."""
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
        asyncio.ensure_future(run())

    def _build_background(self) -> ft.Control:
        """Static backdrop (rebrand): a single, calm vertical gradient from the
        backdrop colour to the panel surface — no animation, no neon blooms, and
        no perf-gated fork. Everyone gets the same consistent surface."""
        self._bg_layers = []   # disables the (now no-op) drift loop
        return ft.Container(
            expand=True,
            gradient=ft.LinearGradient(
                begin=ft.Alignment.TOP_CENTER, end=ft.Alignment.BOTTOM_CENTER,
                colors=[C.BG, C.PANEL],
            ),
        )

    async def _status_pulse_loop(self) -> None:
        """Gently breathe the status dot's scale and colored glow to create a pulsating effect."""
        on = True
        while True:
            try:
                await asyncio.sleep(0.8)
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

        # Room controls — flex to share the card width instead of fixed widths
        # (fixed 100+100 overflowed the room box).
        self.btn_create_room  = ft.FilledButton(
            "Create", icon=ft.Icons.ADD,
            on_click=self._create_room, expand=True, height=40,
            style=_filled_style(C.VIOLET, "#ffffff", radius=R.MD, pad_h=0, pad_v=10),
        )
        self.btn_join_room    = ft.FilledButton(
            "Join", icon=ft.Icons.LOGIN,
            on_click=self._show_join_room, expand=True, height=40,
            style=_filled_style(C.ELEV2, C.TEXT, radius=R.MD, pad_h=0, pad_v=10),
        )

        def _copy_room_code(e):
            if self._room_id:
                # Flet 0.85: clipboard is a service accessed via page.clipboard.set()
                self.page.clipboard.set(self._room_id)
                self._log(f"Room code {self._room_id} copied.")

        self.room_code_label  = ft.Text("", size=12, color=C.SUBTLE, selectable=True,
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
                ft.Row([self.room_code_label, self.btn_copy_room, self.btn_invite,
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
        )
        self.file_progress = ft.ProgressBar(value=0, visible=False, color=C.CYAN,
                                            bgcolor=C.ELEV, border_radius=R.PILL, height=4)

        self.btn_send     = ft.IconButton(ft.Icons.SEND_ROUNDED, on_click=self._send_chat,
                                          icon_color=C.CYAN, tooltip="Send",
                                          disabled=True)
        self.btn_call     = ft.IconButton(ft.Icons.CALL,         on_click=self._start_call,   disabled=True, icon_color=C.SUBTLE,  tooltip="Voice call")
        self.btn_screen   = ft.IconButton(ft.Icons.SCREEN_SHARE, on_click=self._toggle_screen, disabled=True, icon_color=C.SUBTLE,  tooltip="Share screen")
        self.btn_file     = ft.IconButton(ft.Icons.ATTACH_FILE,  on_click=self._send_file,    disabled=True, icon_color=C.SUBTLE,  tooltip="Send file")
        self.btn_mute     = ft.IconButton(ft.Icons.MIC,          on_click=self._toggle_mute,  disabled=True, icon_color=C.SUBTLE,  tooltip="Mute mic")
        self.btn_volume   = ft.IconButton(ft.Icons.VOLUME_UP,    on_click=self._show_volume,  icon_color=C.SUBTLE,  tooltip="Call volume")
        self.btn_hangup   = ft.IconButton(ft.Icons.CALL_END,     on_click=self._hangup,       disabled=True, icon_color=C.RED,     tooltip="Hang up")
        self.btn_join_call = ft.FilledButton(
            "Join call", icon=ft.Icons.CALL, on_click=self._start_call,
            visible=False, style=_filled_style(C.GREEN, C.BTN_GREEN),
        )
        self.btn_diag     = ft.IconButton(ft.Icons.INSIGHTS,  on_click=self._show_diagnostics, tooltip="Connection diagnostics", icon_color=C.SUBTLE)
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

        # Chat header bar — shows the selected conversation as live context
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
                # Persistent call-status pill — always visible while a call or
                # screen share is active, so you know a session is ongoing.
                self._make_call_status_pill(),
                self.btn_diag,
                self.btn_settings,
            ], vertical_alignment=ft.CrossAxisAlignment.CENTER, spacing=10),
        )

        # Composer card (input + inline send button)
        self._composer = ft.Container(
            padding=ft.Padding.symmetric(horizontal=8, vertical=8),
            border_radius=R.XL, bgcolor=C.ELEV, border=ft.Border.all(1, C.BORDER2),
            animate=_anim(D.MED),
            content=ft.Row([self.msg_input, self.btn_send],
                           vertical_alignment=ft.CrossAxisAlignment.CENTER, spacing=4),
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

        # Prominent incoming-call banner — overlays the top of the chat area so
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
        app_frame = ft.Container(
            expand=True,
            margin=ft.Margin.all(10),
            border_radius=R.LG,
            bgcolor=C.PANEL + "ee",
            border=ft.Border.all(1, C.BORDER2),
            shadow=ft.BoxShadow(blur_radius=40, spread_radius=-6, color="#000000aa"),
            clip_behavior=ft.ClipBehavior.ANTI_ALIAS,
            content=ft.Column([
                presence_bar,
                ft.Row([sidebar, chat_panel], expand=True, spacing=0),
            ], spacing=0, expand=True),
            opacity=0, scale=0.985,
            animate_opacity=_anim(280, _EASE_IO),
            animate_scale=_anim(280, _EASE_IO),
        )

        # Full-screen screen-share viewer — overlays everything when a tile is
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
            {"id": "join",      "title": "Join room", "icon": ft.Icons.LOGIN,
             "keywords": "group enter", "action": lambda: self._show_join_room(None)},
            {"id": "call",      "title": "Start voice call", "icon": ft.Icons.CALL,
             "keywords": "audio mic talk", "action": lambda: self._start_call(None)},
            {"id": "share",     "title": "Share screen", "icon": ft.Icons.SCREEN_SHARE,
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
            {"id": "diag",      "title": "Connection diagnostics", "icon": ft.Icons.INSIGHTS,
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
        self._sidebar_collapsed = not getattr(self, "_sidebar_collapsed", False)
        self._sidebar.visible = not self._sidebar_collapsed
        self.btn_sidebar_toggle.icon = (
            ft.Icons.MENU if self._sidebar_collapsed else ft.Icons.MENU_OPEN)
        try:
            self._sidebar.update()
            self.btn_sidebar_toggle.update()
        except Exception:
            pass

    def _on_key(self, e) -> None:
        # Global shortcuts: Ctrl/Cmd+K palette, Esc closes it, Ctrl+B sidebar,
        # Ctrl+, settings.
        key = (getattr(e, "key", "") or "")
        mod = getattr(e, "ctrl", False) or getattr(e, "meta", False)
        if mod and key.lower() == "k":
            self._close_palette() if getattr(self, "_palette_open", False) else self._open_palette()
        elif key == "Escape" and getattr(self, "_palette_open", False):
            self._close_palette()
        elif mod and key.lower() == "b":
            self._toggle_sidebar()
        elif mod and key == ",":
            self._show_settings(None)

    # ---- home / landing view -------------------------------------------

    def _build_home_view(self) -> ft.Control:
        def action(icon, label, fn, primary=False):
            return ft.FilledButton(
                label, icon=icon, on_click=lambda e: fn(),
                style=_filled_style(C.CYAN if primary else C.ELEV2,
                                    C.BTN_CYAN if primary else C.TEXT),
            )
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
                    action(ft.Icons.LOGIN, "Join room", lambda: self._show_join_room(None)),
                    action(ft.Icons.PERSON_ADD, "Add contact", lambda: self._show_add_contact(None)),
                ], alignment=ft.MainAxisAlignment.CENTER, spacing=10, wrap=True),
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
        def on_state(peer: str, state: str):
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
                        self._log(f"🛰 Relay hub {peer} dropped — re-electing a new hub…")
                        asyncio.ensure_future(self._on_topology_changed())
                else:
                    self._room_peers[peer] = state
                    self._refresh_participant_list()
                # Honest aggregate status across the WHOLE room (not last-wins).
                self._apply_aggregate_status(self._room_peers, group=True)
            else:
                # 1-to-1 peer state changed — flip its presence dot/wifi promptly
                # and refresh the header if it's the open conversation.
                self._refresh_contact_list()
                if peer == self._active_contact and not self._room_id:
                    self._update_chat_header_contact(peer)
                self._apply_aggregate_status({peer: state}, group=False)
            if state == "connected":
                self.msg_input.disabled  = False
                self.btn_send.disabled   = False
                self.btn_call.disabled   = False
                self.btn_screen.disabled = False
                self.btn_file.disabled   = False
                self.page.update()
            elif state in ("failed", "disconnected", "closed"):
                if not any(s == "connected" for s in self._room_peers.values()):
                    self.msg_input.disabled  = True
                    self.btn_send.disabled   = True
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
                try:
                    await asyncio.sleep(25)
                except asyncio.CancelledError:
                    return
                if self._ringing:
                    _stop_ring()
                    self.engine.reject_call(sender)
                    self._hide_call_banner()
                    self._log(f"Missed call from {sender} (timed out).")
                    self.page.update()

            self._show_call_banner(sender, accept, reject)
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
            self.btn_screen.icon_color = C.SUBTLE
            self.btn_screen.tooltip    = "Share screen"
            self._set_mute_banner(False)
            # Remote hung up — clear ALL incoming screen shares and exit full
            # screen / PiP so nothing stale remains after the call ends.
            self._clear_all_video()
            self._update_call_status(False)
            self._log("[Call ended]")
            self._refresh_call_controls()
            self.page.update()

        def on_video_frame(sender: str, img):
            # Coalesce to a UI-friendly rate so a fast sender can't pile up
            # per-frame work on a weak receiver, then dispatch the CPU-bound
            # JPEG encode to a thread so the event loop stays responsive.
            now  = time.monotonic()
            last = self._last_tile_render.get(sender, 0.0)
            if now - last < self._tile_render_interval:
                return
            self._last_tile_render[sender] = now
            asyncio.ensure_future(self._update_video_tile(sender, img))

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

        def on_session_ready(peer: str):
            # Peer-assisted history sync (feature E): once the encrypted session
            # with a room peer is up, ask them for anything we missed while offline.
            # Ephemeral rooms persist nothing, so there's nothing to sync.
            if self._room_id and peer in self._room_peers and not self._ephemeral:
                since = last_room_message_ts(self._room_id) or ""
                asyncio.ensure_future(
                    self.engine.send_history_request(peer, self._room_id, since))

        def on_history_request(peer: str, room_id: str, since: str):
            if not room_id or room_id != self._room_id or self._ephemeral:
                return
            msgs = read_room_messages_since(
                room_id, since, self.history_key, self.settings.security_mode,
                self.engine.my_username, limit=self.engine.HISTORY_SYNC_MAX)
            if msgs:
                asyncio.ensure_future(
                    self.engine.send_history_response(peer, room_id, msgs))

        def on_history_response(peer: str, room_id: str, messages: list):
            if not room_id or room_id != self._room_id:
                return
            me   = self.engine.my_username
            seen = read_room_message_keys(room_id, self.history_key, self.settings.security_mode)
            room_open = (self._room_id == room_id) and not self._active_contact
            added = 0
            for m in messages:
                sender  = (m.get("sender") or peer)
                content = m.get("content") or ""
                if not content or sender == me:        # I authored it / empty — skip
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

        self.engine.on_state_change   = on_state
        self.engine.on_key_change     = on_key_change
        self.engine.on_message        = on_message
        self.engine.on_call_incoming  = on_call_incoming
        self.engine.on_call_accepted  = on_call_accepted
        self.engine.on_file_chunk     = on_file_chunk
        self.engine.on_file_complete  = on_file_complete
        self.engine.on_hangup         = on_hangup
        self.engine.on_video_frame    = on_video_frame
        # Incoming screen track ended (sender stopped / call dropped) → remove the
        # tile and drop out of full screen / PiP so nothing stale lingers.
        self.engine.on_video_end      = lambda sender: self._remove_video_tile(sender)
        def on_membership_change(peer: str, is_member: bool):
            # Feature D: refresh the participant badge (✓ member / ⚠ unvouched).
            if peer in self._room_peers:
                self._refresh_participant_list()

        self.engine.on_session_ready  = on_session_ready
        self.engine.on_history_request  = on_history_request
        self.engine.on_history_response = on_history_response
        self.engine.on_membership_change = on_membership_change

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
            self._update_status("SIGNALING", C.YELLOW)
            self._toast(f"Connected as “{uname}”" + (f" in {room}" if room else ""), "success")
            print(f"[connect] websocket OPEN to {safe_url}", flush=True)
            sounds.play("reactivated")
            asyncio.ensure_future(self._signaling_listener())
            asyncio.ensure_future(self._query_presence())   # immediate presence refresh
        except Exception as ex:
            self.engine.last_error = f"signaling: {type(ex).__name__}"
            self._toast(f"Cannot reach server: {ex}", "error")
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

                    elif t == "presence":
                        # Server-confirmed online set for our contacts.
                        self._apply_presence(data.get("online", []))

                    elif t == "error":
                        msg_text = data if isinstance(data, str) else msg.get("error", str(data))
                        match = _re.search(r"User '(.+?)' is offline", msg_text)
                        if match and match.group(1) in self._pending_invites:
                            username = match.group(1)
                            self._pending_invites.discard(username)
                            self._toast(f"Could not invite {username} — they are offline", "warn")
                        else:
                            self._toast(msg_text, "error")
                except Exception as inner_ex:
                    print(f"[signaling] Error handling message {t} from {sender}: {inner_ex}", flush=True)

        except Exception as ex:
            self._toast(f"Disconnected from signaling: {ex}", "error")
            self._update_status("IDLE", C.FAINT)
            self._clear_all_video()
            for _peer in list(self.engine.pcs.keys()):
                asyncio.ensure_future(self.engine.remove_peer(_peer))
            self._purge_ephemeral()   # auto-destruct an ephemeral room on ws close

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
        code = generate_room_code()

        ephem_cb = ft.Checkbox(
            label="🔥 Ephemeral — auto-destruct (nothing saved to disk)", value=False)

        # Two doors, lock on the secure one: an invite-only room is gated by a
        # pre-shared key (joinable ONLY with the invite link); an open room is
        # joinable by anyone who types the room code.
        def choose(secure: bool):
            self._close_dialog(dlg)
            self._room_psk = invites.generate_psk() if secure else None
            self._ephemeral = bool(ephem_cb.value)
            asyncio.ensure_future(self._create_room_finish(code, secure))

        dlg = ft.AlertDialog(
            title=ft.Text(f"Create room {code}"),
            content=ft.Column([
                ft.Text("How can people join?", size=12, color=C.SUBTLE),
                ft.Text("🔒 Invite-only — join only with the invite link (a pre-shared "
                        "key hides the room from anyone without it). Recommended.",
                        size=11, color=C.MUTED),
                ft.Text("🌐 Open — anyone who knows the room code can join.",
                        size=11, color=C.MUTED),
                ephem_cb,
                ft.Text("Ephemeral rooms keep messages in memory only and purge keys, "
                        "logs and tracks the moment you disconnect.", size=11, color=C.MUTED),
            ], tight=True, spacing=8, width=360),
            actions=[
                ft.FilledButton("🔒 Invite-only", on_click=lambda e: choose(True),
                                style=_filled_style(C.CYAN)),
                ft.TextButton("🌐 Open", on_click=lambda e: choose(False)),
                ft.TextButton("Cancel", on_click=lambda e: self._close_dialog(dlg)),
            ],
        )
        self._show_dialog(dlg)

    async def _create_room_finish(self, code: str, secure: bool) -> None:
        print(f"[create_room] generated {code} (secure={secure}), joining…", flush=True)
        await self._join_room(code, is_creator=True)
        if secure:
            self._log("Invite-only room created — share the invite link to let others in.")
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
        self.page.update()
        self._refresh_hub_indicator()
        await self._connect_signaling(None, room=code)

    # ------------------------------------------------------------------
    # Invite links (HELU-INV1) — copy / redeem
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

        def generate(ev):
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
            self.page.clipboard.set(code)
            self._log("Invite link copied to clipboard.")
            self.page.update()

        dlg = ft.AlertDialog(
            title=ft.Text("Invite link"),
            content=ft.Column([
                ft.Text(f"Room {self._room_id}  ·  {_redact_url(self.settings.signaling_url)}",
                        size=12, color=C.SUBTLE),
                incl_pw,
                ft.Text("Anyone with this link can reach your signaling server and join the "
                        "room — share it only over a trusted channel.", size=11, color=C.YELLOW),
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
            asyncio.ensure_future(self._join_room(info["room_id"], is_creator=False))

        dlg = ft.AlertDialog(
            title=ft.Text("Join room?"),
            content=ft.Column(rows, tight=True, spacing=10, width=360),
            actions=[
                ft.FilledButton("Join room", icon=ft.Icons.LOGIN,
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
        if not contacts:
            self.contact_list.controls.append(self._empty_state(
                ft.Icons.PERSON_ADD_ALT_1,
                "No contacts yet",
                "Add a contact or share your identity code to start a private conversation.",
            ))
        else:
            for c in contacts:
                self.contact_list.controls.append(self._contact_card(c))
        self.page.update()

    def _empty_state(self, icon, title: str, subtitle: str = "") -> ft.Container:
        """A calm, centered placeholder for an empty list/area — replaces blank
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
                       tooltip="Not verified — click ··· to view fingerprint")

    def _avatar(self, display: str, verified: bool, size: int = 34) -> ft.Container:
        return ft.Container(
            content=ft.Text((display or "?")[0].upper(), color="#ffffff",
                            weight=ft.FontWeight.W_800, size=int(size * 0.4)),
            width=size, height=size, border_radius=R.PILL,
            alignment=ft.Alignment.CENTER, gradient=self._avatar_gradient(verified),
        )

    def _contact_card(self, c) -> ft.Container:
        display   = c.nickname or c.username
        is_active = c.username == self._active_contact and not self._room_id
        is_online = self._is_contact_online(c.username)
        verified  = c.verified if self.settings.security_mode == "e2ee" else False
        dot_color = C.GREEN if is_online else C.FAINT

        avatar = ft.Stack([
            self._avatar(display, verified, 34),
            ft.Container(
                width=11, height=11, border_radius=R.PILL, bgcolor=dot_color,
                border=ft.Border.all(2, C.PANEL), right=0, bottom=0,
                shadow=_glow(dot_color, blur=8, spread=0) if is_online else None,
            ),
        ], width=34, height=34)

        name = ft.Row(
            [
                ft.Text(display, size=13,
                        color=C.TEXT if is_active else C.SUBTLE,
                        weight=ft.FontWeight.W_700 if is_active else ft.FontWeight.W_500,
                        max_lines=1, overflow=ft.TextOverflow.ELLIPSIS),
                *([badge] if (badge := self._verify_badge(verified)) else []),
            ],
            spacing=4, tight=True,
        )
        wifi = ft.Icon(ft.Icons.WIFI if is_online else ft.Icons.WIFI_OFF,
                       color=C.GREEN if is_online else C.FAINT, size=15)
        btn_menu = ft.IconButton(
            ft.Icons.MORE_VERT, icon_size=14, icon_color=C.FAINT,
            tooltip="Contact options",
            on_click=lambda e, u=c.username: self._show_contact_menu(u),
            style=ft.ButtonStyle(padding=ft.Padding.all(2)),
        )

        base_bg = C.CYAN + "1a" if is_active else C.ELEV + "00"
        tile = ft.Container(
            content=ft.Row([avatar, name, ft.Container(expand=True), wifi, btn_menu],
                           spacing=10, vertical_alignment=ft.CrossAxisAlignment.CENTER),
            bgcolor=base_bg,
            padding=ft.Padding.symmetric(horizontal=8, vertical=7),
            border_radius=R.MD,
            border=ft.Border.all(1, C.CYAN if is_active else C.ELEV + "00"),
            on_click=lambda e, u=c.username: self._select_contact(u),
            on_long_press=lambda e, u=c.username: self._show_contact_menu(u),
            animate=_anim(D.FAST), ink=True,
        )

        def on_hover(e, _t=tile, _active=is_active):
            if _active:
                return
            _t.bgcolor = C.ELEV2 if e.data == "true" else C.ELEV + "00"
            try:
                _t.update()
            except Exception:
                pass
        tile.on_hover = on_hover
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
        name = ft.Row(
            [ft.Text(display, size=12, color=C.TEXT, weight=ft.FontWeight.W_500,
                     max_lines=1, overflow=ft.TextOverflow.ELLIPSIS),
             *([b] if (b := self._verify_badge(verified, size=11)) else [])],
            spacing=4, tight=True,
        )
        wifi = ft.Icon(ft.Icons.WIFI if online else ft.Icons.WIFI_OFF,
                       color=dot_color if online else C.MUTED, size=13)
        # Membership badge (feature D) — only shown when membership is in play.
        member_badge = []
        if self.engine.room_creator_pubkey:
            if self.engine.is_member(username):
                member_badge = [ft.Icon(ft.Icons.WORKSPACE_PREMIUM, color=C.GREEN, size=13,
                                        tooltip="Verified member (creator-signed)")]
            else:
                member_badge = [ft.Icon(ft.Icons.HELP_OUTLINE, color=C.YELLOW, size=13,
                                        tooltip="Not a vouched member")]
        return ft.Container(
            content=ft.Row([avatar, name, ft.Container(expand=True), *member_badge, wifi],
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
        self.chat_header_avatar.content = ft.Text(display[0].upper(), color="#ffffff",
                                                  weight=ft.FontWeight.W_800)
        self.chat_header_avatar.gradient = self._avatar_gradient(verified)
        self.chat_header_title.value = display
        self.chat_header_status_dot.visible = True
        self.chat_header_status_dot.bgcolor = C.GREEN if online else C.FAINT
        self.chat_header_status_text.visible = True
        self.chat_header_status_text.value = "online" if online else "offline"
        self.chat_header_status_text.color = C.GREEN if online else C.MUTED

    def _update_chat_header_room(self, code: str) -> None:
        self.chat_header_lead.visible = False
        self.chat_header_avatar.visible = True
        self.chat_header_avatar.content = ft.Icon(ft.Icons.GROUPS, color="#ffffff", size=18)
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
            asyncio.ensure_future(self._ring_pulse())

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
                # A mismatch means the key you're seeing is NOT your contact's —
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
                title=ft.Text(f"Fingerprint — {c.nickname or username}"),
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
                    ft.FilledButton("Matches — Verify", icon=ft.Icons.VERIFIED,
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
        self._refresh_contact_list()              # move the active highlight
        self._update_chat_header_contact(username)  # show selected conversation as context
        self._update_main_view()                  # leave home → show conversation
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
        self._bulk_load = True
        for m in msgs:
            self._append_to_log(m["direction"], m["content"], bool(m["verified"]))
        self._bulk_load = False
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
        self._update_main_view()                  # leave home → show conversation
        self.page.update()

    def _load_more_room_history(self) -> None:
        msgs = read_room_messages(
            self._room_id, self.history_key,
            self.settings.security_mode, limit=100, offset=self._history_offset,
        )
        self._bulk_load = True
        for m in msgs:
            self._append_to_log(
                m["direction"], m["content"], bool(m["verified"]),
                label=m.get("sender") or "You",
            )
        self._bulk_load = False
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
        if contact and not (self._ephemeral and self._room_id):  # ephemeral → memory only
            write_message(
                contact, "sent", "chat", text,
                self.history_key, self.settings.security_mode,
                room_id=self._room_id or None,
                sender=None,
            )
        self._append_to_log("sent", text, False)
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
        self._update_call_status(True)
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
        self.btn_screen.icon_color = C.CYAN         # active = sharing (accent)
        self.btn_screen.tooltip    = "Stop sharing"
        self._update_call_status(True)
        self._log("[Screen sharing started] — tip: start a call too if you also want to talk.")
        self.page.update()

    async def _toggle_screen(self, e) -> None:
        if self._in_screen_share:
            await self._stop_screen()
        else:
            await self._start_screen(e)

    async def _stop_screen(self) -> None:
        # Stop just the screen track — voice (if any) keeps flowing.
        if self._room_id:
            for peer in list(self.engine.pcs.keys()):
                await self.engine.stop_screen_share(peer)
        else:
            await self.engine.stop_screen_share(self._active_contact)
        self._in_screen_share = False
        self.btn_screen.icon_color = C.SUBTLE
        self.btn_screen.tooltip    = "Share screen"
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
            asyncio.ensure_future(self._hide_mute_banner_delayed())
        self.page.update()

    async def _hangup(self, e) -> None:
        # Stop screen share cleanly before hanging up so the screen source is
        # released and peers receive a renegotiation (track removed gracefully).
        if self._in_screen_share:
            await self._stop_screen()
        self.engine.hangup()
        # Tear down any INCOMING screen shares too — a hung-up call must never
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
        self.btn_screen.tooltip    = "Share screen"
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
        except Exception:
            pass

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
            bgcolor="#000000aa", padding=ft.Padding.symmetric(horizontal=8, vertical=4),
            border_radius=ft.BorderRadius.all(R.PILL),
            margin=ft.Margin.all(8),
        )
        fs_hint = ft.Container(
            content=ft.Icon(ft.Icons.FULLSCREEN, color=C.WHITE, size=16),
            bgcolor="#000000aa", padding=ft.Padding.all(4),
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
            # the stream we were viewing ended — switch to another or close
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
        self._log(f"🖥 {sender} is sharing their screen — click their tile to view it full screen.")
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
                ft.Text("Adjust remote participant volume — applies instantly.",
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
        # One chip per active incoming stream — tap to switch which is maximized.
        self._fs_switcher.controls = [
            ft.FilledButton(
                s, on_click=lambda e, u=s: self._open_fullscreen(u),
                style=_filled_style(C.MAGENTA if s == self._fullscreen_sender else C.ELEV2,
                                    "#ffffff", pad_h=12, pad_v=8),
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
                    "Matches — Verify.", size=11, color=C.MUTED),
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
            await picker.save_file(file_name="helucryptic-backup.helu", src_bytes=blob)
            self._log("Encrypted backup saved.")

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
            for p in list(self.engine.pcs.keys()):
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

    def _show_diagnostics(self, e) -> None:
        self._diag_open = True
        body = ft.Text("", size=12, color=C.TEXT, selectable=True, font_family="monospace")
        logview = ft.Text("", size=11, color=C.SUBTLE, selectable=True, font_family="monospace")

        def render_state() -> str:
            d = self.engine.get_diagnostics()
            lines = [
                "helucryptic — client_claude",
                f"Data dir   : {paths.DATA_DIR}"
                + ("  (portable)" if paths.is_portable() else ""),
                f"Signaling  : {d['signaling']}",
                f"Server URL : {_redact_url(self.settings.signaling_url)}",
                f"Username   : {d['my_username'] or '(not set)'}",
                f"Security   : {d['security_mode']}",
                f"Room       : {d['room_id'] or '(none)'}"
                + (f'   hub={d["hub"] or "?"}' if d["room_id"] else ""),
                f"TURN       : {'configured' if d['turn_configured'] else 'not configured'}",
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
            return "\n".join(lines)

        def render_log() -> str:
            return "\n".join(list(LOG_BUFFER)[-300:]) or "(no log captured yet)"

        body.value = render_state()
        logview.value = render_log()

        async def refresh_loop():
            while self._diag_open:
                try:
                    body.value = render_state()
                    logview.value = render_log()
                    body.update()
                    logview.update()
                except Exception:
                    break
                await asyncio.sleep(1)

        def copy_all(ev):
            self.page.clipboard.set(render_state() + "\n\n===== LOG =====\n" + render_log())
            self._log("Diagnostics + log copied to clipboard.")

        def close(ev):
            self._diag_open = False
            self._close_dialog(dlg)

        dlg = ft.AlertDialog(
            title=ft.Text("Connection diagnostics"),
            content=ft.Container(width=560, height=460, content=ft.Column([
                ft.Container(
                    content=body, padding=ft.Padding.all(10),
                    bgcolor=C.ELEV, border_radius=R.MD, border=ft.Border.all(1, C.BORDER),
                ),
                ft.Text("Live log (newest last) — captured for .exe builds:",
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
        asyncio.ensure_future(refresh_loop())

    def _purge_ephemeral(self) -> None:
        """Auto-destruct (feature H): wipe an ephemeral room's in-RAM traces —
        messages, video tiles, session/room keys, and room references in the
        captured-log buffer. Disk was never written for these rooms."""
        if not self._ephemeral:
            return
        rid = self._room_id
        self.chat_log.controls.clear()
        for sender in list(self._video_tiles.keys()):
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
        self._log("🔥 Ephemeral room purged from memory — no trace on disk.")
        try:
            self.page.update()
        except Exception:
            pass

    async def _switch_profile(self, name: str) -> None:
        """Hot-swap to another profile: stop this session, re-point the data dir
        to the profile's sandbox, and rebuild the app against its keys/contacts/
        history — without restarting the process."""
        self._log(f"Switching to profile '{name}'…")
        self._purge_ephemeral()   # don't carry an ephemeral room across profiles
        # Stop this session's background loops + live connections.
        for t in self._bg_tasks:
            t.cancel()
        self._bg_tasks = []
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
        for p in list(self.engine.pcs.keys()):
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
        pw = self._server_password
        self.page.controls.clear()
        self.page.update()
        app = HelucrypticApp(self.page)
        app._server_password = pw
        app._refresh_contact_list()

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
        custom_days   = _neon_field(
            label="Days", width=100, dense=True,
            visible=(preset_value == "custom"),
            value=str(self.settings.retention_days) if preset_value == "custom" else "1",
        )
        custom_error  = ft.Text("", color=C.RED, size=11, visible=False)
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

        url_field = _neon_field(
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
        turn_url_f  = _neon_field(label="TURN URL (turn:host:port)", value=self.settings.turn_url,
                                   width=280, dense=True)
        turn_user_f = _neon_field(label="TURN username", value=self.settings.turn_username,
                                   width=280, dense=True)
        turn_pass_f = _neon_field(label="TURN password", value=self.settings.turn_password,
                                   width=280, dense=True, password=True, can_reveal_password=True)
        turn_result = ft.Text("", size=11)
        async def do_test_turn(ev):
            from webrtc_engine import test_turn
            turn_result.value = "Testing…"; turn_result.color = C.SUBTLE; self.page.update()
            ok, msg = await test_turn(turn_url_f.value.strip(), turn_user_f.value.strip(), turn_pass_f.value)
            turn_result.value = msg; turn_result.color = C.GREEN if ok else C.RED; self.page.update()
        btn_test_turn = ft.TextButton("Test TURN", on_click=do_test_turn)

        # --- Port forwarding (advanced) ---
        pf_enabled_cb = ft.Checkbox(
            label="I'm port-forwarding (VPN/router)",
            value=self.settings.port_forward_enabled,
        )
        pf_port_f = _neon_field(
            label="Forwarded port", value=str(self.settings.forwarded_port or ""),
            width=280, dense=True,
        )
        pf_result = ft.Text("", size=11)

        async def do_pf_autodetect(ev):
            pf_result.value = "Detecting…"; pf_result.color = C.SUBTLE; self.page.update()
            gw   = await asyncio.to_thread(discover_gateway) or PROTON_GATEWAY
            ip   = await asyncio.to_thread(local_ip_for, gw)
            port = await asyncio.to_thread(request_mapping_over_socket, gw)
            if port and ip:
                pf_port_f.value = str(port)
                pf_result.value = f"Got port {port} on {ip}"; pf_result.color = C.GREEN
            else:
                pf_result.value = "No NAT-PMP mapping — enter the port manually"
                pf_result.color = C.RED
            self.page.update()
        btn_pf_detect = ft.TextButton("Auto-detect (NAT-PMP)", on_click=do_pf_autodetect)

        async def do_pf_test(ev):
            from webrtc_engine import test_forwarded_port
            try:
                port = int(pf_port_f.value or 0)
            except ValueError:
                port = 0
            if not (1024 <= port <= 65535):
                pf_result.value = "Enter a valid port (1024–65535)"; pf_result.color = C.RED
                self.page.update(); return
            pf_result.value = "Testing…"; pf_result.color = C.SUBTLE; self.page.update()
            gw = await asyncio.to_thread(discover_gateway) or PROTON_GATEWAY
            ip = await asyncio.to_thread(local_ip_for, gw)
            if not ip:
                pf_result.value = "Could not determine local IP"; pf_result.color = C.RED
                self.page.update(); return
            ok, msg = await asyncio.to_thread(test_forwarded_port, ip, port)
            pf_result.value = msg; pf_result.color = C.GREEN if ok else C.RED
            self.page.update()
        btn_pf_test = ft.TextButton("Test", on_click=do_pf_test)

        pf_caption = ft.Text(
            "Needs full-tunnel VPN; applies to one peer at a time.",
            size=11, color=C.MUTED,
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

        # --- Profiles (feature G) ---
        prof_active = profiles.active_name() or "default (root)"
        prof_dd = ft.Dropdown(
            value=profiles.active_name(), width=200, hint_text="Choose a profile",
            options=[ft.dropdown.Option(p) for p in profiles.list_profiles()],
        )
        new_prof = _neon_field(label="New profile name", width=200)
        prof_err = ft.Text("", color=C.RED, size=11, visible=False)

        def do_switch_profile(ev):
            name = prof_dd.value
            if name and name != profiles.active_name():
                self._close_dialog(dlg)
                asyncio.ensure_future(self._switch_profile(name))

        def do_create_profile(ev):
            try:
                safe = profiles.create_profile(new_prof.value)
            except ValueError as ex:
                prof_err.value = str(ex); prof_err.visible = True; self.page.update(); return
            self._close_dialog(dlg)
            asyncio.ensure_future(self._switch_profile(safe))

        _sec = self._settings_section
        sections = [
            _sec("Profiles", ft.Icons.SWITCH_ACCOUNT, [
                ft.Text(f"Active: {prof_active}", size=12, color=C.SUBTLE),
                ft.Text("Each profile is a fully separate identity, contacts and history.",
                        size=11, color=C.MUTED),
                ft.Row([prof_dd, ft.FilledButton("Switch", on_click=do_switch_profile,
                                                 style=_filled_style(C.CYAN))]),
                ft.Row([new_prof, ft.FilledButton("Create & switch", on_click=do_create_profile,
                                                  style=_filled_style(C.VIOLET, "#ffffff"))]),
                prof_err,
            ], accent=C.VIOLET),
            _sec("Security & privacy", ft.Icons.SHIELD_MOON, [
                ft.Text("Encryption mode", size=11, color=C.MUTED),
                mode_radio,
                ft.Text("Message retention", size=11, color=C.MUTED),
                ft.Row([retention_dd, custom_days]),
                custom_error,
            ]),
            _sec("Connection", ft.Icons.LANGUAGE, [url_field], accent=C.VIOLET),
            _sec("Performance", ft.Icons.SPEED, [profile_dd, overclock_warn], accent=C.VIOLET),
            _sec("TURN relay", ft.Icons.ROUTER, [
                ft.Text("Optional — fixes strict-NAT connections.", size=11, color=C.MUTED),
                turn_url_f, turn_user_f, turn_pass_f,
                ft.Row([btn_test_turn, turn_result]),
            ], accent=C.VIOLET),
            _sec("Port forwarding", ft.Icons.SETTINGS_ETHERNET, [
                ft.Text("Advanced — direct connect via a forwarded port.", size=11, color=C.MUTED),
                pf_enabled_cb, pf_port_f,
                ft.Row([btn_pf_detect, btn_pf_test]),
                pf_result, pf_caption,
            ], accent=C.VIOLET),
            _sec("Trust & verification", ft.Icons.VERIFIED_USER, [
                verified_only_cb, btn_show_identity,
            ], accent=C.GREEN),
            _sec("Identity keys", ft.Icons.KEY, [
                ft.Row([
                    ft.FilledButton("Export Keys", on_click=export_keys, style=_filled_style(C.ELEV2, C.TEXT)),
                    ft.FilledButton("Import Keys", on_click=import_keys, style=_filled_style(C.ELEV2, C.TEXT)),
                    ft.FilledButton("Regenerate Keys", on_click=regen_keys, style=_filled_style(C.ELEV2, C.TEXT)),
                ], wrap=True, spacing=8),
            ], accent=C.GREEN),
            _sec("Data & backup", ft.Icons.STORAGE, [
                ft.Text(f"Data folder: {paths.DATA_DIR}"
                        + ("  (portable)" if paths.is_portable() else ""),
                        size=11, color=C.SUBTLE, selectable=True),
                ft.Row([
                    ft.FilledButton("Backup Profile…", on_click=self._show_backup, style=_filled_style(C.ELEV2, C.TEXT)),
                    ft.FilledButton("Restore Profile…", on_click=self._show_restore, style=_filled_style(C.ELEV2, C.TEXT)),
                ], wrap=True, spacing=8),
                ft.TextButton("⚠ Emergency Wipe…", on_click=self._show_wipe,
                              style=ft.ButtonStyle(color=C.RED)),
            ], accent=C.RED),
        ]

        header = ft.Row([
            ft.Container(content=ft.Icon(ft.Icons.SETTINGS, color=C.CYAN, size=20),
                         padding=ft.Padding.all(9), border_radius=R.MD, bgcolor=C.CYAN + "1f",
                         shadow=_glow(C.CYAN + "55", blur=14)),
            ft.Column([
                ft.Text("Settings", size=18, weight=ft.FontWeight.W_800, color=C.WHITE),
                ft.Text("Security, performance & connection", size=11, color=C.MUTED),
            ], spacing=0, tight=True),
        ], spacing=12)

        dlg = ft.AlertDialog(
            title=header,
            content=ft.Container(width=540, height=520, content=ft.Column(
                sections, tight=True, spacing=12, scroll=ft.ScrollMode.AUTO)),
            actions=[
                ft.FilledButton("Save", icon=ft.Icons.CHECK, on_click=save_settings_cb,
                                style=_filled_style(C.CYAN)),
                ft.TextButton("Cancel", on_click=lambda ev: self._close_dialog(dlg)),
            ],
        )
        self._show_dialog(dlg)
        # Staggered fade/scale-in for the section cards.
        for i, card in enumerate(sections):
            self._reveal(card, delay=0.05 + i * 0.05)

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
        color = getattr(C, self._STATUS_COLORS.get(s["level"], "FAINT"))
        self._update_status(s["label"], color)

    def _update_status(self, label: str, color: str) -> None:
        self.status_dot.bgcolor      = color
        self.engine.signaling_status = label.lower()
        if self._motion_ok:
            if self._status_label_task and not self._status_label_task.done():
                self._status_label_task.cancel()
            self._status_label_task = asyncio.ensure_future(
                self._crossfade_status_label(label, color))
            if color == C.GREEN:
                asyncio.ensure_future(self._status_connect_bloom())
        else:
            self.status_label.value = label
            self.status_label.color = color
        self.page.update()

    def _append_to_log(self, direction: str, text: str, verified: bool, label: str = "") -> None:
        is_sent = direction == "sent"
        prefix  = "You" if is_sent else (label or self._active_contact or "Peer")
        self.chat_log.controls.append(self._make_bubble(prefix, text, verified, is_sent))

    def _make_bubble(self, name: str, text: str, verified: bool, is_sent: bool) -> ft.Control:
        """A chat bubble. With the single-accent rebrand, sent vs received are
        distinguished WITHOUT a colour pair: sent = accent-tinted fill + accent
        label on the right; received = neutral surface + muted label on the
        left. Asymmetric corners reinforce direction. Slides+fades in on arrival
        (suppressed during bulk history loads)."""
        # Sent leans on the accent; received stays neutral so a busy room of
        # peers doesn't turn into a wall of accent colour.
        name_color   = C.CYAN if is_sent else C.SUBTLE
        fill         = C.CYAN_DIM if is_sent else C.ELEV
        border_color = (C.CYAN + "55") if is_sent else C.BORDER2
        header = ft.Row(
            [
                ft.Text(name, size=10, color=name_color, weight=ft.FontWeight.W_700),
                *([ft.Icon(ft.Icons.VERIFIED, size=11, color=C.GREEN)] if verified else []),
            ],
            spacing=4, tight=True,
        )
        inner = ft.Container(
            content=ft.Column([
                header,
                ft.Text(text, size=13, color=C.TEXT, selectable=True),
            ], spacing=4, tight=True,
                horizontal_alignment=ft.CrossAxisAlignment.END if is_sent
                else ft.CrossAxisAlignment.START),
            padding=ft.Padding.symmetric(horizontal=14, vertical=10),
            bgcolor=fill,
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
            padding=ft.Padding.only(left=40 if is_sent else 0, right=0 if is_sent else 40),
        )
        if not self._bulk_load:
            bubble.opacity = 0
            bubble.scale = 0.96
            bubble.animate_opacity = _anim(D.MED)
            bubble.animate_scale = _anim(D.MED)
            self._reveal(bubble)
        return bubble

    def _log(self, text: str) -> None:
        # Clean, console-style system line: a centered hairline divider with the
        # message in muted monospace — no italics, reads as intentional system
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
        self.page.update()

    def _toast(self, text: str, level: str = "info") -> None:
        """Surface a transient system/connection message as a toast OVERLAY
        (not inside the conversation transcript). Defensive: if the SnackBar
        API isn't available, it degrades to a chat-log pill so the user still
        sees the message."""
        accent = {"error": C.RED, "warn": C.YELLOW, "success": C.GREEN}.get(level, C.CYAN)
        try:
            self.page.open(ft.SnackBar(
                content=ft.Row(
                    [ft.Icon(ft.Icons.INFO_OUTLINE if level == "info"
                             else ft.Icons.ERROR_OUTLINE if level == "error"
                             else ft.Icons.CHECK_CIRCLE_OUTLINE if level == "success"
                             else ft.Icons.WARNING_AMBER_ROUNDED,
                             color=accent, size=18),
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
# Startup screen
# ---------------------------------------------------------------------------

class StartupScreen:
    def __init__(self, page: ft.Page, on_done):
        self.page      = page
        self.on_done   = on_done
        self._selected = "a"
        self._build()

    def _build(self) -> None:
        self._pw_field  = _neon_field(
            label="Password", password=True, can_reveal_password=True, width=300,
        )
        self._pw_error  = ft.Text("", color=C.RED, size=11, visible=False)
        self._url_field = _neon_field(
            label="Server URL", value="ws://", width=300,
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

        # Make cards clickable to select option
        def select_a(e):
            if self._radio_group.value != "a":
                self._radio_group.value = "a"
                self._on_radio_change(None)

        def select_b(e):
            if self._radio_group.value != "b":
                self._radio_group.value = "b"
                self._on_radio_change(None)

        card_a.on_click = select_a
        card_b.on_click = select_b

        radio_group = ft.RadioGroup(
            value="a",
            content=ft.Column([
                card_a,
                card_b
            ], spacing=16, horizontal_alignment=ft.CrossAxisAlignment.CENTER),
        )
        self._radio_group = radio_group
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
            "Connect", icon=ft.Icons.BOLT, on_click=connect, width=220,
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

        # Entrance animation.
        async def reveal():
            try:
                await asyncio.sleep(0.06)
            except Exception:
                pass
            try:
                panel.opacity = 1
                panel.scale = 1
                panel.update()
            except Exception:
                pass
        asyncio.ensure_future(reveal())

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


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def main(page: ft.Page) -> None:
    _install_log_capture()   # mirror stdout/stderr into the in-app diagnostics log
    # Suppress aiortc SCTP "Cannot send data, not connected" noise: these are
    # background Tasks inside aiortc that try to flush a dead DTLS transport.
    # They are expected on abrupt disconnects and not actionable from our side.
    _loop = asyncio.get_event_loop()
    def _sctp_filter(lp, ctx):
        exc = ctx.get("exception")
        if isinstance(exc, ConnectionError) and "Cannot send data" in str(exc):
            return
        lp.default_exception_handler(ctx)
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

    StartupScreen(page, on_done=launch_app)


if __name__ == "__main__":
    ft.app(target=main)
