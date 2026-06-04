"""Pure, framework-agnostic UI-state helpers.

Kept free of Flet so the logic is unit-testable in isolation (part of the
"extract state/" refactor). The client maps the returned semantic ``level`` to
concrete palette colours.
"""
from __future__ import annotations

# WebRTC connectionState values we treat as "in progress".
_CONNECTING = {"new", "connecting", "checking"}
_CONNECTED = "connected"


def summarize_peer_states(states: dict[str, str], *, group: bool = False) -> dict:
    """Collapse a {peer: connectionState} map into one honest status summary.

    Returns a dict: ``{level, label, connected, total}`` where ``level`` is one
    of: ``idle | connecting | connected | partial | disconnected``.

    This replaces the old "last peer wins" behaviour: in a mesh/room the status
    now reflects the WHOLE set (e.g. "1/3 connected"), not whichever peer
    transitioned most recently.
    """
    total = len(states)
    connected = sum(1 for s in states.values() if s == _CONNECTED)
    connecting = any(s in _CONNECTING for s in states.values())

    if total == 0:
        return {"level": "idle", "label": "Idle", "connected": 0, "total": 0}

    if connected == total:
        level = "connected"
        label = f"{connected} connected" if group else "Connected"
    elif connected > 0:
        level = "partial"
        label = f"{connected}/{total} connected"
    elif connecting:
        level = "connecting"
        label = f"Connecting {connected}/{total}" if group else "Connecting"
    else:
        level = "disconnected"
        label = "Disconnected"

    return {"level": level, "label": label, "connected": connected, "total": total}
