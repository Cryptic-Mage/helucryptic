"""Per-peer offline outbox for 1-to-1 chat.

A message sent while the peer's DataChannel isn't open is queued here (in order,
bounded) and flushed once the session is ready — so "send while the other side
is offline" becomes at-least-once, in-order delivery on reconnect rather than a
hard failure. Pure logic (no I/O), so it's unit-testable in isolation.
"""
from __future__ import annotations

from collections import deque


class Outbox:
    """Bounded FIFO queue of pending messages keyed by peer username."""

    def __init__(self, max_per_peer: int = 500) -> None:
        self._q: dict[str, deque] = {}
        self._max = max_per_peer

    def enqueue(self, peer: str, item) -> bool:
        """Queue ``item`` for ``peer``. Returns False (and drops the OLDEST) if
        the per-peer cap is hit, so a long offline period can't grow unbounded."""
        dq = self._q.setdefault(peer, deque())
        dropped = False
        while len(dq) >= self._max:
            dq.popleft()
            dropped = True
        dq.append(item)
        return not dropped

    def pending(self, peer: str) -> int:
        return len(self._q.get(peer, ()))

    def has_any(self, peer: str) -> bool:
        return bool(self._q.get(peer))

    def drain(self, peer: str) -> list:
        """Remove and return all queued items for ``peer`` in FIFO order."""
        dq = self._q.pop(peer, None)
        return list(dq) if dq else []

    def clear(self, peer: str | None = None) -> None:
        if peer is None:
            self._q.clear()
        else:
            self._q.pop(peer, None)

    def peers_with_pending(self) -> list[str]:
        return [p for p, dq in self._q.items() if dq]
