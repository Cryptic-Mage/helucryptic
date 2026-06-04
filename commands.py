"""Pure command-palette matching (framework-agnostic, no Flet).

The client builds the concrete command registry (titles + bound actions); this
module only ranks/filters it against a query, so the matching logic is unit
testable in isolation.
"""
from __future__ import annotations


def _is_subsequence(q: str, text: str) -> bool:
    it = iter(text)
    return all(ch in it for ch in q)


def _score(text: str, q: str):
    """Lower is better; None means no match."""
    if not text:
        return None
    if text.startswith(q):
        return 0
    if any(w.startswith(q) for w in text.split()):
        return 1
    if q in text:
        return 2
    if _is_subsequence(q, text):
        return 3
    return None


def filter_commands(commands: list[dict], query: str) -> list[dict]:
    """Return commands matching ``query``, best matches first.

    Match priority: title prefix > title word-start > title substring >
    title subsequence, then the same against keywords (ranked lower). An empty
    query returns every command in its original order.
    """
    q = (query or "").strip().lower()
    if not q:
        return list(commands)

    ranked = []
    for cmd in commands:
        title = str(cmd.get("title", "")).lower()
        kw = str(cmd.get("keywords", "")).lower()
        s_title = _score(title, q)
        s_kw = _score(kw, q)
        scores = [s for s in (s_title, (None if s_kw is None else s_kw + 4)) if s is not None]
        if scores:
            ranked.append((min(scores), cmd))

    # Stable sort keeps original order within equal scores.
    ranked.sort(key=lambda pair: pair[0])
    return [cmd for _, cmd in ranked]
