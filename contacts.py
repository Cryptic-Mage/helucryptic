import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from crypto import compute_fingerprint

from paths import DATA_DIR, write_private_text
_CONTACTS_PATH = DATA_DIR / "contacts.json"


@dataclass
class Contact:
    username: str
    nickname: str = ""
    x25519_pub: str = ""
    ed25519_pub: str = ""
    fingerprint: str = ""
    verified: bool = False
    added_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    last_seen: str = ""


def _load_raw() -> list[dict]:
    DATA_DIR.mkdir(exist_ok=True)
    if _CONTACTS_PATH.exists():
        try:
            return json.loads(_CONTACTS_PATH.read_text())
        except Exception:
            return []
    return []


def _save_raw(contacts: list[dict]) -> None:
    DATA_DIR.mkdir(exist_ok=True)
    write_private_text(_CONTACTS_PATH, json.dumps(contacts, indent=2))


def load_contacts() -> list[Contact]:
    return [Contact(**c) for c in _load_raw()]


def save_contacts(contacts: list[Contact]) -> None:
    _save_raw([asdict(c) for c in contacts])


def get_contact(username: str) -> Optional[Contact]:
    return next((c for c in load_contacts() if c.username == username), None)


def upsert_contact(
    username: str,
    x25519_pub: str = "",
    ed25519_pub: str = "",
) -> Contact:
    contacts = load_contacts()
    existing = next((c for c in contacts if c.username == username), None)
    if existing:
        # A changed public key on a known contact may indicate a MITM or a
        # re-keyed peer. Either way the old verification no longer applies, so
        # drop the verified flag — the user must re-verify the new fingerprint.
        key_changed = bool(
            (x25519_pub  and existing.x25519_pub  and x25519_pub  != existing.x25519_pub) or
            (ed25519_pub and existing.ed25519_pub and ed25519_pub != existing.ed25519_pub)
        )
        if x25519_pub:
            existing.x25519_pub = x25519_pub
            existing.fingerprint = compute_fingerprint(x25519_pub)
        if ed25519_pub:
            existing.ed25519_pub = ed25519_pub
        if key_changed:
            existing.verified = False
        existing.last_seen = datetime.now(timezone.utc).isoformat()
        save_contacts(contacts)
        return existing
    new_contact = Contact(
        username=username,
        x25519_pub=x25519_pub,
        ed25519_pub=ed25519_pub,
        fingerprint=compute_fingerprint(x25519_pub) if x25519_pub else "",
    )
    contacts.append(new_contact)
    save_contacts(contacts)
    return new_contact


def delete_contact(username: str) -> None:
    save_contacts([c for c in load_contacts() if c.username != username])


def set_verified(username: str, verified: bool) -> None:
    contacts = load_contacts()
    for c in contacts:
        if c.username == username:
            c.verified = verified
    save_contacts(contacts)


def rename_contact(username: str, nickname: str) -> None:
    contacts = load_contacts()
    for c in contacts:
        if c.username == username:
            c.nickname = nickname
    save_contacts(contacts)
