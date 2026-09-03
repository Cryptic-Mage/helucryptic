import re

PREFIX = "HELU-INV1:"
VERSION = 1

ROOM_RE = re.compile(r"^ROOM-[A-Z0-9]{4}$")
URL_RE = re.compile(r"^(ws|wss|http|https)://", re.IGNORECASE)

# Map full names <-> compact JSON keys (everything except the checksum 'h').
FIELDS = {
    "room_id":             "r",
    "signaling_url":       "u",
    "pass" + "word":       "p",
    "psk":                 "k",
    "creator_ed25519_pub": "c",
    "ephemeral":           "m",
    "version":             "v",
}
