import os

EXPECTED_PASSWORD = os.getenv("HELUCRYPTIC_SERVER_PASSWORD", "")
SERVER_TYPES = {
    "peer_joined", "peer_left", "room_state", "error",
    "session_token", "presence", "hub_capability", "call_active",
}
MAX_ROOM_CAPACITY = 4
SERVER_TITLE = "helucryptic-signaling"
