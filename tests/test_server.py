# pyrefly: ignore [missing-import]
import json
from contextlib import ExitStack, contextmanager

import pytest
from fastapi.testclient import TestClient

import server


@contextmanager
def patch_password(pw):
    old = server.EXPECTED_PASSWORD
    server.EXPECTED_PASSWORD = pw
    try:
        yield
    finally:
        server.EXPECTED_PASSWORD = old

@pytest.fixture(autouse=True)
def clear_server_state():
    # Reset in-memory signaling state before each test
    server.reset_server_state()

def test_signaling_websocket_connect():
    client = TestClient(server.app)
    with patch_password(""), client.websocket_connect("/ws/alice"):
        assert "alice" in server.active_connections

import asyncio
import socket
import threading

import uvicorn
import websockets


def get_free_port():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind(('127.0.0.1', 0))
    port = s.getsockname()[1]
    s.close()
    return port

class UvicornThread(threading.Thread):
    def __init__(self, app, port):
        super().__init__()
        self.app = app
        self.port = port
        config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning")
        self.server = uvicorn.Server(config)
        self.daemon = True

    def run(self):
        self.server.run()

    def stop(self):
        self.server.should_exit = True

@pytest.mark.asyncio
async def test_password_auth():
    port = get_free_port()
    # NOTE: use a dummy value here - never the real server password (this file
    # is committed to git; the real one lives only in .env, which is ignored).
    with patch_password("test-password-123"):
        thread = UvicornThread(server.app, port)
        thread.start()
        # Wait for server to start
        for _ in range(50):
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.1)
                s.connect(('127.0.0.1', port))
                s.close()
                break
            except Exception:
                await asyncio.sleep(0.05)

        _ws_exc = websockets.exceptions.InvalidHandshake
        try:
            # 1. Connecting without password should be rejected (403)
            with pytest.raises(_ws_exc):
                async with websockets.connect(f"ws://127.0.0.1:{port}/ws/alice") as ws:
                    pass

            # 2. Connecting with wrong password should be rejected (403)
            with pytest.raises(_ws_exc):
                async with websockets.connect(f"ws://127.0.0.1:{port}/ws/alice?password=wrong") as ws:
                    pass

            # 3. Connecting with correct password should succeed
            async with websockets.connect(f"ws://127.0.0.1:{port}/ws/alice?password=test-password-123") as ws:
                await ws.send(json.dumps({"target": "system", "type": "ping"}))

        finally:
            thread.stop()
            thread.join()

def test_duplicate_username_replaces_old():
    client = TestClient(server.app)
    with patch_password(""), client.websocket_connect("/ws/alice") as ws1:
        # Drain session_token so we can read the next message
        token_msg = ws1.receive_json()
        assert token_msg["type"] == "session_token"
        token_msg["data"]["token"]

        # Second connection without the session token should be rejected;
        # ws1 stays alive.
        with client.websocket_connect("/ws/alice") as ws2:
            rejection = ws2.receive_json()
            assert rejection["type"] == "error"
            assert "already in use" in rejection["data"]

def test_p2p_message_routing():
    client = TestClient(server.app)
    with patch_password(""), client.websocket_connect("/ws/alice") as ws_alice:
        ws_alice.receive_json()  # drain session_token
        with client.websocket_connect("/ws/bob") as ws_bob:
            ws_bob.receive_json()  # drain session_token

            # Alice sends a message to Bob
            payload = {
                "target": "bob",
                "type": "offer",
                "data": {"sdp": "dummy sdp"}
            }
            ws_alice.send_json(payload)

            # Bob should receive the message
            received = ws_bob.receive_json()
            assert received["sender"] == "alice"
            assert received["type"] == "offer"
            assert received["data"]["sdp"] == "dummy sdp"


def test_legacy_relay_cannot_bypass_frame_limit():
    client = TestClient(server.app)
    with patch_password(""), client.websocket_connect("/ws/alice") as ws_alice:
        ws_alice.receive_json()
        with client.websocket_connect("/ws/bob") as ws_bob:
            ws_bob.receive_json()
            ws_alice.send_json({
                "target": "bob",
                "type": "p2p_relay",
                "data": "x" * (server._RELAY_FRAME_MAX_BYTES + 1),
            })
            error = ws_alice.receive_json()
            assert error["type"] == "error"
            assert "too large" in error["data"]

def test_room_join_and_state_broadcasts():
    client = TestClient(server.app)
    with patch_password(""):
        # 1. Alice joins room
        with client.websocket_connect("/ws/alice?room=ROOM1") as ws_alice:
            ws_alice.receive_json()  # drain session_token
            data = ws_alice.receive_json()
            assert data["type"] == "room_state"
            assert data["peers"] == []  # Alice is first

            # 2. Bob joins room
            with client.websocket_connect("/ws/bob?room=ROOM1") as ws_bob:
                ws_bob.receive_json()  # drain session_token
                # Bob receives room state with Alice listed
                bob_state = ws_bob.receive_json()
                assert bob_state["type"] == "room_state"
                assert "alice" in bob_state["peers"]

                # Alice receives notification that Bob joined
                alice_notif = ws_alice.receive_json()
                assert alice_notif["type"] == "peer_joined"
                assert alice_notif["sender"] == "bob"

def test_room_capacity_limit():
    client = TestClient(server.app)
    usernames = ["user1", "user2", "user3", "user4"]
    websockets_list = []

    with patch_password(""), ExitStack() as stack:
        # Connect 4 users to same room
        for name in usernames:
            ws = stack.enter_context(client.websocket_connect(f"/ws/{name}?room=ROOM1"))
            ws.receive_json()  # drain session_token
            ws.receive_json()  # drain room_state (or peer_joined for earlier users)
            websockets_list.append(ws)

        # Try to connect 5th user
        with client.websocket_connect("/ws/user5?room=ROOM1") as ws_fifth:
            ws_fifth.receive_json()  # drain session_token
            # Should receive full room error
            data = ws_fifth.receive_json()
            assert data["type"] == "error"
            assert "Room is full" in data["data"]

def test_peer_left_broadcast():
    client = TestClient(server.app)

    with patch_password(""):
        # Alice and Bob join room
        with client.websocket_connect("/ws/alice?room=ROOM1") as ws_alice:
            ws_alice.receive_text()  # drain session_token
            ws_alice.receive_text()  # drain room_state

            with client.websocket_connect("/ws/bob?room=ROOM1") as ws_bob:
                ws_bob.receive_text()  # drain session_token
                ws_bob.receive_text()  # drain room_state
                ws_alice.receive_text()  # drain peer_joined(bob)

                # Bob exits (closes context)

            # Alice should receive peer_left notification
            data = ws_alice.receive_json()
            assert data["type"] == "peer_left"
            assert data["sender"] == "bob"
