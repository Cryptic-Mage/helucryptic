import pytest
import json
from fastapi.testclient import TestClient
from contextlib import ExitStack, contextmanager
import server

@contextmanager
def patch_password(pw):
    old = server._EXPECTED_PASSWORD
    server._EXPECTED_PASSWORD = pw
    try:
        yield
    finally:
        server._EXPECTED_PASSWORD = old

@pytest.fixture(autouse=True)
def clear_server_state():
    # Reset in-memory signaling state before each test
    server.active_connections.clear()
    server.rooms.clear()
    server.room_of.clear()

def test_signaling_websocket_connect():
    client = TestClient(server.app)
    with patch_password(""):
        with client.websocket_connect("/ws/alice") as ws:
            assert "alice" in server.active_connections

import threading
import time
import socket
import uvicorn
import websockets
import asyncio

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
    with patch_password("CrypticKodu"):
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
                
        try:
            # 1. Connecting without password should raise websockets.exceptions.InvalidStatusCode (403)
            with pytest.raises(websockets.exceptions.InvalidStatusCode) as exc_info:
                async with websockets.connect(f"ws://127.0.0.1:{port}/ws/alice") as ws:
                    pass
            assert exc_info.value.status_code == 403

            # 2. Connecting with wrong password should raise websockets.exceptions.InvalidStatusCode (403)
            with pytest.raises(websockets.exceptions.InvalidStatusCode) as exc_info:
                async with websockets.connect(f"ws://127.0.0.1:{port}/ws/alice?password=wrong") as ws:
                    pass
            assert exc_info.value.status_code == 403

            # 3. Connecting with correct password should succeed
            async with websockets.connect(f"ws://127.0.0.1:{port}/ws/alice?password=CrypticKodu") as ws:
                await ws.send(json.dumps({"target": "system", "type": "ping"}))
                
        finally:
            thread.stop()
            thread.join()

def test_duplicate_username_rejected():
    client = TestClient(server.app)
    with patch_password(""):
        with client.websocket_connect("/ws/alice") as ws1:
            # Try connecting second client with same username
            with client.websocket_connect("/ws/alice") as ws2:
                # Expect to get an error message and then closed
                data = ws2.receive_json()
                assert data["type"] == "error"
                assert "already connected" in data["data"]

def test_p2p_message_routing():
    client = TestClient(server.app)
    with patch_password(""):
        with client.websocket_connect("/ws/alice") as ws_alice:
            with client.websocket_connect("/ws/bob") as ws_bob:
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

def test_room_join_and_state_broadcasts():
    client = TestClient(server.app)
    with patch_password(""):
        # 1. Alice joins room
        with client.websocket_connect("/ws/alice?room=ROOM1") as ws_alice:
            data = ws_alice.receive_json()
            assert data["type"] == "room_state"
            assert data["peers"] == []  # Alice is first
            
            # 2. Bob joins room
            with client.websocket_connect("/ws/bob?room=ROOM1") as ws_bob:
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
    websockets = []
    
    with patch_password(""):
        with ExitStack() as stack:
            # Connect 4 users to same room
            for name in usernames:
                ws = stack.enter_context(client.websocket_connect(f"/ws/{name}?room=ROOM1"))
                # Drain the initial room_state message
                ws.send_text(ws.receive_text())
                websockets.append(ws)
                
            # Try to connect 5th user
            with client.websocket_connect("/ws/user5?room=ROOM1") as ws_fifth:
                # Should receive full room error
                data = ws_fifth.receive_json()
                assert data["type"] == "error"
                assert "Room is full" in data["data"]

def test_peer_left_broadcast():
    client = TestClient(server.app)
    
    with patch_password(""):
        # Alice and Bob join room
        with client.websocket_connect("/ws/alice?room=ROOM1") as ws_alice:
            ws_alice.receive_text()  # drain room_state
            
            with client.websocket_connect("/ws/bob?room=ROOM1") as ws_bob:
                ws_bob.receive_text()  # drain room_state
                ws_alice.receive_text() # drain Bob joined notification
                
                # Bob exits (closes context)
                
            # Alice should receive peer_left notification
            data = ws_alice.receive_json()
            assert data["type"] == "peer_left"
            assert data["sender"] == "bob"
