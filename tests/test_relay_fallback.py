import pytest

from crypto import generate_and_save_keys, paseto_encrypt
from webrtc_engine import WebRTCEngine


class MockSettings:
    security_mode = "e2ee"
    turn_url = ""
    port_forward_enabled = False
    forwarded_port = 0


@pytest.mark.asyncio
async def test_signaling_hello_and_relay_chat_fallback():
    alice_keys = generate_and_save_keys()
    bob_keys = generate_and_save_keys()

    alice = WebRTCEngine("alice", MockSettings(), alice_keys)
    bob = WebRTCEngine("bob", MockSettings(), bob_keys)

    alice_ws_sent = []
    bob_ws_sent = []

    async def alice_send_ws(msg):
        alice_ws_sent.append(msg)

    async def bob_send_ws(msg):
        bob_ws_sent.append(msg)

    alice._send_ws = alice_send_ws
    bob._send_ws = bob_send_ws

    # Step 1: Alice initiates connection to Bob -> sends signaling hello
    await alice._send_signaling_hello("bob")
    assert len(alice_ws_sent) == 1
    hello_msg = alice_ws_sent[0]
    assert hello_msg["type"] == "hello_signaling"
    assert hello_msg["target"] == "bob"

    # Step 2: Bob receives Alice's signaling hello
    # Bob processes Alice's hello, derives session key, and responds with his signaling hello
    await bob.handle_signaling_hello(hello_msg["data"], "alice")
    assert "alice" in bob.session_keys
    assert "alice" in bob._epoch_ids
    assert len(bob_ws_sent) == 1  # Bob replied with his signaling hello

    # Step 3: Alice processes Bob's signaling hello reply
    await alice.handle_signaling_hello(bob_ws_sent[0]["data"], "bob")
    assert "bob" in alice.session_keys
    assert "bob" in alice._epoch_ids

    # Both sides share the identical session key and epoch without any DataChannel!
    assert alice.session_keys["bob"] == bob.session_keys["alice"]
    assert alice._epoch_ids["bob"] == bob._epoch_ids["alice"]

    # Step 4: Alice sends a chat message via Relay-First transport
    alice.target_peer = "bob"
    received_messages = []

    def on_bob_message(sender, text, verified):
        received_messages.append((sender, text))

    bob.on_message = on_bob_message

    alice_relay_sent = []

    async def alice_relay_ws(msg):
        alice_relay_sent.append(msg)
        # Directly deliver relayed message to Bob
        if msg["type"] == "relay_e2ee":
            await bob.handle_relay_message(msg["data"], "alice")

    alice._send_ws = alice_relay_ws

    mid = await alice.send_chat("Hello Bob via E2EE Relay!")
    assert mid is not None
    assert len(alice_relay_sent) == 1
    assert alice_relay_sent[0]["type"] == "relay_e2ee"

    # Verify Bob received the plaintext message after AAD-authenticated decryption
    assert len(received_messages) == 1
    assert received_messages[0] == ("alice", "Hello Bob via E2EE Relay!")


@pytest.mark.asyncio
async def test_replay_window_rejection():
    alice_keys = generate_and_save_keys()
    bob_keys = generate_and_save_keys()

    alice = WebRTCEngine("alice", MockSettings(), alice_keys)
    bob = WebRTCEngine("bob", MockSettings(), bob_keys)

    # Establish keys
    async def alice_send_ws(msg):
        if msg["type"] == "hello_signaling":
            await bob.handle_signaling_hello(msg["data"], "alice")

    async def bob_send_ws(msg):
        if msg["type"] == "hello_signaling":
            await alice.handle_signaling_hello(msg["data"], "bob")

    alice._send_ws = alice_send_ws
    bob._send_ws = bob_send_ws
    await alice._send_signaling_hello("bob")

    received = []
    bob.on_message = lambda sender, text, verified: received.append(text)

    # Build and encrypt a frame with seq=5
    payload = {"__type": "chat", "text": "Message 5", "id": "m5", "seq": 5}
    frame = alice._encrypt_frame_for(payload, "bob")

    # First receipt should succeed
    await bob.handle_relay_message(frame, "alice")
    assert len(received) == 1
    assert received[0] == "Message 5"

    # Replay of the exact same frame must be rejected by replay window / deduplication
    await bob.handle_relay_message(frame, "alice")
    assert len(received) == 1  # Not delivered again!


@pytest.mark.asyncio
async def test_relay_rejects_frame_without_authenticated_transport_binding():
    """A valid token without the sender/recipient AAD must not be accepted."""
    alice_keys = generate_and_save_keys()
    bob_keys = generate_and_save_keys()
    alice = WebRTCEngine("alice", MockSettings(), alice_keys)
    bob = WebRTCEngine("bob", MockSettings(), bob_keys)

    async def alice_send_ws(msg):
        if msg["type"] == "hello_signaling":
            await bob.handle_signaling_hello(msg["data"], "alice")

    async def bob_send_ws(msg):
        if msg["type"] == "hello_signaling":
            await alice.handle_signaling_hello(msg["data"], "bob")

    alice._send_ws = alice_send_ws
    bob._send_ws = bob_send_ws
    await alice._send_signaling_hello("bob")
    received = []
    bob.on_message = lambda sender, text, verified: received.append(text)

    # Model an old/stripped frame: it is valid PASETO, but lacks the required
    # transport binding and must never be accepted by the new protocol.
    legacy = {
        "__type": "chat",
        "token": paseto_encrypt(
            {"__type": "chat", "text": "downgrade", "id": "legacy", "seq": 1},
            alice.session_keys["bob"],
        ),
    }
    await bob.handle_relay_message(legacy, "alice")
    assert received == []
