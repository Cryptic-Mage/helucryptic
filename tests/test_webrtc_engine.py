import asyncio
import json
import time
from collections import deque
from pathlib import Path
from unittest.mock import ANY, AsyncMock, MagicMock, patch

import numpy as np
import pytest

import webrtc_engine


# Mock settings class
class MockSettings:
    def __init__(self):
        self.security_mode = "e2ee"
        self.push_to_talk_key = ""

@pytest.fixture
def mock_keys():
    return {
        "x25519_private": "dGVzdF94MjU1MTlfcHJpdmF0ZV9rZXk=",
        "x25519_public": "dGVzdF94MjU1MTlfcHVibGljX2tleQ==",
        "ed25519_private": "dGVzdF9lZDI1NTE5X3ByaXZhdGVfa2V5",
        "ed25519_public": "dGVzdF9lZDI1NTE5X3B1YmxpY19rZXk="
    }

@pytest.fixture
def engine(mock_keys):
    settings = MockSettings()
    return webrtc_engine.WebRTCEngine("alice", settings, mock_keys)

def test_engine_init(engine):
    assert engine.my_username == "alice"
    assert engine.pcs == {}
    assert engine.data_channels == {}
    assert engine.session_keys == {}
    assert engine.target_peer == ""
    assert engine.group_key is None
    assert engine.room_id is None

def test_set_room_creator(engine):
    engine.set_room("ROOM-CODE", is_creator=True)
    assert engine.room_id == "ROOM-CODE"
    assert engine.is_room_creator is True
    # Room creator must generate a cryptographically secure 32-byte group key
    assert engine.group_key is not None
    assert len(engine.group_key) == 32

def test_set_room_guest(engine):
    engine.set_room("ROOM-CODE", is_creator=False)
    assert engine.room_id == "ROOM-CODE"
    assert engine.is_room_creator is False
    assert engine.group_key is None

@pytest.mark.asyncio
@patch("webrtc_engine.RTCPeerConnection")
async def test_add_peer_offerer(mock_pc_class, engine):
    # Setup mock PC
    mock_pc = MagicMock()
    mock_pc.createOffer = AsyncMock()
    mock_pc.setLocalDescription = AsyncMock()
    mock_pc_class.return_value = mock_pc

    ws_send = AsyncMock()

    # Alice (alphabetically lower than bob) should send the offer
    await engine.add_peer("bob", ws_send)

    assert "bob" in engine.pcs
    assert "bob" in engine.data_channels
    # verify that a DataChannel was created
    mock_pc.createDataChannel.assert_called_with("chat", ordered=True)

@pytest.mark.asyncio
@patch("webrtc_engine.RTCPeerConnection")
async def test_add_peer_answerer(mock_pc_class, engine):
    mock_pc = MagicMock()
    mock_pc_class.return_value = mock_pc
    ws_send = AsyncMock()

    # Alice (alphabetically higher than aaron) should wait for offer
    await engine.add_peer("aaron", ws_send)

    assert "aaron" in engine.pcs
    # shouldn't create offer DataChannel directly
    assert "aaron" not in engine.data_channels

@pytest.mark.asyncio
@patch("webrtc_engine.RTCPeerConnection")
async def test_remove_peer(mock_pc_class, engine):
    mock_pc = MagicMock()
    mock_pc_class.return_value = mock_pc

    engine.pcs["bob"] = mock_pc
    engine.data_channels["bob"] = MagicMock()
    engine.session_keys["bob"] = b"key"

    await engine.remove_peer("bob")

    assert "bob" not in engine.pcs
    assert "bob" not in engine.data_channels
    assert "bob" not in engine.session_keys
    mock_pc.close.assert_called_once()

@pytest.mark.asyncio
@patch("webrtc_engine.RTCPeerConnection")
async def test_host_migration_lowest_peer(mock_pc_class, engine):
    engine.set_room("ROOM-CODE", is_creator=False)
    engine.pcs["charlie"] = MagicMock()
    engine.pcs["dave"] = MagicMock()
    engine.session_keys["charlie"] = b"c_key"
    engine.session_keys["dave"] = b"d_key"
    engine.data_channels["charlie"] = MagicMock()
    engine.data_channels["dave"] = MagicMock()

    # Remaining members in room: alice, charlie, dave.
    # Alice is alphabetically lowest, so she should become the creator when the current creator leaves
    await engine.remove_peer("bob") # Assume creator bob leaves

    assert engine.is_room_creator is True
    assert engine.group_key is not None
    assert len(engine.group_key) == 32

def test_mic_mute_toggling(engine):
    mock_mic = MagicMock()
    engine._mic_source = mock_mic

    # Mute
    engine.set_mic_muted(True)
    mock_mic.set_active.assert_called_with(False)

    # Unmute
    engine.set_mic_muted(False)
    mock_mic.set_active.assert_called_with(True)

def test_pcm_mixer_clipping():
    # Test summing of frames and saturation clipping limits
    frames = [
        np.array([[20000]], dtype=np.int32),
        np.array([[15000]], dtype=np.int32)
    ]

    # Total sum is 35000, which exceeds signed 16-bit limit (32767)
    mixed = np.clip(sum(frames), -32768, 32767).astype(np.int16)
    assert mixed[0][0] == 32767

    # Check negative clipping
    neg_frames = [
        np.array([[-25000]], dtype=np.int32),
        np.array([[-10000]], dtype=np.int32)
    ]
    neg_mixed = np.clip(sum(neg_frames), -32768, 32767).astype(np.int16)
    assert neg_mixed[0][0] == -32768

def test_play_callback_mixing(engine):
    # Set up audio chunks in the deque
    engine._play_chunks["bob"] = deque([
        np.array([1000, 2000, 3000], dtype=np.int16),
        np.array([4000, 5000], dtype=np.int16)
    ])
    engine._play_chunks["charlie"] = deque([
        np.array([100, 200, 300, 400], dtype=np.int16)
    ])

    # We want to mix 4 frames of audio
    outdata = np.zeros((4, 1), dtype=np.int16)
    engine._play_callback(outdata, 4, None, None)

    # Base mix BEFORE the playback gain:
    # Frame 0: bob[0] (1000) + charlie[0] (100) = 1100
    # Frame 1: bob[1] (2000) + charlie[1] (200) = 2200
    # Frame 2: bob[2] (3000) + charlie[2] (300) = 3300
    # Frame 3: bob's next chunk[0] (4000) + charlie[3] (400) = 4400
    # Output applies the engine's adjustable gain, then clips to int16.
    base = np.array([1100, 2200, 3300, 4400], dtype=np.float32)
    expected = np.clip(base * engine._volume, -32768, 32767).astype(np.int16).reshape(-1, 1)
    assert np.array_equal(outdata, expected)

    # Check remaining chunks:
    # bob had 5 samples, consumed 4. Left: 1 sample in second chunk: [5000]
    # charlie had 4 samples, consumed 4. Left: empty deque
    assert len(engine._play_chunks["bob"]) == 1
    assert np.array_equal(engine._play_chunks["bob"][0], np.array([5000], dtype=np.int16))
    assert len(engine._play_chunks["charlie"]) == 0

def test_audio_backlog_dropping(engine):
    dq = deque()
    engine._play_chunks["bob"] = dq

    # Append chunks. Max buffered is 48000. Add 5 chunks of 10000 samples. Total = 50000.
    for i in range(5):
        dq.append(np.zeros(10000, dtype=np.int16))

    # Emulate the queue bounding logic
    total = sum(len(c) for c in dq)
    MAX_BUFFERED = 48000
    while total > MAX_BUFFERED and len(dq) > 1:
        total -= len(dq.popleft())

    # Since we added 5 chunks of 10000, total was 50000.
    # 50000 > 48000, so we pop the first chunk (10000).
    # New total is 40000. 40000 <= 48000, so loop terminates.
    # Deque length should now be 4.
    assert len(dq) == 4

@pytest.mark.asyncio
async def test_send_file_chunked(engine, tmp_path):
    # Create a dummy file
    file_path = tmp_path / "test.bin"
    file_content = b"A" * 150 * 1024 # 150 KB (more than one 64 KB chunk)
    file_path.write_bytes(file_content)

    # Mock data channel
    mock_ch = MagicMock()
    mock_ch.readyState = "open"
    mock_ch.bufferedAmount = 0 # Ensure it behaves as an integer, not a MagicMock!
    engine.data_channels["bob"] = mock_ch
    engine.target_peer = "bob"
    engine.settings.security_mode = "dtls" # simple mode

    # Call send_file
    await engine.send_file(str(file_path))

    # Verify mock_ch.send was called
    # Call 1: file_meta
    # Call 2: chunk 1 (64 KB)
    # Call 3: chunk 2 (64 KB)
    # Call 4: chunk 3 (22 KB)
    # Call 5: file_end
    assert mock_ch.send.call_count == 5

    # Check that first call was file_meta
    first_call_args = mock_ch.send.call_args_list[0][0][0]
    meta = json.loads(first_call_args)
    assert meta["__type"] == "file_meta"
    assert meta["filename"] == "test.bin"
    assert meta["size"] == len(file_content)

    # Check that the middle calls were the binary data chunks
    chunk1 = mock_ch.send.call_args_list[1][0][0]
    chunk2 = mock_ch.send.call_args_list[2][0][0]
    chunk3 = mock_ch.send.call_args_list[3][0][0]
    assert isinstance(chunk1, bytes)
    assert len(chunk1) == 64 * 1024
    assert len(chunk2) == 64 * 1024
    assert len(chunk3) == 22 * 1024

    # Check that last call was file_end
    last_call_args = mock_ch.send.call_args_list[4][0][0]
    end = json.loads(last_call_args)
    assert end["__type"] == "file_end"
    assert end["filename"] == "test.bin"


@pytest.mark.asyncio
async def test_send_room_file_uses_group_key(engine, tmp_path):
    from crypto import paseto_decrypt

    file_path = tmp_path / "room.bin"
    file_path.write_bytes(b"A" * 1024)

    mock_ch = MagicMock()
    mock_ch.readyState = "open"
    mock_ch.bufferedAmount = 0
    engine.data_channels["hub"] = mock_ch
    engine.target_peer = "hub"
    engine.set_room("ROOM", is_creator=True)
    engine.settings.security_mode = "e2ee"

    await engine.send_file(str(file_path), target="hub")

    meta = json.loads(mock_ch.send.call_args_list[0][0][0])
    assert meta["__type"] == "file_meta"
    assert "token" in meta
    payload = paseto_decrypt(meta["token"], engine.group_key)
    assert payload["filename"] == "room.bin"


@pytest.mark.asyncio
async def test_receive_file_streams_to_temp_path(engine):
    data = b"hello from disk"
    sha = __import__("hashlib").sha256(data).hexdigest()
    got = {}

    engine.settings.security_mode = "dtls"
    engine.on_file_complete = lambda fname, path, ok: got.update(fname=fname, path=path, ok=ok)
    engine._hello_sent["bob"] = True
    engine._peer_hello_verified["bob"] = True

    await engine._handle_text(json.dumps({
        "__type": "file_meta",
        "filename": "../hello.txt",
        "size": len(data),
        "sha256": sha,
    }), "bob")
    await engine._handle_binary(data, "bob")
    await engine._handle_text(json.dumps({
        "__type": "file_end",
        "filename": "hello.txt",
        "sha256": sha,
    }), "bob")

    assert got["fname"] == "hello.txt"
    assert got["ok"] is True
    assert Path(got["path"]).read_bytes() == data
    Path(got["path"]).unlink()

@pytest.mark.asyncio
@patch("webrtc_engine.get_contact")
@patch("webrtc_engine.upsert_contact")
async def test_hello_handshake_key_change_trigger(mock_upsert, mock_get_contact, engine):
    import base64

    from contacts import Contact

    # Mock verified contact
    mock_get_contact.return_value = Contact(
        username="bob",
        verified=True,
        x25519_pub=base64.b64encode(b"old_x25519_key_32_bytes_long_123").decode(),
        ed25519_pub=base64.b64encode(b"old_ed25519_key_32_bytes_long_12").decode(),
    )

    # Configure callback spy
    key_change_spy = MagicMock()
    engine.on_key_change = key_change_spy

    # Hello frame with new x25519 public key
    payload = {
        "username": "bob",
        "x25519_pub": base64.b64encode(b"new_x25519_key_32_bytes_long_123").decode(),
        "ed25519_pub": base64.b64encode(b"old_ed25519_key_32_bytes_long_12").decode(),
        "iat": "2026-06-01T12:00:00Z"
    }

    # Mock paseto_verify, derive_session_key_v2 and urlsafe_b64decode
    with patch("webrtc_engine._b64.urlsafe_b64decode") as mock_b64_decode, \
         patch("webrtc_engine.paseto_verify") as mock_paseto_verify, \
         patch("webrtc_engine.derive_session_key_v2") as mock_derive:

        mock_b64_decode.return_value = json.dumps({"ed25519_pub": "dummy"}).encode() + b"0" * 64
        mock_paseto_verify.return_value = payload
        mock_derive.return_value = b"sessionkey"

        # Test handle_hello
        frame = {"token": "v4.public.dummy_token"}
        await engine._handle_hello(frame, "bob")

        # Verify callback was called
        key_change_spy.assert_called_once_with("bob")


@patch("webrtc_engine.sd")
def test_microphone_track_threadsafe_callback(mock_sd):
    from unittest.mock import ANY, patch
    # Mock sounddevice InputStream
    mock_input_stream = MagicMock()
    mock_sd.InputStream.return_value = mock_input_stream


    from webrtc_engine import MicrophoneTrack

    # Mock event loop
    mock_loop = MagicMock()

    with patch("asyncio.get_event_loop", return_value=mock_loop):
        track = MicrophoneTrack(push_to_talk=False)

        # Verify loop was captured
        assert track._loop == mock_loop

        # Verify InputStream was created and started
        mock_sd.InputStream.assert_called_once()
        mock_input_stream.start.assert_called_once()

        # Trigger callback from sounddevice C-thread
        dummy_data = np.zeros(960, dtype=np.int16)
        track._audio_callback(dummy_data, 960, None, None)

        # Verify callback used call_soon_threadsafe instead of put_nowait directly
        mock_loop.call_soon_threadsafe.assert_called_once_with(track._queue_put, ANY)

        # Now verify that _queue_put calls put_nowait
        track._queue = MagicMock()
        track._queue_put(dummy_data)
        track._queue.put_nowait.assert_called_once_with(dummy_data)


def _fake_frame():
    return np.zeros((960, 1), dtype=np.int16)


@patch("webrtc_engine.sd")
def test_microphone_track_noise_reduce_off_by_default(mock_sd):
    mock_sd.InputStream.return_value = MagicMock()
    from webrtc_engine import MicrophoneTrack

    mock_loop = MagicMock()
    with patch("asyncio.get_event_loop", return_value=mock_loop):
        track = MicrophoneTrack(push_to_talk=False)

    assert track._reducer is None
    # Callback still feeds the asyncio queue directly (unchanged behaviour).
    track._audio_callback(_fake_frame(), 960, None, None)
    mock_loop.call_soon_threadsafe.assert_called_once_with(track._queue_put, ANY)


@patch("webrtc_engine.sd")
def test_microphone_track_noise_reduce_routes_frames_to_reducer(mock_sd):
    mock_sd.InputStream.return_value = MagicMock()
    from webrtc_engine import MicrophoneTrack

    mock_loop = MagicMock()
    fake_nr = MagicMock()
    with patch("asyncio.get_event_loop", return_value=mock_loop), \
         patch("webrtc_engine._load_noisereduce", return_value=fake_nr), \
         patch("webrtc_engine._NoiseReducer") as MockReducer:
        track = MicrophoneTrack(noise_reduce=True)

        assert track._reducer is MockReducer.return_value
        track._audio_callback(_fake_frame(), 960, None, None)

        track._reducer.submit.assert_called_once()
        mock_loop.call_soon_threadsafe.assert_not_called()


@patch("webrtc_engine.sd")
def test_microphone_track_noise_reduce_import_failure_falls_back(mock_sd):
    mock_sd.InputStream.return_value = MagicMock()
    from webrtc_engine import MicrophoneTrack

    mock_loop = MagicMock()
    with patch("asyncio.get_event_loop", return_value=mock_loop), \
         patch("webrtc_engine._load_noisereduce", side_effect=ImportError("nope")):
        track = MicrophoneTrack(noise_reduce=True)

    assert track._reducer is None
    track._audio_callback(_fake_frame(), 960, None, None)
    mock_loop.call_soon_threadsafe.assert_called_once_with(track._queue_put, ANY)


@patch("webrtc_engine.sd")
def test_microphone_track_stop_stops_reducer(mock_sd):
    mock_sd.InputStream.return_value = MagicMock()
    from webrtc_engine import MicrophoneTrack

    with patch("asyncio.get_event_loop", return_value=MagicMock()), \
         patch("webrtc_engine._load_noisereduce", return_value=MagicMock()), \
         patch("webrtc_engine._NoiseReducer") as MockReducer:
        track = MicrophoneTrack(noise_reduce=True)
        track.stop()

    MockReducer.return_value.stop.assert_called_once()


def test_noise_reducer_denoises_frame_and_preserves_layout():
    from webrtc_engine import _NoiseReducer

    fake_nr = MagicMock()
    fake_nr.reduce_noise.side_effect = lambda y, **kw: y
    sink = MagicMock()
    loop = MagicMock()

    r = _NoiseReducer(48000, True, sink, loop, fake_nr)
    try:
        out = r._denoise(_fake_frame())
    finally:
        r.stop()

    _, kwargs = fake_nr.reduce_noise.call_args
    assert kwargs["sr"] == 48000
    assert kwargs["stationary"] is True
    assert out.dtype == np.int16
    assert out.shape == (960, 1)


def test_noise_reducer_respects_non_stationary_setting():
    from webrtc_engine import _NoiseReducer

    fake_nr = MagicMock()
    fake_nr.reduce_noise.side_effect = lambda y, **kw: y
    r = _NoiseReducer(48000, False, MagicMock(), MagicMock(), fake_nr)
    try:
        r._denoise(_fake_frame())
    finally:
        r.stop()

    _, kwargs = fake_nr.reduce_noise.call_args
    assert kwargs["stationary"] is False


def test_noise_reducer_denoise_falls_back_to_raw_on_error():
    from webrtc_engine import _NoiseReducer

    fake_nr = MagicMock()
    fake_nr.reduce_noise.side_effect = RuntimeError("boom")
    r = _NoiseReducer(48000, True, MagicMock(), MagicMock(), fake_nr)
    frame = _fake_frame()
    try:
        out = r._denoise(frame)
    finally:
        r.stop()

    assert np.array_equal(out, frame)


def test_noise_reducer_skips_denoise_under_backlog():
    from webrtc_engine import _NoiseReducer

    fake_nr = MagicMock()
    fake_nr.reduce_noise.side_effect = lambda y, **kw: y
    sink = MagicMock()
    loop = MagicMock()

    r = _NoiseReducer(48000, True, sink, loop, fake_nr)
    r.stop()  # kill the worker thread so we can drive _emit deterministically

    # Drain any shutdown sentinel, then simulate a backlog.
    while not r._q.empty():
        r._q.get_nowait()
    fake_nr.reduce_noise.reset_mock()
    for _ in range(webrtc_engine._NR_OVERLOAD_FRAMES + 3):
        r._q.put_nowait(_fake_frame())

    r._emit(_fake_frame())

    fake_nr.reduce_noise.assert_not_called()
    loop.call_soon_threadsafe.assert_called_once()


def test_noise_reducer_emits_denoised_frame_when_not_backlogged():
    from webrtc_engine import _NoiseReducer

    fake_nr = MagicMock()
    fake_nr.reduce_noise.side_effect = lambda y, **kw: y
    sink = MagicMock()
    loop = MagicMock()

    r = _NoiseReducer(48000, True, sink, loop, fake_nr)
    r.stop()
    while not r._q.empty():
        r._q.get_nowait()
    fake_nr.reduce_noise.reset_mock()

    r._emit(_fake_frame())

    fake_nr.reduce_noise.assert_called_once()
    loop.call_soon_threadsafe.assert_called_once_with(sink, ANY)


@patch("webrtc_engine.sd")
def test_get_mic_source_passes_noise_reduce_settings(mock_sd, engine, monkeypatch):
    engine.settings.noise_reduce = True
    engine.settings.noise_reduce_stationary = False
    captured = {}

    class FakeMic:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    monkeypatch.setattr(webrtc_engine, "MicrophoneTrack", FakeMic)
    engine._get_mic_source()

    assert captured["noise_reduce"] is True
    assert captured["noise_reduce_stationary"] is False


def test_forwarded_port_rewrites_only_matching_bind():
    import webrtc_engine as we

    calls = []

    async def fake_orig(factory, *a, local_addr=None, **k):
        calls.append(local_addr)
        return ("transport", "protocol")

    we.set_forwarded_port("10.2.0.5", 55000)
    try:
        wrapped = we._make_bind_wrapper(fake_orig)

        async def run():
            await wrapped(object, local_addr=("10.2.0.5", 0))      # rewritten
            await wrapped(object, local_addr=("192.168.1.5", 0))   # untouched
            we.clear_forwarded_port()
            await wrapped(object, local_addr=("10.2.0.5", 0))      # untouched now

        asyncio.run(run())
        assert calls == [
            ("10.2.0.5", 55000),
            ("192.168.1.5", 0),
            ("10.2.0.5", 0),
        ]
    finally:
        we.clear_forwarded_port()


def test_forward_wrapper_assigns_from_pool_then_falls_through():
    import asyncio

    import webrtc_engine as we
    calls = []
    async def fake_orig(factory, *a, local_addr=None, **k):
        calls.append(local_addr); return ("t","p")
    we.set_forwarded_ports("10.2.0.5", [55000, 55001])
    try:
        wrapped = we._make_bind_wrapper(fake_orig)
        async def run():
            await wrapped(object, local_addr=("10.2.0.5", 0))   # -> 55000
            await wrapped(object, local_addr=("10.2.0.5", 0))   # -> 55001
            await wrapped(object, local_addr=("10.2.0.5", 0))   # pool empty -> untouched
            await wrapped(object, local_addr=("192.168.1.5", 0))# non-matching -> untouched
        asyncio.run(run())
        assert calls == [("10.2.0.5",55000),("10.2.0.5",55001),("10.2.0.5",0),("192.168.1.5",0)]
    finally:
        we.clear_forwarded_port()


def test_install_forward_patch_is_idempotent():
    import webrtc_engine as we

    class FakeLoop:
        def __init__(self):
            self.create_datagram_endpoint = lambda *a, **k: None

    loop = FakeLoop()
    first = loop.create_datagram_endpoint
    we.install_forward_patch(loop)
    patched = loop.create_datagram_endpoint
    assert patched is not first
    we.install_forward_patch(loop)
    assert loop.create_datagram_endpoint is patched  # not double-wrapped
