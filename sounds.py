"""Notification / call sound cues.

Backed by `av` (decodes the mp3 cues once) + `sounddevice` (plays/mixes them) —
both already required for WebRTC media, so this adds no dependency and keeps the
packaged binary small (no pygame/SDL).

All methods are safe no-ops if a backend is missing or audio init fails, so the
app always runs.
"""
import threading
from pathlib import Path

import numpy as np

_TRACKS = Path(__file__).parent / "tracks"
_RATE = 48000  # mono int16 @ 48 kHz, matching the call audio path

# Logical name -> filename in tracks/
_FILES = {
    "message":     "gta_notifaction_bell.mp3",        # new received text
    "authorized":  "isac_authorization_granted.mp3",  # password accepted
    "reactivated": "isac_reactivated.mp3",            # connected to signaling
    "incoming":    "isac_incoming_backup_request.mp3",# incoming call (looped)
    "call_start":  "isac_transmission_start.mp3",     # call established
    "call_end":    "isac_transmission_end.mp3",       # call ended
}


def _decode_mp3(path: Path) -> np.ndarray:
    """Decode an mp3 to a 1-D int16 mono array at 48 kHz, or empty on failure."""
    import av

    container = av.open(str(path))
    resampler = av.AudioResampler(format="s16", layout="mono", rate=_RATE)
    chunks: list[np.ndarray] = []

    def _collect(frames):
        if not frames:
            return
        for fr in (frames if isinstance(frames, list) else [frames]):
            chunks.append(fr.to_ndarray().reshape(-1))

    try:
        for frame in container.decode(audio=0):
            _collect(resampler.resample(frame))
        _collect(resampler.resample(None))  # flush
    finally:
        container.close()

    if not chunks:
        return np.zeros(0, dtype=np.int16)
    return np.concatenate(chunks).astype(np.int16)


class SoundManager:
    """One persistent output stream mixes any number of overlapping one-shot
    cues plus a single looping cue (the ringtone)."""

    def __init__(self) -> None:
        self._ok = False
        self._sd = None
        self._sounds: dict[str, np.ndarray] = {}
        self._stream = None
        self._lock = threading.Lock()
        # Active playback state (guarded by _lock):
        self._oneshots: list[list] = []   # [ [samples, pos], ... ]
        self._loop: np.ndarray | None = None
        self._loop_pos = 0

        try:
            import sounddevice as sd
            self._sd = sd
            loaded = 0
            for name, fn in _FILES.items():
                path = _TRACKS / fn
                if not path.exists():
                    continue
                try:
                    samples = _decode_mp3(path)
                    if len(samples):
                        self._sounds[name] = samples
                        loaded += 1
                except Exception as ex:
                    print(f"[sounds] could not load {fn}: {ex}", flush=True)
            self._ok = loaded > 0
            print(f"[sounds] ready ({loaded} cues loaded)", flush=True)
        except Exception as ex:
            print(f"[sounds] disabled (audio backend unavailable): {ex}", flush=True)

    # ------------------------------------------------------------------
    # Mixing callback (runs in sounddevice's audio thread)
    # ------------------------------------------------------------------

    def _callback(self, outdata, frames, time_info, status):
        mix = np.zeros(frames, dtype=np.int32)
        with self._lock:
            # One-shot cues (overlap freely; drop when exhausted).
            still: list[list] = []
            for entry in self._oneshots:
                samples, pos = entry
                chunk = samples[pos:pos + frames]
                mix[:len(chunk)] += chunk.astype(np.int32)
                if pos + frames < len(samples):
                    entry[1] = pos + frames
                    still.append(entry)
            self._oneshots = still
            # Looping cue (wraps until stopped).
            if self._loop is not None and len(self._loop):
                arr, pos, out_i, need = self._loop, self._loop_pos, 0, frames
                while need > 0:
                    chunk = arr[pos:pos + need]
                    mix[out_i:out_i + len(chunk)] += chunk.astype(np.int32)
                    out_i += len(chunk)
                    need -= len(chunk)
                    pos = pos + len(chunk)
                    if pos >= len(arr):
                        pos = 0
                self._loop_pos = pos
        np.clip(mix, -32768, 32767, out=mix)
        outdata[:, 0] = mix.astype(np.int16)

    def _ensure_stream(self) -> bool:
        if self._stream is not None:
            return True
        if not self._ok or self._sd is None:
            return False
        try:
            self._stream = self._sd.OutputStream(
                samplerate=_RATE, channels=1, dtype="int16",
                blocksize=960, callback=self._callback,
            )
            self._stream.start()
            return True
        except Exception as ex:
            print(f"[sounds] could not open output stream: {ex}", flush=True)
            self._stream = None
            return False

    # ------------------------------------------------------------------
    # Public API (matches the previous pygame-backed interface)
    # ------------------------------------------------------------------

    def play(self, name: str) -> None:
        """Fire-and-forget one-shot cue (cues may overlap)."""
        if not self._ok:
            return
        snd = self._sounds.get(name)
        if snd is None or not self._ensure_stream():
            return
        with self._lock:
            self._oneshots.append([snd, 0])

    def play_loop(self, name: str) -> None:
        """Loop a cue until stop_loop()."""
        if not self._ok:
            return
        snd = self._sounds.get(name)
        if snd is None or not self._ensure_stream():
            return
        with self._lock:
            self._loop = snd
            self._loop_pos = 0

    def stop_loop(self) -> None:
        with self._lock:
            self._loop = None
            self._loop_pos = 0


# Module-level singleton used by client.py
manager = SoundManager()
