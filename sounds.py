"""Notification / call sound cues, backed by pygame.mixer.

All methods are safe no-ops if pygame is not installed or audio init fails, so
the app always runs. Install with:  pip install pygame
"""
from pathlib import Path

_TRACKS = Path(__file__).parent / "tracks"

# Logical name -> filename in tracks/
_FILES = {
    "message":     "gta_notifaction_bell.mp3",        # new received text
    "authorized":  "isac_authorization_granted.mp3",  # password accepted
    "reactivated": "isac_reactivated.mp3",            # connected to signaling
    "incoming":    "isac_incoming_backup_request.mp3",# incoming call (looped)
    "call_start":  "isac_transmission_start.mp3",     # call established
    "call_end":    "isac_transmission_end.mp3",       # call ended
}

# Dedicated mixer channel index reserved for the looping ringtone so it can be
# started/stopped independently of overlapping one-shot cues.
_RING_CHANNEL = 5


class SoundManager:
    def __init__(self) -> None:
        self._ok = False
        self._pygame = None
        self._sounds: dict = {}
        self._ring_channel = None
        try:
            import pygame
            self._pygame = pygame
            pygame.mixer.init()
            for name, fn in _FILES.items():
                path = _TRACKS / fn
                if path.exists():
                    try:
                        self._sounds[name] = pygame.mixer.Sound(str(path))
                    except Exception as ex:
                        print(f"[sounds] could not load {fn}: {ex}", flush=True)
            if pygame.mixer.get_num_channels() <= _RING_CHANNEL:
                pygame.mixer.set_num_channels(_RING_CHANNEL + 1)
            self._ring_channel = pygame.mixer.Channel(_RING_CHANNEL)
            self._ok = True
            print(f"[sounds] ready ({len(self._sounds)} cues loaded)", flush=True)
        except Exception as ex:
            print(f"[sounds] disabled (install pygame for audio cues): {ex}", flush=True)

    def play(self, name: str) -> None:
        """Fire-and-forget one-shot cue (cues may overlap)."""
        if not self._ok:
            return
        snd = self._sounds.get(name)
        if snd is not None:
            try:
                snd.play()
            except Exception:
                pass

    def play_loop(self, name: str) -> None:
        """Loop a cue on the reserved ring channel until stop_loop()."""
        if not self._ok or self._ring_channel is None:
            return
        snd = self._sounds.get(name)
        if snd is not None:
            try:
                self._ring_channel.play(snd, loops=-1)
            except Exception:
                pass

    def stop_loop(self) -> None:
        if not self._ok or self._ring_channel is None:
            return
        try:
            self._ring_channel.stop()
        except Exception:
            pass


# Module-level singleton used by client.py
manager = SoundManager()
