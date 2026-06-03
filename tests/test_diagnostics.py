import webrtc_engine as W


class S:
    turn_url = "turn:relay.example:3478"
    turn_username = "u"
    turn_password = "p"
    screen_max_w = 1280
    screen_max_h = 720
    screen_fps = 10


_KEYS = {"x25519_public": "", "ed25519_public": "", "x25519_private": "", "ed25519_private": ""}


def _engine():
    return W.WebRTCEngine("me", S(), _KEYS)


def test_ice_servers_include_turn_when_configured():
    assert len(_engine()._ice_servers()) == 3  # 2 STUN + 1 TURN


def test_ice_servers_stun_only_without_turn():
    class NoTurn(S):
        turn_url = ""
    e = W.WebRTCEngine("me", NoTurn(), _KEYS)
    assert len(e._ice_servers()) == 2


def test_get_diagnostics_shape_and_redaction():
    e = _engine()
    e.signaling_status = "connected"
    e._ice_states["bob"] = "checking"
    d = e.get_diagnostics()
    assert d["signaling"] == "connected"
    assert d["turn_configured"] is True
    assert isinstance(d["peers"], list)
    blob = repr(d).lower()
    for forbidden in ("password", "candidate", "sdp", "private", "\"p\""):
        assert forbidden not in blob
