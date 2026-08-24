"""Tests for sounds.py - SoundManager mixing callback.

All tests bypass real audio hardware by constructing the manager via
object.__new__ and setting up internal state directly.
"""
import threading
from unittest.mock import MagicMock

import numpy as np
import pytest

from sounds import SoundManager


@pytest.fixture
def manager():
    mgr = object.__new__(SoundManager)
    mgr._ok = True
    mgr._sd = MagicMock()
    mgr._stream = MagicMock()
    mgr._lock = threading.Lock()
    mgr._sounds = {}
    mgr._oneshots = []
    mgr._loop = None
    mgr._loop_pos = 0
    mgr._sounds["ping"] = np.array([1000, 2000, 3000, 4000], dtype=np.int16)
    mgr._sounds["loop_snd"] = np.array([100, 200, 300], dtype=np.int16)
    return mgr


def test_mixing_callback_oneshot(manager):
    manager.play("ping")
    outdata = np.zeros((4, 1), dtype=np.int16)
    manager._callback(outdata, 4, None, None)
    expected = np.array([[1000], [2000], [3000], [4000]], dtype=np.int16)
    assert np.array_equal(outdata, expected)
    assert manager._oneshots == []


def test_mixing_callback_oneshot_partial_consumption(manager):
    manager.play("ping")
    outdata = np.zeros((2, 1), dtype=np.int16)
    manager._callback(outdata, 2, None, None)
    expected = np.array([[1000], [2000]], dtype=np.int16)
    assert np.array_equal(outdata, expected)
    assert len(manager._oneshots) == 1


def test_mixing_callback_loop(manager):
    manager.play_loop("loop_snd")
    outdata = np.zeros((5, 1), dtype=np.int16)
    manager._callback(outdata, 5, None, None)
    expected = np.array([[100], [200], [300], [100], [200]], dtype=np.int16)
    assert np.array_equal(outdata, expected)


def test_mixing_callback_loop_stop(manager):
    manager.play_loop("loop_snd")
    manager.stop_loop()
    outdata = np.zeros((3, 1), dtype=np.int16)
    manager._callback(outdata, 3, None, None)
    assert np.array_equal(outdata, np.zeros((3, 1), dtype=np.int16))


def test_mixing_callback_oneshot_and_loop(manager):
    manager.play("ping")
    manager.play_loop("loop_snd")
    outdata = np.zeros((3, 1), dtype=np.int16)
    manager._callback(outdata, 3, None, None)
    expected = np.array([[1100], [2200], [3300]], dtype=np.int16)
    assert np.array_equal(outdata, expected)


def test_play_noop_on_missing_name(manager):
    manager.play("nonexistent")
    assert manager._oneshots == []


def test_play_noop_when_not_ok(manager):
    manager._ok = False
    manager.play("ping")
    assert manager._oneshots == []


def test_play_loop_noop_on_missing_name(manager):
    manager.play_loop("nonexistent")
    assert manager._loop is None


def test_stop_loop_idempotent(manager):
    manager.play_loop("loop_snd")
    manager.stop_loop()
    manager.stop_loop()
    assert manager._loop is None
    assert manager._loop_pos == 0


def test_clipping_prevents_overflow(manager):
    loud = np.array([30000, 30000], dtype=np.int16)
    manager._sounds["loud"] = loud
    manager._sounds["loud2"] = loud
    manager.play("loud")
    manager.play("loud2")
    outdata = np.zeros((2, 1), dtype=np.int16)
    manager._callback(outdata, 2, None, None)
    assert outdata[0][0] == 32767
    assert outdata[1][0] == 32767
