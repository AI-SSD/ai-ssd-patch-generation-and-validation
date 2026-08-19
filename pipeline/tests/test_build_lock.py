"""Tests for the host-global build semaphore (cve_aggregator.utils.build_lock).

flock is associated with the open file *description*, so two separate open()
calls in one process contend — which lets us exercise the cross-process
semaphore semantics within a single test process.
"""
import pytest

from cve_aggregator.utils import build_lock
from cve_aggregator.utils.build_lock import build_slot, is_enabled

_HAS_FLOCK = build_lock.fcntl is not None


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    # Pin the lock dir to a temp dir and start from a clean (disabled) env.
    monkeypatch.setenv("SSD_BUILD_LOCK_DIR", str(tmp_path))
    monkeypatch.delenv("SSD_BUILD_SLOTS", raising=False)
    monkeypatch.delenv("SSD_BUILD_SLOT_TIMEOUT", raising=False)
    yield


def test_disabled_by_default():
    # Unset SSD_BUILD_SLOTS => no-op, byte-identical to legacy (unbounded builds).
    assert is_enabled() is False
    with build_slot() as held:
        assert held is False


def test_invalid_or_nonpositive_slots_is_off(monkeypatch):
    for bad in ("notanint", "0", "-3", ""):
        monkeypatch.setenv("SSD_BUILD_SLOTS", bad)
        assert is_enabled() is False, bad


def test_env_overrides_arg(monkeypatch):
    monkeypatch.setenv("SSD_BUILD_SLOTS", "0")
    assert is_enabled(2) is False          # env 0 overrides arg 2
    monkeypatch.setenv("SSD_BUILD_SLOTS", "1")
    assert is_enabled(0) is True           # env 1 overrides arg 0


@pytest.mark.skipif(not _HAS_FLOCK, reason="no fcntl/flock on this host")
def test_enabled_acquires_and_creates_lockfile(tmp_path, monkeypatch):
    monkeypatch.setenv("SSD_BUILD_SLOTS", "2")
    assert is_enabled() is True
    with build_slot(label="x") as held:
        assert held is True
        assert (tmp_path / "build-slot-1.lock").exists()


@pytest.mark.skipif(not _HAS_FLOCK, reason="no fcntl/flock on this host")
def test_single_slot_is_mutually_exclusive(monkeypatch):
    monkeypatch.setenv("SSD_BUILD_SLOTS", "1")
    with build_slot() as outer:
        assert outer is True
        # The only slot is held; a second acquire cannot get it within the
        # timeout and yields False (best-effort proceed, logged).
        with build_slot(wait_timeout=0.4) as inner:
            assert inner is False


@pytest.mark.skipif(not _HAS_FLOCK, reason="no fcntl/flock on this host")
def test_two_slots_allow_two_concurrent_then_block_third(monkeypatch):
    monkeypatch.setenv("SSD_BUILD_SLOTS", "2")
    with build_slot() as a:
        assert a is True
        with build_slot() as b:                 # second slot is free
            assert b is True
            with build_slot(wait_timeout=0.4) as c:   # both busy now
                assert c is False


@pytest.mark.skipif(not _HAS_FLOCK, reason="no fcntl/flock on this host")
def test_slot_released_on_exit_is_reacquirable(monkeypatch):
    monkeypatch.setenv("SSD_BUILD_SLOTS", "1")
    with build_slot() as first:
        assert first is True
    # Slot freed on context exit → immediately acquirable again.
    with build_slot(wait_timeout=0.4) as second:
        assert second is True
