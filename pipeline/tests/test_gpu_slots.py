#!/usr/bin/env python3
"""Tests for multi-GPU support: slot detection (gpu_slots), the gpu_lock
counting semaphore, and the gpu_monitor residency budget.

No Docker/LLM/GPU is touched — probes are monkeypatched, flock runs on
tmp_path lock dirs.

Run: ``python3 -m pytest tests/test_gpu_slots.py -v`` from the pipeline dir.
"""

import logging
import os
from pathlib import Path

import pytest

from cve_aggregator.utils import gpu_lock as gl
from cve_aggregator.utils import gpu_monitor as gm
from cve_aggregator.utils import gpu_slots as gs

LOG = logging.getLogger("test_gpu_slots")

CSV_TWO_FREE = "1024, 46068\n2048, 46068\n"
CSV_ONE_BUSY = "45000, 46068\n2048, 46068\n"
CSV_ALL_BUSY = "45000, 46068\n44000, 46068\n"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    monkeypatch.delenv("SSD_GPU_SLOTS", raising=False)
    monkeypatch.delenv("SSD_GPU_LOCK", raising=False)
    gs._cache.clear()
    yield
    gs._cache.clear()


# --- detection ladder --------------------------------------------------------
def test_env_var_wins(monkeypatch):
    monkeypatch.setenv("SSD_GPU_SLOTS", "3")
    assert gs.detect_gpu_slots({"gpu_slots": 1}, use_cache=False) == 3


def test_config_int_and_numeric_string():
    assert gs.detect_gpu_slots({"gpu_slots": 2}, use_cache=False) == 2
    assert gs.detect_gpu_slots({"gpu_slots": "2"}, use_cache=False) == 2


def test_probe_command_bare_integer(monkeypatch):
    monkeypatch.setattr(gs, "_run_probe", lambda cmd, frac, log: 2)
    n = gs.detect_gpu_slots({"gpu_slots": "auto", "gpu_probe_command": "true"},
                            use_cache=False)
    assert n == 2


def test_probe_csv_counts_only_available():
    assert gs._parse_probe_output(CSV_TWO_FREE, 0.9) == 2
    assert gs._parse_probe_output(CSV_ONE_BUSY, 0.9) == 1
    assert gs._parse_probe_output("2", 0.9) == 2
    assert gs._parse_probe_output("not,csv,at all\ngarbage", 0.9) is None


def test_all_busy_clamps_to_one(monkeypatch):
    monkeypatch.setattr(gs, "_run_probe",
                        lambda cmd, frac, log: gs._parse_probe_output(CSV_ALL_BUSY, frac))
    n = gs.detect_gpu_slots({"gpu_probe_command": "true"}, use_cache=False)
    assert n == 1


def test_remote_endpoint_skips_local_nvidia_smi(monkeypatch):
    calls = []
    monkeypatch.setattr(gs, "_local_nvidia_smi",
                        lambda frac, log: calls.append(1) or 2)
    n = gs.detect_gpu_slots({}, endpoint="http://10.3.1.226:80/api/chat",
                            use_cache=False)
    assert n == 1 and not calls          # remote → rung skipped → default 1
    n = gs.detect_gpu_slots({}, endpoint="http://localhost:11434/api/chat",
                            use_cache=False)
    assert n == 2 and calls              # local → rung used


def test_invalid_values_fall_through(monkeypatch):
    monkeypatch.setenv("SSD_GPU_SLOTS", "banana")
    monkeypatch.setattr(gs, "_local_nvidia_smi", lambda frac, log: None)
    assert gs.detect_gpu_slots({"gpu_slots": "auto"}, use_cache=False) == 1


def test_endpoint_taken_from_cfg_keys():
    assert gs._is_local_endpoint("") is True
    assert gs._is_local_endpoint("http://127.0.0.1:11434/api/chat") is True
    assert gs._is_local_endpoint("http://10.3.1.226:80/api/chat") is False


# --- gpu_lock counting semaphore ---------------------------------------------
def test_two_slots_admit_two_holders_and_block_third(tmp_path, monkeypatch):
    monkeypatch.setenv("SSD_GPU_LOCK_DIR", str(tmp_path))
    with gl.gpu_lock("ollama", endpoint="ep", slots=2, logger=LOG) as h1:
        assert h1 is True
        with gl.gpu_lock("ollama", endpoint="ep", slots=2, logger=LOG) as h2:
            assert h2 is True
            # Both slot files exist and a third acquisition times out unheld.
            with gl.gpu_lock("ollama", endpoint="ep", slots=2,
                             wait_timeout=1.5, logger=LOG) as h3:
                assert h3 is False


def test_single_slot_uses_legacy_lock_filename(tmp_path, monkeypatch):
    monkeypatch.setenv("SSD_GPU_LOCK_DIR", str(tmp_path))
    with gl.gpu_lock("ollama", endpoint="ep", slots=1, logger=LOG) as held:
        assert held is True
        files = sorted(p.name for p in Path(tmp_path).glob("gpu-*"))
    assert len(files) == 1
    assert files[0].endswith(".lock") and ".s" not in files[0]
    assert files[0] == gl.lock_path("ep").name


def test_slot_paths_distinct_and_slot0_is_legacy():
    p0, p1 = gl.lock_path("ep", 0), gl.lock_path("ep", 1)
    assert p0 != p1
    assert p0 == gl.lock_path("ep")
    assert p1.name.endswith(".s1.lock")


def test_slots_default_resolves_env(tmp_path, monkeypatch):
    monkeypatch.setenv("SSD_GPU_LOCK_DIR", str(tmp_path))
    monkeypatch.setenv("SSD_GPU_SLOTS", "2")
    assert gl._resolve_slots(None) == 2
    with gl.gpu_lock("ollama", endpoint="ep", logger=LOG) as h1:
        with gl.gpu_lock("ollama", endpoint="ep", logger=LOG) as h2:
            assert h1 is True and h2 is True


def test_non_ollama_provider_is_noop(tmp_path, monkeypatch):
    monkeypatch.setenv("SSD_GPU_LOCK_DIR", str(tmp_path))
    with gl.gpu_lock("openai", endpoint="ep", slots=2, logger=LOG) as held:
        assert held is False
    assert not list(Path(tmp_path).glob("gpu-*"))


# --- gpu_monitor residency budget --------------------------------------------
def _entry(name):
    return {"name": name, "model": name, "size": 8 << 30, "size_vram": 8 << 30}


def test_budget_two_allows_one_foreigner(monkeypatch):
    monkeypatch.setattr(gm, "loaded_models",
                        lambda ep, auth, timeout=10: [_entry("other:7b")])
    evictions = []
    monkeypatch.setattr(gm, "evict_others",
                        lambda *a, **kw: evictions.append(kw.get("running")))
    assert gm.ensure_exclusive("ep", model="mine:7b", mode="evict",
                               timeout=5, slots=2) is True
    assert not evictions


def test_budget_two_evicts_only_excess(monkeypatch):
    snapshots = [
        [_entry("a:7b"), _entry("b:7b")],   # 2 foreigners → 1 is excess
        [_entry("a:7b")],                   # excess gone → pass
    ]
    monkeypatch.setattr(gm, "loaded_models",
                        lambda ep, auth, timeout=10: snapshots.pop(0))
    evictions = []
    monkeypatch.setattr(gm, "evict_others",
                        lambda *a, **kw: evictions.append(kw.get("running")))
    assert gm.ensure_exclusive("ep", model="mine:7b", mode="evict",
                               timeout=30, poll_interval=0, slots=2) is True
    assert len(evictions) == 1
    assert [e["name"] for e in evictions[0]] == ["b:7b"]   # kept a:7b


def test_budget_one_keeps_legacy_exclusive_semantics(monkeypatch):
    snapshots = [
        [_entry("a:7b")],   # any foreigner blocks at slots=1
        [],                 # gone → pass
    ]
    monkeypatch.setattr(gm, "loaded_models",
                        lambda ep, auth, timeout=10: snapshots.pop(0))
    evictions = []
    monkeypatch.setattr(gm, "evict_others",
                        lambda *a, **kw: evictions.append(kw.get("running")))
    assert gm.ensure_exclusive("ep", model="mine:7b", mode="evict",
                               timeout=30, poll_interval=0, slots=1) is True
    assert len(evictions) == 1
    assert [e["name"] for e in evictions[0]] == ["a:7b"]   # evicts ALL others


def test_our_resident_model_never_counts_against_budget(monkeypatch):
    monkeypatch.setattr(gm, "loaded_models",
                        lambda ep, auth, timeout=10: [_entry("mine:7b"),
                                                      _entry("other:7b")])
    assert gm.ensure_exclusive("ep", model="mine:7b", mode="wait",
                               timeout=5, slots=2) is True


# --- live slots file + current_slots (the periodic-timer layer) --------------
def test_live_file_roundtrip_and_default(tmp_path, monkeypatch):
    monkeypatch.setenv("SSD_GPU_LOCK_DIR", str(tmp_path))
    assert gs.read_current_slots(default=1) == 1          # absent → default
    gs.write_current_slots(2)
    assert gs.slots_file().exists()
    assert gs.read_current_slots(default=1) == 2          # published value


def test_live_file_staleness_ignored(tmp_path, monkeypatch):
    monkeypatch.setenv("SSD_GPU_LOCK_DIR", str(tmp_path))
    gs.write_current_slots(2)
    # Backdate the file well past the max-age → treated as a dead poller.
    old = os.stat(gs.slots_file()).st_mtime - 100_000
    os.utime(gs.slots_file(), (old, old))
    assert gs.read_current_slots(default=1, max_age=900) == 1
    assert gs.read_current_slots(default=1, max_age=None) == 2  # check disabled


def test_current_slots_precedence(tmp_path, monkeypatch):
    monkeypatch.setenv("SSD_GPU_LOCK_DIR", str(tmp_path))
    monkeypatch.delenv("SSD_GPU_SLOTS", raising=False)
    # No file, no env → caller default.
    assert gs.current_slots(default=1) == 1
    # Env set → env wins over default.
    monkeypatch.setenv("SSD_GPU_SLOTS", "2")
    assert gs.current_slots(default=1) == 2
    # Live file present → wins over env (poller is authoritative).
    gs.write_current_slots(3)
    assert gs.current_slots(default=1) == 3


def test_gpu_lock_reads_live_file_dynamically(tmp_path, monkeypatch):
    monkeypatch.setenv("SSD_GPU_LOCK_DIR", str(tmp_path))
    monkeypatch.delenv("SSD_GPU_SLOTS", raising=False)
    # Poller publishes 2 → the semaphore admits a 2nd concurrent holder even
    # though the caller's static default is 1.
    gs.write_current_slots(2)
    with gl.gpu_lock("ollama", endpoint="ep", slots=1, logger=LOG) as h1:
        with gl.gpu_lock("ollama", endpoint="ep", slots=1, logger=LOG) as h2:
            assert h1 is True and h2 is True


def test_poller_publishes_detected_count(tmp_path, monkeypatch):
    monkeypatch.setenv("SSD_GPU_LOCK_DIR", str(tmp_path))
    monkeypatch.setattr(gs, "detect_gpu_slots",
                        lambda *a, **kw: 2)
    gs.run_poller({}, interval=0.01, iterations=1, logger=LOG)
    assert gs.read_current_slots(default=1) == 2
