#!/usr/bin/env python3
"""Tests for the GPU exclusivity gate (cve_aggregator/utils/gpu_monitor.py).

Covers: mode resolution (env > config > default), /api/ps parsing, the
empty-or-ours pass-through, target-name matching (:latest tolerance), active
eviction of foreign models via keep_alive:0, wait-mode passivity, timeout
behaviour, unreachable-endpoint fail-open, and the offload report. All HTTP is
stubbed via monkeypatching requests — no server is touched.

Run: ``python3 -m pytest tests/test_gpu_monitor.py -v`` from the pipeline dir.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cve_aggregator.utils import gpu_monitor as gm  # noqa: E402

ENDPOINT = "http://gpu-proxy:80/api/chat"


class _Resp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def _entry(name, size=10, size_vram=10):
    gib = 1024 ** 3
    return {"name": name, "model": name, "size": size * gib,
            "size_vram": size_vram * gib}


@pytest.fixture
def http(monkeypatch):
    """Stub requests.get (/api/ps) + requests.post (unload) with scripting.

    ``http.ps_batches`` is a list of /api/ps model-lists returned in order
    (the last one repeats); ``http.posts`` records every unload request.
    """
    class Stub:
        ps_batches = [[]]
        posts = []
        gets = 0

    def fake_get(url, timeout=10, auth=None):
        assert url.endswith("/api/ps")
        i = min(Stub.gets, len(Stub.ps_batches) - 1)
        Stub.gets += 1
        return _Resp({"models": Stub.ps_batches[i]})

    def fake_post(url, json=None, timeout=30, auth=None):
        assert url.endswith("/api/generate")
        Stub.posts.append(json)
        return _Resp({})

    monkeypatch.setattr(gm.requests, "get", fake_get)
    monkeypatch.setattr(gm.requests, "post", fake_post)
    monkeypatch.setattr(gm.time, "sleep", lambda s: None)
    return Stub


# --- mode resolution ---------------------------------------------------------
def test_mode_default_and_config(monkeypatch):
    monkeypatch.delenv("SSD_GPU_EXCLUSIVE", raising=False)
    assert gm.resolve_mode() == "evict"
    assert gm.resolve_mode("wait") == "wait"
    assert gm.resolve_mode("bogus") == "evict"


def test_mode_env_wins(monkeypatch):
    monkeypatch.setenv("SSD_GPU_EXCLUSIVE", "off")
    assert gm.resolve_mode("evict") == "off"


# --- target matching ---------------------------------------------------------
def test_target_matching_latest_tag():
    assert gm._is_target(_entry("qwen2.5:32b"), "qwen2.5:32b")
    assert gm._is_target(_entry("devstral:latest"), "devstral")
    assert gm._is_target(_entry("devstral"), "devstral:latest")
    assert not gm._is_target(_entry("qwen2.5:7b"), "qwen2.5:32b")
    assert not gm._is_target(_entry("qwen2.5:7b"), None)


# --- ensure_exclusive --------------------------------------------------------
def test_empty_gpu_passes(http):
    http.ps_batches = [[]]
    assert gm.ensure_exclusive(ENDPOINT, model="m1") is True
    assert http.posts == []


def test_only_our_model_passes(http):
    http.ps_batches = [[_entry("m1")]]
    assert gm.ensure_exclusive(ENDPOINT, model="m1") is True
    assert http.posts == []


def test_mode_off_never_touches_http(http):
    http.ps_batches = [[_entry("foreign")]]
    assert gm.ensure_exclusive(ENDPOINT, model="m1", mode="off") is True
    assert http.gets == 0


def test_evict_unloads_foreign_then_passes(http):
    http.ps_batches = [[_entry("foreign"), _entry("m1")], []]
    assert gm.ensure_exclusive(ENDPOINT, model="m1", mode="evict",
                               timeout=60) is True
    assert http.posts == [{"model": "foreign", "keep_alive": 0}]


def test_wait_mode_never_evicts(http):
    http.ps_batches = [[_entry("foreign")], [_entry("foreign")], []]
    assert gm.ensure_exclusive(ENDPOINT, model="m1", mode="wait",
                               timeout=60) is True
    assert http.posts == []


def test_timeout_returns_false(http, monkeypatch):
    http.ps_batches = [[_entry("stuck")]]
    clock = iter([0, 0, 200, 200, 400, 400, 600, 600])
    monkeypatch.setattr(gm.time, "time", lambda: next(clock))
    assert gm.ensure_exclusive(ENDPOINT, model="m1", mode="wait",
                               timeout=120) is False


def test_unreachable_fails_open(monkeypatch):
    def boom(*a, **k):
        raise OSError("no route")
    monkeypatch.setattr(gm.requests, "get", boom)
    assert gm.ensure_exclusive(ENDPOINT, model="m1") is True


# --- evict_others ------------------------------------------------------------
def test_evict_others_keeps_target(http):
    http.ps_batches = [[_entry("m1"), _entry("f1"), _entry("f2")]]
    evicted = gm.evict_others(ENDPOINT, keep="m1")
    assert sorted(evicted) == ["f1", "f2"]
    assert all(p["keep_alive"] == 0 for p in http.posts)


def test_evict_others_empty_gpu_noop(http):
    http.ps_batches = [[]]
    assert gm.evict_others(ENDPOINT, keep="m1") == []
    assert http.posts == []


# --- offload report ----------------------------------------------------------
def test_offload_report_partial(http):
    http.ps_batches = [[_entry("m1", size=20, size_vram=12)]]
    size, vram = gm.offload_report(ENDPOINT, "m1")
    assert vram < size  # partial CPU offload visible via the API alone


def test_offload_report_absent(http):
    http.ps_batches = [[_entry("other")]]
    assert gm.offload_report(ENDPOINT, "m1") is None
