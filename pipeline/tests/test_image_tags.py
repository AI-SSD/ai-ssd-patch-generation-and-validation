#!/usr/bin/env python3
"""Tests for per-cell/per-repeat Docker image+container tag uniqueness (#7).

This is the keystone that lets cells, overlapping families and repeats run
concurrently without colliding on Docker image/container names. The tag was
previously keyed on (cve, model) only; now an optional ``cell`` discriminator
(the run base_dir basename) makes it unique per parallel unit while an empty
``cell`` reproduces the LEGACY name byte-for-byte.

``docker``/``pandas`` are stubbed (not present on the dev host, unused by the
tag logic); ``setdefault`` keeps the real packages when present (CI).

Run: ``python3 -m pytest tests/test_image_tags.py -v`` from the pipeline dir.
"""

import sys
import types
from pathlib import Path

import pytest

for _m in ("docker", "pandas"):
    sys.modules.setdefault(_m, types.ModuleType(_m))
if not hasattr(sys.modules["docker"], "errors"):
    _err = types.ModuleType("docker.errors")
    for _n in ("BuildError", "ContainerError", "ImageNotFound", "APIError", "NotFound"):
        setattr(_err, _n, type(_n, (Exception,), {}))
    sys.modules["docker.errors"] = _err
    sys.modules["docker"].errors = _err

import patch_validator as pv  # noqa: E402

CVE = "CVE-2015-7547"
MODEL = "gpt-4.1-mini"  # contains a dot → safe_model = gpt-4_1-mini


def _pi(cell=""):
    return pv.PatchInfo(cve_id=CVE, model_name=MODEL, patch_dir=Path("."), cell=cell)


# --- default preservation ----------------------------------------------------
def test_legacy_tag_unchanged_when_cell_empty():
    pi = _pi()
    assert pi.image_name == "ai-ssd-patch/cve-2015-7547-gpt-4_1-mini:latest"
    assert pi.container_name == "patch-test-cve-2015-7547-gpt-4_1-mini"


# --- per-cell uniqueness ------------------------------------------------------
def test_cell_makes_image_and_container_unique():
    a = _pi("glibc__openai-fast__rep1")
    b = _pi("glibc__openai-fast__rep2")
    c = _pi("glibc__openai-fast")  # baseline-profile sweep, untagged repeat
    names = {a.image_name, b.image_name, c.image_name}
    assert len(names) == 3, names                      # all distinct
    assert a.image_name == "ai-ssd-patch/cve-2015-7547-gpt-4_1-mini-glibc__openai-fast__rep1:latest"
    assert a.container_name == "patch-test-cve-2015-7547-gpt-4_1-mini-glibc__openai-fast__rep1"
    # image and container carry the SAME discriminator (so cleanup stays aligned)
    assert a.image_name.split("/", 1)[1].rsplit(":", 1)[0] == a.container_name[len("patch-test-"):]


def test_same_model_different_profiles_dont_collide():
    # Two profiles that share an attempt-1 model (the historical collision case)
    a = _pi("glibc__openai-fast")
    b = _pi("glibc__openai-codex")
    assert a.image_name != b.image_name


# --- sanitization -------------------------------------------------------------
def test_docker_safe_name():
    assert pv._docker_safe_name("Glibc__OpenAI-Fast__REP2!!") == "glibc__openai-fast__rep2"
    assert pv._docker_safe_name("a/b:c.d") == "a-b-c.d"
    assert pv._docker_safe_name("") == "run"
    assert pv._docker_safe_name("---") == "run"
    # idempotent on an already-safe token
    assert pv._docker_safe_name("glibc__openai-fast__rep2") == "glibc__openai-fast__rep2"


# --- dashboard cleanup attribution (model exact OR model- prefix) -------------
def _matches(safe_m, want):
    return any(safe_m == w or safe_m.startswith(w + "-") for w in want)


def test_dashboard_match_handles_legacy_and_celled():
    want = {"gpt-4_1-mini"}
    assert _matches("gpt-4_1-mini", want)                                  # legacy tag
    assert _matches("gpt-4_1-mini-glibc__openai-fast__rep2", want)         # celled tag
    assert not _matches("gpt-5-mini-glibc__x", want)                       # different model


# --- regression: PatchDiscovery must thread cell_disc (was a crash) ----------
def test_patch_discovery_threads_cell_disc(tmp_path):
    """Regression for the AttributeError that broke the default Phase-3 path:
    PatchDiscovery now accepts/sets cell_disc and stamps it onto each PatchInfo."""
    import logging
    md = tmp_path / "CVE-2015-7547" / "gpt-4.1-mini"
    md.mkdir(parents=True)
    (md / "foo.c").write_text("int foo(){return 0;}\n")
    (md / "response.json").write_text('{"original_filepath":"src/foo.c","syntax_valid":true}')
    pd = pv.PatchDiscovery(tmp_path, logging.getLogger("t"), "glibc__openai-fast")
    patches = pd.discover_patches()   # must NOT raise AttributeError
    assert len(patches) == 1
    assert patches[0].cell == "glibc__openai-fast"
    assert patches[0].image_name.endswith("-glibc__openai-fast:latest")
    # default (no cell_disc arg) keeps the legacy name
    pd0 = pv.PatchDiscovery(tmp_path, logging.getLogger("t"))
    assert pd0.discover_patches()[0].cell == ""


# --- regression: Phase-3 cleanup must not over-delete across profiles --------
def test_phase3_cleanup_attribution_no_overmatch():
    """Regression for the HIGH over-match: selecting one profile for patched-image
    cleanup must not match a different profile that shares/dash-prefixes the model."""
    dc = __import__("dashboard_control")
    want_models = {"gpt-4_1-mini"}
    want_cells = {dc._safe_cell("glibc__openai-fast")}  # only profile A selected
    assert dc._phase3_attributed("gpt-4_1-mini-glibc__openai-fast", want_models, want_cells)
    assert dc._phase3_attributed("gpt-4_1-mini-glibc__openai-fast__rep2", want_models, want_cells)
    assert dc._phase3_attributed("gpt-4_1-mini", want_models, want_cells)   # legacy un-celled
    # profile B sharing the same model → must NOT be attributed to A
    assert not dc._phase3_attributed("gpt-4_1-mini-glibc__openai-mix", want_models, want_cells)
    # a different model that dash-prefixes the selected one → must NOT match
    assert not dc._phase3_attributed("gpt-4_1-mini-turbo-glibc__openai-mix", want_models, want_cells)
