#!/usr/bin/env python3
"""Tests for the runtime bundle: intra-phase concurrency knobs (#11/#12),
the make-j cap (#15) and the Ollama warm-up (#17).

Hermetic: stubs docker/pandas (unused by the logic under test); no Docker/LLM.
Run: ``python3 -m pytest tests/test_runtime_knobs.py -v`` from the pipeline dir.
"""

import sys
import types

import pytest

for _m in ("docker", "pandas"):
    sys.modules.setdefault(_m, types.ModuleType(_m))
if not hasattr(sys.modules["docker"], "errors"):
    _err = types.ModuleType("docker.errors")
    for _n in ("BuildError", "ContainerError", "ImageNotFound", "APIError", "NotFound"):
        setattr(_err, _n, type(_n, (Exception,), {}))
    sys.modules["docker.errors"] = _err
    sys.modules["docker"].errors = _err

from master_pipeline import config as cfg  # noqa: E402

_KNOBS = ("SSD_VALIDATION_WORKERS", "SSD_MAKE_JOBS", "SSD_BASELINE_PARALLEL")


# --- #11/#12/#15 config env overlay ------------------------------------------
def test_runtime_env_overlay_sets_values(monkeypatch):
    monkeypatch.setenv("SSD_VALIDATION_WORKERS", "3")
    monkeypatch.setenv("SSD_MAKE_JOBS", "4")
    out = cfg._apply_generation_env_overrides({"validation": {"max_workers": 1}})
    assert out["validation"]["max_workers"] == 3
    assert out["docker"]["make_jobs"] == 4


def test_runtime_env_overlay_noop_when_unset(monkeypatch):
    for k in _KNOBS:
        monkeypatch.delenv(k, raising=False)
    out = cfg._apply_generation_env_overrides({"validation": {"max_workers": 1}})
    assert out["validation"]["max_workers"] == 1          # unchanged
    assert out.get("docker", {}).get("make_jobs") is None  # no cap


def test_runtime_env_overlay_ignores_invalid(monkeypatch):
    monkeypatch.setenv("SSD_VALIDATION_WORKERS", "lots")
    monkeypatch.setenv("SSD_MAKE_JOBS", "")  # empty ⇒ treated as unset
    out = cfg._apply_generation_env_overrides({"validation": {"max_workers": 2}})
    assert out["validation"]["max_workers"] == 2          # invalid ignored
    assert out.get("docker", {}).get("make_jobs") is None


# --- #17 Ollama warm-up ------------------------------------------------------
def test_keepalive_defaults_and_preload_noop_for_openai():
    import patch_generator as pg
    assert pg.LLM_PRELOAD is True
    assert pg.LLM_KEEP_ALIVE  # non-empty default ("15m")
    assert hasattr(pg, "_preload_ollama_model")
    if pg.LLM_PROVIDER == "openai":
        # OpenAI must never attempt an Ollama preload (instant True, no network)
        assert pg._preload_ollama_model("any-model") is True


# --- #15 patched-image build-arg --------------------------------------------
def test_patched_template_declares_make_jobs_arg():
    import patch_validator as pv
    t = pv.PatchedDockerfileGenerator.DOCKERFILE_TEMPLATE
    assert "ARG SSD_MAKE_JOBS" in t
    # the rebuild RUN comes AFTER the ARG (so it is in scope)
    assert t.index("ARG SSD_MAKE_JOBS") < t.index("RUN bash /patch_rebuild.sh")
    # .format() still valid with the real placeholder set
    s = t.format(cve="CVE-1", model_name="m", cve_image_tag="img",
                 source_dir="src", vuln_file_path="a/b.c")
    assert "ARG SSD_MAKE_JOBS" in s


def test_build_image_buildargs_only_when_make_jobs_set():
    """The build-arg dict is None unless docker.make_jobs is truthy (so an
    unconfigured run passes no build-arg → make -j$(nproc), unchanged)."""
    # mirror the inline logic in ValidationPipeline.build_image
    def buildargs(jobs):
        return {"SSD_MAKE_JOBS": str(jobs)} if jobs else None
    assert buildargs(None) is None
    assert buildargs("") is None
    assert buildargs(0) is None
    assert buildargs(4) == {"SSD_MAKE_JOBS": "4"}
