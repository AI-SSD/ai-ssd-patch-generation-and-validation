#!/usr/bin/env python3
"""Regression test: Phase-3 patch discovery must ignore feedback-loop artifacts.

Bug: ``PatchDiscovery.discover_patches`` skipped ``*_retryN`` dirs but NOT the
best-of-N fan-out dirs (``*_fanout1``, and the compounded ``*_fanout1_fanout2``).
On a standalone Phase-3 re-run (``--phases 3 4`` over a directory that already
holds a prior feedback loop's artifacts) it therefore validated every fan-out
candidate as if it were a fresh Phase-2 patch — inflating the validated count far
beyond the real per-CVE patch count (e.g. 23 -> 54), cascading into the feedback
loop's input, and even fanning out AGAIN on top of an existing fan-out dir.

Only the canonical Phase-2 model dir (e.g. ``gpt-4.1-mini``) must be discovered.

Hermetic: stubs docker/pandas; no Docker/LLM. Run:
``python3 -m pytest tests/test_patch_discovery.py -v`` from the pipeline dir.
"""
import json
import logging
import sys
import types

for _m in ("docker", "pandas"):
    sys.modules.setdefault(_m, types.ModuleType(_m))
if not hasattr(sys.modules["docker"], "errors"):
    _err = types.ModuleType("docker.errors")
    for _n in ("BuildError", "ContainerError", "ImageNotFound", "APIError", "NotFound"):
        setattr(_err, _n, type(_n, (Exception,), {}))
    sys.modules["docker.errors"] = _err
    sys.modules["docker"].errors = _err

import patch_validator as pv  # noqa: E402


def _make_model_dir(cve_dir, model, filepath="ssl/foo.c"):
    d = cve_dir / model
    d.mkdir(parents=True)
    (d / "foo.c").write_text("int foo(void){return 0;}\n")
    (d / "response.json").write_text(json.dumps(
        {"original_filepath": filepath, "syntax_valid": True}))
    return d


def test_discovery_skips_retry_and_fanout_keeps_canonical(tmp_path):
    patches = tmp_path / "patches"
    cve = patches / "CVE-2009-5155"
    # Canonical Phase-2 patch (the ONLY one that should be discovered)
    _make_model_dir(cve, "gpt-4.1-mini")
    # Feedback-loop artifacts that must be ignored
    for junk in ("gpt-4.1-mini_retry2", "gpt-4.1-mini_retry3", "gpt-4.1_retry4",
                 "gpt-4.1-mini_fanout1", "gpt-4.1-mini_fanout2",
                 "gpt-4.1-mini_fanout1_fanout1", "gpt-4.1-mini_fanout1_fanout2"):
        _make_model_dir(cve, junk)

    disc = pv.PatchDiscovery(patches, logging.getLogger("test"))
    found = disc.discover_patches()

    assert len(found) == 1, f"expected only the canonical patch, got {len(found)}"
    # PatchInfo.model_name round-trips '_'->':'; the canonical dir has no '_'.
    assert found[0].cve_id == "CVE-2009-5155"


def test_discovery_multi_cve_counts_one_canonical_each(tmp_path):
    patches = tmp_path / "patches"
    for cve in ("CVE-2009-5155", "CVE-2014-0475", "CVE-2014-4043"):
        cdir = patches / cve
        _make_model_dir(cdir, "gpt-4.1-mini")
        _make_model_dir(cdir, "gpt-4.1-mini_fanout1")
        _make_model_dir(cdir, "gpt-5-mini_retry2")

    disc = pv.PatchDiscovery(patches, logging.getLogger("test"))
    found = disc.discover_patches()

    assert len(found) == 3, f"expected 3 canonical patches (1/CVE), got {len(found)}"


if __name__ == "__main__":
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
