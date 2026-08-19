#!/usr/bin/env python3
"""Regression tests for the in-tree (Option A) Phase-3 no-verdict classification.

Bug: an in-tree regression-test CVE whose PATCHED build fails to compile (or no
longer yields a runtime) emits no ``SSD_TEST_RESULT=PASS|FAIL`` marker, so
``run_intree_test`` returns NORESULT. Phase 3 used to blanket every no-verdict as
``Execution Error`` — a NON-retryable status — so these patch-induced failures were
silently dropped from the feedback loop instead of being retried with the build log
as context. Since Phase 1 (unpatched, same era/image) DID reproduce the CVE with the
same test, a NORESULT on the patched build is patch-induced ⇒ it must map to
``Build Error`` (retryable), while genuine environment failures (TIMEOUT / harness
ERROR) stay ``Execution Error``.

Hermetic: stubs docker/pandas; no Docker/LLM. Run:
``python3 -m pytest tests/test_intree_classification.py -v`` from the pipeline dir.
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

import patch_validator as pv  # noqa: E402
from master_pipeline.config import cfg_section  # noqa: E402


# --- the mapping itself ------------------------------------------------------
def test_noresult_maps_to_retryable_build_error():
    """A patch-induced no-verdict must be a Build Error (the fix)."""
    assert pv._intree_error_status("NORESULT") == pv.ValidationStatus.BUILD_ERROR.value


@pytest.mark.parametrize("marker", ["TIMEOUT", "ERROR"])
def test_genuine_env_failures_stay_execution_error(marker):
    """Timeouts and harness exceptions remain non-retryable Execution Errors."""
    assert pv._intree_error_status(marker) == pv.ValidationStatus.EXECUTION_ERROR.value


def test_build_error_is_not_execution_error():
    """Guard against a regression that collapses the two back together."""
    assert (pv._intree_error_status("NORESULT")
            != pv._intree_error_status("TIMEOUT"))


# --- retryability wiring: Build Error reaches the loop, Execution Error does not
def test_build_error_retryable_by_default_but_execution_error_dropped():
    """The feedback loop's retryable set (config default) must include the
    reclassified 'Build Error' and still exclude 'Execution Error'.

    This is what actually makes the reclassification reach the loop — mirrors the
    status filter in PipelineOrchestrator._run_feedback_loop.
    """
    # Rebuild the retryable set exactly as the orchestrator does, from config.yaml.
    retry_on = (cfg_section("feedback_loop", pv._BASE_DIR) or {}).get("retry_on", {}) or {}
    retryable = set()
    if retry_on.get("poc_still_works", True):
        retryable.add("PoC Still Works")
    if retry_on.get("sast_failed", True):
        retryable.add("SAST Failed")
    if retry_on.get("build_error", False):
        retryable.add("Build Error")
    if retry_on.get("poc_hang", True):
        retryable.add("Patch Caused Hang")

    build_err = pv._intree_error_status("NORESULT")   # "Build Error"
    exec_err = pv._intree_error_status("TIMEOUT")      # "Execution Error"
    assert build_err in retryable, (
        "config.yaml feedback_loop.retry_on.build_error must be true so the "
        "reclassified in-tree failures actually reach the feedback loop")
    assert exec_err not in retryable


if __name__ == "__main__":
    sys.exit(pytest.main([__file__, "-v"]))
