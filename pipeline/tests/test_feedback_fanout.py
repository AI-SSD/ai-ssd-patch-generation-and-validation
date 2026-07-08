#!/usr/bin/env python3
"""Wiring tests for the best-of-N attempt-1 fan-out in the feedback loop.

These exercise ``IterativeFeedbackLoop._run_attempt1_fanout`` against stubbed
generation (``generate_one_candidate``) and a stubbed Phase-3 validator
(``_validate_retry_patch``), so no LLM / Docker / GPU is involved. The method is
invoked unbound on a lightweight stub ``self`` to avoid the loop's real
``__init__`` (which dynamically imports the pandas/docker-heavy Phase 2/3
modules).

Run: ``python3 -m pytest tests/test_feedback_fanout.py -v`` from the pipeline dir.
"""

import logging
import types
from pathlib import Path

import pytest

from master_pipeline.feedback import IterativeFeedbackLoop
from master_pipeline.candidates import Candidate

SUCCESS = "Success"


# --- Stubs -------------------------------------------------------------------
class _Val:
    """Minimal stand-in for a Phase-3 ValidationResult."""
    def __init__(self, status, poc_blocked=False, sast_passed=True, error=None):
        self.status = status
        self.poc_blocked = poc_blocked
        self.sast_passed = sast_passed
        self.error_message = error


def _make_loop(tmp_path, gen_cfg, *, files_by_index, success_indices):
    """Build a stub `self` carrying exactly what _run_attempt1_fanout touches."""
    stub = types.SimpleNamespace()
    stub.generation_cfg = gen_cfg
    stub._base_temperature = 0.2
    stub.logger = logging.getLogger("test.fanout")
    stub.config = types.SimpleNamespace(base_dir=Path(tmp_path))

    # Fake patch_generator module.
    pg = types.SimpleNamespace()
    pg.EXPLOITS_DIR = Path(tmp_path) / "exploits"
    pg.sanitize_model_name = lambda m: m.replace(":", "_").replace("/", "_")

    def _gen(row, model, recipe):
        return Candidate(
            recipe=recipe,
            full_patched_file=files_by_index.get(recipe.index, f"PATCH-{recipe.index}"),
            patched_function=f"fn-{recipe.index}",
            syntax_valid=True,
            raw_response=f"resp-{recipe.index}",
            changes=1,
        )
    pg.generate_one_candidate = _gen
    stub.patch_generator = pg

    # Fake patch_validator module exposing ValidationStatus.SUCCESS.value.
    pv = types.SimpleNamespace()
    pv.ValidationStatus = types.SimpleNamespace(SUCCESS=types.SimpleNamespace(value=SUCCESS))
    stub.patch_validator = pv

    # Real _write_fanout_candidate (writes to tmp); fake _validate_retry_patch.
    stub._write_fanout_candidate = types.MethodType(
        IterativeFeedbackLoop._write_fanout_candidate, stub)

    calls = []

    def _fake_validate(cve_id, model_name, patch_file, vuln_data,
                       attempt_number, generation_model=None):
        calls.append(Path(patch_file))
        # The candidate's recipe index is encoded in the fan-out dir name suffix.
        # Decide success by which fan-out slot validated.
        return _Val(SUCCESS) if (len(calls) in success_indices) else _Val("PoC Still Works")
    stub._validate_retry_patch = _fake_validate
    stub._validate_calls = calls

    return stub


_VULN = {"FilePath": "src/foo.c", "F_NAME": "foo", "V_FUNCTION": "int foo(){}",
         "V_FILE": "int foo(){}", "CVE": "CVE-2099-0001"}


# --- Tests -------------------------------------------------------------------
def test_num_candidates_one_is_a_noop(tmp_path):
    """Default config (num_candidates: 1) -> no fan-out, no validation calls."""
    loop = _make_loop(tmp_path, {"num_candidates": 1}, files_by_index={}, success_indices=set())
    fan_file, fan_val, history = IterativeFeedbackLoop._run_attempt1_fanout(
        loop, "CVE-2099-0001", "gpt-4.1-mini", _VULN, greedy_patch_content="GREEDY")
    assert fan_file is None and fan_val is None and history == []
    assert loop._validate_calls == []  # nothing validated


def test_fanout_picks_first_validating_candidate(tmp_path):
    """The 2nd validated diversity candidate passes -> returned as winner."""
    loop = _make_loop(
        tmp_path,
        {"num_candidates": 4, "candidate_temperatures": [0.2, 0.6, 0.9]},
        files_by_index={1: "P1", 2: "P2", 3: "P3"},
        success_indices={2},  # the 2nd validation call succeeds
    )
    fan_file, fan_val, history = IterativeFeedbackLoop._run_attempt1_fanout(
        loop, "CVE-2099-0001", "gpt-4.1-mini", _VULN, greedy_patch_content="GREEDY")
    assert fan_file is not None
    assert fan_val is not None and fan_val.status == SUCCESS
    # Lazy: generated/validated until first success, so exactly 2 validations.
    assert len(loop._validate_calls) == 2
    assert len(history) == 2 and all(h["is_fanout"] for h in history)
    assert history[-1]["status"] == SUCCESS


def test_candidate_identical_to_greedy_is_not_revalidated(tmp_path):
    """A diversity candidate equal to the failed greedy is skipped (no Docker)."""
    loop = _make_loop(
        tmp_path,
        {"num_candidates": 4, "candidate_temperatures": [0.2, 0.6, 0.9]},
        files_by_index={1: "GREEDY", 2: "P2", 3: "P3"},  # index 1 == greedy
        success_indices=set(),  # nothing validates
    )
    fan_file, fan_val, history = IterativeFeedbackLoop._run_attempt1_fanout(
        loop, "CVE-2099-0001", "gpt-4.1-mini", _VULN, greedy_patch_content="GREEDY")
    assert fan_file is None
    # Only the two NON-greedy candidates reached the validator.
    assert len(loop._validate_calls) == 2
    # The greedy-duplicate produced no history entry.
    assert len(history) == 2
    assert all(h["recipe"] for h in history)


def test_no_candidate_validates_returns_none_with_full_history(tmp_path):
    loop = _make_loop(
        tmp_path,
        {"num_candidates": 3, "candidate_temperatures": [0.2, 0.6, 0.9]},
        files_by_index={1: "P1", 2: "P2"},
        success_indices=set(),
    )
    fan_file, fan_val, history = IterativeFeedbackLoop._run_attempt1_fanout(
        loop, "CVE-2099-0001", "gpt-4.1-mini", _VULN, greedy_patch_content="GREEDY")
    assert fan_file is None and fan_val is None
    assert len(history) == len(loop._validate_calls) >= 1


def test_fanout_writes_each_candidate_to_a_unique_dir(tmp_path):
    loop = _make_loop(
        tmp_path,
        {"num_candidates": 3, "candidate_temperatures": [0.2, 0.6, 0.9]},
        files_by_index={1: "P1", 2: "P2"},
        success_indices=set(),
    )
    IterativeFeedbackLoop._run_attempt1_fanout(
        loop, "CVE-2099-0001", "gpt-4.1-mini", _VULN, greedy_patch_content="GREEDY")
    # Distinct patch files were written under per-candidate fanout dirs.
    assert len({p.parent for p in loop._validate_calls}) == len(loop._validate_calls)
    for p in loop._validate_calls:
        assert p.exists() and p.name == "foo.c"
        assert "_fanout" in p.parent.name
