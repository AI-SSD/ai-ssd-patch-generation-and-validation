#!/usr/bin/env python3
"""Regression test for the dashboard feedback-card counts.

Bug: ``_load_feedback_counts`` picked the final validation attempt with
``max(history, key=lambda h: int(h["attempt"]))``. The best-of-N fan-out labels
its candidates with dotted STRING attempts ("1.1", "1.2", ...), so ``int("1.1")``
raised ValueError. The caller swallowed the exception, collapsing the ENTIRE
feedback card to zeros — every completed cell showed "Failed (in) 0 / Retry 0"
even after dozens of real retries. Parsing the attempt as float fixes it.

Hermetic: dashboard_control imports no Docker/LLM deps. Run:
``python3 -m pytest tests/test_dashboard_feedback_counts.py -v`` from the pipeline dir.
"""
import json
import os
import tempfile

import dashboard_control as ctl


def _write(tmp, payload):
    p = os.path.join(tmp, "feedback_loop_results_20260101_000000.json")
    with open(p, "w") as f:
        json.dump(payload, f)
    return p


def _payload():
    # One unpatchable patch whose history includes fan-out candidates ("1.1"/"1.2")
    # AND serial retries (2, 3). The final (highest) attempt is retry 3, which
    # failed the PoC only (poc_blocked False, sast_passed True).
    return {
        "summary": {
            "total_patches_processed": 1,
            "successful": 0,
            "unpatchable": 1,
            "failed": 0,
            "total_retry_attempts": 4,
        },
        "outcome_breakdown": {"successful_after_retry": 0},
        "results": [{
            "final_status": "PatchStatus.UNPATCHABLE",
            "validation_history": [
                {"attempt": 1, "poc_blocked": False, "sast_passed": True},
                {"attempt": "1.1", "poc_blocked": False, "sast_passed": True},
                {"attempt": "1.2", "poc_blocked": False, "sast_passed": True},
                {"attempt": 2, "poc_blocked": False, "sast_passed": True},
                {"attempt": 3, "poc_blocked": False, "sast_passed": True},
            ],
        }],
    }


def test_fanout_string_attempt_does_not_crash_and_counts_are_correct():
    with tempfile.TemporaryDirectory() as tmp:
        path = _write(tmp, _payload())
        out = ctl._load_feedback_counts(path)   # must NOT raise on "1.1"
    assert out["total"] == 1
    assert out["unpatchable"] == 1
    assert out["retries"] == 4
    # Final attempt (retry 3) failed the PoC only -> counted as poc_only, not zeros.
    assert out["failed_poc_only"] == 1
    assert out["failed_both"] == 0
    assert out["failed_sast_only"] == 0


def test_attempt_sort_key_orders_fanout_below_retries():
    # retry 2 must outrank fan-out candidate 1.3 (the final attempt is a retry).
    assert ctl._attempt_sort_key({"attempt": 2}) > ctl._attempt_sort_key({"attempt": "1.3"})
    assert ctl._attempt_sort_key({"attempt": "1.1"}) > ctl._attempt_sort_key({"attempt": 1})
    assert ctl._attempt_sort_key({"attempt": None}) == 0.0
    assert ctl._attempt_sort_key({"attempt": "garbage"}) == 0.0
