#!/usr/bin/env python3
"""Tests for the richer feedback memory (recommendation #6).

Covers the gated retry-prompt enrichments in patch_generator: applied diff,
earlier-attempt history (anti-oscillation) and the Reflexion 'DIAGNOSIS:' step,
plus the default-preservation guarantee (all flags off ⇒ legacy prompt).

``pandas`` is only imported at patch_generator's module top and is unused by the
functions under test, so we register a stub before import (``setdefault`` keeps a
real pandas when present, e.g. in CI). No LLM/Docker is touched.

Run: ``python3 -m pytest tests/test_feedback_richer_context.py -v`` (pipeline dir).
"""

import sys
import types

import pytest

try:  # prefer the real pandas when installed (VM); stub it otherwise (dev hosts)
    import pandas  # noqa: F401
except ImportError:
    _pd_stub = types.ModuleType("pandas")
    _pd_stub.DataFrame = _pd_stub.Series = object  # annotation targets (eager on <3.14)
    sys.modules["pandas"] = _pd_stub
import patch_generator as pg  # noqa: E402

ORIG_FN = "int f(int n){\n  char b[8];\n  memcpy(b, s, n);\n  return 0;\n}"
PATCH_A = "int f(int n){\n  char b[8];\n  if (n > 8) return -1;\n  memcpy(b, s, n);\n  return 0;\n}"
PATCH_B = "int f(int n){\n  char b[8];\n  if (n < 0) return -1;\n  memcpy(b, s, n);\n  return 0;\n}"
FAIL = {"status": "PoC Still Works", "poc_blocked": False, "sast_passed": True}


def _prompt(**kwargs):
    return pg.create_feedback_prompt(
        "CVE-2099-1", "f", ORIG_FN, "/* file */", PATCH_A, FAIL, 2, **kwargs)


# --- _unified_diff -----------------------------------------------------------
def test_unified_diff_empty_inputs():
    assert pg._unified_diff("", "x") == ""
    assert pg._unified_diff("x", "") == ""


def test_unified_diff_identical_is_empty():
    assert pg._unified_diff(ORIG_FN, ORIG_FN) == ""


def test_unified_diff_shows_added_line():
    d = pg._unified_diff(ORIG_FN, PATCH_A)
    assert d and "+  if (n > 8) return -1;" in d


def test_unified_diff_truncates():
    big_a = "\n".join(f"a{i};" for i in range(200))
    big_b = "\n".join(f"b{i};" for i in range(200))
    d = pg._unified_diff(big_a, big_b, max_lines=30)
    assert "diff truncated" in d


# --- default preservation ----------------------------------------------------
def test_default_prompt_byte_identical_with_flags_off():
    legacy = _prompt()
    explicit_off = _prompt(prior_attempts=[{"attempt_number": 1,
                                            "patched_function": PATCH_A,
                                            "outcome": "PoC Still Works"}],
                           include_diff=False, include_history=False, reflexion=False)
    assert legacy == explicit_off


# --- applied diff ------------------------------------------------------------
def test_applied_diff_section_added():
    p = _prompt(include_diff=True)
    assert "WHAT YOU CHANGED LAST TIME" in p
    assert "+  if (n > 8) return -1;" in p


# --- reflexion ---------------------------------------------------------------
def test_reflexion_adds_diagnosis_directive():
    p = _prompt(reflexion=True)
    assert "DIAGNOSIS:" in p


# --- earlier-attempt history -------------------------------------------------
def test_history_lists_earlier_attempts_excluding_the_immediately_previous():
    # 3 prior attempts; the LAST (PATCH_A) is the immediately-previous shown in
    # full, so the EARLIER section should reference attempts 1 and 2 only.
    prior = [
        {"attempt_number": 1, "patched_function": ORIG_FN, "outcome": "Build Failed"},
        {"attempt_number": 2, "patched_function": PATCH_B, "outcome": "PoC Still Works"},
        {"attempt_number": 3, "patched_function": PATCH_A, "outcome": "PoC Still Works"},
    ]
    p = _prompt(prior_attempts=prior, include_history=True)
    assert "EARLIER FAILED ATTEMPTS" in p
    assert "Attempt 2" in p  # the one before the immediately-previous


def test_history_noop_with_single_prior_attempt():
    prior = [{"attempt_number": 1, "patched_function": PATCH_A, "outcome": "fail"}]
    p = _prompt(prior_attempts=prior, include_history=True)
    assert "EARLIER FAILED ATTEMPTS" not in p


def test_all_flags_compose():
    prior = [
        {"attempt_number": 1, "patched_function": PATCH_B, "outcome": "Build Failed"},
        {"attempt_number": 2, "patched_function": PATCH_A, "outcome": "PoC Still Works"},
    ]
    p = _prompt(prior_attempts=prior, include_diff=True, include_history=True, reflexion=True)
    assert "WHAT YOU CHANGED LAST TIME" in p
    assert "EARLIER FAILED ATTEMPTS" in p
    assert "DIAGNOSIS:" in p
