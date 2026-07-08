#!/usr/bin/env python3
"""Unit tests for the candidate fan-out framework (master_pipeline/candidates.py).

These tests are hermetic: the framework is pure (stdlib only) and the LLM call +
Docker validation are injected, so nothing here touches the network, Docker, a
GPU, or config.yaml. The module is loaded directly by path to avoid executing
``master_pipeline/__init__.py`` (which imports the heavyweight orchestrator).

Run: ``python3 -m pytest tests/test_candidates.py -v`` from the pipeline dir.
"""

import importlib.util
import sys
from pathlib import Path

import pytest

# --- Load candidates.py directly (no package import side effects) ------------
# Registered in sys.modules before exec so dataclass annotation resolution
# (with `from __future__ import annotations`) can find the module namespace.
_CAND_PATH = Path(__file__).resolve().parents[1] / "master_pipeline" / "candidates.py"
_spec = importlib.util.spec_from_file_location("_candidates_under_test", _CAND_PATH)
cand = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = cand
_spec.loader.exec_module(cand)

Recipe = cand.Recipe
Candidate = cand.Candidate
Verdict = cand.Verdict
build_recipes = cand.build_recipes
dedupe_candidates = cand.dedupe_candidates
prefilter_syntactic = cand.prefilter_syntactic
generate_and_select = cand.generate_and_select

BASE_TEMP = 0.2


# --- Test doubles ------------------------------------------------------------
class FakeOracle:
    """Validates a candidate by consulting a {recipe_index: success} verdict map."""

    def __init__(self, success_by_index, poc_by_index=None, sast_by_index=None):
        self.success_by_index = success_by_index
        self.poc_by_index = poc_by_index or {}
        self.sast_by_index = sast_by_index or {}
        self.evaluated_indices = []

    def evaluate(self, candidate):
        i = candidate.recipe.index
        self.evaluated_indices.append(i)
        return Verdict(
            success=bool(self.success_by_index.get(i, False)),
            poc_blocked=self.poc_by_index.get(i),
            sast_passed=self.sast_by_index.get(i),
            status="SUCCESS" if self.success_by_index.get(i) else "Failed",
        )


def make_generate_fn(file_by_index=None, syntax_by_index=None, changes_by_index=None):
    """Return a generate_fn that maps a recipe to a deterministic Candidate."""
    file_by_index = file_by_index or {}
    syntax_by_index = syntax_by_index or {}
    changes_by_index = changes_by_index or {}

    def _gen(recipe):
        i = recipe.index
        return Candidate(
            recipe=recipe,
            full_patched_file=file_by_index.get(i, f"FILE-{i}"),
            patched_function=f"fn-{i}",
            syntax_valid=syntax_by_index.get(i, True),
            raw_response=f"resp-{i}",
            changes=changes_by_index.get(i, 1),
        )

    return _gen


# --- build_recipes -----------------------------------------------------------
def test_default_config_is_single_greedy_recipe():
    """Empty/default config -> exactly one recipe identical to today."""
    for cfg in (None, {}, {"num_candidates": 1}):
        recipes = build_recipes(cfg, base_temperature=BASE_TEMP)
        assert len(recipes) == 1
        r = recipes[0]
        assert r.index == 0
        assert r.temperature == pytest.approx(BASE_TEMP)
        assert r.granularity == "minimal"
        assert r.chain_of_thought is False
        assert r.is_greedy
        # The greedy recipe contributes no extra prompt text -> today's prompt.
        assert r.prompt_suffix() == ""


def test_num_candidates_with_temperature_ladder():
    recipes = build_recipes(
        {"num_candidates": 3, "candidate_temperatures": [0.2, 0.6, 0.9]},
        base_temperature=BASE_TEMP,
    )
    assert len(recipes) == 3
    # Greedy first, at the base temperature.
    assert recipes[0].is_greedy and recipes[0].temperature == pytest.approx(0.2)
    temps = sorted(r.temperature for r in recipes)
    assert temps == pytest.approx([0.2, 0.6, 0.9])
    # Indices are unique and contiguous from 0.
    assert [r.index for r in recipes] == [0, 1, 2]


def test_greedy_is_always_first_and_cot_off_even_when_cot_enabled():
    recipes = build_recipes(
        {"num_candidates": 3, "candidate_temperatures": [0.2, 0.7],
         "chain_of_thought": True},
        base_temperature=BASE_TEMP,
    )
    assert recipes[0].is_greedy
    assert recipes[0].chain_of_thought is False         # greedy stays CoT-off
    assert any(r.chain_of_thought for r in recipes[1:])  # diversity recipes use CoT


def test_granularity_expansion():
    recipes = build_recipes(
        {"num_candidates": 4, "granularities": ["minimal", "guard"],
         "candidate_temperatures": [0.2, 0.8]},
        base_temperature=BASE_TEMP,
    )
    grans = {r.granularity for r in recipes}
    assert "guard" in grans
    # A guard recipe carries the guard instruction in its prompt suffix.
    guard = next(r for r in recipes if r.granularity == "guard")
    assert "GRANULARITY" in guard.prompt_suffix()


def test_small_budget_diversifies_granularity_before_temperature():
    # Regression (Phase B under-test): with BOTH a granularity list and a
    # temperature ladder but a tight budget, granularity — the qualitatively
    # different, higher-impact axis — must be covered first. Otherwise the whole
    # budget goes to temperature variants of "minimal" and guard/whole_function
    # never run (which is exactly what happened before the temp-outer fix).
    recipes = build_recipes(
        {"num_candidates": 4,
         "granularities": ["minimal", "guard", "whole_function"],
         "candidate_temperatures": [0.2, 0.6, 0.9]},
        base_temperature=0.2,
    )
    grans = {r.granularity for r in recipes}
    assert grans == {"minimal", "guard", "whole_function"}  # all edit-shapes covered
    # guard & whole_function are exercised at the base temperature first, before
    # the ladder is walked — so a 4-candidate budget spans edit-shapes, not temps.
    for g in ("guard", "whole_function"):
        r = next(x for x in recipes if x.granularity == g)
        assert r.temperature == pytest.approx(0.2)


def test_padding_when_candidates_exceed_distinct_combos():
    # 1 granularity x 1 temperature = 1 distinct combo, but ask for 4 candidates.
    recipes = build_recipes({"num_candidates": 4}, base_temperature=BASE_TEMP)
    assert len(recipes) == 4
    assert recipes[0].is_greedy
    assert all(r.temperature == pytest.approx(BASE_TEMP) for r in recipes)


def test_recipe_prompt_suffix_cot_contains_analysis_directive():
    r = Recipe(index=1, temperature=0.7, granularity="minimal", chain_of_thought=True)
    suffix = r.prompt_suffix()
    assert "ANALYSIS:" in suffix


# --- dedupe / prefilter ------------------------------------------------------
def test_dedupe_drops_identical_patched_files():
    cands = [
        Candidate(recipe=Recipe(0, 0.2), full_patched_file="SAME"),
        Candidate(recipe=Recipe(1, 0.6), full_patched_file="SAME"),
        Candidate(recipe=Recipe(2, 0.9), full_patched_file="DIFF"),
    ]
    out = dedupe_candidates(cands)
    assert len(out) == 2
    assert out[0].recipe.index == 0 and out[1].recipe.index == 2  # first kept


def test_prefilter_keeps_valid_but_falls_back_when_all_invalid():
    valid = Candidate(recipe=Recipe(0, 0.2), full_patched_file="a", syntax_valid=True)
    invalid = Candidate(recipe=Recipe(1, 0.6), full_patched_file="b", syntax_valid=False)
    assert prefilter_syntactic([valid, invalid]) == [valid]
    # All invalid -> return the original list (so the caller can feed back a failure).
    only_invalid = [invalid]
    assert prefilter_syntactic(only_invalid) == only_invalid


# --- generate_and_select -----------------------------------------------------
def test_lazy_stops_at_greedy_on_success():
    recipes = build_recipes(
        {"num_candidates": 3, "candidate_temperatures": [0.2, 0.6, 0.9]},
        base_temperature=BASE_TEMP,
    )
    gen = make_generate_fn()
    oracle = FakeOracle(success_by_index={0: True})  # greedy validates
    res = generate_and_select(recipes, gen, oracle, lazy=True)
    assert res.succeeded
    assert res.winner.recipe.index == 0
    assert res.fanned_out is False
    # Only the greedy candidate was generated AND evaluated (no wasted budget).
    assert oracle.evaluated_indices == [0]
    assert len(res.candidates) == 1


def test_lazy_fans_out_when_greedy_fails():
    recipes = build_recipes(
        {"num_candidates": 3, "candidate_temperatures": [0.2, 0.6, 0.9]},
        base_temperature=BASE_TEMP,
    )
    gen = make_generate_fn()
    oracle = FakeOracle(success_by_index={2: True})  # only the 3rd validates
    res = generate_and_select(recipes, gen, oracle, lazy=True)
    assert res.succeeded
    assert res.winner.recipe.index == 2
    assert res.fanned_out is True
    assert len(res.candidates) == 3  # all generated after greedy failed


def test_no_candidate_validates_returns_best_failing_by_rank():
    recipes = build_recipes(
        {"num_candidates": 3, "candidate_temperatures": [0.2, 0.6, 0.9]},
        base_temperature=BASE_TEMP,
    )
    gen = make_generate_fn()
    # None succeed; candidate 1 blocks the PoC (best failing), others do not.
    oracle = FakeOracle(
        success_by_index={},
        poc_by_index={0: False, 1: True, 2: False},
        sast_by_index={0: True, 1: True, 2: True},
    )
    res = generate_and_select(recipes, gen, oracle, lazy=True)
    assert not res.succeeded
    assert res.winner is not None
    assert res.winner.recipe.index == 1  # PoC-blocked failure ranks highest


def test_eager_generates_all_up_front():
    recipes = build_recipes(
        {"num_candidates": 3, "candidate_temperatures": [0.2, 0.6, 0.9]},
        base_temperature=BASE_TEMP,
    )
    gen = make_generate_fn()
    oracle = FakeOracle(success_by_index={1: True})
    res = generate_and_select(recipes, gen, oracle, lazy=False)
    assert res.succeeded and res.winner.recipe.index == 1
    assert len(res.candidates) == 3


def test_dedupe_prevents_duplicate_oracle_calls():
    recipes = build_recipes(
        {"num_candidates": 3, "candidate_temperatures": [0.2, 0.6, 0.9]},
        base_temperature=BASE_TEMP,
    )
    # All three recipes produce the IDENTICAL patched file.
    gen = make_generate_fn(file_by_index={0: "X", 1: "X", 2: "X"})
    oracle = FakeOracle(success_by_index={})  # nothing validates
    res = generate_and_select(recipes, gen, oracle, lazy=True, dedupe=True)
    # Greedy evaluated once; the fan-out batch dedupes to nothing new -> the
    # oracle is never called on the duplicates.
    assert oracle.evaluated_indices == [0]
    assert not res.succeeded
