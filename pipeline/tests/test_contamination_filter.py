#!/usr/bin/env python3
"""Tests for the training-data contamination filter (Phase 2 scope gate).

Covers: cutoff-date parsing, active-ramp model resolution, effective-cutoff
selection (max across the ramp — "the latest model's date governs"), the
loud abort on unknown models, the env overlay (SSD_CONTAMINATION_FILTER /
LLM_TRAINING_CUTOFF), publication-date sourcing (CSV → poc_map JSON →
CVE-ID-year fallback), and the strict "published AFTER the cutoff" boundary.
No Docker/LLM is touched.

Run: ``python3 -m pytest tests/test_contamination_filter.py -v`` from the
pipeline dir.
"""

import json
import sys
from datetime import date
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from master_pipeline.contamination import (  # noqa: E402
    ContaminationConfigError,
    active_ramp_models,
    parse_cutoff_date,
    published_date_for,
    published_dates_from_results,
    resolve_cutoff,
    split_post_cutoff,
)
from master_pipeline.config import _apply_contamination_env_overrides  # noqa: E402


# --- date parsing ------------------------------------------------------------
def test_parse_plain_date():
    assert parse_cutoff_date("2020-09-05") == date(2020, 9, 5)


def test_parse_nvd_iso_datetime():
    assert parse_cutoff_date("2016-02-18T21:59:00.120") == date(2016, 2, 18)


def test_parse_empty_and_garbage():
    assert parse_cutoff_date("") is None
    assert parse_cutoff_date(None) is None
    assert parse_cutoff_date("not-a-date") is None


# --- ramp model resolution ---------------------------------------------------
def _cfg(provider="ollama", ramp=None, models=None, openai_model="",
         enabled=True, cutoffs=None, override=None):
    cfg = {
        "llm": {"provider": provider, "models": models or [],
                "openai_model": openai_model},
        "feedback_loop": {"models_by_attempt": ramp or {}},
        "contamination_filter": {"enabled": enabled,
                                 "model_cutoffs": cutoffs or {}},
    }
    if override:
        cfg["contamination_filter"]["cutoff_override"] = override
    return cfg


def test_ramp_models_uniform_profile_collapse():
    cfg = _cfg(ramp={1: "qwen2.5:32b", 2: "qwen2.5:32b",
                     3: "qwen2.5:32b", 4: "qwen2.5:32b"},
               models=["qwen2.5:32b"])
    assert active_ramp_models(cfg) == ["qwen2.5:32b"]


def test_ramp_models_openai_includes_base_model():
    cfg = _cfg(provider="openai", ramp={1: "gpt-5-mini"}, openai_model="gpt-5-mini")
    assert active_ramp_models(cfg) == ["gpt-5-mini"]


def test_ramp_models_provider_scopes_base_list():
    # An openai run must not drag llm.models (the ollama list) into the ramp.
    cfg = _cfg(provider="openai", ramp={}, models=["qwen2.5:7b"],
               openai_model="gpt-5-mini")
    assert active_ramp_models(cfg) == ["gpt-5-mini"]


# --- effective cutoff --------------------------------------------------------
def test_disabled_returns_none():
    cutoff, source = resolve_cutoff(_cfg(enabled=False))
    assert cutoff is None and source == "disabled"


def test_single_model_cutoff():
    cfg = _cfg(ramp={1: "m1"}, models=["m1"], cutoffs={"m1": "2020-09-05"})
    cutoff, source = resolve_cutoff(cfg)
    assert cutoff == date(2020, 9, 5)
    assert "m1" in source


def test_ramp_uses_latest_models_date():
    # Scale-up ramp: the newest (max) cutoff governs.
    cfg = _cfg(ramp={1: "small", 2: "big"}, models=["small"],
               cutoffs={"small": "2023-10-01", "big": "2024-11-12"})
    cutoff, source = resolve_cutoff(cfg)
    assert cutoff == date(2024, 11, 12)
    assert "big" in source


def test_unknown_model_aborts():
    cfg = _cfg(ramp={1: "mystery-model"}, models=["mystery-model"], cutoffs={})
    with pytest.raises(ContaminationConfigError, match="mystery-model"):
        resolve_cutoff(cfg)


def test_override_wins_over_map_and_unknown_models():
    cfg = _cfg(ramp={1: "mystery-model"}, models=["mystery-model"],
               cutoffs={}, override="2021-01-31")
    cutoff, source = resolve_cutoff(cfg)
    assert cutoff == date(2021, 1, 31) and source == "cutoff_override"


def test_invalid_override_aborts():
    cfg = _cfg(ramp={1: "m1"}, models=["m1"], cutoffs={"m1": "2020-01-01"},
               override="soon")
    with pytest.raises(ContaminationConfigError, match="cutoff_override"):
        resolve_cutoff(cfg)


# --- env overlay -------------------------------------------------------------
def test_env_overlay_enables_and_overrides(monkeypatch):
    monkeypatch.setenv("SSD_CONTAMINATION_FILTER", "1")
    monkeypatch.setenv("LLM_TRAINING_CUTOFF", "2024-09-30")
    cfg = _apply_contamination_env_overrides({})
    sec = cfg["contamination_filter"]
    assert sec["enabled"] is True
    assert sec["cutoff_override"] == "2024-09-30"


def test_env_overlay_noop_when_unset(monkeypatch):
    monkeypatch.delenv("SSD_CONTAMINATION_FILTER", raising=False)
    monkeypatch.delenv("LLM_TRAINING_CUTOFF", raising=False)
    assert _apply_contamination_env_overrides({}) == {}


def test_env_overlay_can_disable(monkeypatch):
    monkeypatch.setenv("SSD_CONTAMINATION_FILTER", "0")
    monkeypatch.delenv("LLM_TRAINING_CUTOFF", raising=False)
    cfg = _apply_contamination_env_overrides(
        {"contamination_filter": {"enabled": True}})
    assert cfg["contamination_filter"]["enabled"] is False


# --- publication-date sourcing ----------------------------------------------
def test_csv_value_preferred():
    pub, source = published_date_for("CVE-2020-1234", "2020-10-01", {})
    assert pub == date(2020, 10, 1) and source == "csv"


def test_poc_map_fallback():
    pub, source = published_date_for(
        "cve-2020-1234", "", {"CVE-2020-1234": "2020-12-31T10:00:00"})
    assert pub == date(2020, 12, 31) and source == "poc_map"


def test_cve_year_last_resort():
    pub, source = published_date_for("CVE-2020-1234", "", {})
    assert pub == date(2020, 1, 1) and source == "cve_year"


def test_unparseable_id_gives_none():
    pub, source = published_date_for("GHSA-xxxx", "", {})
    assert pub is None and source == "unknown"


def test_published_dates_from_results(tmp_path):
    (tmp_path / "proj_cve_poc_map.json").write_text(json.dumps({
        "cves": {"CVE-2021-1": {"metadata": {"published_date": "2021-03-04T00:00:00"}},
                 "CVE-2021-2": {"metadata": {}}}}))
    dates = published_dates_from_results(tmp_path)
    assert dates == {"CVE-2021-1": "2021-03-04T00:00:00"}


def test_published_dates_missing_dir_is_empty(tmp_path):
    assert published_dates_from_results(tmp_path / "nope") == {}


# --- the split (strictly-after boundary) ------------------------------------
CUTOFF = date(2020, 9, 5)


def test_day_after_cutoff_kept_same_day_excluded():
    kept, skipped = split_post_cutoff(
        {"CVE-2020-A": "2020-09-06", "CVE-2020-B": "2020-09-05"}, CUTOFF)
    assert kept == ["CVE-2020-A"]
    assert skipped == ["CVE-2020-B"]


def test_pre_cutoff_excluded_and_unknown_conservative():
    kept, skipped = split_post_cutoff(
        {"CVE-2019-X": "2019-01-01", "GHSA-????": ""}, CUTOFF)
    assert kept == []
    assert sorted(skipped) == ["CVE-2019-X", "GHSA-????"]


def test_cve_year_fallback_is_conservative():
    # CVE-2020-* with no date resolves to 2020-01-01 < cutoff -> excluded,
    # even though its true publication date might have been after Sept 5.
    kept, skipped = split_post_cutoff({"CVE-2020-Z": ""}, CUTOFF)
    assert kept == [] and skipped == ["CVE-2020-Z"]


def test_poc_map_dir_feeds_split(tmp_path):
    (tmp_path / "p_cve_poc_map.json").write_text(json.dumps({
        "cves": {"CVE-2020-M": {"metadata":
                                {"published_date": "2020-11-30T08:15:00.000"}}}}))
    kept, skipped = split_post_cutoff({"CVE-2020-M": ""}, CUTOFF,
                                      results_dir=tmp_path)
    assert kept == ["CVE-2020-M"] and skipped == []
