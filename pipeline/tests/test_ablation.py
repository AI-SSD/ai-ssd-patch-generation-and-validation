#!/usr/bin/env python3
"""Tests for the ablation/evaluation harness (#5) and prompt-component toggles.

Covers: the SSD_* env overlay, the prompt-component ablation in patch_generator
(PoC/CWE/description/project-priming toggles), the ablation metrics aggregator,
variant loading, and the runner's pure plan builder. No Docker/LLM is touched.

Run: ``python3 -m pytest tests/test_ablation.py -v`` from the pipeline dir.
"""

import json
import sys
import types
from pathlib import Path

import pytest

try:  # prefer the real pandas when installed (VM); stub it otherwise (dev hosts)
    import pandas  # noqa: F401
except ImportError:
    _pd_stub = types.ModuleType("pandas")
    _pd_stub.DataFrame = _pd_stub.Series = object  # annotation targets (eager on <3.14)
    sys.modules["pandas"] = _pd_stub

from master_pipeline import config as cfg          # noqa: E402
from master_pipeline import ablation as ab          # noqa: E402
import patch_generator as pg                         # noqa: E402
import run_ablation as ra                            # noqa: E402

_SSD_VARS = [
    "SSD_NUM_CANDIDATES", "SSD_CANDIDATE_TEMPERATURES", "SSD_GRANULARITIES",
    "SSD_CHAIN_OF_THOUGHT", "SSD_PROMPT_INCLUDE_POC", "SSD_PROMPT_INCLUDE_CWE",
    "SSD_PROMPT_INCLUDE_DESCRIPTION", "SSD_PROMPT_PROJECT_PRIMING",
    "SSD_FEEDBACK_APPLIED_DIFF", "SSD_FEEDBACK_ATTEMPT_HISTORY", "SSD_FEEDBACK_REFLEXION",
]


# --- env overlay -------------------------------------------------------------
def test_generation_env_overlay_applies(monkeypatch):
    monkeypatch.setenv("SSD_NUM_CANDIDATES", "4")
    monkeypatch.setenv("SSD_CANDIDATE_TEMPERATURES", "0.2,0.6,0.9")
    monkeypatch.setenv("SSD_GRANULARITIES", "minimal,guard")
    monkeypatch.setenv("SSD_PROMPT_INCLUDE_POC", "0")
    monkeypatch.setenv("SSD_PROMPT_PROJECT_PRIMING", "false")
    monkeypatch.setenv("SSD_FEEDBACK_REFLEXION", "1")
    out = cfg._apply_generation_env_overrides({"generation": {"num_candidates": 1}})
    gen = out["generation"]
    assert gen["num_candidates"] == 4
    assert gen["candidate_temperatures"] == [0.2, 0.6, 0.9]
    assert gen["granularities"] == ["minimal", "guard"]
    assert gen["prompt_components"]["include_poc"] is False
    assert gen["prompt_components"]["project_priming"] is False
    assert out["feedback_loop"]["richer_context"]["reflexion"] is True


def test_generation_env_overlay_noop_when_unset(monkeypatch):
    for k in _SSD_VARS:
        monkeypatch.delenv(k, raising=False)
    out = cfg._apply_generation_env_overrides({"generation": {"num_candidates": 2}})
    assert out["generation"]["num_candidates"] == 2  # unchanged
    # No toggles set ⇒ prompt_components carries no overrides.
    assert out["generation"]["prompt_components"] == {}


def test_invalid_num_candidates_is_ignored(monkeypatch):
    monkeypatch.setenv("SSD_NUM_CANDIDATES", "notanint")
    out = cfg._apply_generation_env_overrides({"generation": {"num_candidates": 1}})
    assert out["generation"]["num_candidates"] == 1


# --- prompt-component toggles (patch_generator) ------------------------------
def test_build_vuln_context_drops_cwe_and_keeps_description(monkeypatch):
    monkeypatch.setattr(pg, "PROMPT_INCLUDE_POC", False)
    monkeypatch.setattr(pg, "PROMPT_INCLUDE_CWE", False)
    monkeypatch.setattr(pg, "PROMPT_INCLUDE_DESCRIPTION", True)
    ctx = pg._build_vulnerability_context(
        "CVE-X", description="a heap overflow", cwe="CWE-787", cwe_description="OOB write")
    assert "VULNERABILITY DESCRIPTION" in ctx
    assert "WEAKNESS CLASS" not in ctx


def test_all_components_off_gives_empty_context(monkeypatch):
    for g in ("PROMPT_INCLUDE_POC", "PROMPT_INCLUDE_CWE", "PROMPT_INCLUDE_DESCRIPTION"):
        monkeypatch.setattr(pg, g, False)
    ctx = pg._build_vulnerability_context("CVE-X", description="d", cwe="CWE-1", cwe_description="x")
    assert ctx == ""


def test_project_priming_toggle(monkeypatch):
    proj = {"system_prompt": "PROJECT_SPECIAL_PRIMING_XYZ", "language": "c"}
    try:
        monkeypatch.setattr(pg, "PROMPT_PROJECT_PRIMING", False)
        pg._apply_phase2(proj)
        assert "PROJECT_SPECIAL_PRIMING_XYZ" not in pg.SYSTEM_PROMPT  # generic used

        monkeypatch.setattr(pg, "PROMPT_PROJECT_PRIMING", True)
        pg._apply_phase2(proj)
        assert "PROJECT_SPECIAL_PRIMING_XYZ" in pg.SYSTEM_PROMPT      # project used
    finally:
        pg._apply_phase2({})  # reset module globals


# --- ablation harness --------------------------------------------------------
def test_load_variants_and_stringify(tmp_path):
    p = tmp_path / "v.yaml"
    p.write_text(
        "variants:\n"
        "  - name: baseline\n    env: {}\n"
        "  - name: no_poc\n    description: d\n    env: {SSD_PROMPT_INCLUDE_POC: 0}\n"
        "  - name: bestof\n    env: {SSD_NUM_CANDIDATES: 4, SSD_CHAIN_OF_THOUGHT: true}\n")
    vs = ab.load_variants(p)
    assert [v["name"] for v in vs] == ["baseline", "no_poc", "bestof"]
    assert vs[1]["env"] == {"SSD_PROMPT_INCLUDE_POC": "0"}
    assert vs[2]["env"] == {"SSD_NUM_CANDIDATES": "4", "SSD_CHAIN_OF_THOUGHT": "1"}


def test_load_variants_rejects_duplicate_names(tmp_path):
    p = tmp_path / "v.yaml"
    p.write_text("variants:\n  - name: a\n  - name: a\n")
    with pytest.raises(ValueError):
        ab.load_variants(p)


def test_shipped_variants_file_is_valid():
    vs = ab.load_variants(Path(ra.PIPELINE_ROOT) / "ablation" / "variants.yaml")
    names = [v["name"] for v in vs]
    assert names[0] == "baseline" and "no_poc" in names and "bestof4" in names


def test_parse_run_metrics(tmp_path):
    (tmp_path / "patches").mkdir()
    (tmp_path / "patches" / "pipeline_summary.json").write_text(
        json.dumps({"summary": {"total_tasks": 10, "syntax_valid": 8}}))
    (tmp_path / "validation_results").mkdir()
    (tmp_path / "validation_results" / "validation_summary_1.json").write_text(json.dumps({
        "by_cve": {
            "CVE-1": [{"status": "Success"}],
            "CVE-2": [{"status": "PoC Still Works"}],
            "CVE-3": [{"status": "x", "poc_blocked": True, "sast_passed": True}],
        }}))
    (tmp_path / "results").mkdir()
    (tmp_path / "results" / "feedback_loop_results_1.json").write_text(
        json.dumps({"successful": 1, "total_patches": 1}))  # real schema: top-level
    row = ab.parse_run_metrics(tmp_path, "baseline")
    assert row["validated_cves"] == 3
    assert row["initial_success"] == 2          # CVE-1 (status) + CVE-3 (poc+sast)
    assert row["feedback_success"] == 1
    assert row["patched"] == 3 and row["attempted"] == 3
    assert row["success_rate"] == 100.0


def test_parse_run_metrics_missing_files(tmp_path):
    row = ab.parse_run_metrics(tmp_path, "empty")
    assert row["patched"] == 0 and row["success_rate"] == 0.0


def test_build_comparison_table_orders_baseline_first():
    rows = [
        {"variant": "no_poc", "attempted": 3, "initial_success": 1,
         "feedback_success": 0, "patched": 1, "success_rate": 33.3},
        {"variant": "baseline", "attempted": 3, "initial_success": 2,
         "feedback_success": 1, "patched": 3, "success_rate": 100.0},
    ]
    t = ab.build_comparison_table(rows)
    assert t.index("baseline") < t.index("no_poc")
    assert "Success%" in t
    assert "33.3" in t


# --- runner plan (pure) ------------------------------------------------------
def test_build_plan_constructs_commands():
    variants = [
        {"name": "baseline", "description": "d", "env": {}},
        {"name": "no_poc", "description": "d", "env": {"SSD_PROMPT_INCLUDE_POC": "0"}},
    ]
    plan = ra.build_plan(variants, Path("/tmp/out"), "glibc",
                         ["2", "3"], [], False, 3)
    assert [p["name"] for p in plan] == ["baseline", "no_poc"]
    cmd0 = plan[0]["cmd"]
    assert "--project" in cmd0 and "glibc" in cmd0
    assert "--base-dir" in cmd0 and "/tmp/out/baseline" in cmd0
    assert "--max-retries" in cmd0 and "3" in cmd0
    assert plan[1]["env"] == {"SSD_PROMPT_INCLUDE_POC": "0"}
