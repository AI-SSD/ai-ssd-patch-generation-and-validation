#!/usr/bin/env python3
"""Tests for the per-CVE spear-prompt template variables (Phase 2 + feedback).

Covers: CWE token resolution from the Phase 0 CSV columns (CWE /
CWE_Description), fallback wording when NVD records no usable CWE, token-exact
substitution (foreign braces pass through), the include_cwe ablation gate, the
assembled project prompts, and the guard that every project YAML's phase2
prompts actually carry the {cwe} variable. No Docker/LLM is touched.

Run: ``python3 -m pytest tests/test_spear_prompts.py -v`` from the pipeline dir.
"""

import sys
import types
from pathlib import Path

import pytest
import yaml

try:  # prefer the real pandas when installed (VM); stub it otherwise (dev hosts)
    import pandas  # noqa: F401
except ImportError:
    _pd_stub = types.ModuleType("pandas")
    _pd_stub.DataFrame = _pd_stub.Series = object  # annotation targets (eager on <3.14)
    sys.modules["pandas"] = _pd_stub

import patch_generator as pg  # noqa: E402

PIPELINE_DIR = Path(pg.__file__).parent


# --- token resolution --------------------------------------------------------
def test_known_cwe_renders_id_and_name():
    out = pg.render_system_prompt("Fix {cwe}.", "CVE-1", cwe="CWE-125")
    assert out == "Fix CWE-125 (Out-of-bounds Read)."


def test_multiple_cwes_all_rendered():
    out = pg.render_system_prompt("{cwe}", cwe="CWE-125,CWE-787")
    assert "CWE-125 (Out-of-bounds Read)" in out
    assert "CWE-787 (Out-of-bounds Write)" in out


def test_individual_id_and_name_tokens():
    out = pg.render_system_prompt("[{cwe_id}] [{cwe_name}]", cwe="CWE-416")
    assert out == "[CWE-416] [Use After Free]"


def test_unknown_cwe_name_taken_from_description_column():
    out = pg.render_system_prompt(
        "{cwe}", cwe="CWE-9999",
        cwe_description="CWE-9999: Made-Up Weakness | CWE-1: Other")
    assert out == "CWE-9999 (Made-Up Weakness)"


def test_unknown_cwe_without_description_renders_bare_id():
    out = pg.render_system_prompt("{cwe}", cwe="CWE-9999")
    assert out == "CWE-9999"


# --- fallbacks ---------------------------------------------------------------
@pytest.mark.parametrize("cwe_field", ["", None, "nan", "none",
                                       "NVD-CWE-Other", "NVD-CWE-noinfo"])
def test_unusable_cwe_renders_neutral_fallback(cwe_field):
    out = pg.render_system_prompt("Fix {cwe}.", "CVE-1", cwe=cwe_field)
    assert out == f"Fix {pg._CWE_COMBINED_FALLBACK}."
    assert "{" not in out


def test_cve_id_token_and_fallback():
    assert pg.render_system_prompt("{cve_id}", "CVE-2015-7547") == "CVE-2015-7547"
    assert pg.render_system_prompt("{cve_id}") == "this CVE"


def test_catchall_mixed_with_real_cwe_keeps_only_real():
    out = pg.render_system_prompt("{cwe}", cwe="NVD-CWE-noinfo,CWE-190")
    assert out == "CWE-190 (Integer Overflow or Wraparound)"


# --- token-exact substitution ------------------------------------------------
def test_foreign_braces_pass_through():
    tpl = "struct {int x;} and {not_a_var} plus {cwe_id}"
    out = pg.render_system_prompt(tpl, cwe="CWE-476")
    assert out == "struct {int x;} and {not_a_var} plus CWE-476"


def test_template_without_variables_unchanged():
    tpl = "A static project prompt with no variables."
    assert pg.render_system_prompt(tpl, "CVE-1", cwe="CWE-125") == tpl


# --- ablation gate -----------------------------------------------------------
def test_include_cwe_off_forces_fallback(monkeypatch):
    monkeypatch.setattr(pg, "PROMPT_INCLUDE_CWE", False)
    out = pg.render_system_prompt("Fix {cwe}.", "CVE-1", cwe="CWE-125")
    assert out == f"Fix {pg._CWE_COMBINED_FALLBACK}."


# --- assembled prompts -------------------------------------------------------
def test_default_preambles_are_spear_templates():
    assert "{cwe}" in pg._DEFAULT_SYSTEM_PREAMBLE
    assert "{cwe}" in pg._DEFAULT_FEEDBACK_PREAMBLE


def test_apply_phase2_keeps_template_then_render_fills_it():
    try:
        pg._apply_phase2({"system_prompt": "Project X. This CVE is {cwe}.",
                          "language": "c"})
        assert "{cwe}" in pg.SYSTEM_PROMPT           # template preserved
        rendered = pg.render_system_prompt(pg.SYSTEM_PROMPT, "CVE-1", cwe="CWE-415")
        assert "CWE-415 (Double Free)" in rendered
        assert "SEARCH" in rendered                   # edit contract still appended
        assert "{cwe}" not in rendered
    finally:
        pg._apply_phase2({})  # reset module globals


def test_default_assembled_prompts_render_clean():
    try:
        pg._apply_phase2({})
        for tpl in (pg.SYSTEM_PROMPT, pg.FEEDBACK_SYSTEM_PROMPT):
            rendered = pg.render_system_prompt(tpl)
            assert pg._CWE_COMBINED_FALLBACK in rendered
            assert not pg._PROMPT_VAR_RE.search(rendered)
    finally:
        pg._apply_phase2({})


# --- feedback path carries the CWE context -----------------------------------
def test_vuln_context_weakness_line_from_csv_fields():
    ctx = pg._build_vulnerability_context(
        "CVE-X", description="desc", cwe="CWE-787",
        cwe_description="CWE-787: Out-of-bounds Write")
    assert "WEAKNESS CLASS: CWE-787" in ctx


# --- every project config is a spear template --------------------------------
def test_all_project_configs_use_cwe_variable():
    configs = sorted((PIPELINE_DIR / "cve_aggregator").glob("*_config.yaml"))
    assert configs, "no project configs found"
    for cfg_path in configs:
        cfg = yaml.safe_load(cfg_path.read_text())
        phase2 = (cfg or {}).get("phase2") or {}
        for key in ("system_prompt", "feedback_system_prompt"):
            prompt = phase2.get(key)
            if prompt is None:
                continue
            assert "{cwe}" in prompt, f"{cfg_path.name}: {key} lacks {{cwe}}"
            rendered = pg.render_system_prompt(prompt, "CVE-1", cwe="CWE-125")
            assert not pg._PROMPT_VAR_RE.search(rendered), (
                f"{cfg_path.name}: {key} has an unrendered variable")
