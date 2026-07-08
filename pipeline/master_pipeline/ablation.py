#!/usr/bin/env python3
"""Ablation / config-sweep harness for the patch-generation improvements.

Pure helpers (no Docker / LLM / network): load variant definitions, map a variant
to the ``SSD_*`` environment it sets, parse a completed run's result JSONs into a
metrics row, and render a comparison table. The per-variant pipeline EXECUTION is
driven by ``run_ablation.py`` (pipeline root), which calls into here.

Why env, not per-variant YAML: each variant is one pipeline run distinguished only
by the generation/prompt/feedback knobs, and the config loader already overlays
``SSD_*`` env onto config.yaml (see ``config._apply_generation_env_overrides``).
So a variant is just ``{name, description, env}`` and the runner exports ``env``
before launching the pipeline — the same profile/env-transport pattern the LLM
profiles use. ``baseline`` (empty env) reproduces the current system exactly.

Result files read per run (all tolerated-missing):
  * ``patches/pipeline_summary.json``                  — Phase 2 generation
  * ``validation_results/validation_summary_*.json``   — Phase 3 validation (latest)
  * ``results/feedback_loop_results_*.json``           — feedback-loop outcomes (latest)
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml
except Exception:  # pragma: no cover - yaml is a pipeline dependency
    yaml = None


# ---------------------------------------------------------------------------
# Variant definitions
# ---------------------------------------------------------------------------

def load_variants(path: Path) -> List[Dict[str, Any]]:
    """Load ``[{name, description, env}]`` from an ablation variants YAML.

    The file is ``{variants: [ {name, description?, env?}, ... ]}``. Each ``env``
    is a mapping of ``SSD_*`` var → value. Raises ValueError on a malformed file
    so a typo'd sweep fails loudly instead of silently running one variant.
    """
    if yaml is None:
        raise RuntimeError("PyYAML is required to load ablation variants")
    data = yaml.safe_load(Path(path).read_text()) or {}
    raw = data.get("variants")
    if not isinstance(raw, list) or not raw:
        raise ValueError(f"{path}: expected a non-empty 'variants:' list")
    variants: List[Dict[str, Any]] = []
    seen = set()
    for i, v in enumerate(raw):
        if not isinstance(v, dict) or not v.get("name"):
            raise ValueError(f"{path}: variant #{i} is missing a 'name'")
        name = str(v["name"])
        if name in seen:
            raise ValueError(f"{path}: duplicate variant name {name!r}")
        seen.add(name)
        variants.append({
            "name": name,
            "description": str(v.get("description", "")),
            "env": variant_env(v.get("env") or {}),
        })
    return variants


def variant_env(env: Dict[str, Any]) -> Dict[str, str]:
    """Normalise a variant's env mapping to ``{str: str}`` (values stringified)."""
    out: Dict[str, str] = {}
    for k, val in (env or {}).items():
        if isinstance(val, bool):
            out[str(k)] = "1" if val else "0"
        elif isinstance(val, (list, tuple)):
            out[str(k)] = ",".join(str(x) for x in val)
        else:
            out[str(k)] = str(val)
    return out


# ---------------------------------------------------------------------------
# Metrics extraction from a completed run
# ---------------------------------------------------------------------------

def _read_json(path: Path) -> Dict[str, Any]:
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def _latest(paths: List[Path]) -> Optional[Path]:
    paths = [p for p in paths if p.exists()]
    if not paths:
        return None
    return max(paths, key=lambda p: p.stat().st_mtime)


def _is_success_status(status: Any) -> bool:
    return str(status or "").strip().lower() == "success"


def parse_run_metrics(base_dir: Path, variant_name: str = "") -> Dict[str, Any]:
    """Parse one run's result JSONs into a flat metrics row.

    Computes an end-to-end patchability figure as
    ``(unique CVEs whose Phase-3 validation passed) + (feedback-loop fixes)``
    over the CVEs that reached validation — feedback only runs on CVEs whose
    initial validation FAILED, so the two never double-count. Returns zeros for
    any stage whose summary file is absent (e.g. a generation-only run).
    """
    base_dir = Path(base_dir)
    row: Dict[str, Any] = {"variant": variant_name}

    # Phase 2 — generation
    gen = _read_json(base_dir / "patches" / "pipeline_summary.json")
    gsum = gen.get("summary", gen) if isinstance(gen, dict) else {}
    row["gen_total"] = int(gsum.get("total_tasks", 0) or 0)
    row["gen_syntax_valid"] = int(gsum.get("syntax_valid", 0) or 0)

    # Phase 3 — validation (latest summary)
    vfile = _latest(list((base_dir / "validation_results").glob("validation_summary_*.json")))
    initial_success_cves: set = set()
    attempted_cves: set = set()
    if vfile is not None:
        vdata = _read_json(vfile)
        by_cve = vdata.get("by_cve", {}) if isinstance(vdata, dict) else {}
        for cve_id, items in by_cve.items():
            attempted_cves.add(cve_id)
            for item in (items or []):
                if _is_success_status(item.get("status")) or (
                        item.get("poc_blocked") and item.get("sast_passed")):
                    initial_success_cves.add(cve_id)
                    break
    row["validated_cves"] = len(attempted_cves)
    row["initial_success"] = len(initial_success_cves)

    # Feedback loop — fixes among initially-failed CVEs (latest results file)
    ffile = _latest(list((base_dir / "results").glob("feedback_loop_results_*.json")))
    fb = _read_json(ffile) if ffile is not None else {}
    fb_sum = fb.get("summary", fb) if isinstance(fb, dict) else {}
    row["feedback_success"] = int(fb_sum.get("successful", 0) or 0)

    # End-to-end patchability
    attempted = row["validated_cves"] or row["gen_total"]
    patched = row["initial_success"] + row["feedback_success"]
    row["patched"] = patched
    row["attempted"] = attempted
    row["success_rate"] = round(100.0 * patched / attempted, 1) if attempted else 0.0
    return row


# ---------------------------------------------------------------------------
# Comparison table
# ---------------------------------------------------------------------------

_COLUMNS = [
    ("variant", "Variant"),
    ("attempted", "Attempted"),
    ("initial_success", "Initial✓"),
    ("feedback_success", "Feedback✓"),
    ("patched", "Patched"),
    ("success_rate", "Success%"),
]


def build_comparison_table(rows: List[Dict[str, Any]]) -> str:
    """Render metric rows as a GitHub-flavoured markdown table (baseline first)."""
    if not rows:
        return "(no ablation results)"
    ordered = sorted(rows, key=lambda r: (r.get("variant") != "baseline", r.get("variant", "")))
    header = "| " + " | ".join(h for _, h in _COLUMNS) + " |"
    sep = "| " + " | ".join("---" for _ in _COLUMNS) + " |"
    lines = [header, sep]
    for r in ordered:
        cells = []
        for key, _ in _COLUMNS:
            v = r.get(key, "")
            cells.append(f"{v:g}" if isinstance(v, float) else str(v))
        lines.append("| " + " | ".join(cells) + " |")
    return "\n".join(lines)


def to_csv(rows: List[Dict[str, Any]]) -> str:
    """Render metric rows as CSV (header from _COLUMNS)."""
    keys = [k for k, _ in _COLUMNS]
    out = [",".join(k for k in keys)]
    for r in rows:
        out.append(",".join(str(r.get(k, "")) for k in keys))
    return "\n".join(out)
