"""Training-data contamination filter (Phase 2 scope gate).

When ``contamination_filter.enabled`` is on in ``config.yaml``, patch
generation is restricted to CVEs whose NVD publication date is STRICTLY AFTER
the active model's training-data cutoff, so the model cannot have seen the
vulnerability, its advisory, or its fix during training. The effective cutoff
is the LATEST (max) cutoff across the active profile's model ramp — with the
uniform single-model profiles that is simply that model's date; if a ramp is
ever reintroduced, the newest model's date governs (a CVE is only "clean" if
it postdates EVERY model that may touch it).

The filter applies at Phase 2 only: Phases 0-1 use no generation LLM and their
baselines are shared across model profiles, so the dataset and reproduction
baselines stay identical across cells; Phases 3-4 and the feedback loop only
consume Phase 2's output and inherit the narrowed set automatically.

Per-CVE publication dates come from (in order): the Phase 0 CSV's
``CVE_Published`` column, the ``*_cve_poc_map.json`` dataset next to it
(``cves.<CVE>.metadata.published_date``), and — as a last, conservative
resort — the CVE ID's year interpreted as January 1st (which can only
over-exclude, never let a contaminated CVE through).
"""
from __future__ import annotations

import glob
import json
import logging
import os
from datetime import date, datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class ContaminationConfigError(RuntimeError):
    """Raised when the filter is enabled but the cutoff cannot be resolved.

    Deliberately fatal: silently including possibly-contaminated CVEs would
    invalidate the contamination study, so a missing/invalid cutoff must abort
    the run loudly rather than degrade quietly.
    """


def parse_cutoff_date(raw: Any) -> Optional[date]:
    """Parse a cutoff/publication date string into a ``date``.

    Accepts ``YYYY-MM-DD`` and full ISO datetimes (NVD publishes e.g.
    ``2016-02-18T21:59:00.120``). Returns None for empty/unparseable input.
    """
    s = str(raw or "").strip()
    if not s:
        return None
    try:
        return datetime.fromisoformat(s).date()
    except ValueError:
        pass
    try:
        return datetime.strptime(s[:10], "%Y-%m-%d").date()
    except ValueError:
        return None


def active_ramp_models(cfg: Dict[str, Any]) -> List[str]:
    """The set of models the active profile may use for generation.

    Union of the per-attempt ramp (``feedback_loop.models_by_attempt``) and the
    provider's base model(s) (``llm.openai_model`` for openai, ``llm.models``
    for ollama). With a profile's ``LLM_MODELS_BY_ATTEMPT`` overlay these all
    collapse to the ramp itself (attempt 1 == the base model).
    """
    llm = cfg.get("llm") if isinstance(cfg.get("llm"), dict) else {}
    fb = cfg.get("feedback_loop") if isinstance(cfg.get("feedback_loop"), dict) else {}
    provider = str(llm.get("provider", "ollama")).lower()

    models: List[str] = []
    for m in (fb.get("models_by_attempt") or {}).values():
        if m:
            models.append(str(m))
    if provider == "openai":
        base = str(llm.get("openai_model", "") or "")
        if base:
            models.append(base)
    else:
        for m in llm.get("models") or []:
            if m:
                models.append(str(m))
    # Preserve order, drop duplicates.
    seen = set()
    return [m for m in models if not (m in seen or seen.add(m))]


def resolve_cutoff(cfg: Dict[str, Any]) -> Tuple[Optional[date], str]:
    """Resolve the effective training-data cutoff for the active configuration.

    Returns ``(cutoff_date, source_description)``; ``(None, reason)`` when the
    filter is disabled. Raises :class:`ContaminationConfigError` when the
    filter is enabled but a cutoff cannot be determined for every ramp model.
    """
    section = cfg.get("contamination_filter")
    section = section if isinstance(section, dict) else {}
    if not section.get("enabled", False):
        return None, "disabled"

    override = parse_cutoff_date(section.get("cutoff_override"))
    if section.get("cutoff_override") and override is None:
        raise ContaminationConfigError(
            f"contamination_filter.cutoff_override "
            f"{section.get('cutoff_override')!r} is not a valid YYYY-MM-DD date"
        )
    if override:
        return override, "cutoff_override"

    cutoffs = section.get("model_cutoffs")
    cutoffs = cutoffs if isinstance(cutoffs, dict) else {}
    models = active_ramp_models(cfg)
    if not models:
        raise ContaminationConfigError(
            "contamination_filter is enabled but no active model could be "
            "determined (empty llm.models / feedback_loop.models_by_attempt)"
        )

    resolved: Dict[str, date] = {}
    missing: List[str] = []
    for m in models:
        d = parse_cutoff_date(cutoffs.get(m))
        if d is None:
            missing.append(m)
        else:
            resolved[m] = d
    if missing:
        raise ContaminationConfigError(
            "contamination_filter is enabled but these active models have no "
            f"(valid) entry in contamination_filter.model_cutoffs: {missing}. "
            "Add their documented training-data cutoff (YYYY-MM-DD) to "
            "config.yaml, or set LLM_TRAINING_CUTOFF to override."
        )
    # The newest model's date governs: a CVE is only uncontaminated if it
    # postdates EVERY model in the ramp.
    model, cutoff = max(resolved.items(), key=lambda kv: kv[1])
    return cutoff, f"model_cutoffs[{model}]"


def published_dates_from_results(results_dir: Path) -> Dict[str, str]:
    """Per-CVE NVD publication dates from the Phase 0 ``*_cve_poc_map.json``.

    Fallback source for datasets whose CSV predates the ``CVE_Published``
    column. Returns ``{CVE-ID (upper): iso-date-string}``; empty on any error.
    """
    out: Dict[str, str] = {}
    for path in sorted(glob.glob(os.path.join(str(results_dir), "*_cve_poc_map.json"))):
        try:
            with open(path) as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            continue
        for cve_id, entry in (data.get("cves") or {}).items():
            meta = entry.get("metadata") if isinstance(entry, dict) else None
            pub = (meta or {}).get("published_date", "")
            if pub:
                out[str(cve_id).upper()] = str(pub)
    return out


def published_date_for(cve_id: str, csv_value: Any,
                       map_dates: Dict[str, str]) -> Tuple[Optional[date], str]:
    """Best-available publication date for *cve_id* → ``(date, source)``.

    Order: CSV ``CVE_Published`` value → ``*_cve_poc_map.json`` → the CVE ID's
    year as January 1st (conservative: can only over-exclude). ``(None, ...)``
    only when even the ID year is unparseable.
    """
    d = parse_cutoff_date(csv_value)
    if d:
        return d, "csv"
    d = parse_cutoff_date(map_dates.get(str(cve_id).upper()))
    if d:
        return d, "poc_map"
    parts = str(cve_id).upper().split("-")
    if len(parts) == 3 and parts[0] == "CVE" and parts[1].isdigit():
        return date(int(parts[1]), 1, 1), "cve_year"
    return None, "unknown"


def split_post_cutoff(cve_rows: Dict[str, Any], cutoff: date,
                      results_dir: Optional[Path] = None,
                      log: Optional[logging.Logger] = None,
                      ) -> Tuple[List[str], List[str]]:
    """Split CVEs into (kept, skipped) around *cutoff*.

    *cve_rows* maps CVE id → the CSV's ``CVE_Published`` value (may be empty).
    Kept = published STRICTLY AFTER the cutoff day (a Sept-5 cutoff keeps CVEs
    from Sept 6 onwards). CVEs whose date is unknown from every source are
    SKIPPED (conservative) with a warning.
    """
    log = log or logger
    map_dates = published_dates_from_results(results_dir) if results_dir else {}
    kept: List[str] = []
    skipped: List[str] = []
    for cve_id, csv_value in cve_rows.items():
        pub, source = published_date_for(cve_id, csv_value, map_dates)
        if pub is None:
            log.warning("%s: no publication date from any source — treating as "
                        "pre-cutoff (excluded)", cve_id)
            skipped.append(cve_id)
        elif pub > cutoff:
            kept.append(cve_id)
        else:
            if source == "cve_year":
                log.warning("%s: publication date unavailable, used CVE-ID year "
                            "(%s) — excluded as pre-cutoff (conservative)",
                            cve_id, pub.isoformat())
            skipped.append(cve_id)
    return sorted(kept), sorted(skipped)
