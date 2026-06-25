"""Shared Phase-1 readiness classifier — single source of truth for the gate
that decides whether a Phase-0 CVE will be ATTEMPTED in Phase 1.

Both the Phase 1 orchestrator (``orchestrator.Phase0CSVParser.parse``) and the
dashboard's Phase-0 summary (``dashboard_control.get_progress``) call this, so
their counts cannot drift apart. Previously the dashboard used optimistic
*any-row* semantics ("with PoC" = a CVE has a PoC in any of its rows) while the
orchestrator used strict *first-row* gating, so the Phase-0 card and the Phase-1
"Attempted" count never reconciled.

The classifier mirrors ``orchestrator.parse()``'s per-CVE gating, evaluated on a
CVE's FIRST row (the orchestrator dedupes by first occurrence). It deliberately
does NOT include the Ubuntu/era-resolution gate: that needs the project repo and
the YAML era maps and so cannot be evaluated from the CSV alone. ``READY`` is
therefore the *upper bound* on Phase 1 "attempted" — it exceeds the attempted
count only by the CVEs Phase 1 later drops because no Ubuntu era resolves, which
the orchestrator logs as "Skipped (no ubuntu version info)" (normally zero,
since Phase 0 populates ``ubuntu_version``).
"""
from __future__ import annotations

from typing import Dict, Iterable, Mapping

# Phase-1 readiness verdicts (mirror orchestrator.Phase0CSVParser.parse gates).
READY = "ready"                     # has PoC + V_COMMIT, not flagged → Phase 1 attempts it
SKIPPED_MANUAL = "skipped_manual"   # flagged manual_review (pending) or in skipped_cves
NOT_READY = "not_ready"             # missing V_COMMIT or poc_path

_TRUTHY = ("true", "1", "yes")


def classify_phase1_readiness(row: Mapping[str, str],
                              skipped_cves: Iterable[str] = ()) -> str:
    """Classify a single CVE's FIRST Phase-0 CSV row.

    Evaluation order matches ``orchestrator.parse()``:
    ``skipped_cves`` (manual-review timeout) → manual-review flag → V_COMMIT/PoC
    readiness. Returns one of ``READY`` / ``SKIPPED_MANUAL`` / ``NOT_READY``
    (mutually exclusive).
    """
    cve = (row.get("CVE") or "").strip()
    if cve and cve in set(skipped_cves):
        return SKIPPED_MANUAL
    mr = str(row.get("manual_review_required", "")).strip().lower()
    mv = str(row.get("manual_verified", "")).strip().lower()
    if mr in _TRUTHY and mv != "done":
        return SKIPPED_MANUAL
    if not (row.get("V_COMMIT", "") or "").strip() or not (row.get("poc_path", "") or "").strip():
        return NOT_READY
    return READY


def summarize_phase0_readiness(rows: Iterable[Mapping[str, str]],
                               skipped_cves: Iterable[str] = ()) -> Dict[str, int]:
    """Dedupe ``rows`` by CVE (FIRST occurrence, as the orchestrator does) and
    return reconciling Phase-0 counts.

    The three readiness buckets partition the fetched set exactly:
    ``total_cves == ready + manual_pending + not_ready``. ``ready`` is the set
    Phase 1 will attempt (upper bound — see module docstring). ``with_poc`` and
    ``manual_done`` are informational and may overlap the buckets.
    """
    skip = set(skipped_cves)
    seen: set = set()
    counts = {"total_cves": 0, "with_poc": 0, "ready": 0,
              "manual_pending": 0, "manual_done": 0, "not_ready": 0}
    for row in rows:
        cve = (row.get("CVE") or "").strip()
        if not cve or cve in seen:
            continue
        seen.add(cve)
        counts["total_cves"] += 1
        if (row.get("poc_path") or "").strip():
            counts["with_poc"] += 1
        mr = str(row.get("manual_review_required", "")).strip().lower()
        mv = str(row.get("manual_verified", "")).strip().lower()
        if mr in _TRUTHY and mv == "done":
            counts["manual_done"] += 1
        verdict = classify_phase1_readiness(row, skip)
        if verdict == READY:
            counts["ready"] += 1
        elif verdict == SKIPPED_MANUAL:
            counts["manual_pending"] += 1
        else:
            counts["not_ready"] += 1
    return counts
