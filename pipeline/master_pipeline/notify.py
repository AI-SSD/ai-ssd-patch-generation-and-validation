"""Push notifications (ntfy / Slack / Discord) for pipeline state changes.

This is the *Python* half of the notification system; the *shell* half lives in
``run_all.sh`` (its ``notify()``/``notify_evt()`` helpers). Both read the SAME
``notifications:`` block in ``config.yaml`` and honour the SAME granularity
toggles, so a topic configured once drives phone pushes from both layers:

    run_all.sh          ──▶  run start / stage / project / cell transitions
    master_pipeline      ──▶  per-phase start / done / failure (this module)

Design rules:
  * Best-effort and silent: a notification failure (no network, bad topic, no
    ``requests``) NEVER breaks a pipeline run — every send is wrapped and the
    return value is ignored by callers.
  * Zero hard dependencies: uses ``urllib`` from the stdlib, not ``requests``.
  * Single source of truth: the ``notifications:`` block in the pipeline-root
    ``config.yaml`` (NOT a per-project workdir copy). The env vars
    ``NTFY_TOPIC`` / ``NTFY_SERVER`` / ``NTFY_TOKEN`` override the config, exactly
    like ``run_all.sh``.

Granularity toggles (flat keys under ``notifications:``; default true = "complete"):
    notify_phase     per-phase start/done inside a cell  (this module)
    notify_run / notify_stage / notify_project / notify_cell   (run_all.sh)
ISSUES (any failure / timeout) are ALWAYS sent regardless of the toggles, as
long as ``enabled`` is true.

CLI (so shell or ad-hoc callers can reuse the exact same logic/config):
    python3 -m master_pipeline.notify --event phase_done --message "..." [--priority high]
"""
from __future__ import annotations

import json
import logging
import os
import urllib.request
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger("pipeline")

# Map each event to the config toggle that gates it. ``None`` => always send
# (issues/lifecycle endpoints that should never be silently dropped).
_EVENT_TOGGLE: Dict[str, Optional[str]] = {
    "phase_start": "notify_phase",
    "phase_done": "notify_phase",
    "phase_failed": None,   # issue — always
    "cell_start": "notify_cell",
    "cell_done": "notify_cell",
    "test": None,
}

# Per-event default priority + tag (ntfy emoji shortcode). Issues escalate.
_EVENT_PRIORITY: Dict[str, str] = {
    "phase_start": "low",       # delivered, but silent — avoids buzzing on every phase
    "phase_done": "default",
    "phase_failed": "high",
    "cell_start": "default",
    "cell_done": "default",
    "test": "high",
}
_EVENT_TAGS: Dict[str, str] = {
    "phase_start": "arrow_forward",
    "phase_done": "white_check_mark",
    "phase_failed": "x",
    "cell_start": "arrow_forward",
    "cell_done": "white_check_mark",
    "test": "test_tube",
}


def _pipeline_root() -> Path:
    """Pipeline root (where config.yaml definitively lives)."""
    try:
        from .config import BASE_DIR  # local import to avoid cycles at module load
        return Path(BASE_DIR)
    except Exception:
        return Path(__file__).resolve().parent.parent


def _load_notif_cfg() -> Dict[str, Any]:
    """Read the ``notifications:`` block from the pipeline-root config.yaml.

    Reads the file directly (not via the cached ``get_config``) so a stale cache
    populated from a per-project base_dir can't hide or mangle the block.
    """
    try:
        import yaml
        with open(_pipeline_root() / "config.yaml", "r") as fh:
            cfg = yaml.safe_load(fh) or {}
        block = cfg.get("notifications", {})
        return block if isinstance(block, dict) else {}
    except Exception:
        return {}


def _resolve_target(cfg: Dict[str, Any]) -> Dict[str, Optional[str]]:
    """Resolve ntfy server/topic/token: env wins, else the config ``ntfy_url``."""
    topic = os.environ.get("NTFY_TOPIC")
    server = os.environ.get("NTFY_SERVER")
    token = os.environ.get("NTFY_TOKEN")
    if not topic:
        url = (cfg.get("ntfy_url") or "").strip()
        if url:
            server = server or url.rsplit("/", 1)[0]
            topic = url.rsplit("/", 1)[-1]
        token = token or (cfg.get("ntfy_token") or "").strip() or None
    return {"server": server or "https://ntfy.sh", "topic": topic or None, "token": token}


def _enabled(cfg: Dict[str, Any]) -> bool:
    # Default to enabled only when a topic is actually resolvable; an empty
    # config means "no notifications", not "spam to nowhere".
    if not cfg:
        return bool(os.environ.get("NTFY_TOPIC"))
    return bool(cfg.get("enabled", True))


def _event_allowed(event: str, cfg: Dict[str, Any]) -> bool:
    toggle = _EVENT_TOGGLE.get(event, None)
    if toggle is None:
        return True   # always-send event (issue/lifecycle)
    val = cfg.get(toggle, True)   # missing toggle => on ("complete" by default)
    return str(val).lower() != "false"


def send(event: str, message: str, *, priority: Optional[str] = None,
         title: Optional[str] = None, tags: Optional[str] = None,
         base_dir: Optional[Path] = None) -> bool:
    """Send a notification for ``event``. Best-effort; never raises.

    Returns True if a push was actually dispatched, False if it was suppressed
    (disabled, toggled off, or no topic) or failed.
    """
    try:
        cfg = _load_notif_cfg()
        if not _enabled(cfg):
            return False
        if not _event_allowed(event, cfg):
            return False
        tgt = _resolve_target(cfg)
        if not tgt["topic"]:
            return False

        prio = priority or _EVENT_PRIORITY.get(event, cfg.get("default_priority", "default"))
        tag = tags or _EVENT_TAGS.get(event, "")
        ttl = title or "AI-SSD pipeline"

        url = f"{tgt['server'].rstrip('/')}/{tgt['topic']}"
        headers = {"Title": ttl, "Priority": str(prio)}
        if tag:
            headers["Tags"] = tag
        if tgt["token"]:
            headers["Authorization"] = f"Bearer {tgt['token']}"

        req = urllib.request.Request(url, data=message.encode("utf-8"),
                                     headers=headers, method="POST")
        urllib.request.urlopen(req, timeout=5).read()
        return True
    except Exception as e:  # noqa: BLE001 — notifications must never break a run
        logger.debug("notify(%s) suppressed: %s", event, e)
        return False


# ---------------------------------------------------------------------------
# Per-phase headline metric — a best-effort one-liner appended to phase_done so
# the push carries the result, not just "Phase N done". Mirrors the file shapes
# dashboard_control.get_progress() reads. Any parse error → empty string.
# ---------------------------------------------------------------------------
_PHASE_LABELS = {0: "Aggregation", 1: "Reproduction", 2: "Patch Gen",
                 3: "Validation", 4: "Reporting"}


def phase_label(phase: int) -> str:
    return _PHASE_LABELS.get(phase, f"Phase {phase}")


def _json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        with open(path) as fh:
            return json.load(fh)
    except Exception:
        return None


def phase_headline(phase: int, base_dir: Path) -> str:
    """Return a short metric string for a finished phase, or '' if unavailable."""
    try:
        base = Path(base_dir)
        if phase == 0:
            import csv as _csv
            import glob as _glob
            hits = _glob.glob(str(base / "results" / "*_cve_poc_complete.csv"))
            if not hits:
                return ""
            total = with_poc = 0
            with open(hits[0], newline="") as fh:
                for row in _csv.DictReader(fh):
                    total += 1
                    if (row.get("poc_path") or "").strip():
                        with_poc += 1
            return f"{total} CVEs, {with_poc} with PoC" if total else ""
        if phase == 1:
            d = _json(base / "results" / "results.json")
            if not d:
                return ""
            res = d.get("results", []) or []
            repro = sum(1 for r in res if r.get("vulnerability_reproduced"))
            manual = sum(1 for r in res if not r.get("vulnerability_reproduced")
                         and r.get("needs_manual_revision"))
            tail = f", {manual} manual" if manual else ""
            return f"{repro}/{len(res)} reproduced{tail}" if res else ""
        if phase == 2:
            d = _json(base / "patches" / "pipeline_summary.json")
            if not d:
                return ""
            s = d.get("summary", {}) or {}
            tot = s.get("total_tasks", 0)
            valid = s.get("syntax_valid", 0)
            return f"{valid}/{tot} valid patches" if tot else ""
        if phase == 3:
            import glob as _glob
            files = sorted(_glob.glob(
                str(base / "validation_results" / "validation_summary_*.json")))
            if not files:
                return ""
            d = _json(Path(files[-1]))
            if not d:
                return ""
            tot = d.get("metadata", {}).get("total_validations", 0)
            ok = d.get("summary", {}).get("successful", 0)
            return f"{ok}/{tot} validated OK" if tot else ""
    except Exception:
        return ""
    return ""


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description="Send an AI-SSD pipeline notification.")
    ap.add_argument("--event", default="test", help="event key (e.g. phase_done, test)")
    ap.add_argument("--message", required=True)
    ap.add_argument("--priority", default=None)
    ap.add_argument("--title", default=None)
    ap.add_argument("--tags", default=None)
    a = ap.parse_args()
    ok = send(a.event, a.message, priority=a.priority, title=a.title, tags=a.tags)
    print("sent" if ok else "suppressed/failed")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(_main())
