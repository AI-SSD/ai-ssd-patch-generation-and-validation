#!/usr/bin/env python3
"""Run-control + selective-deletion engine for the AI-SSD dashboard.

Pure logic, no web framework — the web layer (``dashboard_server.py``) calls
these functions. Keeping the dangerous operations (signal a run, delete data,
remove Docker images) here makes them auditable and unit-testable in one place.

SECURITY MODEL
--------------
Callers pass SELECTIONS (project names, profile names, phase numbers, run ids) —
never raw filesystem paths or docker refs. Every selection is validated against
what actually exists on disk / under ``profiles/`` and then mapped to concrete
paths/refs HERE. Subprocesses are spawned with argv LISTS (never a shell
string), so a selection can never inject a command. Deletion is two-step:
``plan_deletion()`` returns an itemised, sized preview plus a token derived from
the (normalised) selection; that token must be echoed back to
``apply_deletion()`` so a client cannot delete something it did not preview.
Every path slated for deletion is re-checked to live under ``projects/`` or
``runs/`` before removal.
"""
from __future__ import annotations

import csv as _csv
import glob
import hashlib
import sys as _sys
_csv.field_size_limit(_sys.maxsize)
import json
import os
import re
import shlex
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import zipfile
from typing import Any, Dict, List, Optional, Tuple

from cve_aggregator.utils.phase1_readiness import summarize_phase0_readiness

ROOT = os.path.dirname(os.path.abspath(__file__))
PROJECTS_DIR = os.path.join(ROOT, "projects")
RUNS_DIR = os.path.join(ROOT, "runs")
PROFILES_DIR = os.path.join(ROOT, "profiles")
CONFIG_DIR = os.path.join(ROOT, "cve_aggregator")
PHASES = ("0", "1", "2", "3", "4")

# Docker image repo prefixes (match orchestrator.py / patch_validator.py).
_DEFAULT_BASE_PREFIX = "ai-ssd/{project}-base"
_DEFAULT_CVE_PREFIX = "ai-ssd/{project}-cve"
_PATCH_PREFIX = "ai-ssd-patch"  # hardcoded in patch_validator.py (no project)


# ---------------------------------------------------------------------------
# Inventory (the allowlists every selection is validated against)
# ---------------------------------------------------------------------------
def _config_map() -> Dict[str, str]:
    """Authoritative {project -> config path}, parsed from run_project.sh's
    ``CONFIG_MAP`` (the same names run_project.sh accepts and uses for the
    ``projects/<project>__<profile>/`` dir, e.g. 'linux-kernel'). Falls back to
    ``cve_aggregator/<stem>_config.yaml`` globbing if the script can't be read.
    """
    out: Dict[str, str] = {}
    try:
        txt = open(os.path.join(ROOT, "run_project.sh"), encoding="utf-8").read()
        block = re.search(r"CONFIG_MAP=\((.*?)\)", txt, re.S)
        if block:
            for name, path in re.findall(r'\[([^\]]+)\]="([^"]+)"', block.group(1)):
                out[name] = path
    except OSError:
        pass
    if not out:
        for p in sorted(glob.glob(os.path.join(CONFIG_DIR, "*_config.yaml"))):
            stem = os.path.basename(p)[: -len("_config.yaml")]
            if stem != "aggregator":
                out[stem] = os.path.join("cve_aggregator", os.path.basename(p))
    return out


def list_projects() -> List[str]:
    """Launchable project names (run_project.sh CONFIG_MAP keys)."""
    return sorted(_config_map())


def _profile_env(profile: str) -> str:
    f = os.path.join(PROFILES_DIR, profile + ".env")
    try:
        return open(f, encoding="utf-8").read()
    except OSError:
        return ""


def list_profiles() -> List[Dict[str, Any]]:
    """All profiles with provider + attempt models (from ``profiles/*.env``)."""
    out = []
    for p in sorted(glob.glob(os.path.join(PROFILES_DIR, "*.env"))):
        name = os.path.basename(p)[:-4]
        txt = open(p, encoding="utf-8").read()
        prov = _grep1(r'LLM_PROVIDER="([^"]*)"', txt) or (
            "ollama" if name.startswith("ollama") else "openai")
        out.append({"name": name, "provider": prov, "models": profile_models(name)})
    return out


def _grep1(pattern: str, text: str) -> str:
    m = re.search(pattern, text)
    return m.group(1) if m else ""


def profile_models(profile: str) -> List[str]:
    """The concrete model ids a profile runs (its 4-attempt ramp, deduped)."""
    txt = _profile_env(profile)
    ramp = _grep1(r'LLM_MODELS_BY_ATTEMPT="([^"]*)"', txt)
    models = [m.strip() for m in ramp.split(",") if m.strip()] if ramp else []
    if not models:
        single = (_grep1(r'LLM_OPENAI_MODEL="([^"]*)"', txt)
                  or _grep1(r'LLM_MODEL="([^"]*)"', txt))
        if single:
            models = [single]
    # preserve order, dedupe
    seen, uniq = set(), []
    for m in models:
        if m not in seen:
            seen.add(m); uniq.append(m)
    return uniq


def _safe_model(model: str) -> str:
    """Mirror patch_validator.PatchInfo: ':' and '.' -> '_'."""
    return model.replace(":", "_").replace(".", "_")


def _safe_cell(s: str) -> str:
    """Mirror patch_validator._docker_safe_name (per-cell tag discriminator)."""
    return re.sub(r"[^a-z0-9_.-]+", "-", str(s).lower()).strip("-._") or "run"


_REP_RE = re.compile(r"^rep(\d+)$")


def _split_cell_name(cell: str) -> Tuple[str, str, str]:
    """Split a cell name into ``(project, repeat_tag, profile)``.

    Cell names are ``<proj>__<prof>`` or ``<proj>__<prof>__rep<K>`` (run_all.sh
    repeat runs export ``RUN_TAG="rep<K>"``). Profiles never contain ``__``, so a
    trailing ``rep<N>`` segment is the repeat tag and everything between the
    project and it is the profile. A plain ``partition("__")`` would fold
    ``__rep<K>`` into the profile — breaking the profile lookup AND the resume
    base-dir (which must carry ``RUN_TAG`` to hit ``projects/…__rep<K>/``).
    Untagged cells get repeat ``""``. Mirrors ``dashboard_server._split_cell_name``.
    """
    segs = str(cell).split("__")
    proj = segs[0]
    rest = segs[1:]
    rep = ""
    if rest and _REP_RE.match(rest[-1]):
        rep = rest[-1]
        rest = rest[:-1]
    return proj, rep, "__".join(rest)


def _phase3_attributed(safe_m: str, want_models: set, want_cells: set) -> bool:
    """True if a patched-image tag tail belongs to a selected (project, profile).

    ``safe_m`` is "<model>" (legacy) or "<model>-<cell>" (per-cell tag), where
    <cell> = sanitized "<proj>__<prof>[__repN]". A legacy tag matches by model
    alone (profile-agnostic, as before); a celled tag matches ONLY when its
    <cell> is one of the selected cells — or a "<cell>__repN" repeat — so a
    different profile that shares or dash-prefixes the model is NOT over-matched.
    """
    if safe_m in want_models:
        return True
    for w in want_models:
        if safe_m.startswith(w + "-"):
            cell = safe_m[len(w) + 1:]
            if any(cell == c or cell.startswith(c + "__rep") for c in want_cells):
                return True
    return False


def list_cells() -> List[Dict[str, str]]:
    """Existing ``projects/<project>__<profile>/`` working dirs."""
    out = []
    if not os.path.isdir(PROJECTS_DIR):
        return out
    for d in sorted(os.listdir(PROJECTS_DIR)):
        full = os.path.join(PROJECTS_DIR, d)
        if not os.path.isdir(full) or "__" not in d:
            continue
        proj, _rep, prof = _split_cell_name(d)
        out.append({"cell": d, "project": proj, "profile": prof,
                    "size_bytes": _dir_size(full)})
    return out


def list_runs() -> List[Dict[str, Any]]:
    """Run-tracking dirs under ``runs/`` (newest first), with a state summary."""
    out = []
    if not os.path.isdir(RUNS_DIR):
        return out
    for d in sorted(glob.glob(os.path.join(RUNS_DIR, "*")), reverse=True):
        if not os.path.isdir(d) or os.path.basename(d) == "latest":
            continue
        rid = os.path.basename(d)
        states: Dict[str, int] = {}
        for sf in glob.glob(os.path.join(d, "cells", "*.state")):
            try:
                st = open(sf).read().split("|", 1)[0]
                states[st] = states.get(st, 0) + 1
            except OSError:
                pass
        out.append({"run_id": rid,
                    "complete": os.path.exists(os.path.join(d, "COMPLETE")),
                    "states": states, "size_bytes": _dir_size(d)})
    return out


# ---------------------------------------------------------------------------
# Sizing helpers
# ---------------------------------------------------------------------------
def _dir_size(path: str) -> int:
    total = 0
    for dp, _dn, fn in os.walk(path):
        for f in fn:
            try:
                total += os.lstat(os.path.join(dp, f)).st_size
            except OSError:
                pass
    return total


def human_bytes(n: int) -> str:
    f = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if f < 1024 or unit == "TB":
            return f"{f:.0f} {unit}" if unit == "B" else f"{f:.1f} {unit}"
        f /= 1024
    return f"{f:.1f} TB"


# ---------------------------------------------------------------------------
# Run control (signal the run's process group)
# ---------------------------------------------------------------------------
def _pgid_file() -> Optional[str]:
    """Newest run dir's pgid file (prefer the ``latest`` symlink)."""
    cands = [os.path.join(RUNS_DIR, "latest", "run_all.pgid")]
    cands += [os.path.join(d, "run_all.pgid")
              for d in sorted(glob.glob(os.path.join(RUNS_DIR, "*")), reverse=True)]
    for c in cands:
        if os.path.isfile(c):
            return c
    return None


def _read_pgid() -> Optional[int]:
    f = _pgid_file()
    if not f:
        return None
    try:
        pgid = int(open(f).read().strip())
    except (OSError, ValueError):
        return None
    # Reject anything that isn't a real, signalable process group. killpg(0,…)
    # would hit the server's OWN group and killpg(-1,…) broadcasts to every
    # process — a corrupt/empty pgid file must never be allowed to do either.
    return pgid if pgid > 1 else None


def _pgid_alive(pgid: int) -> bool:
    try:
        os.killpg(pgid, 0)
        return True
    except (ProcessLookupError, PermissionError):
        return pgid > 0 and isinstance(_proc_state(pgid), str)
    except OSError:
        return False


def _proc_state(pid: int) -> Optional[str]:
    """The leader process' scheduler state char ('R','S','T' stopped, ...)."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            data = f.read()
        # field 3 is state; account for a ')' inside comm
        return data[data.rindex(")") + 2]
    except (OSError, ValueError, IndexError):
        return None


def _pgid_is_ours(pgid: int) -> Optional[bool]:
    """True if the group leader is actually a run_all.sh process — guards against
    signalling a recycled PID after a crash that left a stale pgid file. Returns
    None when /proc is unavailable (non-Linux) so callers can fall back."""
    try:
        with open(f"/proc/{pgid}/cmdline", "rb") as f:
            cmd = f.read().replace(b"\x00", b" ").decode("utf-8", "replace")
        return "run_all.sh" in cmd
    except FileNotFoundError:
        if not os.path.isdir("/proc"):
            return None          # not Linux — can't verify, let caller proceed
        return False             # /proc exists but pid gone → not ours
    except OSError:
        return None


def run_status() -> Dict[str, Any]:
    """Liveness + paused state of the most-recent run's process group."""
    pgid = _read_pgid()
    active = bool(pgid and _pgid_alive(pgid))
    paused = bool(active and _proc_state(pgid) == "T")
    rid = ""
    latest = os.path.join(RUNS_DIR, "latest")
    if os.path.islink(latest) or os.path.isdir(latest):
        rid = os.path.basename(os.path.realpath(latest))
    complete = os.path.exists(os.path.join(latest, "COMPLETE")) if rid else False
    return {"active": active, "paused": paused, "pgid": pgid,
            "run_id": rid, "complete": complete}


def _signal_run(sig: int) -> Dict[str, Any]:
    pgid = _read_pgid()
    if not pgid or not _pgid_alive(pgid):
        return {"ok": False, "error": "no active run found"}
    if _pgid_is_ours(pgid) is False:   # verified NOT run_all.sh (recycled PID)
        return {"ok": False, "error": "stale run reference (process group is not "
                "run_all.sh) — refusing to signal it"}
    try:
        os.killpg(pgid, sig)
        return {"ok": True, "pgid": pgid, "signal": sig}
    except OSError as e:
        return {"ok": False, "error": str(e)}


def stop_run() -> Dict[str, Any]:
    """SIGTERM the run's group — run_all.sh's trap aborts cells cleanly."""
    return _signal_run(signal.SIGTERM)


def pause_run() -> Dict[str, Any]:
    """SIGSTOP the run's group (best effort; in-flight Docker steps continue)."""
    return _signal_run(signal.SIGSTOP)


def resume_run() -> Dict[str, Any]:
    return _signal_run(signal.SIGCONT)


# ---------------------------------------------------------------------------
# Per-cell control (project pages): pause/resume toggle, stop, resume-after-fail.
#
# Unlike the whole-run controls above (which signal run_all.sh's process group),
# these target ONE cell (project__profile). Cells launched by run_all.sh share
# its process group, so killpg can't isolate one — instead we signal the cell's
# own process SUBTREE (its pipeline.py / phase-subprocess leaders, located via
# their --base-dir cmdline, plus all descendants). Every action is appended,
# timestamped, to projects/<cell>/logs/control_audit.log so there is a durable
# record of WHEN each pause/resume/stop/resume-after-fail occurred.
# ---------------------------------------------------------------------------
CONTROL_AUDIT = "control_audit.log"


def _valid_cell(cell: str) -> bool:
    """A real project__profile working dir (guards path joins on the cell name)."""
    return bool(re.fullmatch(r"[A-Za-z0-9._+-]+__[A-Za-z0-9._+-]+", cell or "")) \
        and os.path.isdir(os.path.join(PROJECTS_DIR, cell))


def _cell_audit_path(cell: str) -> str:
    return os.path.join(PROJECTS_DIR, cell, "logs", CONTROL_AUDIT)


def _audit_cell(cell: str, msg: str) -> None:
    """Append one timestamped control event to the cell's audit log (best-effort)."""
    try:
        d = os.path.join(PROJECTS_DIR, cell, "logs")
        os.makedirs(d, exist_ok=True)
        with open(os.path.join(d, CONTROL_AUDIT), "a", encoding="utf-8") as f:
            f.write(f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')}  {msg}\n")
    except OSError:
        pass


def _read_audit(cell: str, n: int = 6) -> List[str]:
    try:
        with open(_cell_audit_path(cell), encoding="utf-8", errors="replace") as f:
            return [ln.rstrip("\n") for ln in f.readlines()[-n:]]
    except OSError:
        return []


def _latest_cell_state(cell: str) -> Tuple[Optional[str], List[str], Optional[str]]:
    """(state, fields, statefile) from the newest run dir that has this cell's
    ``.state`` (format ``STATE|STAGE|STARTED|ENDED|EXIT|LOGFILE``)."""
    for d in sorted(glob.glob(os.path.join(RUNS_DIR, "*")), reverse=True):
        if os.path.basename(d) == "latest":
            continue
        sf = os.path.join(d, "cells", cell + ".state")
        if os.path.isfile(sf):
            try:
                parts = open(sf, encoding="utf-8").read().strip().split("|")
            except OSError:
                parts = []
            return (parts[0] if parts else None), parts, sf
    return None, [], None


def _cell_phases_from_state(parts: List[str]) -> str:
    """Phases to replay for resume-after-fail. Prefer the exact list the cell
    logged ("Phases to Execute: [2, 3, 4]"); fall back to the stage convention
    (baseline=>'0 1', sweep=>'2 3 4')."""
    log = parts[5] if len(parts) > 5 else ""
    try:
        if log and os.path.isfile(log):
            with open(log, "rb") as f:
                try:
                    f.seek(0, os.SEEK_END)
                    size = f.tell()
                    f.seek(max(0, size - 20000))
                except OSError:
                    f.seek(0)
                txt = f.read().decode("utf-8", "replace")
            matches = re.findall(r"Phases to Execute:\s*\[([0-9,\s]+)\]", txt)
            if matches:
                ph = [c for c in re.split(r"[,\s]+", matches[-1].strip()) if c in PHASES]
                if ph:
                    return " ".join(ph)
    except OSError:
        pass
    stage = parts[1] if len(parts) > 1 else ""
    return "0 1" if stage == "baseline" else "2 3 4"


def _proc_cmdline(pid: int) -> str:
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as f:
            return f.read().replace(b"\x00", b" ").decode("utf-8", "replace")
    except OSError:
        return ""


def _all_pids() -> List[int]:
    try:
        return [int(p) for p in os.listdir("/proc") if p.isdigit()]
    except OSError:
        return []


def _proc_ppid(pid: int) -> Optional[int]:
    """Parent PID from /proc/<pid>/stat (field 4, after the state char)."""
    try:
        with open(f"/proc/{pid}/stat") as f:
            data = f.read()
        return int(data[data.rindex(")") + 2:].split()[1])
    except (OSError, ValueError, IndexError):
        return None


# Pipeline entry points whose cmdline carries the cell's --base-dir. Requiring
# one of these (alongside the base-dir path) keeps _cell_root_pids from matching
# unrelated processes that merely mention the path (a tail, an editor, a curl
# whose JSON names the cell).
_CELL_PROC_TOKENS = ("pipeline.py", "patch_generator.py", "orchestrator.py",
                     "patch_validator.py", "reporter.py", "poc_repair",
                     "cve_aggregator", "run_project.sh")


def _cmd_targets_base(cmd: str, base: str) -> bool:
    """True if *base* appears in *cmd* as a whole path (the --base-dir value or a
    prefix of a path UNDER it), not merely as a substring of a longer cell name.
    Critical because one cell name can be a prefix of another, e.g.
    ``…__ollama-proxy-qwen`` is a prefix of ``…__ollama-proxy-qwen-coder`` — a
    plain ``base in cmd`` would mis-attribute the coder's processes to the qwen
    cell. We require the char after the match to be a path/arg boundary."""
    i = cmd.find(base)
    while i >= 0:
        nxt = cmd[i + len(base): i + len(base) + 1]
        if nxt in ("", " ", "/", "\t", "\n"):
            return True
        i = cmd.find(base, i + 1)
    return False


def _cell_root_pids(cell: str) -> List[int]:
    """Live PIDs that are pipeline processes for this cell (cmdline carries the
    cell's base-dir AND a pipeline entry point) — the leaders that anchor the
    cell's process subtree."""
    base = os.path.join(PROJECTS_DIR, cell)
    me = os.getpid()
    out = []
    for pid in _all_pids():
        if pid == me:
            continue
        cmd = _proc_cmdline(pid)
        if _cmd_targets_base(cmd, base) and any(tok in cmd for tok in _CELL_PROC_TOKENS):
            out.append(pid)
    return out


def _proc_subtree(roots: List[int]) -> List[int]:
    """``roots`` plus every descendant (so a paused/stopped cell takes its phase
    subprocess — patch_generator.py, the docker driver, … — down with it)."""
    children: Dict[int, List[int]] = {}
    for pid in _all_pids():
        pp = _proc_ppid(pid)
        if pp is not None:
            children.setdefault(pp, []).append(pid)
    seen: set = set()
    stack = list(roots)
    while stack:
        p = stack.pop()
        if p in seen:
            continue
        seen.add(p)
        stack.extend(children.get(p, []))
    return sorted(seen)


def _signal_cell_tree(cell: str, sig: int) -> Tuple[int, List[int]]:
    roots = _cell_root_pids(cell)
    if not roots:
        return 0, []
    done = []
    for pid in _proc_subtree(roots):
        try:
            os.kill(pid, sig)
            done.append(pid)
        except OSError:
            pass
    return len(done), done


def cell_status(cell: str) -> Dict[str, Any]:
    """Live/paused/last-state + which controls are valid, for the project page."""
    if not _valid_cell(cell):
        return {"cell": cell, "live": False, "paused": False, "last_state": None,
                "can_pause": False, "can_resume": False, "can_stop": False,
                "can_resume_fail": False, "audit": [], "error": "unknown cell"}
    roots = _cell_root_pids(cell)
    live = bool(roots)
    states = [s for s in (_proc_state(p) for p in roots) if s]
    paused = bool(live and states and all(s == "T" for s in states))
    last_state, _parts, _sf = _latest_cell_state(cell)
    return {
        "cell": cell, "live": live, "paused": paused, "last_state": last_state,
        "pids": roots,
        "can_pause": live and not paused,
        "can_resume": live and paused,
        "can_stop": live,
        "can_resume_fail": (not live) and (last_state in ("FAILED", "ABORTED")),
        "audit": _read_audit(cell),
    }


def live_cells() -> Dict[str, bool]:
    """One /proc sweep → ``{cell: paused}`` for EVERY cell with a live pipeline
    process (paused=True when all its matched leaders are stopped, 'T'). Lets the
    grid render RUNNING/RESUMED/PAUSED from real liveness without a per-cell scan
    — so a resume-after-fail in progress no longer shows its stale FAILED .state."""
    if not os.path.isdir(PROJECTS_DIR):
        return {}
    bases = {os.path.join(PROJECTS_DIR, d): d
             for d in os.listdir(PROJECTS_DIR)
             if "__" in d and os.path.isdir(os.path.join(PROJECTS_DIR, d))}
    me = os.getpid()
    states: Dict[str, List[Optional[str]]] = {}
    for pid in _all_pids():
        if pid == me:
            continue
        cmd = _proc_cmdline(pid)
        if not any(tok in cmd for tok in _CELL_PROC_TOKENS):
            continue
        for base, cell in bases.items():
            if _cmd_targets_base(cmd, base):
                states.setdefault(cell, []).append(_proc_state(pid))
                break
    return {cell: (bool(s) and all(x == "T" for x in s))
            for cell, s in states.items()}


def pause_cell(cell: str) -> Dict[str, Any]:
    if not _valid_cell(cell):
        return {"ok": False, "error": "unknown cell"}
    st = cell_status(cell)
    if not st["live"]:
        return {"ok": False, "error": "cell is not running"}
    if st["paused"]:
        return {"ok": False, "error": "cell is already paused"}
    n, pids = _signal_cell_tree(cell, signal.SIGSTOP)
    if not n:
        return {"ok": False, "error": "no signalable process found"}
    _audit_cell(cell, f"PAUSE  via dashboard — SIGSTOP {n} proc(s) {pids}")
    return {"ok": True, "cell": cell, "action": "pause", "signaled": n}


def resume_cell(cell: str) -> Dict[str, Any]:
    if not _valid_cell(cell):
        return {"ok": False, "error": "unknown cell"}
    st = cell_status(cell)
    if not st["live"]:
        return {"ok": False, "error": "cell is not running"}
    n, _pids = _signal_cell_tree(cell, signal.SIGCONT)
    if not n:
        return {"ok": False, "error": "no signalable process found"}
    _audit_cell(cell, f"RESUME via dashboard — SIGCONT {n} proc(s)")
    return {"ok": True, "cell": cell, "action": "resume", "signaled": n}


def pause_toggle_cell(cell: str) -> Dict[str, Any]:
    """The single button that flips between Pause and Resume by current state."""
    if not _valid_cell(cell):
        return {"ok": False, "error": "unknown cell"}
    st = cell_status(cell)
    if not st["live"]:
        return {"ok": False, "error": "cell is not running"}
    return resume_cell(cell) if st["paused"] else pause_cell(cell)


def stop_cell(cell: str) -> Dict[str, Any]:
    if not _valid_cell(cell):
        return {"ok": False, "error": "unknown cell"}
    st = cell_status(cell)
    if not st["live"]:
        return {"ok": False, "error": "cell is not running"}
    if st["paused"]:                      # un-stop first so it can act on the TERM
        _signal_cell_tree(cell, signal.SIGCONT)
    n, pids = _signal_cell_tree(cell, signal.SIGTERM)
    if not n:
        return {"ok": False, "error": "no signalable process found"}
    _audit_cell(cell, f"STOP   via dashboard — SIGTERM {n} proc(s) {pids}")
    return {"ok": True, "cell": cell, "action": "stop", "signaled": n}


_RESUME_WRAPPER = r'''#!/usr/bin/env bash
set -uo pipefail
ROOT=@@ROOT@@
LOG=@@LOG@@
STATE=@@STATE@@
AUDIT=@@AUDIT@@
START=$(date +%s)
{
  echo "================================================================"
  echo " RESUME-AFTER-FAIL — @@CELL@@ (phases @@PHASES@@)"
  echo " Triggered from the dashboard at $(date -Is)."
  echo " Previous cell state was FAILED/ABORTED — this run supersedes it."
  echo "================================================================"
} | tee "$LOG"
RUN_INLINE=1 RUN_TAG=@@RUNTAG@@ bash "$ROOT/run_project.sh" @@PROJ@@ --profile @@PROF@@ --phases @@PHASES@@ >> "$LOG" 2>&1
RC=$?
END=$(date +%s)
ST=DONE; [ "$RC" -ne 0 ] && ST=FAILED
printf '%s|resume|%s|%s|%s|%s\n' "$ST" "$START" "$END" "$RC" "$LOG" > "$STATE"
printf '%s  RESUME-AFTER-FAIL finished rc=%s dur=%ss -> %s\n' "$(date -Is)" "$RC" "$((END-START))" "$ST" >> "$AUDIT"
'''


def resume_failed_cell(cell: str) -> Dict[str, Any]:
    """Re-launch a FAILED/ABORTED cell standalone (detached), replaying the same
    phases. The wrapper rewrites the cell ``.state`` with THIS run's clean
    duration on exit (so the failed attempt drops out of any cell-duration total)
    and records start+finish in the audit log."""
    if not _valid_cell(cell):
        return {"ok": False, "error": "unknown cell"}
    st = cell_status(cell)
    if st["live"]:
        return {"ok": False, "error": "cell is currently running — stop it first"}
    last, parts, sf = _latest_cell_state(cell)
    if last not in ("FAILED", "ABORTED"):
        return {"ok": False, "error": f"resume-after-fail only applies to a "
                f"FAILED/ABORTED cell (last state: {last or 'unknown'})"}
    proj, rep, prof = _split_cell_name(cell)
    if proj not in set(list_projects()):
        return {"ok": False, "error": f"unknown project {proj!r}"}
    if prof not in {p["name"] for p in list_profiles()}:
        return {"ok": False, "error": f"unknown profile {prof!r}"}
    phases = _cell_phases_from_state(parts)
    if not re.fullmatch(r"[0-4](?: [0-4])*", phases):
        return {"ok": False, "error": f"refusing to launch with unsafe phases {phases!r}"}
    run_dir = os.path.dirname(os.path.dirname(sf))   # …/runs/<run_id>
    ts = time.strftime("%Y%m%d_%H%M%S")
    log = os.path.join(run_dir, "logs", f"{cell}.resume_{ts}.log")
    wrapper = os.path.join(run_dir, f"resume_{cell}_{ts}.sh")
    script = (_RESUME_WRAPPER
              .replace("@@ROOT@@", shlex.quote(ROOT))
              .replace("@@LOG@@", shlex.quote(log))
              .replace("@@STATE@@", shlex.quote(sf))
              .replace("@@AUDIT@@", shlex.quote(_cell_audit_path(cell)))
              .replace("@@PROJ@@", shlex.quote(proj))
              .replace("@@PROF@@", shlex.quote(prof))
              .replace("@@RUNTAG@@", shlex.quote(rep))
              .replace("@@PHASES@@", phases)
              .replace("@@CELL@@", cell))
    try:
        os.makedirs(os.path.dirname(log), exist_ok=True)
        with open(wrapper, "w", encoding="utf-8") as f:
            f.write(script)
        os.chmod(wrapper, 0o755)
    except OSError as e:
        return {"ok": False, "error": f"could not stage wrapper: {e}"}
    try:
        proc = subprocess.Popen(
            ["bash", wrapper], cwd=ROOT, env=dict(os.environ),
            stdout=subprocess.DEVNULL, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, start_new_session=True)
    except OSError as e:
        return {"ok": False, "error": f"launch failed: {e}"}
    try:  # reflect RUNNING at once so the page flips to pause/stop controls
        with open(sf, "w", encoding="utf-8") as f:
            f.write(f"RUNNING|resume|{int(time.time())}|||{log}")
    except OSError:
        pass
    _audit_cell(cell, f"RESUME-AFTER-FAIL via dashboard — relaunch phases "
                      f"'{phases}' (pid {proc.pid}); log {log}")
    return {"ok": True, "cell": cell, "action": "resume_fail",
            "pid": proc.pid, "phases": phases, "log": log}


def start_run(projects: List[str], profiles: List[str], baseline_profile: str,
              baseline_phases: List[str], sweep_phases: List[str],
              manual_phase0_hold: bool = False, manual_phase1_gate: bool = False,
              manual_timeout: int = 1800,
              repeats: int = 1, reuse_baseline: bool = False,
              overlap_families: bool = False, repeat_parallel: bool = False,
              validation_workers: int = 0, baseline_parallel: int = 0,
              make_jobs: int = 0) -> Dict[str, Any]:
    """Launch run_all.sh detached with a validated, allowlisted selection.

    Per-phase manual review (transported as env so config.yaml is untouched):
      manual_phase0_hold  -> Phase 0 HOLDS for review (else auto-skips, the default)
      manual_phase1_gate  -> Phase 1 HOLDS for review (else drops flagged, the default)
      manual_timeout      -> seconds either gate waits before auto-continuing
    Defaults reproduce the historical unattended behavior exactly.
    """
    if run_status()["active"]:
        return {"ok": False, "error": "a run is already active — stop it first"}

    known_projects = set(list_projects())
    known_profiles = {p["name"]: p for p in list_profiles()}
    projects = [p for p in projects if p in known_projects]
    profiles = [p for p in profiles if p in known_profiles]
    if not projects:
        return {"ok": False, "error": "no valid projects selected"}
    if not profiles:
        return {"ok": False, "error": "no valid profiles selected"}
    if baseline_profile not in known_profiles:
        baseline_profile = next((p for p in profiles
                                 if known_profiles[p]["provider"] == "openai"), profiles[0])
    bphases = [p for p in baseline_phases if p in PHASES]
    sphases = [p for p in sweep_phases if p in PHASES]
    if not bphases and not sphases:
        return {"ok": False, "error": "no phases selected"}

    # Repeat the SWEEP N times over the once-built baseline (run_all.sh REPEATS).
    # Clamp to a sane range so a typo can't launch hundreds of sweeps.
    try:
        repeats = max(1, min(int(repeats), 50))
    except (TypeError, ValueError):
        repeats = 1

    openai = [p for p in profiles if known_profiles[p]["provider"] == "openai"]
    ollama = [p for p in profiles if known_profiles[p]["provider"] == "ollama"]
    run_id = time.strftime("%Y%m%d_%H%M%S")
    run_dir = os.path.join(RUNS_DIR, run_id)
    os.makedirs(run_dir, exist_ok=True)

    env = dict(os.environ)
    env.update({
        "RUN_ID": run_id,
        "PROJECTS": " ".join(projects),
        "OPENAI_PROFILES": " ".join(openai),
        "OLLAMA_PROFILES": " ".join(ollama),
        "BASELINE_PROFILE": baseline_profile,
        "BASELINE_PHASES": " ".join(bphases) or "0 1",
        "SWEEP_PHASES": " ".join(sphases) or "2 3 4",
        # Repeat the sweep N times over one baseline; optionally reuse an existing
        # baseline (skip Stage-1 rebuild). Defaults preserve single-run behavior.
        "REPEATS": str(repeats),
        "REUSE_BASELINE": "true" if reuse_baseline else "false",
        # Runtime overlap: run the OpenAI + Ollama sweeps concurrently, and/or run
        # the repeats concurrently. Default false = sequential (unchanged).
        "OVERLAP_FAMILIES": "true" if overlap_families else "false",
        "REPEAT_PARALLEL": "true" if repeat_parallel else "false",
        # Per-phase manual review (read by master_pipeline/config.py). Defaults =
        # historical behavior: Phase 0 auto-skips, Phase 1 gate off.
        "MANUAL_VERIFY_AUTO_SKIP": "false" if manual_phase0_hold else "true",
        "PHASE1_MANUAL_GATE": "true" if manual_phase1_gate else "false",
        "MANUAL_VERIFY_TIMEOUT": str(int(manual_timeout) if int(manual_timeout) > 0 else 1800),
    })
    # Intra-phase concurrency + per-build make-j cap (env-overlaid onto config).
    # Only set when > 0 so an untouched control keeps the config default
    # (sequential validation / single baseline run / make -j$(nproc)).
    for _k, _v in (("SSD_VALIDATION_WORKERS", validation_workers),
                   ("SSD_BASELINE_PARALLEL", baseline_parallel),
                   ("SSD_MAKE_JOBS", make_jobs)):
        try:
            _n = int(_v)
        except (TypeError, ValueError):
            continue
        if _n > 0:
            env[_k] = str(min(_n, 64))  # server-side sanity cap (HTML max= is client-only)
    launch_log = open(os.path.join(run_dir, "launch.log"), "ab")
    try:
        proc = subprocess.Popen(
            ["bash", os.path.join(ROOT, "run_all.sh")],
            cwd=ROOT, env=env, stdout=launch_log, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, start_new_session=True,
        )
    except OSError as e:
        return {"ok": False, "error": f"launch failed: {e}"}
    return {"ok": True, "run_id": run_id, "pid": proc.pid,
            "projects": projects, "openai": openai, "ollama": ollama,
            "baseline_profile": baseline_profile,
            "baseline_phases": bphases, "sweep_phases": sphases,
            "manual_phase0_hold": bool(manual_phase0_hold),
            "manual_phase1_gate": bool(manual_phase1_gate),
            "manual_timeout": int(manual_timeout),
            "repeats": repeats, "reuse_baseline": bool(reuse_baseline),
            "overlap_families": bool(overlap_families),
            "repeat_parallel": bool(repeat_parallel),
            "validation_workers": int(validation_workers or 0),
            "baseline_parallel": int(baseline_parallel or 0),
            "make_jobs": int(make_jobs or 0)}


# ---------------------------------------------------------------------------
# Deletion — phase → in-cell path globs (results/ & logs/ are SHARED, so target
# phase-specific files, never the whole shared dir). {project} is filled in.
# ---------------------------------------------------------------------------
PHASE_GLOBS: Dict[str, List[str]] = {
    "0": ["results/{project}_cve_poc_map.json",
          "results/{project}_cve_poc_map_filtered.json",
          "results/{project}_cve_poc_complete.csv",
          "results/.{project}_cve_poc_*.tmp",
          "results/{project}_poc_repair_report.json",
          "results/poc_repair_report.json",
          "results/{project}_syntax_validation_report.json",
          "results/syntax_validation_report.json",
          "results/{project}_manual_review_queue.json",
          "results/manual_review_queue.json",
          "results/pipeline_run_*.json",
          "exploits",
          "manual_supervision",   # whole dir: PoC files + .validation.json + reports
          "logs/{project}_cve_aggregator.log",
          "logs/run_*.log"],
    "1": ["results/{project}_image_manifest.json", "results/image_manifest.json",
          "results/results.json", "logs/orchestrator_*.log"],
    "2": ["patches", "logs/patch_generator_*.log", "logs/syntax_errors.log"],
    "3": ["validation_results", "validation_builds", "logs/validator_*.log",
          "logs/feedback_loop_*.log", "results/feedback_loop_results_*.json"],
    "4": ["reports", "logs/reporter_*.log"],
}


def _project_config_text(project: str) -> str:
    rel = _config_map().get(project, f"cve_aggregator/{project}_config.yaml")
    try:
        return open(os.path.join(ROOT, rel), encoding="utf-8").read()
    except OSError:
        return ""


def _docker_prefixes(project: str) -> Tuple[str, str]:
    """(base_prefix, cve_prefix) from the project YAML, else the defaults."""
    txt = _project_config_text(project)
    base = _grep1(r'docker_base_image_prefix:\s*["\']?([^\s"\']+)', txt) \
        or _DEFAULT_BASE_PREFIX.format(project=project)
    cve = _grep1(r'docker_cve_image_prefix:\s*["\']?([^\s"\']+)', txt) \
        or _DEFAULT_CVE_PREFIX.format(project=project)
    return base, cve


def _under(path: str, roots: List[str]) -> bool:
    rp = os.path.realpath(path)
    return any(rp == os.path.realpath(r) or rp.startswith(os.path.realpath(r) + os.sep)
               for r in roots)


# ---------------------------------------------------------------------------
# Archive one execution — a single ZIP with everything needed to preserve a
# project__profile run (results, logs, reports, metrics, patches, validation
# outputs, exploits, manual review) plus the config that produced it. The web
# layer (dashboard_server.py) streams the file to the browser and deletes it.
# ---------------------------------------------------------------------------
def _archive_manifest(cell: str, project: str, profile: str, cell_dir: str,
                      extras: List[Tuple[str, str]], ts: str) -> str:
    lines = [
        "AI-SSD pipeline execution archive",
        "=" * 40,
        f"cell:      {cell}",
        f"project:   {project}",
        f"profile:   {profile}",
        f"model(s):  {', '.join(profile_models(profile)) or 'n/a'}",
        f"archived:  {ts}",
        f"host:      {socket.gethostname()}",
        f"size:      {human_bytes(_dir_size(cell_dir))} (cell artifacts, uncompressed)",
        "",
        "Layout (relative to this archive's top folder):",
        "  results/              Phase 0-1 datasets, manifests, run records, metrics",
        "  exploits/             PoC scripts used for reproduction",
        "  patches/              generated patches per CVE / model",
        "  validation_results/   Phase 3 verdicts (PoC + SAST)",
        "  validation_builds/    Phase 3 build artifacts",
        "  reports/              Phase 4 report + charts",
        "  logs/                 per-phase logs",
        "  manual_supervision/   manual-review queue + decisions",
        "  config/               config.yaml + project Phase-0 YAML + profile .env",
        "  MANIFEST.txt          this file",
        "",
        "Bundled config files:",
    ]
    lines += [f"  {rel}" for _src, rel in extras] or ["  (none found)"]
    return "\n".join(lines) + "\n"


def build_cell_archive(cell: str) -> Dict[str, Any]:
    """Build a single ZIP archiving one ``projects/<project>__<profile>/`` run:
    the WHOLE cell tree (results, logs, reports, metrics, patches, validation
    outputs, exploits, manual review) PLUS the config that produced it (global
    ``config.yaml``, the project Phase-0 YAML, the profile ``.env``) and a
    ``MANIFEST.txt``. Returns ``{"path", "filename", "size_bytes"}``; the caller
    streams the file and removes it. Raises ``ValueError`` for an unknown cell.

    Files are compressed (``ZIP_DEFLATED``), so even an oversized artifact (e.g.
    an unbounded ``results.json``) packs down rather than ballooning the download.
    """
    if not _valid_cell(cell):
        raise ValueError("unknown cell")
    cell_dir = os.path.join(PROJECTS_DIR, cell)
    if not _under(cell_dir, [PROJECTS_DIR]):   # defense in depth on the cell name
        raise ValueError("unknown cell")
    project, _rep, profile = _split_cell_name(cell)
    ts = time.strftime("%Y%m%d_%H%M%S")
    arcroot = f"{cell}_{ts}"                    # top-level folder inside the ZIP

    # Config that produced the run (disk path -> arcname under <arcroot>/config/).
    extras: List[Tuple[str, str]] = []
    gcfg = os.path.join(ROOT, "config.yaml")
    if os.path.isfile(gcfg):
        extras.append((gcfg, "config/config.yaml"))
    prel = _config_map().get(project, os.path.join("cve_aggregator", f"{project}_config.yaml"))
    pcfg = os.path.join(ROOT, prel)
    if os.path.isfile(pcfg):
        extras.append((pcfg, f"config/{os.path.basename(pcfg)}"))
    penv = os.path.join(PROFILES_DIR, profile + ".env")
    if os.path.isfile(penv):
        extras.append((penv, f"config/{profile}.env"))

    fd, tmp = tempfile.mkstemp(prefix="ssd_archive_", suffix=".zip")
    os.close(fd)
    try:
        with zipfile.ZipFile(tmp, "w", compression=zipfile.ZIP_DEFLATED,
                             allowZip64=True) as zf:
            zf.writestr(f"{arcroot}/MANIFEST.txt",
                        _archive_manifest(cell, project, profile, cell_dir, extras, ts))
            for dp, _dn, fn in os.walk(cell_dir):
                for f in fn:
                    fp = os.path.join(dp, f)
                    if os.path.islink(fp):
                        continue               # don't follow symlinks out of the tree
                    arc = f"{arcroot}/" + os.path.relpath(fp, cell_dir)
                    try:
                        zf.write(fp, arc)
                    except OSError:
                        pass                   # file vanished mid-walk (live run) — skip
            for src, rel in extras:
                try:
                    zf.write(src, f"{arcroot}/{rel}")
                except OSError:
                    pass
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    return {"path": tmp, "filename": f"{arcroot}.zip",
            "size_bytes": os.path.getsize(tmp)}


def _docker(*args: str, timeout: int = 60) -> Tuple[int, str]:
    try:
        p = subprocess.run(["docker", *args], capture_output=True, text=True,
                           timeout=timeout)
        return p.returncode, (p.stdout or "") + (p.stderr or "")
    except FileNotFoundError:
        return 127, "docker not found"
    except subprocess.TimeoutExpired:
        return 124, "docker timed out"


def _docker_available() -> bool:
    return _docker("version", "--format", "{{.Server.Version}}", timeout=10)[0] == 0


def _images_by_reference(reference: str) -> List[Dict[str, Any]]:
    """`docker images` rows matching a reference glob, with exact byte sizes."""
    rc, out = _docker("images", "--filter", f"reference={reference}",
                      "--format", "{{.Repository}}:{{.Tag}}|{{.ID}}")
    if rc != 0:
        return []
    rows = []
    for ln in out.splitlines():
        if "|" not in ln:
            continue
        ref, iid = ln.split("|", 1)
        if ref.endswith(":<none>") or ref.startswith("<none>"):
            continue
        rows.append({"ref": ref.strip(), "id": iid.strip()})
    # exact sizes via a single inspect
    if rows:
        ids = [r["id"] for r in rows]
        rc2, out2 = _docker("image", "inspect", "--format", "{{.Id}}|{{.Size}}", *ids)
        sizes = {}
        if rc2 == 0:
            for ln in out2.splitlines():
                if "|" in ln:
                    k, v = ln.split("|", 1)
                    try:
                        sizes[k.strip()] = int(v.strip())
                    except ValueError:
                        pass
        for r in rows:
            r["size_bytes"] = sizes.get(r["id"], 0)
    return rows


def _project_cve_set(project: str) -> set:
    """CVE ids that belong to a project (from any of its cells' manifests)."""
    cves = set()
    for mf in glob.glob(os.path.join(PROJECTS_DIR, f"{project}__*", "results",
                                     "*image_manifest*.json")):
        try:
            data = json.load(open(mf))
        except (OSError, ValueError):
            continue
        for entry in (data.get("cve_images") or []):
            cve = entry.get("cve")
            if cve:
                cves.add(cve.upper())
    return cves


def _read_live(results_dir: str, phase: int) -> Tuple[Optional[Dict[str, Any]], float]:
    """Read a phase's live-progress heartbeat (``.live_progress_p{N}.json``).

    Returns ``(payload, mtime)`` or ``(None, 0.0)`` when absent/unreadable. The
    file is written by each pipeline phase after every item (see
    ``cve_aggregator/utils/live_progress.py``) so the dashboard can show counts
    that climb in real time, before the phase's final artifact exists.
    """
    path = os.path.join(results_dir, f".live_progress_p{phase}.json")
    try:
        mt = os.path.getmtime(path)
        with open(path, encoding="utf-8") as f:
            return json.load(f), mt
    except Exception:
        return None, 0.0


# get_progress() runs on every page load and poll, across every project cell.
# Some run artifacts are huge — the Phase-0 CSVs embed PoC source (tens of MB
# each) and a runaway PoC (e.g. an infinite-loop test whose container_logs are
# captured) can bloat a Phase-1 results.json to several GB. Re-reading those on
# every request froze the dashboard. We therefore (a) parse each artifact at
# most once per (mtime, size) and serve a cached summary otherwise, and (b) read
# only the small `metadata` header of results.json instead of its multi-GB body.
_ARTIFACT_CACHE: Dict[str, Tuple[Tuple[float, int], Any]] = {}
# Hard ceiling for any whole-file JSON/CSV parse fallback (bytes). Above this we
# refuse to load the full file into memory (it would freeze the dashboard / OOM).
_MAX_FULL_PARSE_BYTES = 64 * 1024 * 1024


def _cached_artifact(path: str, loader):
    """Return ``loader(path)``, memoised by the file's (mtime, size) so an
    unchanged artifact is parsed at most once. Keyed by (path, loader) because a
    single file (e.g. feedback_loop_results.json) is read by more than one loader
    that return different shapes — keying on path alone would cross them."""
    cache_key = (path, getattr(loader, "__name__", repr(loader)))
    try:
        st = os.stat(path)
        key = (st.st_mtime, st.st_size)
    except OSError:
        return loader(path)
    hit = _ARTIFACT_CACHE.get(cache_key)
    if hit is not None and hit[0] == key:
        return hit[1]
    val = loader(path)
    _ARTIFACT_CACHE[cache_key] = (key, val)
    return val


def _load_phase0_summary(path: str) -> Dict[str, int]:
    with open(path, newline="", encoding="utf-8") as f:
        return summarize_phase0_readiness(_csv.DictReader(f))


def _read_results_metadata(path: str, max_bytes: int = 65536) -> Optional[dict]:
    """Decode just the leading ``"metadata"`` object of a Phase-1 results.json
    without reading the (potentially multi-GB) rest of the file."""
    with open(path, "r", encoding="utf-8", errors="replace") as f:
        head = f.read(max_bytes)
    i = head.find('"metadata"')
    if i == -1:
        return None
    j = head.find("{", i)
    if j == -1:
        return None
    try:
        obj, _ = json.JSONDecoder().raw_decode(head[j:])
        return obj
    except ValueError:
        return None


def _load_phase1_counts(path: str) -> Dict[str, int]:
    """Phase-1 reproduction counts. Prefers the authoritative ``metadata``
    header (cheap, bounded read); falls back to counting the per-CVE records
    only for small legacy files that lack it."""
    md = _read_results_metadata(path)
    if md and "total_vulnerabilities" in md:
        total = int(md.get("total_vulnerabilities") or 0)
        reproduced = int(md.get("successful_reproductions") or 0)
        manual = int(md.get("needs_manual_revision") or 0)
        return {"total": total, "reproduced": reproduced,
                "manual_revision": manual,
                "failed": max(0, total - reproduced - manual)}
    counts = {"total": 0, "reproduced": 0, "manual_revision": 0, "failed": 0}
    try:
        if os.path.getsize(path) > _MAX_FULL_PARSE_BYTES:
            return counts  # too large to parse safely and no metadata header
    except OSError:
        return counts
    data = json.loads(open(path).read())
    for r in data.get("results", []):
        counts["total"] += 1
        if r.get("vulnerability_reproduced"):
            counts["reproduced"] += 1
        elif r.get("needs_manual_revision"):
            counts["manual_revision"] += 1
        else:
            counts["failed"] += 1
    return counts


def _load_feedback_counts(path: str) -> Dict[str, int]:
    """Counts for the Iterative Feedback Loop card, from the cell's
    ``results/feedback_loop_results_*.json`` summary.

    Also derives a PoC-only / SAST-only / both-failed three-way breakdown from
    the final validation attempt stored per result in ``validation_history``.
    The final attempt is the last entry in the history list (attempt with the
    highest attempt number); its ``poc_blocked`` / ``sast_passed`` fields give
    the definitive failure reason for non-successful patches.
    """
    d = json.loads(open(path).read())
    s = d.get("summary", {}) or {}
    ob = d.get("outcome_breakdown", {}) or {}

    # Three-way breakdown from per-result validation history
    poc_only = sast_only = both_failed = 0
    for r in (d.get("results") or []):
        # Only consider patches that ultimately did NOT succeed
        final_status = str(r.get("final_status") or "").lower().rsplit(".", 1)[-1]
        if final_status == "success":
            continue
        history = r.get("validation_history") or []
        if not history:
            continue
        # Last entry = the final attempt (highest attempt index)
        last = max(history, key=lambda h: int(h.get("attempt") or 0), default=None)
        if last is None:
            continue
        poc_blocked = bool(last.get("poc_blocked"))
        sast_passed = bool(last.get("sast_passed"))
        if not poc_blocked and not sast_passed:
            both_failed += 1
        elif not poc_blocked:
            poc_only += 1
        elif not sast_passed:
            sast_only += 1

    return {
        "total": int(s.get("total_patches_processed") or 0),
        "successful": int(s.get("successful") or 0),
        "unpatchable": int(s.get("unpatchable") or 0),
        "failed": int(s.get("failed") or 0),
        "after_retry": int(ob.get("successful_after_retry") or 0),
        "retries": int(s.get("total_retry_attempts") or 0),
        "failed_poc_only": poc_only,
        "failed_sast_only": sast_only,
        "failed_both": both_failed,
    }


def _success_from_validation(path: str) -> Dict[str, list]:
    """Phase 3 CVE sets: CVEs with a patch that both blocked the PoC and passed
    SAST (``fixed``), and all CVEs that reached validation (``all``). Returns
    lists (cacheable). Matches reporter.py's ``fixed_cves`` definition."""
    try:
        if os.path.getsize(path) > _MAX_FULL_PARSE_BYTES:
            return {"fixed_cves": [], "all_cves": []}
    except OSError:
        return {"fixed_cves": [], "all_cves": []}
    d = json.loads(open(path).read())
    fixed, allc = set(), set()
    for r in d.get("all_results", []) or []:
        cve = (r.get("cve_id") or "").upper()
        if not cve:
            continue
        allc.add(cve)
        if r.get("poc_blocked") and r.get("sast_passed"):
            fixed.add(cve)
    return {"fixed_cves": sorted(fixed), "all_cves": sorted(allc)}


def _success_from_feedback(path: str) -> Dict[str, list]:
    """Feedback-loop CVE sets: CVEs whose final_status == success after retries
    (``fixed``), and all CVEs the loop processed (``all``). The loop only handles
    patches that FAILED the initial Phase 3, so this MUST be unioned with the
    Phase 3 sets — on its own it omits first-try successes."""
    d = json.loads(open(path).read())
    fixed, allc = set(), set()
    for r in d.get("results", []) or []:
        cve = (r.get("cve_id") or "").upper()
        if not cve:
            continue
        allc.add(cve)
        if str(r.get("final_status") or "").lower().rsplit(".", 1)[-1] == "success":
            fixed.add(cve)
    return {"fixed_cves": sorted(fixed), "all_cves": sorted(allc)}


def _load_pipeline_success(cell_dir: str) -> Optional[Dict[str, int]]:
    """Unique CVEs fixed end-to-end by the full pipeline for one cell, or None if
    the cell has not produced validation results yet.

    Merges (unions) the Phase 3 validation summary with the feedback-loop final
    verdict: a CVE is fixed if it passed the initial validation OR was salvaged
    by a retry. Counting either source alone undercounts (validation misses
    retry saves; feedback misses first-try successes).

    While the feedback loop is still running (no final artifact yet), the live
    heartbeat's ``successful`` count is folded in. The loop only retries Phase-3
    failures so its fixed set is disjoint from Phase 3's — no double-counting."""
    fixed: set = set()
    allc: set = set()
    found = False
    v3 = sorted(glob.glob(os.path.join(
        cell_dir, "validation_results", "validation_summary_*.json")))
    if v3:
        found = True
        s = _cached_artifact(v3[-1], _success_from_validation)
        fixed |= set(s["fixed_cves"]); allc |= set(s["all_cves"])
    fb = sorted(glob.glob(os.path.join(
        cell_dir, "results", "feedback_loop_results_*.json")))
    if fb:
        found = True
        s = _cached_artifact(fb[-1], _success_from_feedback)
        fixed |= set(s["fixed_cves"]); allc |= set(s["all_cves"])
    if not found:
        return None
    # No final feedback artifact yet — check the live heartbeat so the banner
    # reflects in-progress retry successes without waiting for the loop to finish.
    if not fb:
        live_pfb, _ = _read_live(os.path.join(cell_dir, "results"), "fb")
        if live_pfb:
            fb_succ = int((live_pfb.get("counts") or {}).get("successful") or 0)
            if fb_succ:
                return {"fixed": len(fixed) + fb_succ, "validated": len(allc)}
    return {"fixed": len(fixed), "validated": len(allc)}


def _feedback_live_from_log(cell_dir: str) -> Optional[Dict[str, Any]]:
    """Live Feedback-Loop counts parsed from the cell run log.

    Used only when the loop is running under an orchestrator process that
    predates the fb heartbeat (so there is no ``.live_progress_pfb.json`` and no
    final results json yet) — without this the card would read "not started"
    while the loop is clearly running. Returns a heartbeat-shaped dict or None.
    """
    logs = sorted(glob.glob(os.path.join(cell_dir, "logs", "run_*.log")))
    if not logs:
        return None
    try:
        with open(logs[-1], "rb") as f:
            f.seek(0, 2)
            sz = f.tell()
            f.seek(max(0, sz - 2_000_000))  # tail is plenty; run logs stay small
            txt = f.read().decode("utf-8", "replace")
    except OSError:
        return None
    m = re.findall(r"Found (\d+) failed patches for retry", txt)
    if not m:
        return None  # the loop hasn't announced its work list yet
    total = int(m[-1])
    comp = re.findall(r"\[FEEDBACK LOOP\] Completed [^:\n]+: (\w+) \(attempts: (\d+)", txt)
    succ = sum(1 for s, _ in comp if s == "success")
    unpatch = sum(1 for s, _ in comp if s == "unpatchable")
    failed = sum(1 for s, _ in comp if s == "failed")
    retries = sum(max(0, int(a) - 1) for _, a in comp)
    proc = re.findall(r"Processing \((\d+)/\d+\)", txt)
    done = int(proc[-1]) if proc else len(comp)  # current patch index ≈ progress
    return {"done": min(done, total), "total": total, "successful": succ,
            "unpatchable": unpatch, "failed": failed, "after_retry": succ,
            "retries": retries, "running": True}


def _detect_running_phase(cell: str, cell_dir: str) -> str:
    """Best-effort label of the phase a cell is running RIGHT NOW, or "" if the
    cell is not currently running.

    Phases 0–3 expose a live-progress heartbeat (``running`` flag); the feedback
    loop and Phase 4 do not, so they are inferred from their own artifacts:
      * Feedback loop — its log is being written and not yet finalised. It also
        re-runs generation+validation internally, re-firing the p2/p3
        heartbeats, so the feedback log (not those heartbeats) is the
        authoritative signal and wins when it is at least as fresh.
      * Phase 4 — the reports/ dir is being written but the final report .md
        does not exist yet.
    Gated by the cell's RUNNING state so a finished cell shows no running phase.
    """
    if not _cell_is_running(cell):
        return ""
    res = os.path.join(cell_dir, "results")
    best_rec, best_label = -1.0, ""
    # A heartbeat with running==true marks that phase in progress. The feedback
    # loop ("fb") and Phase 4 now emit heartbeats too; "fb" is checked last so it
    # wins ties against the p2/p3 heartbeats it re-fires during retries.
    for n in (0, 1, 2, 3, 4, "fb"):
        live, mt = _read_live(res, n)
        if live and live.get("running"):
            rec = float(live.get("ts") or mt or 0.0)
            if rec >= best_rec:
                best_rec = rec
                best_label = "Feedback loop" if n == "fb" else f"Phase {n}"
    # Fallback for runs predating the fb/p4 heartbeats:
    # Feedback loop — fresh log, no final results json newer than it.
    fb_logs = glob.glob(os.path.join(cell_dir, "logs", "feedback_loop_*.log"))
    if fb_logs:
        fb_mt = max((_safe_mtime(p) for p in fb_logs), default=0.0)
        done_mt = max((_safe_mtime(p) for p in glob.glob(
            os.path.join(res, "feedback_loop_results_*.json"))), default=0.0)
        if fb_mt > done_mt and fb_mt >= best_rec - 1.0:
            best_rec, best_label = fb_mt, "Feedback loop"
    # Phase 4: reports/ being written, final report not yet produced.
    rep_dir = os.path.join(cell_dir, "reports")
    if os.path.isdir(rep_dir):
        if not glob.glob(os.path.join(rep_dir, "pipeline_report_*.md")):
            rep_mt = max((_safe_mtime(p) for p in glob.glob(
                os.path.join(rep_dir, "*"))), default=0.0)
            if rep_mt >= best_rec:
                best_rec, best_label = rep_mt, "Phase 4"
    return best_label or "…"


def _safe_mtime(path: str) -> float:
    try:
        return os.path.getmtime(path)
    except OSError:
        return 0.0


def get_progress() -> Dict[str, Any]:
    """Aggregate per-phase metrics across all project cell directories.

    Returns a dict with keys phase0..phase3, each containing counts derived
    from the JSON/CSV artifacts written by the respective pipeline phase.
    Reads are best-effort: any unreadable file is silently skipped.

    While a phase is mid-run its final artifact does not exist yet, so the
    per-cell stats are taken from the live-progress heartbeat instead (and the
    cell dict carries ``done``/``total``/``running`` for a live "15/30" display).
    The heartbeat wins whenever it is newer than the final artifact, so a fresh
    run's live counts are never masked by a previous run's stale artifact.
    """
    p0: Dict[str, Any] = {"cells": 0, "total_cves": 0, "with_poc": 0, "ready": 0,
                           "manual_pending": 0, "manual_done": 0, "not_ready": 0,
                           "by_cell": {}}
    p1: Dict[str, Any] = {"cells": 0, "total": 0, "reproduced": 0,
                           "manual_revision": 0, "failed": 0, "by_cell": {}}
    p2: Dict[str, Any] = {"cells": 0, "total_tasks": 0, "syntax_valid": 0,
                           "syntax_invalid": 0, "by_cell": {}}
    p3: Dict[str, Any] = {"cells": 0, "total": 0, "success": 0, "poc_blocked": 0,
                           "sast_passed": 0, "poc_still_works": 0, "sast_failures": 0,
                           "build_failures": 0, "execution_errors": 0, "no_baseline": 0,
                           "failed_poc_only": 0, "failed_sast_only": 0, "failed_both": 0,
                           "by_cell": {}}
    pfb: Dict[str, Any] = {"cells": 0, "total": 0, "successful": 0, "unpatchable": 0,
                            "failed": 0, "after_retry": 0, "retries": 0,
                            "failed_poc_only": 0, "failed_sast_only": 0, "failed_both": 0,
                            "by_cell": {}}
    p4: Dict[str, Any] = {"cells": 0, "reports": 0, "charts": 0, "by_cell": {}}
    # Full-pipeline outcome: unique CVEs fixed end-to-end (PoC blocked + SAST passed).
    psum: Dict[str, Any] = {"cells": 0, "fixed": 0, "validated": 0, "by_cell": {}}
    running_phase: Dict[str, str] = {}  # cell -> "Phase N" / "Feedback loop" / "Phase 4"

    for cell_dir in sorted(glob.glob(os.path.join(PROJECTS_DIR, "*"))):
        if not os.path.isdir(cell_dir):
            continue
        cell = os.path.basename(cell_dir)
        live_dir = os.path.join(cell_dir, "results")
        # final-artifact mtimes; "fb" = feedback loop, 4 = reporting
        art_mt = {0: 0.0, 1: 0.0, 2: 0.0, 3: 0.0, "fb": 0.0, 4: 0.0}

        # ---- Phase 0: *_cve_poc_complete.csv ----------------------------------
        csv_files = glob.glob(os.path.join(cell_dir, "results", "*_cve_poc_complete.csv"))
        if csv_files:
            try:
                art_mt[0] = os.path.getmtime(csv_files[0])
            except OSError:
                pass
            p0["cells"] += 1
            cs: Dict[str, Any] = {"total_cves": 0, "with_poc": 0, "ready": 0,
                                   "manual_pending": 0, "manual_done": 0,
                                   "not_ready": 0, "running": False}
            try:
                # Reconcile with Phase 1 by using the SAME first-row gating the
                # orchestrator applies (shared classifier). "ready" is the set
                # Phase 1 attempts; total == ready + manual_pending + not_ready.
                # (Earlier any-row "with_poc" logic over-counted the Phase 1
                #  input and hid flagged-but-has-PoC CVEs from manual_pending.)
                # skipped_cves is the orchestrator's in-memory manual-timeout
                # exclusion set — not persisted to the CSV, so we can't see it
                # here; the manual_review_required column covers the rest.
                # Cached by (mtime, size): these CSVs are tens of MB each.
                summary = _cached_artifact(csv_files[0], _load_phase0_summary)
                for k in ("total_cves", "with_poc", "ready",
                          "manual_pending", "manual_done", "not_ready"):
                    cs[k] = summary[k]
            except Exception:
                pass
            for k in ("total_cves", "with_poc", "ready",
                      "manual_pending", "manual_done", "not_ready"):
                p0[k] += cs[k]
            p0["by_cell"][cell] = cs

        # ---- Phase 1: results/results.json ------------------------------------
        r1_path = os.path.join(cell_dir, "results", "results.json")
        if os.path.isfile(r1_path):
            try:
                art_mt[1] = os.path.getmtime(r1_path)
            except OSError:
                pass
            p1["cells"] += 1
            cs1: Dict[str, Any] = {"total": 0, "reproduced": 0,
                                    "manual_revision": 0, "failed": 0,
                                    "done": 0, "running": False}
            try:
                # Read only the metadata header (cached by mtime,size). A
                # runaway PoC can bloat results.json to multiple GB; never load
                # the whole body just to count reproductions.
                stats = _cached_artifact(r1_path, _load_phase1_counts)
                for k in ("total", "reproduced", "manual_revision", "failed"):
                    cs1[k] = stats[k]
            except Exception:
                pass
            for k in ("total", "reproduced", "manual_revision", "failed"):
                p1[k] += cs1[k]
            cs1["done"] = cs1["total"]
            p1["by_cell"][cell] = cs1

        # ---- Phase 2: patches/pipeline_summary.json ---------------------------
        r2_path = os.path.join(cell_dir, "patches", "pipeline_summary.json")
        if os.path.isfile(r2_path):
            try:
                art_mt[2] = os.path.getmtime(r2_path)
            except OSError:
                pass
            p2["cells"] += 1
            cs2: Dict[str, Any] = {"total_tasks": 0, "syntax_valid": 0,
                                   "syntax_invalid": 0, "task_cves": 0,
                                   "funnel_reproduced": None,
                                   "skipped_no_function": None,
                                   "done": 0, "running": False}
            try:
                data = json.loads(open(r2_path).read())
                s = data.get("summary", {})
                cs2["total_tasks"] = s.get("total_tasks", 0)
                cs2["syntax_valid"] = s.get("syntax_valid", 0)
                cs2["syntax_invalid"] = (data.get("outcome_breakdown", {})
                                         .get("syntax_invalid_count", 0))
                # Distinct CVE count (the funnel hand-off unit). total_tasks counts
                # CVE×model, so for reconciling Phase 1→2 we need unique CVEs. Prefer
                # the per-CVE map; fall back to the results list, then total_tasks.
                cve_stats = data.get("cve_statistics") or {}
                if cve_stats:
                    cs2["task_cves"] = len(cve_stats)
                else:
                    cs2["task_cves"] = len({(r.get("cve_id") or "").upper()
                                            for r in (data.get("results") or [])
                                            if r.get("cve_id")}) or cs2["total_tasks"]
                # Authoritative funnel hand-off (Phase 2 records the exact reproduced
                # set it consumed + how many it dropped for no patchable function).
                # Preferred over cross-artifact inference so a partial/scoped re-run
                # can't fabricate a drop; older artifacts lack it → None → the
                # renderer falls back to inference.
                fn = data.get("funnel") or {}
                cs2["funnel_reproduced"] = fn.get("phase1_reproduced")
                cs2["skipped_no_function"] = fn.get("skipped_no_function_count")
            except Exception:
                pass
            for k in ("total_tasks", "syntax_valid", "syntax_invalid"):
                p2[k] += cs2[k]
            cs2["done"] = cs2["total_tasks"]
            p2["by_cell"][cell] = cs2

        # ---- Phase 3: validation_results/validation_summary_*.json ------------
        v3_files = sorted(glob.glob(
            os.path.join(cell_dir, "validation_results", "validation_summary_*.json")))
        if v3_files:
            try:
                art_mt[3] = os.path.getmtime(v3_files[-1])
            except OSError:
                pass
            p3["cells"] += 1
            cs3: Dict[str, Any] = {"total": 0, "success": 0, "poc_blocked": 0,
                                    "sast_passed": 0, "poc_still_works": 0,
                                    "sast_failures": 0, "build_failures": 0,
                                    "execution_errors": 0, "no_baseline": 0,
                                    "validated_cves": 0, "skipped_distinct": None,
                                    "failed_poc_only": 0, "failed_sast_only": 0,
                                    "failed_both": 0,
                                    "done": 0, "running": False}
            try:
                data = json.loads(open(v3_files[-1]).read())
                cs3["total"] = data.get("metadata", {}).get("total_validations", 0)
                # Distinct CVE count actually validated (model-agnostic hand-off
                # unit), for reconciling Phase 2→3. Prefer the per-CVE map.
                by_cve = data.get("by_cve") or {}
                cs3["validated_cves"] = len(by_cve) or len(
                    {(r.get("cve_id") or "").upper()
                     for r in (data.get("all_results") or []) if r.get("cve_id")}
                ) or cs3["total"]
                # Authoritative Phase 2→3 skip count (test-file targets / no usable
                # patch); preferred over inference, None on older artifacts.
                cs3["skipped_distinct"] = (data.get("skipped") or {}).get("distinct_cves")
                s3 = data.get("summary", {})
                fb = data.get("failure_breakdown", {})
                cs3["success"] = s3.get("successful", 0)
                cs3["poc_blocked"] = s3.get("poc_blocked", 0)
                cs3["sast_passed"] = s3.get("sast_passed", 0)
                cs3["build_failures"] = s3.get("build_failures", 0)
                cs3["poc_still_works"] = fb.get("poc_still_works", 0)
                cs3["sast_failures"] = fb.get("sast_failures", 0)
                cs3["execution_errors"] = fb.get("execution_errors", 0)
                # no_baseline = total – accounted statuses
                accounted = (cs3["success"] + cs3["poc_still_works"] +
                             cs3["sast_failures"] + cs3["build_failures"] +
                             cs3["execution_errors"])
                cs3["no_baseline"] = max(0, cs3["total"] - accounted)
                # Three-way failure breakdown from individual validation records.
                # Only attempted when the file is small enough to parse in full;
                # large runs may omit these (they show 0) to protect the dashboard.
                try:
                    fsize = os.path.getsize(v3_files[-1])
                except OSError:
                    fsize = _MAX_FULL_PARSE_BYTES + 1
                if fsize <= _MAX_FULL_PARSE_BYTES:
                    for r in (data.get("all_results") or []):
                        poc_b = bool(r.get("poc_blocked"))
                        sast_p = bool(r.get("sast_passed"))
                        if not poc_b and not sast_p:
                            cs3["failed_both"] += 1
                        elif not poc_b:
                            cs3["failed_poc_only"] += 1
                        elif not sast_p:
                            cs3["failed_sast_only"] += 1
            except Exception:
                pass
            for k in cs3:
                if k in p3 and isinstance(p3[k], int):
                    p3[k] += cs3[k]
            cs3["done"] = cs3["total"]
            p3["by_cell"][cell] = cs3

        # ---- Feedback loop: results/feedback_loop_results_*.json --------------
        fb_files = sorted(glob.glob(os.path.join(
            cell_dir, "results", "feedback_loop_results_*.json")))
        if fb_files:
            art_mt["fb"] = _safe_mtime(fb_files[-1])
            pfb["cells"] += 1
            csfb: Dict[str, Any] = {"total": 0, "successful": 0, "unpatchable": 0,
                                     "failed": 0, "after_retry": 0, "retries": 0,
                                     "failed_poc_only": 0, "failed_sast_only": 0,
                                     "failed_both": 0,
                                     "done": 0, "running": False}
            try:
                csfb.update(_cached_artifact(fb_files[-1], _load_feedback_counts))
            except Exception:
                pass
            for k in ("total", "successful", "unpatchable", "failed",
                      "after_retry", "retries",
                      "failed_poc_only", "failed_sast_only", "failed_both"):
                pfb[k] += csfb.get(k, 0)
            csfb["done"] = csfb["total"]
            pfb["by_cell"][cell] = csfb

        # ---- Phase 4: reports/pipeline_report_*.md ----------------------------
        rep_dir = os.path.join(cell_dir, "reports")
        rep_md = sorted(glob.glob(os.path.join(rep_dir, "pipeline_report_*.md")))
        if rep_md:
            art_mt[4] = _safe_mtime(rep_md[-1])
            p4["cells"] += 1
            charts = len(glob.glob(os.path.join(rep_dir, "*.png")))
            cs4: Dict[str, Any] = {"report": 1, "charts": charts,
                                    "generated": "", "running": False}
            try:
                cs4["generated"] = time.strftime(
                    "%H:%M:%S", time.localtime(os.path.getmtime(rep_md[-1])))
            except OSError:
                pass
            p4["reports"] += 1
            p4["charts"] += charts
            p4["by_cell"][cell] = cs4

        # ---- Full-pipeline outcome: unique CVEs fixed end-to-end --------------
        succ = _load_pipeline_success(cell_dir)
        if succ is not None:
            psum["cells"] += 1
            psum["fixed"] += succ["fixed"]
            psum["validated"] += succ["validated"]
            psum["by_cell"][cell] = succ

        # ---- Current running phase (for the grid column + cell banner) --------
        rp = _detect_running_phase(cell, cell_dir)
        if rp:
            running_phase[cell] = rp

        # ---- Live overlay: a fresh heartbeat supersedes a stale/absent artifact
        for phase, bucket in ((0, p0), (1, p1), (2, p2), (3, p3),
                              ("fb", pfb), (4, p4)):
            live, mt = _read_live(live_dir, phase)
            if not live or mt < art_mt[phase]:
                continue  # phase finished (artifact is newer) or no heartbeat
            counts = live.get("counts") or {}
            stats: Dict[str, Any] = dict(counts)
            stats["done"] = int(live.get("done") or 0)
            stats["total"] = int(live.get("total") or 0)
            stats["running"] = bool(live.get("running"))
            # The heartbeat only carries done/total/running (+ optional counts),
            # but each phase card reads phase-specific keys unconditionally.
            # Backfill them so a mid-run cell renders its live progress instead
            # of raising KeyError in the renderer.
            if phase == 0:
                # Phase 0's card keys differ from the discovery heartbeat; keep
                # the planned CVE total so the card renders a sane denominator.
                stats.setdefault("total_cves", stats["total"])
                for k in ("with_poc", "ready", "manual_pending",
                          "manual_done", "not_ready"):
                    stats.setdefault(k, 0)
            elif phase == 1:
                for k in ("reproduced", "manual_revision", "failed"):
                    stats.setdefault(k, 0)
            elif phase == 2:
                stats.setdefault("total_tasks", stats["total"])
                stats.setdefault("task_cves", stats["total"])
                stats.setdefault("funnel_reproduced", None)
                stats.setdefault("skipped_no_function", None)
                for k in ("syntax_valid", "syntax_invalid"):
                    stats.setdefault(k, 0)
            elif phase == 3:
                stats.setdefault("validated_cves", stats["total"])
                stats.setdefault("skipped_distinct", None)
                for k in ("success", "poc_blocked", "sast_passed",
                          "poc_still_works", "sast_failures", "build_failures",
                          "execution_errors", "no_baseline",
                          "failed_poc_only", "failed_sast_only", "failed_both"):
                    stats.setdefault(k, 0)
            elif phase == "fb":
                for k in ("successful", "unpatchable", "failed",
                          "after_retry", "retries",
                          "failed_poc_only", "failed_sast_only", "failed_both"):
                    stats.setdefault(k, 0)
            elif phase == 4:
                stats.setdefault("charts", 0)
                stats.setdefault("report", 0)
                stats.setdefault("generated", "")
            bucket["by_cell"][cell] = stats

        # ---- Fallback for a feedback loop / Phase 4 running under an OLD
        # orchestrator process (no heartbeat, no final artifact yet): derive a
        # live card so it shows progress instead of a misleading "not started".
        if running_phase.get(cell) == "Feedback loop" and cell not in pfb["by_cell"]:
            lf = _feedback_live_from_log(cell_dir)
            if lf:
                pfb["by_cell"][cell] = lf
        elif running_phase.get(cell) == "Phase 4" and cell not in p4["by_cell"]:
            p4["by_cell"][cell] = {
                "report": 0, "running": True, "done": 0, "total": 7,
                "charts": len(glob.glob(os.path.join(cell_dir, "reports", "*.png"))),
                "generated": "",
            }

    return {"phase0": p0, "phase1": p1, "phase2": p2, "phase3": p3,
            "feedback": pfb, "phase4": p4, "pipeline_success": psum,
            "running_phase": running_phase}


def plan_deletion(sel: Dict[str, Any]) -> Dict[str, Any]:
    """Compute an itemised, sized deletion preview for a selection.

    sel keys: projects[], profiles[], phases[], runs[],
              delete_project_files(bool), delete_runs(bool),
              delete_docker_phase1(bool), delete_docker_phase3(bool).
    Empty projects/profiles ⇒ "all". Empty phases ⇒ whole cell dir (files).
    """
    explicit_projects = bool(sel.get("projects"))
    projects = [p for p in sel.get("projects", []) if p in set(list_projects())] \
        or list_projects()
    all_profiles = {p["name"]: p for p in list_profiles()}
    profiles = [p for p in sel.get("profiles", []) if p in all_profiles] \
        or list(all_profiles)
    phases = [p for p in sel.get("phases", []) if p in PHASES]

    items: List[Dict[str, Any]] = []
    notes: List[str] = []
    roots = [PROJECTS_DIR, RUNS_DIR]

    # --- project working-dir files (per phase, or whole cell if no phase) ---
    if sel.get("delete_project_files"):
        for proj in projects:
            for prof in profiles:
                cell = f"{proj}__{prof}"
                cdir = os.path.join(PROJECTS_DIR, cell)
                if not os.path.isdir(cdir):
                    continue
                if not phases:
                    items.append({"kind": "cell", "label": cell, "path": cdir,
                                  "size_bytes": _dir_size(cdir)})
                    continue
                for ph in phases:
                    for g in PHASE_GLOBS[ph]:
                        for match in glob.glob(os.path.join(cdir, g.format(project=proj))):
                            if not _under(match, roots):
                                continue
                            sz = _dir_size(match) if os.path.isdir(match) else \
                                _safe_size(match)
                            items.append({"kind": f"phase{ph}", "label":
                                          f"{cell}/{os.path.relpath(match, cdir)}",
                                          "path": match, "size_bytes": sz})

    # --- run-tracking dirs ---
    if sel.get("delete_runs"):
        wanted = set(sel.get("runs", []))
        for r in list_runs():
            if wanted and r["run_id"] not in wanted:
                continue
            rdir = os.path.join(RUNS_DIR, r["run_id"])
            if _under(rdir, [RUNS_DIR]):
                items.append({"kind": "run", "label": f"runs/{r['run_id']}",
                              "path": rdir, "size_bytes": r["size_bytes"]})

    # --- docker images ---
    docker_on = _docker_available()
    if sel.get("delete_docker_phase1") and docker_on:
        for proj in projects:
            base, cve = _docker_prefixes(proj)
            for ref in (f"{base}:*", f"{cve}:*"):
                for img in _images_by_reference(ref):
                    items.append({"kind": "image1", "label": img["ref"],
                                  "ref": img["ref"], "id": img["id"],
                                  "size_bytes": img.get("size_bytes", 0)})
    if sel.get("delete_docker_phase3") and docker_on:
        explicit_profiles = bool(sel.get("profiles"))
        want_models = {_safe_model(m) for prof in profiles
                       for m in all_profiles[prof]["models"]}
        # Cell tokens for the selected (project, profile) pairs. Per-cell patched
        # tags are "<model>-<cell>" where cell = sanitized "<proj>__<prof>[__repN]"
        # (see patch_validator._docker_safe_name). Matching the <cell> — not just
        # the model — is what stops cleanup of profile A from deleting profile B's
        # images when they share or prefix a model.
        want_cells = {_safe_cell(f"{proj}__{prof}") for proj in projects for prof in profiles}
        # Project scoping for patched images (no project in the tag) needs a
        # CVE-set join from the manifests. FAIL SAFE: if the user explicitly
        # scoped to projects but we cannot resolve their CVE set, do NOT silently
        # widen to every project's patched images — skip with a note.
        proj_cves = {p: _project_cve_set(p) for p in projects}
        any_cves = set().union(*proj_cves.values()) if proj_cves else set()
        if explicit_projects and not any_cves:
            notes.append("Phase-3 image deletion skipped: no Phase-1 manifest found "
                         "for the selected project(s), so patched images cannot be "
                         "attributed to them (refusing to match all projects).")
        else:
            for img in _images_by_reference(f"{_PATCH_PREFIX}/*:latest"):
                # tag: ai-ssd-patch/<cve_lower>-<safe_model>[-<cell>]:latest
                # (the optional -<cell> suffix isolates concurrent cells/repeats;
                # see patch_validator.PatchInfo.image_name).
                tag = img["ref"].split("/", 1)[1].rsplit(":", 1)[0]
                m = re.match(r"(cve-\d{4}-\d+)-(.+)$", tag)
                if not m:
                    continue
                cve_l, safe_m = m.group(1), m.group(2)
                # Attribute by model AND cell so cleanup of one profile never
                # deletes another profile's images (they share the Docker daemon).
                if explicit_profiles and not _phase3_attributed(safe_m, want_models, want_cells):
                    continue
                if explicit_projects and cve_l.upper() not in any_cves:
                    continue
                items.append({"kind": "image3", "label": img["ref"],
                              "ref": img["ref"], "id": img["id"],
                              "size_bytes": img.get("size_bytes", 0)})

    total = sum(i["size_bytes"] for i in items)
    counts: Dict[str, int] = {}
    for i in items:
        counts[i["kind"]] = counts.get(i["kind"], 0) + 1
    if not docker_on and (sel.get("delete_docker_phase1") or sel.get("delete_docker_phase3")):
        notes.append("Docker not available — image rows were skipped.")
    return {"items": items, "total_bytes": total, "count": len(items),
            "counts": counts, "docker_available": docker_on, "notes": notes,
            "token": _selection_token(sel)}


def _safe_size(path: str) -> int:
    try:
        return os.lstat(path).st_size
    except OSError:
        return 0


def _selection_token(sel: Dict[str, Any]) -> str:
    norm = {k: sorted(v) if isinstance(v, list) else v
            for k, v in sorted(sel.items()) if k != "token" and k != "confirm"}
    return hashlib.sha256(json.dumps(norm, sort_keys=True).encode()).hexdigest()[:16]


def apply_deletion(sel: Dict[str, Any], token: str) -> Dict[str, Any]:
    """Execute a deletion after re-deriving the plan and matching its token."""
    if run_status()["active"]:
        return {"ok": False, "error": "refusing to delete while a run is active"}
    if token != _selection_token(sel):
        return {"ok": False, "error": "stale selection — re-run preview"}
    plan = plan_deletion(sel)
    results, freed = [], 0
    roots = [PROJECTS_DIR, RUNS_DIR]

    # files/dirs first (containment re-checked), then containers, then images.
    file_items = [i for i in plan["items"] if i["kind"] not in ("image1", "image3")]
    img_items = [i for i in plan["items"] if i["kind"] in ("image1", "image3")]

    for it in file_items:
        path = it["path"]
        if not _under(path, roots) or not os.path.exists(path):
            results.append({"label": it["label"], "ok": False, "error": "skipped"})
            continue
        try:
            if os.path.isdir(path) and not os.path.islink(path):
                shutil.rmtree(path)
            else:
                os.remove(path)
            freed += it["size_bytes"]
            results.append({"label": it["label"], "ok": True})
        except OSError as e:
            results.append({"label": it["label"], "ok": False, "error": str(e)})

    if img_items:
        # remove stale containers that would pin the images, then force-rmi.
        _docker_rm_containers(["patch-test-", "ai-ssd-"])
        for it in img_items:
            rc, out = _docker("rmi", "-f", it["ref"])
            ok = rc == 0
            if ok:
                freed += it["size_bytes"]
            results.append({"label": it["label"], "ok": ok,
                            "error": None if ok else out.strip()[:200]})

    ok_n = sum(1 for r in results if r["ok"])
    return {"ok": True, "deleted": ok_n, "failed": len(results) - ok_n,
            "freed_bytes": freed, "results": results}


def _docker_rm_containers(name_prefixes: List[str]) -> None:
    for pref in name_prefixes:
        rc, out = _docker("ps", "-aq", "--filter", f"name={pref}")
        ids = [x for x in out.split() if x.strip()] if rc == 0 else []
        if ids:
            _docker("rm", "-f", *ids)


# ===========================================================================
# Manual review — list / read / edit / approve / discard / retry / proceed.
#
# Every decision flows through MARKER FILES the pipeline's manual-review gates
# poll for (orchestrator._poll_manual_gate / _wait_for_phase1_manual_revision):
#   approve  -> manual_supervision/<CVE>.ok           (Phase 0: gate copies PoC+CSV)
#   discard  -> manual_supervision/<CVE>.skip         (Phase 0) /
#               manual_supervision/<CVE>.phase1-skip  (Phase 1)
#   proceed  -> manual_supervision/.phase{N}_proceed
# Markers are the safe IPC channel: a HELD gate consumes them within one poll
# tick; with no gate active they stage the decision for the next run. retry
# (Phase 1) spawns a detached single-CVE reproduction re-run via run_project.sh.
# ===========================================================================
_CVE_RE = re.compile(r"^CVE-\d{4}-\d{3,8}$", re.IGNORECASE)


def _cell_dir(cell: str) -> Optional[str]:
    """Validated absolute path to projects/<cell>/ (must already exist)."""
    if not cell or "/" in cell or "\\" in cell or ".." in cell or "__" not in cell:
        return None
    full = os.path.join(PROJECTS_DIR, cell)
    if not _under(full, [PROJECTS_DIR]) or not os.path.isdir(full):
        return None
    return full


def _valid_cve(cve: str) -> bool:
    return bool(cve and _CVE_RE.match(cve.strip()))


def _cell_is_running(cell: str) -> bool:
    """True if the latest run currently marks this cell RUNNING (gate may be held)."""
    state = os.path.join(RUNS_DIR, "latest", "cells", f"{cell}.state")
    try:
        return open(state, encoding="utf-8").read().split("|", 1)[0].strip() == "RUNNING"
    except OSError:
        return False


def _cell_csv(cell_dir: str) -> Optional[str]:
    g = glob.glob(os.path.join(cell_dir, "results", "*_cve_poc_complete.csv"))
    return g[0] if g else None


def _cell_manifest(cell_dir: str) -> Optional[str]:
    exact = os.path.join(cell_dir, "results", "image_manifest.json")
    if os.path.isfile(exact):
        return exact
    g = sorted(glob.glob(os.path.join(cell_dir, "results", "*image_manifest*.json")))
    return g[0] if g else None


def manual_review_settings() -> Dict[str, Any]:
    """Persisted manual-review defaults from config.yaml (to prefill Settings UI)."""
    txt = ""
    try:
        txt = open(os.path.join(ROOT, "config.yaml"), encoding="utf-8").read()
    except OSError:
        pass
    auto_skip, phase1_gate, timeout = True, False, 1800
    m = re.search(r"(?ms)^manual_verification:\s*\n(.*?)(?=^\S|\Z)", txt)
    blk = m.group(1) if m else ""
    a = re.search(r"auto_skip:\s*(true|false)", blk, re.I)
    if a:
        auto_skip = a.group(1).lower() == "true"
    g = re.search(r"phase1_gate:\s*(true|false)", blk, re.I)
    if g:
        phase1_gate = g.group(1).lower() == "true"
    t = re.search(r"\btimeout:\s*(\d+)", blk)
    if t:
        timeout = int(t.group(1))
    return {"phase0_hold_default": (not auto_skip),
            "phase1_gate_default": phase1_gate, "timeout_default": timeout}


def _list_dir_files(d: str) -> List[Dict[str, Any]]:
    out = []
    try:
        names = sorted(os.listdir(d))
    except OSError:
        return out
    for name in names:
        fp = os.path.join(d, name)
        if not os.path.isfile(fp):
            continue
        try:
            out.append({"name": name, "size": os.lstat(fp).st_size,
                        "marker": name.startswith(".") or name.endswith(
                            (".ok", ".skip", ".phase1-skip"))})
        except OSError:
            pass
    return out


def list_manual_items() -> Dict[str, Any]:
    """Per-cell manual-review queue: Phase-0 pending CVEs + Phase-1 flagged CVEs,
    plus the files staged in each cell's manual_supervision/ (editable)."""
    cells = []
    for c in list_cells():
        cell = c["cell"]
        cell_dir = os.path.join(PROJECTS_DIR, cell)
        sup = os.path.join(cell_dir, "manual_supervision")
        files = _list_dir_files(sup) if os.path.isdir(sup) else []

        # Phase 0 pending: flagged CSV rows with no runnable PoC (mirrors the gate).
        p0_pending: List[str] = []
        csvp = _cell_csv(cell_dir)
        if csvp:
            has_runnable, flagged = set(), set()
            try:
                with open(csvp, newline="", encoding="utf-8") as f:
                    for row in _csv.DictReader(f):
                        cve = (row.get("CVE") or "").strip()
                        if not cve:
                            continue
                        if (row.get("poc_path") or "").strip():
                            has_runnable.add(cve)
                        mr = (row.get("manual_review_required") or "").strip().lower()
                        mv = (row.get("manual_verified") or "").strip().lower()
                        if mr in ("true", "1", "yes") and mv != "done":
                            flagged.add(cve)
            except OSError:
                pass
            p0_pending = sorted(flagged - has_runnable)

        # Phase 1 flagged: manifest needs_manual_revision.
        p1_flagged: List[str] = []
        mani = _cell_manifest(cell_dir)
        if mani:
            try:
                data = json.load(open(mani, encoding="utf-8"))
                for e in (data.get("cve_images") or []):
                    cve = (e.get("cve") or "").strip()
                    if cve and e.get("needs_manual_revision"):
                        p1_flagged.append(cve)
            except (OSError, ValueError):
                pass
            p1_flagged = sorted(dict.fromkeys(p1_flagged))

        def _has(marker: str) -> bool:
            return os.path.isfile(os.path.join(sup, marker))

        if p0_pending or p1_flagged or files:
            cells.append({
                "cell": cell, "project": c["project"], "profile": c["profile"],
                "running": _cell_is_running(cell),
                "phase0_pending": p0_pending,
                "phase1_flagged": p1_flagged,
                "files": files,
                "proceed0": _has(".phase0_proceed"),
                "proceed1": _has(".phase1_proceed"),
            })
    return {"cells": cells}


def _resolve_manual_file(cell: str, name: str, *, write: bool = False) -> Optional[str]:
    """Path to a non-marker file inside the cell's manual_supervision/ (traversal-safe)."""
    cell_dir = _cell_dir(cell)
    if not cell_dir or not name or "/" in name or "\\" in name or ".." in name:
        return None
    if name.startswith("."):          # dot-markers are not user-editable via the editor
        return None
    sup = os.path.join(cell_dir, "manual_supervision")
    fp = os.path.join(sup, name)
    if not _under(fp, [sup]):
        return None
    if not write and not os.path.isfile(fp):
        return None
    return fp


def read_manual_file(cell: str, name: str) -> Dict[str, Any]:
    fp = _resolve_manual_file(cell, name)
    if not fp:
        return {"ok": False, "error": "invalid file"}
    try:
        raw = open(fp, "rb").read(512_000)
    except OSError as e:
        return {"ok": False, "error": str(e)}
    try:
        text, binary = raw.decode("utf-8"), False
    except UnicodeDecodeError:
        text, binary = "", True
    return {"ok": True, "cell": cell, "name": name,
            "size": os.path.getsize(fp), "binary": binary, "content": text}


def write_manual_file(cell: str, name: str, content: str) -> Dict[str, Any]:
    fp = _resolve_manual_file(cell, name, write=True)
    if not fp:
        return {"ok": False, "error": "invalid file"}
    if len(content) > 1_000_000:
        return {"ok": False, "error": "content too large"}
    try:
        tmp = fp + ".tmp"
        with open(tmp, "w", encoding="utf-8", newline="") as f:
            f.write(content)
        os.replace(tmp, fp)
    except OSError as e:
        return {"ok": False, "error": str(e)}
    return {"ok": True, "cell": cell, "name": name, "size": os.path.getsize(fp)}


def _write_marker(cell_dir: str, name: str, body: str = "") -> bool:
    sup = os.path.join(cell_dir, "manual_supervision")
    try:
        os.makedirs(sup, exist_ok=True)
        with open(os.path.join(sup, name), "w", encoding="utf-8") as f:
            f.write(body)
        return True
    except OSError:
        return False


def approve_manual(cell: str, cve: str) -> Dict[str, Any]:
    """Phase-0 approve: drop a ``<CVE>.ok`` marker the gate honors (copies PoC+CSV)."""
    cell_dir = _cell_dir(cell)
    if not cell_dir or not _valid_cve(cve):
        return {"ok": False, "error": "invalid cell/cve"}
    cve = cve.upper()
    if not _write_marker(cell_dir, f"{cve}.ok"):
        return {"ok": False, "error": "could not write marker"}
    return {"ok": True, "cell": cell, "cve": cve, "action": "approve",
            "held": _cell_is_running(cell)}


def discard_manual(cell: str, cve: str, phase: int = 0) -> Dict[str, Any]:
    """Discard a CVE: it stays excluded. Phase 0 -> .skip, Phase 1 -> .phase1-skip."""
    cell_dir = _cell_dir(cell)
    if not cell_dir or not _valid_cve(cve):
        return {"ok": False, "error": "invalid cell/cve"}
    cve = cve.upper()
    marker = f"{cve}.phase1-skip" if int(phase) == 1 else f"{cve}.skip"
    if not _write_marker(cell_dir, marker):
        return {"ok": False, "error": "could not write marker"}
    return {"ok": True, "cell": cell, "cve": cve, "action": "discard",
            "phase": int(phase), "held": _cell_is_running(cell)}


def proceed_gate(cell: str, phase: int = 0) -> Dict[str, Any]:
    """Continue a held gate now (skip whatever is still pending for that phase)."""
    cell_dir = _cell_dir(cell)
    if not cell_dir or int(phase) not in (0, 1):
        return {"ok": False, "error": "invalid cell/phase"}
    if not _write_marker(cell_dir, f".phase{int(phase)}_proceed"):
        return {"ok": False, "error": "could not write marker"}
    return {"ok": True, "cell": cell, "phase": int(phase), "action": "proceed",
            "held": _cell_is_running(cell)}


def retry_phase1(cell: str, cve: str) -> Dict[str, Any]:
    """Spawn a detached single-CVE Phase-1 re-run (reproduction only) for this cell.

    Reuses run_project.sh so the cell's profile env, API keys, base-dir and
    phase0-config are assembled identically. The Phase-1 gate is forced OFF in
    the child (it just refreshes the manifest and exits); a HELD parent gate then
    observes the updated flag on its next poll.
    """
    cell_dir = _cell_dir(cell)
    if not cell_dir or not _valid_cve(cve):
        return {"ok": False, "error": "invalid cell/cve"}
    proj, rep, prof = _split_cell_name(cell)
    if proj not in set(list_projects()):
        return {"ok": False, "error": "unknown project"}
    if not os.path.isfile(os.path.join(PROFILES_DIR, f"{prof}.env")):
        return {"ok": False, "error": "unknown profile"}
    cve = cve.upper()
    env = dict(os.environ)
    env.update({"RUN_INLINE": "1", "PHASE1_MANUAL_GATE": "false",
                "MANUAL_VERIFY_AUTO_SKIP": "true", "RUN_TAG": rep})
    logdir = os.path.join(cell_dir, "logs")
    try:
        os.makedirs(logdir, exist_ok=True)
        out = open(os.path.join(logdir, f"retry_phase1_{cve}.log"), "ab")
    except OSError as e:
        return {"ok": False, "error": str(e)}
    try:
        proc = subprocess.Popen(
            ["bash", os.path.join(ROOT, "run_project.sh"), proj,
             "--profile", prof, "--phases", "1", "--cve", cve],
            cwd=ROOT, env=env, stdout=out, stderr=subprocess.STDOUT,
            stdin=subprocess.DEVNULL, start_new_session=True)
    except OSError as e:
        return {"ok": False, "error": f"launch failed: {e}"}
    return {"ok": True, "cell": cell, "cve": cve, "action": "retry", "pid": proc.pid}


def manual_action(cell: str, action: str, cve: str = "", phase: int = 0) -> Dict[str, Any]:
    """Single dispatch for the dashboard POST /api/manual/action endpoint."""
    try:
        phase = int(phase)
    except (TypeError, ValueError):
        phase = 0
    if action == "approve":
        return approve_manual(cell, cve)
    if action == "discard":
        return discard_manual(cell, cve, phase)
    if action == "proceed":
        return proceed_gate(cell, phase)
    if action == "retry":
        return retry_phase1(cell, cve)
    return {"ok": False, "error": f"unknown action '{action}'"}
