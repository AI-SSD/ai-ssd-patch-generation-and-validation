#!/usr/bin/env python3
"""Live web dashboard + log viewer for a run_all.sh benchmark run.

Endpoints:
  /                  project x profile grid (each cell links to its logs)
  /cell/<cell>       one cell: orchestration log + detailed per-phase logs
  /view?f=<relpath>  view a log file (ANSI-stripped; &full=1 = whole file)
  /raw?f=<relpath>   plain-text log body (used by the in-page live updater)
  (any page + ?body=1 returns just its inner content, for the JS updater)

Pages do NOT meta-refresh. They update IN PLACE via JS, with a Live/Pause toggle.
The log view tail-follows only when you're already scrolled to the bottom, so
scrolling up to read is never interrupted; Pause freezes updates entirely.

Usage:
  python3 dashboard_server.py [run_dir] [--port 8080] [--bind 0.0.0.0]
"""
import os, sys, glob, time, re, html, json, threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs, quote, unquote

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import dashboard_control as ctl
except Exception as _e:  # keep the viewer working even if the engine fails to load
    ctl = None
    _CTL_ERR = str(_e)

HERE = os.path.dirname(os.path.abspath(__file__))
ANSI = re.compile(r"\x1b\[[0-9;?]*[ -/]*[@-~]")
HCOL = {"DONE": "#1b5e20", "FAILED": "#b71c1c", "RUNNING": "#f9a825", "PENDING": "#424242",
        "SKIPPED": "#6a1b9a", "STALE": "#8d6e63", "ABORTED": "#9e2a2b",
        "RESUMED": "#1565c0", "PAUSED": "#455a64", "HOLD": "#0d47a1"}

# Stages run_all.sh assigns ONLY to a project's once-built Stage-1 baseline cell
# (BASELINE_PROFILE, phases 0-1) — never to a sweep cell (Stage 2/3, phases 2-4),
# even when both are untagged (REPEATS==1). Used to keep the "Baseline (built
# once)" grid section from swallowing untagged sweep cells too.
_BASELINE_STAGES = ("baseline", "baseline-reused")
RUN_DIR = None        # initial arg from main(); may be None if not yet available
_RUN_DIR_ARG = None   # raw arg passed at startup (path string or None)


def _run_dir():
    """Resolve the active run directory on every request.

    Follows the ``runs/latest`` symlink each time so the grid picks up a new
    run automatically without restarting the server.
    """
    # If started with an explicit arg, prefer it (re-check because it may now exist)
    if _RUN_DIR_ARG and os.path.isdir(_RUN_DIR_ARG):
        return os.path.realpath(_RUN_DIR_ARG)
    # Fall back: newest real run dir under runs/ (excludes the ``latest`` symlink)
    candidates = sorted(
        [d for d in glob.glob(os.path.join(HERE, "runs", "*"))
         if os.path.isdir(d) and not os.path.basename(d) == "latest"],
        reverse=True,
    )
    return candidates[0] if candidates else None

STYLE = ("body{font-family:system-ui,Segoe UI,monospace;background:#111;color:#eee;margin:1.2rem}"
         "a{color:#6cf;text-decoration:none}a:hover{text-decoration:underline}"
         "table{border-collapse:collapse;width:100%}td,th{padding:.3rem .55rem;border-bottom:1px solid #333;font-size:14px;text-align:left}"
         "th{color:#9aa}small{color:#888}code{color:#9cf}"
         "pre{background:#000;padding:1rem;border:1px solid #333;overflow:auto;max-height:78vh;"
         "font-size:13px;white-space:pre-wrap;word-break:break-word}"
         ".b{display:inline-block;padding:.05rem .45rem;border-radius:3px;color:#fff;font-weight:700}"
         "#bar{margin:.4rem 0 .8rem;display:flex;gap:.8rem;align-items:center}"
         "button.tg{cursor:pointer;border:0;border-radius:4px;color:#fff;font-weight:700;padding:.3rem .9rem;font-size:14px}"
         "fieldset{border:1px solid #333;border-radius:6px;margin:.8rem 0;padding:.8rem 1rem}"
         "legend{color:#9cf;font-weight:700;padding:0 .4rem}"
         "label.ck{display:inline-block;margin:.15rem .9rem .15rem 0;font-size:13px;white-space:nowrap}"
         ".grp{margin:.3rem 0;line-height:1.8}.grp b{color:#9aa;font-weight:700;margin-right:.5rem}"
         "button.act{cursor:pointer;border:0;border-radius:4px;color:#fff;font-weight:700;padding:.35rem 1rem;font-size:14px;margin:.2rem .4rem .2rem 0}"
         "button.act:disabled{opacity:.4;cursor:not-allowed}"
         ".start{background:#1b5e20}.stop{background:#b71c1c}.pause{background:#f9a825;color:#111}.resume{background:#1565c0}.del{background:#9e2a2b}.prev{background:#37474f}"
         "select{background:#000;color:#eee;border:1px solid #333;border-radius:4px;padding:.2rem}"
         ".res{margin:.5rem 0;padding:.5rem .7rem;background:#000;border:1px solid #333;border-radius:4px;font-size:13px;max-height:40vh;overflow:auto}"
         ".mrow{margin:.25rem 0;line-height:1.9}"
         "input[type=number]{background:#000;color:#eee;border:1px solid #333;border-radius:4px;padding:.2rem}"
         "textarea{font-family:ui-monospace,monospace;font-size:13px}"
         ".ok{color:#6c6}.err{color:#f88}.warn{color:#fc6}")

# Live/Pause toggle button + a tiny hint, shared by all pages.
def toggle_bar(hint):
    return ("<div id=bar><button class=tg id=tg style='background:#b71c1c'>&#9208; Pause</button>"
            "<small>" + hint + "</small></div>")

# JS that polls a fragment URL and swaps #content (grid / cell pages).
def fragment_js(frag_url, secs):
    return ("var live=true,b=document.getElementById('tg');"
            "function setL(v){live=v;b.textContent=live?'\\u23f8 Pause':'\\u25b6 Live';"
            "b.style.background=live?'#b71c1c':'#1b5e20';if(live)tick();}"
            "function tick(){if(!live)return;fetch(" + json.dumps(frag_url) + ")"
            ".then(function(r){return r.text();}).then(function(h){"
            "document.getElementById('content').innerHTML=h;}).catch(function(){});}"
            "b.onclick=function(){setL(!live);};setInterval(tick," + str(secs * 1000) + ");")


def page(title, body, script=""):
    return ("<!doctype html><html><head><meta charset=utf-8><title>" + html.escape(title) +
            "</title><style>" + STYLE + "</style></head><body>" + body +
            (("<script>" + script + "</script>") if script else "") + "</body></html>")


def fmt_dur(s):
    s = int(s); h, m, sec = s // 3600, (s % 3600) // 60, s % 60
    return f"{h}:{m:02d}:{sec:02d}" if h else f"{m}:{sec:02d}"


_REP_RE = re.compile(r"^rep(\d+)$")


def _split_cell_name(name):
    """Split a cell name into (project, repeat_tag, profile).

    Cell names are "<proj>__<prof>" or "<proj>__<prof>__rep<K>" (run_all.sh repeat
    runs). Profiles never contain "__", so a trailing "rep<N>" segment is the
    repeat tag and everything between the project and it is the profile. Untagged
    cells (normal/baseline runs) get repeat "".
    """
    segs = name.split("__")
    proj = segs[0]
    rest = segs[1:]
    rep = ""
    if rest and _REP_RE.match(rest[-1]):
        rep = rest[-1]
        rest = rest[:-1]
    return proj, rep, "__".join(rest)


def _rep_sort_key(rep):
    """Order repeat groups: untagged ("") first, then rep1, rep2, … numerically."""
    if not rep:
        return (0, 0)
    m = _REP_RE.match(rep)
    return (1, int(m.group(1)) if m else 0)


def load_cells(run_dir):
    cells = []
    for f in sorted(glob.glob(os.path.join(run_dir, "cells", "*.state"))):
        try:
            parts = (open(f).read().strip().split("|") + [""] * 6)[:6]
        except Exception:
            continue
        name = os.path.basename(f)[:-6]
        proj, rep, prof = _split_cell_name(name)
        cells.append(dict(name=name, proj=proj, prof=prof, rep=rep, state=parts[0], stage=parts[1],
                          started=parts[2], ended=parts[3], exitc=parts[4], logf=parts[5]))
    return sorted(cells, key=lambda c: (_rep_sort_key(c["rep"]), c["proj"], c["prof"]))


def disp_state(c, complete, live=None):
    """Grid status. Liveness (/proc) overrides a stale .state: a cell that is
    actually running but whose .state still says FAILED/ABORTED (a resume-after-
    fail in progress) shows RESUMED; a live cell that is SIGSTOP'd shows PAUSED;
    otherwise a live cell is RUNNING. Falls back to the recorded .state (with the
    complete+RUNNING => STALE rule) when the cell has no live process."""
    st = c["state"]
    if live and c["name"] in live:
        if live[c["name"]]:
            return "PAUSED"
        return "RESUMED" if st in ("FAILED", "ABORTED") else "RUNNING"
    return "STALE" if (complete and st == "RUNNING") else st


def elapsed_of(c, now):
    if not c["started"]:
        return ""
    try:
        st = int(c["started"]); en = int(c["ended"]) if c["ended"] else now
        return fmt_dur(en - st)
    except Exception:
        return ""


def tail_text(path, full=False, max_bytes=400_000):
    try:
        sz = os.path.getsize(path)
        with open(path, "rb") as f:
            if not full and sz > max_bytes:
                f.seek(sz - max_bytes)
                data = (b"...[truncated; showing last %dKB - use 'full']...\n" % (max_bytes // 1000)) + f.read()
            else:
                data = f.read()
        return ANSI.sub("", data.decode("utf-8", "replace"))
    except Exception as e:
        return f"(cannot read {path}: {e})"


def safe_under(path, roots):
    rp = os.path.realpath(path)
    return any(rp == os.path.realpath(r) or rp.startswith(os.path.realpath(r) + os.sep) for r in roots)


# ---- grid ----------------------------------------------------------------
# get_progress()/live_cells() re-scan every cell's on-disk artifacts (CSV/JSON/
# heartbeats) from the ground up and can legitimately take several seconds on a
# run with many cells. The grid auto-polls every 5s (fragment_js), so without a
# cache each poll re-triggers the full scan; if a scan runs longer than the
# poll interval, requests overlap and pile up (observed: 12s -> 20s -> 53s and
# still climbing). Cache the rendered grid for a few seconds — just under the
# poll interval — so overlapping polls share one computation instead of each
# repeating it.
_GRID_CACHE_TTL = 4.0
_grid_cache_lock = threading.Lock()
_grid_cache = {"run_dir": None, "ts": 0.0, "html": None}


def grid_content(run_dir):
    with _grid_cache_lock:
        now = time.time()
        if (_grid_cache["run_dir"] == run_dir and _grid_cache["html"] is not None
                and now - _grid_cache["ts"] < _GRID_CACHE_TTL):
            return _grid_cache["html"]
        html_out = _grid_content_uncached(run_dir)
        _grid_cache.update(run_dir=run_dir, ts=time.time(), html=html_out)
        return html_out


def _grid_content_uncached(run_dir):
    if not run_dir or not os.path.isdir(run_dir):
        return "<p style='color:#aaa'>No active run directory — start a run via <a href='/control'>Run Control</a>.</p>"
    cells = load_cells(run_dir); now = int(time.time())
    complete = os.path.exists(os.path.join(run_dir, "COMPLETE"))
    try:
        prog = ctl.get_progress() if ctl else {}
    except Exception:
        prog = {}
    running_phase = prog.get("running_phase", {})
    psum = prog.get("pipeline_success", {})
    try:
        live = ctl.live_cells() if ctl else {}
    except Exception:
        live = {}
    # A cell sitting at a manual-review gate (Phase 0 hold / Phase 1 gate) is
    # alive and RUNNING per its .state file, but is doing nothing — no phase
    # heartbeat is active — while it waits on a human decision at /manual. That
    # is a real, distinct condition, not "still working" and DEFINITELY not
    # finished; surface it as its own HOLD state instead of leaving it looking
    # like ordinary RUNNING (or, once the wait times out and the gate auto-
    # resolves, DONE) with no indication anything is waiting.
    #
    # Reuse the manual_pending/manual_revision counts get_progress() already
    # computed above — NOT a second ctl.list_manual_items() scan. That call
    # re-reads every cell's (often tens-of-MB) Phase-0 CSV and Phase-1 JSON
    # from scratch on every grid refresh; on this run it alone added ~6.5s per
    # request on top of get_progress()'s own ~7s, and since the grid polls
    # every 5s the requests piled up faster than they could finish (12s, 20s,
    # 53s and climbing in one measurement). The per-cell counts below come from
    # the same cached-by-mtime artifacts get_progress() already parsed.
    hold_info = {}
    for name, s in prog.get("phase0", {}).get("by_cell", {}).items():
        if s.get("manual_pending"):
            hold_info[name] = ("Phase 1", "awaiting Phase 0 review")
    for name, s in prog.get("phase1", {}).get("by_cell", {}).items():
        if name not in hold_info and s.get("manual_revision"):
            hold_info[name] = ("Phase 2", "awaiting Phase 1 review")

    # The Ollama two-lane scheduler (run_all.sh's run_ollama_two_lane) caps how
    # many Phase-3 Docker validations run at once (OLLAMA_VALIDATE_PARALLEL);
    # a cell whose Phase-2 generation finished but whose Phase 3 hasn't started
    # yet is just waiting for a free slot in that in-process queue — nothing
    # else will happen to it until then. That queue lives in a bash array, not
    # a file, so there is no live heartbeat for it; "generation done, still
    # marked ollama-generate/ollama-validate-queued, run not COMPLETE yet" is
    # the only observable signature of it.
    _OLLAMA_QUEUE_STAGES = ("ollama-validate-queued", "ollama-generate")

    def _hold_reason(c, ds, ph):
        if ds in ("RUNNING", "RESUMED") and not ph:
            h = hold_info.get(c["name"])
            if h:
                return h
        if not complete and c["stage"] in _OLLAMA_QUEUE_STAGES and ds in ("PENDING", "DONE"):
            return ("Phase 3", "queued for a validation slot")
        return None

    counts = {}
    TABLE_HEAD = ("<table><tr><th>project</th><th>profile</th><th>stage</th><th>phase</th>"
                  "<th>state</th><th>elapsed</th><th></th></tr>")

    def _render_rows(cell_list):
        out = ""
        for c in cell_list:
            ds = disp_state(c, complete, live)
            # The pipeline phase running right now (incl. the feedback loop as its
            # own phase), distinct from the run_all.sh sweep "stage" column.
            ph = running_phase.get(c["name"], "") if ds in ("RUNNING", "RESUMED") else ""
            hold = _hold_reason(c, ds, ph)
            if hold:
                ds = "HOLD"
            counts[ds] = counts.get(ds, 0) + 1
            link = "/cell/" + quote(c["name"])
            dlink = "/api/download?cell=" + quote(c["name"])
            if hold:
                nxt_phase, reason = hold
                ph_cell = (f"<span style='color:#42a5f5;font-weight:700'>{html.escape(nxt_phase)}</span> "
                           f"<small style='color:#6ca8d8'>({html.escape(reason)})</small>")
            elif ph:
                ph_cell = f"<span style='color:#f9a825;font-weight:700'>{html.escape(ph)}</span>"
            else:
                ph_cell = "<span style='color:#555'>—</span>"
            out += (f"<tr><td>{c['proj']}</td><td><a href='{link}'>{c['prof']}</a></td>"
                    f"<td>{c['stage']}</td>"
                    f"<td>{ph_cell}</td>"
                    f"<td><span class=b style='background:{HCOL.get(ds, '#333')}'>{ds}</span></td>"
                    f"<td>{elapsed_of(c, now)}</td><td><a href='{link}'>logs &rsaquo;</a> &nbsp; "
                    f"<a href='{dlink}' title='Download all artifacts for this cell as a ZIP'>&#8681; zip</a></td></tr>")
        return out

    def _section(label, cell_list):
        return (f"<h3 style='margin:1.1rem 0 .3rem;color:#9cf;border-bottom:1px solid #333;"
                f"padding-bottom:.2rem'>{html.escape(label)} "
                f"<small style='color:#777;font-weight:400'>({len(cell_list)} cells)</small></h3>"
                + TABLE_HEAD + _render_rows(cell_list) + "</table>")

    # Group cells by repeat tag so the grid SEPARATES each repeat's sweep matrix
    # (run_all.sh REPEATS>1 names cells <proj>__<prof>__repK). Untagged cells
    # (REPEATS==1, the common case) still mix the once-built Stage-1 baseline
    # cell in with the untagged Stage-2/3 sweep cells under the SAME (empty)
    # repeat tag — split those apart by stage so "Baseline (built once)" only
    # ever holds the actual baseline profile, never the sweep.
    groups = {}
    for c in cells:
        groups.setdefault(c["rep"], []).append(c)
    untagged = groups.pop("", [])
    baseline_cells = [c for c in untagged if c["stage"] in _BASELINE_STAGES]
    sweep_cells = [c for c in untagged if c["stage"] not in _BASELINE_STAGES]
    reps = sorted((r for r in groups), key=_rep_sort_key)

    secs = []
    if baseline_cells:
        secs.append(_section("Baseline (built once)", baseline_cells))
    if sweep_cells:
        secs.append(_section("Sweep", sweep_cells))
    for r in reps:      # rep1, rep2, … each its own project×profile matrix
        secs.append(_section("Repeat " + (r[3:] or r), groups[r]))
    body = "".join(secs) if secs else "<p style='color:#666'>no cells yet</p>"

    summ = " &nbsp; ".join(f"{k}: <b>{v}</b>" for k, v in sorted(counts.items()))
    # Run-wide sum-up: unique CVEs fixed end-to-end across every cell that has
    # produced validation results (PoC blocked + SAST passed).
    fixed_total = psum.get("fixed", 0)
    sumup = ""
    if psum.get("cells"):
        sumup = (f" &nbsp;|&nbsp; <span style='color:#6c6;font-weight:700'>&#10003; "
                 f"end-to-end fixed: {fixed_total}/{psum.get('validated', 0)} CVEs</span>")
    head = (f"<p>{time.strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp; {summ}{sumup}"
            + ("  <b style=color:#6c6>COMPLETE</b>" if complete else "") + "</p>")
    return head + body


def cell_progress_html(cell: str) -> str:
    """Render per-phase stats cards for a single cell (project__profile)."""
    try:
        d = ctl.get_progress() if ctl else None
    except Exception:
        d = None
    if not d:
        return ""

    p0 = d["phase0"]; p1 = d["phase1"]; p2 = d["phase2"]; p3 = d["phase3"]
    pfb = d.get("feedback", {}); p4 = d.get("phase4", {})
    s0 = p0["by_cell"].get(cell); s1 = p1["by_cell"].get(cell)
    s2 = p2["by_cell"].get(cell); s3 = p3["by_cell"].get(cell)
    sfb = pfb.get("by_cell", {}).get(cell); s4 = p4.get("by_cell", {}).get(cell)
    ssucc = d.get("pipeline_success", {}).get("by_cell", {}).get(cell)
    running_phase = d.get("running_phase", {}).get(cell, "")

    if not any([s0, s1, s2, s3, sfb, s4]):
        return "<p style='color:#666;font-size:13px'>No progress data yet for this cell.</p>"

    def pct(num, den):
        return f" <small style='color:#777'>({num*100//den}%)</small>" if den else ""

    def row(label, value, col="#eee", warn=False):
        c = "#fc6" if warn and value else col
        return (f"<tr><td style='color:#888;font-size:12px;padding:.15rem .4rem'>{label}</td>"
                f"<td style='font-weight:700;color:{c};text-align:right;padding:.15rem .4rem'>{value}</td></tr>")

    def card(title, color, content, active=True):
        op = "1" if active else "0.4"
        return (f"<div style='flex:1;min-width:160px;background:#1a1a1a;border:1px solid #333;"
                f"border-radius:6px;padding:.6rem .9rem;opacity:{op}'>"
                f"<div style='font-weight:700;color:{color};margin-bottom:.35rem;font-size:13px'>{title}</div>"
                f"<table style='width:100%;border:none'>{content}</table></div>")

    def prog(s, noun="processed"):
        """Live progress header row shown while a phase is mid-run."""
        if not (s and s.get("running")):
            return ""
        done, total = int(s.get("done", 0)), int(s.get("total", 0))
        bar = f" {done*100//total}%" if total else ""
        return (f"<tr><td colspan=2 style='padding:.15rem .4rem'>"
                f"<span style='color:#f9a825;font-weight:700'>&#9654; running</span> "
                f"<span style='color:#9cf;font-weight:700'>{done}/{total}</span>"
                f"<small style='color:#777'>{bar} {noun}</small></td></tr>")

    # while a phase is running its title pulses amber so the live card stands out
    def title_for(name, s):
        return (name, "#f9a825") if (s and s.get("running")) else (name, "#9cf")

    # Phase 0 — during the run the live heartbeat reports commit-discovery
    # progress (a "stage" key); afterwards the CSV gives the fetched/PoC summary.
    if s0 and "stage" in s0:
        c0 = (prog(s0, "CVEs")
              + row("Stage", s0.get("stage", "—"), "#6cf")
              + row("Commits found", s0.get("commits_found", 0), "#6c6"))
        card0 = card("Phase 0 — Aggregation", "#f9a825", c0)
    elif s0:
        # "Phase-1 ready" uses the orchestrator's own first-row gating, so it
        # equals Phase 1 "Attempted" (modulo the rare no-Ubuntu-era skips). The
        # three buckets ready + manual_pending + not_ready sum to fetched.
        c0 = (row("CVEs fetched", s0["total_cves"])
              + row("With PoC", f"{s0['with_poc']}/{s0['total_cves']}{pct(s0['with_poc'], s0['total_cves'])}", "#6cf")
              + row("Phase-1 ready", f"{s0.get('ready', 0)}/{s0['total_cves']}{pct(s0.get('ready', 0), s0['total_cves'])}", "#6c6")
              + (row("Not ready (no PoC or no commit)", s0.get("not_ready", 0), "#f88") if s0.get("not_ready") else "")
              + (row("Manual pending", s0["manual_pending"], warn=True) if s0["manual_pending"] else "")
              + (row("Manual done", s0["manual_done"], "#6c6") if s0["manual_done"] else ""))
        card0 = card("Phase 0 — Aggregation", "#9cf", c0)
    else:
        card0 = card("Phase 0 — Aggregation", "#555", "<tr><td style='color:#555'>not started</td></tr>", active=False)

    # Phase 1 — "done" is the count attempted so far; reproduced/etc. are out of it
    if s1:
        d1 = s1.get("done", s1["total"])
        c1 = (prog(s1, "tested")
              + row("Attempted", f"{d1}/{s1['total']}" if s1.get("running") else s1["total"])
              + row("Reproduced ✓", f"{s1['reproduced']}/{d1}{pct(s1['reproduced'], d1)}", "#6c6")
              + (row("Manual rev ⚠", s1["manual_revision"], warn=True) if s1["manual_revision"] else "")
              + (row("Failed on PoC ✗", s1["failed"], "#f88") if s1["failed"] else ""))
        card1 = card(*title_for("Phase 1 — Reproduction", s1), c1)
    else:
        card1 = card("Phase 1 — Reproduction", "#555", "<tr><td style='color:#555'>not started</td></tr>", active=False)

    # Phase 2
    if s2:
        d2 = s2.get("done", s2["total_tasks"])
        # Funnel reconciliation: Phase 2 only generates patches for CVEs Phase 1
        # reproduced AND that carry an extractable vulnerable function. The gap to
        # Phase 1's "Reproduced" count is reproduced CVEs with no patchable
        # function (empty V_FUNCTION/F_NAME/FilePath — e.g. test-only fix commits),
        # so 26 reproduced → 24 patch tasks reads as a drop, not a lost count.
        # Explicit chain rows so the headline numbers reconcile: "Reproduced (in)"
        # == Phase 1's Reproduced, minus the no-patchable-function CVEs == "Patch
        # tasks". Prefer Phase 2's recorded funnel (immune to a Phase-1-only re-run);
        # fall back to inference for older artifacts lacking the block.
        chain2 = ""
        if s1 and not s2.get("running"):
            nofunc = s2.get("skipped_no_function")
            repro_in = s2.get("funnel_reproduced") or int(s1.get("reproduced", 0))
            if nofunc is None:
                tcves = int(s2.get("task_cves") or s2["total_tasks"])
                nofunc = max(0, int(s1.get("reproduced", 0)) - tcves)
            chain2 = (row("Reproduced (in)", repro_in, "#6cf")
                      + (row("&minus; no patchable fn", nofunc, "#fc6") if nofunc else ""))
        c2 = (prog(s2, "tasks")
              + chain2
              + row("Patch tasks", f"{d2}/{s2['total_tasks']}" if s2.get("running") else s2["total_tasks"])
              + row("Valid patch ✓", f"{s2['syntax_valid']}/{d2}{pct(s2['syntax_valid'], d2)}", "#6c6")
              + (row("Invalid (still validated)", s2["syntax_invalid"], "#f88") if s2["syntax_invalid"] else ""))
        card2 = card(*title_for("Phase 2 — Patch Gen", s2), c2)
    else:
        card2 = card("Phase 2 — Patch Gen", "#555", "<tr><td style='color:#555'>not started</td></tr>", active=False)

    # Phase 3
    if s3:
        d3 = s3.get("done", s3["total"])
        # Explicit chain rows: "Patches (in)" == Phase 2's "Patch tasks" (ALL
        # generated patches — valid AND invalid; syntax validity is not a gate),
        # minus patches whose target is a test file or that produced no usable patch
        # == "Validated". Prefer Phase 3's recorded skip count; fall back to
        # inference. Require Phase 2 settled too: while it re-runs, its live overlay
        # reports the PLANNED total and would skew the drop.
        chain3 = ""
        tcves = int(s2.get("task_cves") or s2.get("total_tasks", 0)) if s2 else 0
        if s2 and not s2.get("running") and not s3.get("running"):
            skipped = s3.get("skipped_distinct")
            if skipped is None:
                vcves = int(s3.get("validated_cves") or s3["total"])
                skipped = max(0, tcves - vcves)
            chain3 = (row("Patches (in)", tcves, "#6cf")
                      + (row("&minus; test-only / no patch", skipped, "#fc6") if skipped else ""))
        c3 = (prog(s3, "validated")
              + chain3
              + row("Validated", f"{d3}/{s3['total']}" if s3.get("running") else s3["total"])
              + row("SUCCESS ✓", f"{s3['success']}/{d3}{pct(s3['success'], d3)}", "#6c6")
              + (row("PoC still works ✗", s3["poc_still_works"], "#f88") if s3["poc_still_works"] else "")
              # Every validated patch lands in exactly one bucket; show them all so
              # success + the failure rows sum to "Validated" (execution_errors was
              # the one bucket previously hidden, leaving 23 ≠ 1+18).
              + (row("Execution error ✗", s3["execution_errors"], "#f88") if s3["execution_errors"] else "")
              + (row("SAST failed ⚠", s3["sast_failures"], warn=True) if s3["sast_failures"] else "")
              + (row("Build error ✗", s3["build_failures"], "#f88") if s3["build_failures"] else "")
              + (row("No baseline", s3["no_baseline"], "#666") if s3["no_baseline"] else "")
              # Three-way breakdown: how many patches failed on PoC only, SAST only, or both.
              # Only shown when at least one of the three counts is non-zero.
              + ((
                  (row("\u2514 PoC only ✗", s3["failed_poc_only"], "#f88") if s3.get("failed_poc_only") else "")
                  + (row("\u2514 SAST only ⚠", s3["failed_sast_only"], warn=True) if s3.get("failed_sast_only") else "")
                  + (row("\u2514 PoC + SAST ✗", s3["failed_both"], "#f88") if s3.get("failed_both") else "")
              ) if (s3.get("failed_poc_only") or s3.get("failed_sast_only") or s3.get("failed_both")) else ""))
        card3 = card(*title_for("Phase 3 — Validation", s3), c3)
    else:
        card3 = card("Phase 3 — Validation", "#555", "<tr><td style='color:#555'>not started</td></tr>", active=False)

    # Feedback Loop (self-healing) — runs between Phases 2 and 3 on failures
    if sfb:
        # The loop retries only the patches that failed Phase 3 in a retryable way
        # (PoC still works) — so its input equals Phase 3's "PoC still works" count;
        # first-try successes and execution errors are not retried. Lead row labels
        # this hand-off so the number chains from the Phase 3 card.
        in_lbl = "Failed (in)" if (s3 and not sfb.get("running")) else "Patches"
        cfb = (prog(sfb, "patches")
               + row(in_lbl, f"{sfb.get('done', sfb['total'])}/{sfb['total']}" if sfb.get("running") else sfb["total"], "#6cf")
               + row("Fixed by retry ✓", f"{sfb['after_retry']}", "#6c6")
               + row("Succeeded", f"{sfb['successful']}/{sfb['total']}{pct(sfb['successful'], sfb['total'])}", "#6c6")
               + (row("Unpatchable ✗", sfb["unpatchable"], "#f88") if sfb["unpatchable"] else "")
               + row("Retry attempts", sfb["retries"], "#6cf")
               # Three-way breakdown for ultimately-failed patches
               + ((
                   (row("\u2514 PoC only ✗", sfb["failed_poc_only"], "#f88") if sfb.get("failed_poc_only") else "")
                   + (row("\u2514 SAST only ⚠", sfb["failed_sast_only"], warn=True) if sfb.get("failed_sast_only") else "")
                   + (row("\u2514 PoC + SAST ✗", sfb["failed_both"], "#f88") if sfb.get("failed_both") else "")
               ) if (sfb.get("failed_poc_only") or sfb.get("failed_sast_only") or sfb.get("failed_both")) else ""))
        cardfb = card(*title_for("Feedback Loop — Self-Healing", sfb), cfb)
    else:
        cardfb = card("Feedback Loop — Self-Healing", "#555", "<tr><td style='color:#555'>not started</td></tr>", active=False)

    # Phase 4 — reporting (live heartbeat while generating; report+charts when done)
    if s4:
        c4 = (prog(s4, "steps")
              + (row("Report ✓", "generated", "#6c6") if s4.get("report") else "")
              + (row("Generated", s4["generated"], "#6cf") if s4.get("generated") else "")
              + row("Charts", s4.get("charts", 0), "#6cf"))
        card4 = card(*title_for("Phase 4 — Reporting", s4), c4)
    else:
        card4 = card("Phase 4 — Reporting", "#555", "<tr><td style='color:#555'>not started</td></tr>", active=False)

    ts = time.strftime("%H:%M:%S")
    banner = ""
    if running_phase:
        banner = (f"<div style='margin-bottom:.5rem;font-size:13px'>"
                  f"<span style='color:#f9a825;font-weight:700'>&#9654; running:</span> "
                  f"<span style='color:#9cf;font-weight:700'>{html.escape(running_phase)}</span></div>")
    # Full-pipeline sum-up: unique CVEs that made it end-to-end (PoC blocked + SAST passed)
    sumup = ""
    if ssucc and ssucc.get("validated"):
        fx, vd = ssucc["fixed"], ssucc["validated"]
        sumup = (f"<div style='margin-bottom:.6rem;padding:.4rem .7rem;background:#13261a;"
                 f"border:1px solid #2e5b3e;border-radius:6px;font-size:13px'>"
                 f"<span style='color:#6c6;font-weight:700'>&#10003; Full pipeline:</span> "
                 f"<span style='color:#eee;font-weight:700'>{fx}/{vd}</span> "
                 f"<span style='color:#9c9'>CVEs fixed end-to-end{pct(fx, vd)}</span> "
                 f"<small style='color:#777'>&mdash; PoC blocked + SAST passed</small></div>")
    return (banner + sumup
            + f"<div style='display:flex;gap:.6rem;flex-wrap:wrap;margin-bottom:.8rem'>"
            f"{card0}{card1}{card2}{card3}{cardfb}{card4}</div>"
            f"<small style='color:#555'>live stats · updated {ts}</small>")


def grid_page(run_dir):
    run_label = os.path.basename(run_dir.rstrip('/')) if run_dir else "no active run"
    body = (f"<h2>AI-SSD benchmark — {run_label} "
            "<small style='font-size:.55em'><a href='/control'>&#9881; run control &amp; data management</a>"
            " &nbsp;·&nbsp; <a href='/manual'>&#9998; manual review &rsaquo;</a></small></h2>"
            + toggle_bar("auto-updates in place; Pause to read/scroll freely")
            + "<div id=content>" + grid_content(run_dir) + "</div>")
    return page("AI-SSD benchmark", body, fragment_js("/?body=1", 5))


# ---- cell ----------------------------------------------------------------
def cell_content(run_dir, cell):
    orch = os.path.join(run_dir, "logs", f"{cell}.log")
    proj_logs = os.path.join(HERE, "projects", cell, "logs")
    files = []
    if os.path.isfile(orch):
        files.append(("orchestration (phase flow)", orch))
    if os.path.isdir(proj_logs):
        for p in sorted(glob.glob(os.path.join(proj_logs, "*.log")),
                        key=lambda x: os.path.getmtime(x), reverse=True):
            files.append((os.path.basename(p), p))
    items = ""
    for label, p in files:
        try:
            mt = time.strftime("%H:%M:%S", time.localtime(os.path.getmtime(p))); kb = os.path.getsize(p) // 1024
        except Exception:
            mt, kb = "?", 0
        rel = os.path.relpath(p, HERE)
        items += (f"<li><a href='/view?f={quote(rel)}'>{html.escape(label)}</a> "
                  f"<small>({kb} KB, {mt})</small></li>")
    if not items:
        items = "<li>(no logs yet — the cell may not have started)</li>"
    return ("<p><small>orchestration = phase-level flow; the per-phase files have the "
            "detailed build/LLM output.</small></p><ul>" + items + "</ul>")


_CELLCTL_BAR = (
    "<div id=cellctl class=res style='display:flex;gap:.5rem;align-items:center;flex-wrap:wrap'>"
    "<span id=cellctl_state style='font-size:13px'>&hellip;</span>"
    "<span id=cellctl_btns></span>"
    "<span id=cellctl_res style='font-size:13px'></span></div>"
    "<div id=cellctl_audit style='font-size:12px;color:#888;margin:.1rem 0 .7rem;white-space:pre-wrap'></div>")

_CELLCTL_JS = r"""
function cpost(u,b){return fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}).then(function(r){return r.json();});}
function cesc(s){return (s+'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function cellAct(action,confirmMsg){
  if(confirmMsg && !confirm(confirmMsg))return;
  var rr=document.getElementById('cellctl_res'); if(rr)rr.innerHTML=' &hellip;';
  cpost('/api/control',{action:action,cell:CELL}).then(function(r){
    if(rr)rr.innerHTML = r.ok ? ' <span class=ok>'+cesc(r.action||action)+' ok</span>'
                              : ' <span class=err>'+cesc(r.error||'failed')+'</span>';
    setTimeout(cellStatus,500);
  }).catch(function(){if(rr)rr.innerHTML=' <span class=err>request failed</span>';});
}
function cellStatus(){
  fetch('/api/cell/status?cell='+encodeURIComponent(CELL)).then(function(r){return r.json();}).then(function(s){
    var stt = s.live ? (s.paused?'paused':'running') : (s.last_state||'idle');
    var col = s.live ? (s.paused?'#fc6':'#6c6')
                     : ((s.last_state==='FAILED'||s.last_state==='ABORTED')?'#f88':'#9cf');
    var el=document.getElementById('cellctl_state');
    if(el)el.innerHTML='this cell: <b style="color:'+col+'">'+cesc(stt)+'</b>';
    var b='';
    if(s.can_pause)       b+='<button class="act pause" onclick="cellAct(\'cell_pause_toggle\')">&#9208; Pause</button>';
    if(s.can_resume)      b+='<button class="act resume" onclick="cellAct(\'cell_pause_toggle\')">&#9654; Resume</button>';
    if(s.can_stop)        b+='<button class="act stop" onclick="cellAct(\'cell_stop\',\'Stop this cell? It will be marked FAILED and can be resumed after.\')">&#9209; Stop</button>';
    if(s.can_resume_fail) b+='<button class="act start" onclick="cellAct(\'cell_resume_fail\')">&#8635; Resume run</button>';
    if(!b)b='<small style="color:#666">no actions available for the current state</small>';
    var bt=document.getElementById('cellctl_btns'); if(bt)bt.innerHTML=b;
    var au=document.getElementById('cellctl_audit');
    if(au){var lines=(s.audit||[]).slice(-4).map(cesc).join('\n');
           au.textContent = lines ? ('control log:\n'+lines) : '';}
  }).catch(function(){});
}
cellStatus();setInterval(cellStatus,4000);
"""


def cell_page(run_dir, cell):
    cell_q = quote(cell)
    stats_js = ("setInterval(function(){"
                "fetch('/api/progress?cell='+encodeURIComponent(" + json.dumps(cell) + "))"
                ".then(function(r){return r.text();})"
                ".then(function(h){var el=document.getElementById('cell-progress');if(el)el.innerHTML=h;})"
                ".catch(function(){});},4000);")
    cellctl_js = "var CELL=" + json.dumps(cell) + ";" + _CELLCTL_JS
    body = (f"<p><a href='/'>&laquo; grid</a> &nbsp;|&nbsp; <a href='/api/download?cell={cell_q}' "
            f"title='Download all artifacts for this cell as a ZIP'>&#8681; download results (ZIP)</a></p>"
            f"<h2>{html.escape(cell)}</h2>"
            + _CELLCTL_BAR
            + f"<div id=cell-progress>{cell_progress_html(cell)}</div>"
            + toggle_bar("the log list refreshes every 8s; click a log to read it")
            + "<div id=content>" + cell_content(run_dir, cell) + "</div>")
    return page(cell, body, fragment_js(f"/cell/{cell_q}?body=1", 8) + stats_js + cellctl_js)


# ---- log view ------------------------------------------------------------
def raw_text(run_dir, relpath, full):
    roots = [run_dir, os.path.join(HERE, "projects")]
    path = os.path.realpath(os.path.join(HERE, relpath))
    if not (path.endswith(".log") and safe_under(path, roots) and os.path.isfile(path)):
        return None
    return tail_text(path, full=full)


def view_page(run_dir, relpath, full):
    txt = raw_text(run_dir, relpath, full)
    if txt is None:
        return None
    base = quote(relpath)
    # Derive the owning cell so EVERY file viewable from the cell page links back
    # to it, next to the grid link. Two path shapes reach /view:
    #   projects/<cell>/logs/<file>.log     (per-phase logs)        -> cell = parts[1]
    #   runs/<run_id>/logs/<cell>.log       (orchestration/phase flow) -> cell = file stem
    parts = relpath.replace("\\", "/").split("/")
    cell_name = ""
    if len(parts) >= 2 and parts[0] == "projects":
        cell_name = parts[1]
    elif len(parts) >= 3 and parts[0] == "runs" and parts[-2] == "logs" \
            and parts[-1].endswith(".log"):
        cell_name = parts[-1][:-len(".log")]
    cell_link = ""
    if cell_name:
        cell_link = (f" &nbsp;|&nbsp; <a href='/cell/{quote(cell_name)}'>"
                     f"&laquo; {html.escape(cell_name)}</a>")
    body = (f"<p><a href='/'>&laquo; grid</a>{cell_link}</p>"
            f"<h3>{html.escape(os.path.basename(relpath))}</h3>"
            + toggle_bar("live tail; Pause to read. Scrolling up won't auto-jump you.")
            + f"<pre id=log>{html.escape(txt)}</pre>")
    js = ("const F=" + json.dumps(relpath) + ";const FULL=" + ("1" if full else "0") + ";"
          "var live=true,b=document.getElementById('tg'),pre=document.getElementById('log');"
          "function setL(v){live=v;b.textContent=live?'\\u23f8 Pause':'\\u25b6 Live';"
          "b.style.background=live?'#b71c1c':'#1b5e20';if(live)tick();}"
          "function tick(){if(!live)return;"
          "fetch('/raw?f='+encodeURIComponent(F)+(FULL=='1'?'&full=1':''))"
          ".then(function(r){return r.text();}).then(function(t){"
          "var atb=pre.scrollTop+pre.clientHeight>=pre.scrollHeight-40;"
          "if(t!==pre.textContent){pre.textContent=t;if(atb)pre.scrollTop=pre.scrollHeight;}"
          "}).catch(function(){});}"
          "b.onclick=function(){setL(!live);};pre.scrollTop=pre.scrollHeight;setInterval(tick,3000);")
    return page(os.path.basename(relpath), body, js)


# ---- control panel (start/stop/pause + delete) ---------------------------
def _ck(group, value, label, checked=False):
    c = " checked" if checked else ""
    return (f"<label class=ck><input type=checkbox data-g='{group}' "
            f"value='{html.escape(value)}'{c}> {html.escape(label)}</label>")


def control_status_html():
    if ctl is None:
        return "<span class=err>control engine unavailable</span>"
    st = ctl.run_status()
    if st["active"] and st["paused"]:
        badge = "<span class=b style='background:#f9a825;color:#111'>PAUSED</span>"
    elif st["active"]:
        badge = "<span class=b style='background:#f9a825'>RUNNING</span>"
    elif st["complete"]:
        badge = "<span class=b style='background:#1b5e20'>IDLE (last run COMPLETE)</span>"
    else:
        badge = "<span class=b style='background:#424242'>IDLE</span>"
    rid = html.escape(st["run_id"] or "—")
    pg = st["pgid"] or "—"
    return f"{badge} &nbsp; run: <code>{rid}</code> &nbsp; pgid: <code>{pg}</code>"


def control_content():
    if ctl is None:
        return f"<p class=err>control engine failed to load: {html.escape(globals().get('_CTL_ERR',''))}</p>"
    projects = ctl.list_projects()
    profiles = ctl.list_profiles()
    runs = ctl.list_runs()
    openai = [p for p in profiles if p["provider"] == "openai"]
    ollama = [p for p in profiles if p["provider"] == "ollama"]

    def prof_label(p):
        ms = ", ".join(p["models"][:4]) or "?"
        return f"{p['name']}  [{p['provider']}: {ms}]"

    # ---- Start form ----
    s_proj = "".join(_ck("s_projects", p, p) for p in projects)
    s_prof = ("<div class=grp><b>OpenAI</b>"
              + "".join(_ck("s_profiles", p["name"], prof_label(p)) for p in openai) + "</div>"
              + "<div class=grp><b>Ollama</b>"
              + "".join(_ck("s_profiles", p["name"], prof_label(p)) for p in ollama) + "</div>")
    s_phase = "".join(_ck("s_phases", ph, f"Phase {ph}", checked=True) for ph in ctl.PHASES)
    base_opts = "".join(
        f"<option value='{html.escape(p['name'])}'"
        + (" selected" if p["name"] == "openai-fast" else "")
        + f">{html.escape(p['name'])}</option>" for p in profiles)

    # Per-phase manual-review settings (prefilled from config.yaml defaults).
    try:
        mset = ctl.manual_review_settings()
    except Exception:
        mset = {"phase0_hold_default": False, "phase1_gate_default": False, "timeout_default": 1800}
    m0c = " checked" if mset.get("phase0_hold_default") else ""
    m1c = " checked" if mset.get("phase1_gate_default") else ""
    mt = int(mset.get("timeout_default") or 1800)
    manual_grp = (
        "<div class=grp><b>Manual review</b> "
        f"<label class=ck><input type=checkbox id=s_m0{m0c}> Hold on Phase&nbsp;0 "
        "<small>(else auto-skip)</small></label> "
        f"<label class=ck><input type=checkbox id=s_m1{m1c}> Hold on Phase&nbsp;1 "
        "<small>(else drop flagged)</small></label> "
        f"&nbsp; timeout <input type=number id=s_mtimeout value='{mt}' min=60 step=30 "
        "style='width:6.5rem'> s"
        " &nbsp;<small>Held phases pause and wait for your "
        "<a href='/manual'>/manual</a> decisions, then auto-continue on timeout. "
        "Defaults = unattended (Phase&nbsp;0 skip, Phase&nbsp;1 drop).</small></div>")

    # Repeat the sweep N times over one baseline (run-to-run variance), and/or
    # reuse an existing baseline instead of rebuilding Phase 0/1.
    repeat_grp = (
        "<div class=grp><b>Repeats</b> &nbsp; "
        "<input type=number id=s_repeats value='1' min=1 max=50 step=1 style='width:5rem'> &times; sweep "
        "<small>(repeat Phase&nbsp;2–4 over the SAME baseline for run-to-run variance; "
        "each repeat in its own dir <code>…__repN</code>)</small> &nbsp; "
        "<label class=ck><input type=checkbox id=s_reuse> Reuse existing baseline "
        "<small>(skip the Phase&nbsp;0–1 build when a baseline already exists)</small></label>"
        "<br><b>Runtime</b> &nbsp; "
        "<label class=ck><input type=checkbox id=s_overlap> Overlap OpenAI + Ollama sweeps "
        "<small>(keeps the remote GPU busy during the OpenAI sweep)</small></label> &nbsp; "
        "<label class=ck><input type=checkbox id=s_reppar> Run repeats in parallel "
        "<small>(independent repeats concurrently)</small></label> "
        "<small>— with either on, keep <code>MAX_PARALLEL</code> / <code>OLLAMA_VALIDATE_PARALLEL</code> "
        "modest (builds are <code>make -j$(nproc)</code>).</small>"
        "<br><b>Intra-phase concurrency</b> &nbsp; "
        "Phase-3 workers <input type=number id=s_vworkers value='0' min=0 max=16 step=1 style='width:4rem'> &nbsp; "
        "Phase-1 baseline parallel <input type=number id=s_bparallel value='0' min=0 max=8 step=1 style='width:4rem'> &nbsp; "
        "make&nbsp;-j cap <input type=number id=s_mjobs value='0' min=0 max=64 step=1 style='width:4rem'> "
        "<small>(0 = config default; set the make-j cap so workers × cap &asymp; cores)</small></div>")

    start_fs = (
        "<fieldset><legend>Start a run</legend>"
        "<div class=grp><b>Projects</b>" + (s_proj or "<i>none</i>") + "</div>"
        "<div class=grp><b>Profiles (AI families)</b></div>" + s_prof +
        "<div class=grp><b>Phases</b>" + s_phase +
        " &nbsp; <small>0–1 build baselines (once, via the baseline profile); 2–4 sweep every profile</small></div>"
        "<div class=grp><b>Baseline profile</b> <select id=s_baseline>" + base_opts + "</select></div>"
        + repeat_grp + manual_grp +
        "<button class='act start' onclick='doStart()'>&#9654; Start run</button>"
        "<span id=startres></span></fieldset>")

    # ---- live control buttons ----
    ctrl_fs = (
        "<fieldset><legend>Control the live run</legend>"
        "<button class='act stop' onclick=\"doSig('stop')\">&#9632; Stop (SIGTERM)</button>"
        "<button class='act pause' onclick=\"doSig('pause')\">&#9208; Pause</button>"
        "<button class='act resume' onclick=\"doSig('resume')\">&#9654; Resume</button>"
        "<span id=sigres></span>"
        "<p><small>Pause is best-effort: it freezes the orchestrator/LLM/Python side; a Docker "
        "build or container already in flight runs to completion, then the run halts before the "
        "next step. Stop aborts cells cleanly via run_all.sh's trap.</small></p></fieldset>")

    # ---- Delete panel ----
    d_proj = "".join(_ck("d_projects", p, p) for p in projects)
    d_prof = "".join(_ck("d_profiles", p["name"], p["name"]) for p in profiles)
    d_phase = "".join(_ck("d_phases", ph, f"Phase {ph}") for ph in ctl.PHASES)
    d_runs = "".join(
        _ck("d_runs", r["run_id"],
            f"{r['run_id']} ({'complete' if r['complete'] else 'partial'}, {ctl.human_bytes(r['size_bytes'])})")
        for r in runs) or "<i>no runs</i>"
    del_fs = (
        "<fieldset><legend>Delete data</legend>"
        "<div class=grp><b>Scope — projects</b> <small>(none = all)</small>" + (d_proj or "<i>none</i>") + "</div>"
        "<div class=grp><b>Scope — profiles</b> <small>(none = all)</small>" + (d_prof or "<i>none</i>") + "</div>"
        "<div class=grp><b>What to delete</b></div>"
        "<div class=grp><label class=ck><input type=checkbox id=d_files> project working files</label>"
        " &nbsp; phases: " + d_phase + " <small>(no phase = whole project dir)</small></div>"
        "<div class=grp><label class=ck><input type=checkbox id=d_runsflag> run-tracking dirs</label> "
        "<small>(pick runs below; none = all)</small><br>" + d_runs + "</div>"
        "<div class=grp><label class=ck><input type=checkbox id=d_img1> Docker images — Phase 1 base/CVE "
        "(by project)</label></div>"
        "<div class=grp><label class=ck><input type=checkbox id=d_img3> Docker images — Phase 3 patched "
        "(by project &cap; profile)</label></div>"
        "<button class='act prev' onclick='doPreview()'>&#128269; Preview</button>"
        "<button class='act del' id=delbtn onclick='doDelete()' disabled>&#128465; Delete previewed</button>"
        "<div id=delpreview></div><div id=delres></div>"
        "<p><small>Deletion is blocked while a run is active. Docker images are global to the daemon; "
        "Phase-1 images are scoped by project repo-prefix, Phase-3 patched images by CVE-set &cap; model. "
        "Preview first — the Delete button stays disabled until you do.</small></p></fieldset>")

    return ("<div id=ctlstatus class=res>" + control_status_html() + "</div>"
            + start_fs + ctrl_fs + del_fs)


_CONTROL_JS = r"""
function vals(g){return Array.from(document.querySelectorAll("[data-g='"+g+"']:checked")).map(function(e){return e.value;});}
function post(u,b){return fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}).then(function(r){return r.json();});}
function esc(s){return (s+'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
function refreshStatus(){fetch('/api/status').then(function(r){return r.json();}).then(function(s){
  var el=document.getElementById('ctlstatus'); if(el&&s.html)el.innerHTML=s.html;
  var dis=!!(s.active); ['delbtn'].forEach(function(id){var b=document.getElementById(id); if(b&&dis){b.disabled=true;}});
}).catch(function(){});}
function doStart(){
  var b={action:'start',projects:vals('s_projects'),profiles:vals('s_profiles'),
    baseline_profile:document.getElementById('s_baseline').value,phases:vals('s_phases'),
    manual_phase0_hold:document.getElementById('s_m0').checked,
    manual_phase1_gate:document.getElementById('s_m1').checked,
    manual_timeout:parseInt(document.getElementById('s_mtimeout').value||'1800',10),
    repeats:parseInt(document.getElementById('s_repeats').value||'1',10),
    reuse_baseline:document.getElementById('s_reuse').checked,
    overlap_families:document.getElementById('s_overlap').checked,
    repeat_parallel:document.getElementById('s_reppar').checked,
    validation_workers:parseInt(document.getElementById('s_vworkers').value||'0',10),
    baseline_parallel:parseInt(document.getElementById('s_bparallel').value||'0',10),
    make_jobs:parseInt(document.getElementById('s_mjobs').value||'0',10)};
  document.getElementById('startres').innerHTML=' …starting…';
  post('/api/control',b).then(function(r){
    document.getElementById('startres').innerHTML = r.ok
      ? " <span class=ok>started run "+esc(r.run_id)+" — projects ["+esc((r.projects||[]).join(', '))+"]</span>"
      : " <span class=err>"+esc(r.error||'failed')+"</span>";
    refreshStatus();});
}
function doSig(action){
  document.getElementById('sigres').innerHTML=' …';
  post('/api/control',{action:action}).then(function(r){
    document.getElementById('sigres').innerHTML = r.ok
      ? " <span class=ok>"+esc(action)+" sent (pgid "+esc(r.pgid)+")</span>"
      : " <span class=err>"+esc(r.error||'failed')+"</span>";
    setTimeout(refreshStatus,400);});
}
function delSel(){return {projects:vals('d_projects'),profiles:vals('d_profiles'),
  phases:vals('d_phases'),runs:vals('d_runs'),
  delete_project_files:document.getElementById('d_files').checked,
  delete_runs:document.getElementById('d_runsflag').checked,
  delete_docker_phase1:document.getElementById('d_img1').checked,
  delete_docker_phase3:document.getElementById('d_img3').checked};}
var DTOKEN=null,DCOUNT=0,DBYTES=0;
function doPreview(){
  document.getElementById('delpreview').innerHTML='<div class=res>…computing…</div>';
  document.getElementById('delres').innerHTML='';
  post('/api/delete/preview',delSel()).then(function(p){
    if(p.error){document.getElementById('delpreview').innerHTML='<div class=res err>'+esc(p.error)+'</div>';return;}
    DTOKEN=p.token;DCOUNT=p.count;DBYTES=p.total_bytes;
    var rows=(p.items||[]).map(function(i){return '<div>['+esc(i.kind)+'] '+esc(i.label)+' <small>'+esc(i.size_h)+'</small></div>';}).join('');
    var more=p.truncated?('<div class=warn>… and '+esc(p.count-(p.items||[]).length)+' more</div>'):'';
    var notes=(p.notes||[]).map(function(n){return '<div class=warn>⚠ '+esc(n)+'</div>';}).join('');
    document.getElementById('delpreview').innerHTML='<div class=res><b>'+esc(p.count)+' item(s), '+esc(p.total_h)+'</b>'+notes+'<hr>'+rows+more+'</div>';
    document.getElementById('delbtn').disabled = (p.count===0);
  });
}
function doDelete(){
  if(!DTOKEN||DCOUNT===0)return;
  if(!confirm('Delete '+DCOUNT+' item(s) ('+(DBYTES/1073741824).toFixed(2)+' GB)? This cannot be undone.'))return;
  var b=delSel(); b.token=DTOKEN;
  document.getElementById('delres').innerHTML='<div class=res>…deleting…</div>';
  document.getElementById('delbtn').disabled=true;
  post('/api/delete/apply',b).then(function(r){
    if(r.error){document.getElementById('delres').innerHTML='<div class=res err>'+esc(r.error)+'</div>';return;}
    var fails=(r.results||[]).filter(function(x){return !x.ok;}).map(function(x){return '<div class=err>✗ '+esc(x.label)+': '+esc(x.error||'')+'</div>';}).join('');
    document.getElementById('delres').innerHTML='<div class=res><span class=ok>✓ deleted '+esc(r.deleted)+', freed ~'+(r.freed_bytes/1073741824).toFixed(2)+' GB</span>'
      +(r.failed?(' <span class=err>('+esc(r.failed)+' failed)</span>'+fails):'')+'</div>';
    DTOKEN=null;
  });
}
setInterval(refreshStatus,5000);
"""


def control_page():
    body = ("<p><a href='/'>&laquo; grid</a> &nbsp;·&nbsp; <a href='/manual'>manual review &raquo;</a></p>"
            "<h2>Run control &amp; data management</h2>"
            + "<div id=content>" + control_content() + "</div>")
    return page("AI-SSD control", body, _CONTROL_JS)


# ---- manual review -------------------------------------------------------
def manual_content():
    """The /manual fragment (?body=1): per-cell review queue. Replaces #content
    on refresh; the editor and result panes live in the page shell (persistent)."""
    if ctl is None:
        return "<p class=err>control engine unavailable</p>"
    cells = ctl.list_manual_items().get("cells", [])
    if not cells:
        return ("<div class=res>No manual-review items. Phase-0 PoCs that fail "
                "auto-repair and Phase-1 un-reproducible CVEs appear here while a held "
                "run waits (and stay listed afterwards so you can stage decisions for "
                "the next run).</div>")
    out = []
    for c in cells:
        ce = html.escape(c["cell"])
        badge = (" <span class=b style='background:#f9a825;color:#111'>HELD/RUNNING</span>"
                 if c["running"] else " <span class=b style='background:#424242'>idle</span>")
        sec = ["<fieldset><legend>" + html.escape(c["project"]) + " &middot; "
               + html.escape(c["profile"]) + badge + "</legend>"]
        if c["phase0_pending"]:
            sec.append("<div class=grp><b>Phase 0 — pending</b> "
                       "<small>(no runnable PoC)</small></div>")
            for cve in c["phase0_pending"]:
                cy = html.escape(cve)
                sec.append("<div class=mrow><code>" + cy + "</code> "
                    "<button class='act start' onclick=\"mAct('" + ce + "','approve','" + cy + "',0)\">Approve</button>"
                    "<button class='act del' onclick=\"mAct('" + ce + "','discard','" + cy + "',0)\">Discard</button>"
                    "</div>")
            sec.append("<button class='act prev' onclick=\"mAct('" + ce + "','proceed','',0)\">"
                       "&#9197; Proceed Phase 0 (skip remaining)</button>")
        if c["phase1_flagged"]:
            sec.append("<div class=grp><b>Phase 1 — flagged</b> "
                       "<small>(un-reproducible)</small></div>")
            for cve in c["phase1_flagged"]:
                cy = html.escape(cve)
                sec.append("<div class=mrow><code>" + cy + "</code> "
                    "<button class='act resume' onclick=\"mAct('" + ce + "','retry','" + cy + "',1)\">Retry repro</button>"
                    "<button class='act del' onclick=\"mAct('" + ce + "','discard','" + cy + "',1)\">Discard</button>"
                    "</div>")
            sec.append("<button class='act prev' onclick=\"mAct('" + ce + "','proceed','',1)\">"
                       "&#9197; Proceed Phase 1 (continue)</button>")
        editable = [f for f in c["files"] if not f["marker"]]
        markers = [f for f in c["files"] if f["marker"]]
        if editable:
            sec.append("<div class=grp><b>Files</b> "
                       "<small>(staged PoCs / reports — click to edit)</small></div>")
            for f in editable:
                nm = html.escape(f["name"])
                sec.append("<div class=mrow>&#128196; "
                    "<a href='#' onclick=\"mEdit('" + ce + "','" + nm + "');return false;\">" + nm + "</a> "
                    "<small>" + str(f["size"]) + " B</small></div>")
        if markers:
            sec.append("<div class=grp><small>pending markers: "
                       + ", ".join("<code>" + html.escape(f["name"]) + "</code>" for f in markers)
                       + "</small></div>")
        sec.append("</fieldset>")
        out.append("".join(sec))
    return "<div id=mlist>" + "".join(out) + "</div>"


_MANUAL_JS = (
    "function esc(s){return (s+'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}"
    "function mPost(u,b){return fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},"
    "body:JSON.stringify(b)}).then(function(r){return r.json();});}"
    "function mForce(){fetch('/manual?body=1').then(function(r){return r.text();})"
    ".then(function(h){document.getElementById('content').innerHTML=h;}).catch(function(){});}"
    "function mShow(msg,cls){var e=document.getElementById('mres');e.style.display='block';"
    "e.className='res '+(cls||'');e.innerHTML=msg;}"
    "function mAct(cell,action,cve,phase){"
    "if(action==='discard'&&!confirm('Discard '+(cve||'')+'? It stays excluded from this run.'))return;"
    "if(action==='proceed'&&!confirm('Proceed phase '+phase+' now? Anything still pending is skipped.'))return;"
    "mPost('/api/manual/action',{cell:cell,action:action,cve:cve,phase:phase}).then(function(r){"
    "mShow(r.ok?('<span class=ok>'+esc(action)+' '+esc(cve||('phase '+phase))+(r.held?' — applied to the held run':"
    "(r.pid?' — re-run launched (pid '+esc(r.pid)+')':' — staged for the next run'))+'</span>')"
    ":('<span class=err>'+esc(r.error||'failed')+'</span>'),'');setTimeout(mForce,700);});}"
    "function mEdit(cell,name){"
    "fetch('/api/manual/file?cell='+encodeURIComponent(cell)+'&name='+encodeURIComponent(name))"
    ".then(function(r){return r.json();}).then(function(r){var e=document.getElementById('meditor');"
    "if(!r.ok){e.innerHTML='<div class=res err>'+esc(r.error||'cannot read')+'</div>';return;}"
    "if(r.binary){e.innerHTML='<div class=res warn>binary file — not editable here</div>';return;}"
    "e.innerHTML='<fieldset><legend>edit '+esc(name)+' <small>('+esc(cell)+')</small></legend>'"
    "+'<textarea id=medit style=\"width:100%;height:42vh;background:#000;color:#eee;border:1px solid #333\">'"
    "+esc(r.content)+'</textarea><div><button class=\"act start\" onclick=\"mSave(\\''+esc(cell)+'\\',\\''+esc(name)+'\\')\">Save</button>'"
    "+'<button class=\"act prev\" onclick=\"document.getElementById(\\'meditor\\').innerHTML=\\'\\'\">Close</button></div></fieldset>';"
    "window.scrollTo(0,document.body.scrollHeight);});}"
    "function mSave(cell,name){var c=document.getElementById('medit').value;"
    "mPost('/api/manual/file',{cell:cell,name:name,content:c}).then(function(r){"
    "mShow(r.ok?('<span class=ok>saved '+esc(name)+' ('+esc(r.size)+' B)</span>')"
    ":('<span class=err>'+esc(r.error||'failed')+'</span>'),'');});}"
) + fragment_js('/manual?body=1', 10)


def manual_page():
    body = ("<p><a href='/'>&laquo; grid</a> &nbsp;·&nbsp; <a href='/control'>control</a></p>"
            "<h2>Manual review</h2>"
            + toggle_bar("approve / discard / retry / proceed — a decision reaches a "
                         "held run within one poll tick; otherwise it's staged for the next run")
            + "<div id=content>" + manual_content() + "</div>"
            + "<div id=meditor></div>"
            + "<div id=mres class=res style='display:none'></div>")
    return page("AI-SSD manual review", body, _MANUAL_JS)


class H(BaseHTTPRequestHandler):
    def _send(self, body, code=200, ctype="text/html; charset=utf-8"):
        data = body.encode("utf-8", "replace")
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        try:
            self.wfile.write(data)
        except BrokenPipeError:
            pass

    def _send_json(self, obj, code=200):
        self._send(json.dumps(obj), code, ctype="application/json; charset=utf-8")

    def _send_file(self, path, filename, ctype="application/zip"):
        """Stream a file as an attachment download (chunked — never read whole into RAM)."""
        try:
            size = os.path.getsize(path)
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(size))
            self.send_header("Content-Disposition",
                             'attachment; filename="%s"' % filename.replace('"', ""))
            self.end_headers()
            with open(path, "rb") as fh:
                while True:
                    chunk = fh.read(256 * 1024)
                    if not chunk:
                        break
                    self.wfile.write(chunk)
        except BrokenPipeError:
            pass

    def _is_local(self):
        # Mutating endpoints are reachable only from localhost — i.e. through the
        # auth-terminating nginx reverse proxy on the same host. A direct request
        # to the app port from the network can READ (GET) but never mutate.
        return self.client_address[0] in ("127.0.0.1", "::1", "::ffff:127.0.0.1")

    def _same_origin(self):
        # CSRF defense: a cross-site browser request cannot forge a matching
        # Origin. We also require application/json (see do_POST), which a simple
        # cross-site <form> cannot set without a CORS preflight the server never
        # answers. When neither Origin nor Referer is present (curl / server-side
        # automation, never a cross-site browser POST) we allow it.
        host = (self.headers.get("Host") or "").strip()
        for h in ("Origin", "Referer"):
            v = self.headers.get(h)
            if v:
                try:
                    return urlparse(v).netloc == host
                except ValueError:
                    return False
        return True

    def _read_json(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n > 0 else b""
            return json.loads(raw.decode("utf-8")) if raw else {}
        except (ValueError, OSError):
            return None

    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.end_headers()

    def do_GET(self):
        u = urlparse(self.path); path = unquote(u.path); q = parse_qs(u.query)
        body_only = bool(q.get("body"))
        rd = _run_dir()  # resolve dynamically — picks up new runs without restart
        try:
            if path in ("/", "/dashboard.html"):
                self._send(grid_content(rd) if body_only else grid_page(rd))
            elif path == "/control":
                self._send(control_content() if body_only else control_page())
            elif path == "/manual":
                self._send(manual_content() if body_only else manual_page())
            elif path == "/api/manual/list":
                self._send_json(ctl.list_manual_items() if ctl else {"cells": []})
            elif path == "/api/manual/file":
                cell = (q.get("cell") or [""])[0]
                name = (q.get("name") or [""])[0]
                self._send_json(ctl.read_manual_file(cell, name) if ctl
                                else {"ok": False, "error": "control engine unavailable"})
            elif path == "/api/status":
                st = ctl.run_status() if ctl else {"active": False, "paused": False}
                st["html"] = control_status_html()
                self._send_json(st)
            elif path == "/api/progress":
                cell_param = (q.get("cell") or [""])[0]
                self._send(cell_progress_html(cell_param) if cell_param else "",
                           ctype="text/html; charset=utf-8")
            elif path == "/api/cell/status":
                cell_param = (q.get("cell") or [""])[0]
                self._send_json(ctl.cell_status(cell_param) if ctl
                                else {"error": "control engine unavailable"})
            elif path.startswith("/cell/"):
                if not rd:
                    self._send("<h3>No active run</h3><a href=/>← grid</a>", 404)
                else:
                    cell = path[len("/cell/"):]
                    self._send(cell_content(rd, cell) if body_only else cell_page(rd, cell))
            elif path == "/raw":
                t = raw_text(rd, (q.get("f") or [""])[0], bool(q.get("full"))) if rd else None
                self._send(t if t is not None else "(not a log file)", 200 if t is not None else 403,
                           ctype="text/plain; charset=utf-8")
            elif path == "/view":
                pg = view_page(rd, (q.get("f") or [""])[0], bool(q.get("full"))) if rd else None
                self._send(pg if pg else "<h3>403 — not a log file</h3><a href=/>&laquo; grid</a>",
                           200 if pg else 403)
            elif path == "/api/download":
                # Bundle one project__profile execution (results, logs, reports,
                # metrics, config, patches, validation outputs) into a single ZIP.
                cell = (q.get("cell") or [""])[0]
                if ctl is None:
                    self._send("control engine unavailable", 503,
                               ctype="text/plain; charset=utf-8")
                elif not self._is_local():
                    self._send("forbidden (downloads are localhost-only — reach the "
                               "dashboard via the nginx auth proxy)", 403,
                               ctype="text/plain; charset=utf-8")
                else:
                    try:
                        arc = ctl.build_cell_archive(cell)
                    except ValueError:
                        self._send("<h3>404 — unknown cell</h3><a href=/>&laquo; grid</a>", 404)
                    else:
                        try:
                            self._send_file(arc["path"], arc["filename"])
                        finally:
                            try:
                                os.remove(arc["path"])
                            except OSError:
                                pass
            else:
                self._send("<h3>404</h3><a href=/>&laquo; grid</a>", 404)
        except Exception as e:
            self._send(f"<pre>error: {html.escape(str(e))}</pre>", 500)

    def do_POST(self):
        path = urlparse(self.path).path
        if ctl is None:
            return self._send_json({"ok": False, "error": "control engine unavailable"}, 503)
        if not self._is_local():
            return self._send_json({"ok": False, "error": "forbidden (mutating ops are "
                                    "localhost-only; reach the dashboard via the nginx "
                                    "auth proxy)"}, 403)
        # CSRF guards: require an application/json body (a cross-site <form> can't
        # send it without a CORS preflight the server never grants) and reject a
        # mismatched Origin/Referer.
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if ctype != "application/json":
            return self._send_json({"ok": False, "error": "Content-Type must be "
                                    "application/json"}, 415)
        if not self._same_origin():
            return self._send_json({"ok": False, "error": "cross-origin request refused"}, 403)
        body = self._read_json()
        if body is None:
            return self._send_json({"ok": False, "error": "bad JSON body"}, 400)
        try:
            if path == "/api/control":
                return self._send_json(self._handle_control(body))
            if path == "/api/delete/preview":
                return self._send_json(self._handle_preview(body))
            if path == "/api/delete/apply":
                tok = body.get("token") or ""
                return self._send_json(ctl.apply_deletion(body, tok))
            if path == "/api/manual/file":
                return self._send_json(ctl.write_manual_file(
                    str(body.get("cell", "")), str(body.get("name", "")),
                    body.get("content", "")))
            if path == "/api/manual/action":
                return self._send_json(ctl.manual_action(
                    str(body.get("cell", "")), str(body.get("action", "")),
                    str(body.get("cve", "")), body.get("phase", 0)))
            return self._send_json({"ok": False, "error": "unknown endpoint"}, 404)
        except Exception as e:
            return self._send_json({"ok": False, "error": str(e)}, 500)

    def _handle_control(self, body):
        action = body.get("action")
        if action == "start":
            phases = [str(p) for p in body.get("phases", [])]
            bphases = [p for p in phases if p in ("0", "1")]
            sphases = [p for p in phases if p in ("2", "3", "4")]
            try:
                mtimeout = int(body.get("manual_timeout") or 1800)
            except (TypeError, ValueError):
                mtimeout = 1800
            try:
                repeats = int(body.get("repeats") or 1)
            except (TypeError, ValueError):
                repeats = 1
            return ctl.start_run(
                projects=list(body.get("projects", [])),
                profiles=list(body.get("profiles", [])),
                baseline_profile=body.get("baseline_profile", ""),
                baseline_phases=bphases, sweep_phases=sphases,
                manual_phase0_hold=bool(body.get("manual_phase0_hold")),
                manual_phase1_gate=bool(body.get("manual_phase1_gate")),
                manual_timeout=mtimeout,
                repeats=repeats, reuse_baseline=bool(body.get("reuse_baseline")),
                overlap_families=bool(body.get("overlap_families")),
                repeat_parallel=bool(body.get("repeat_parallel")),
                validation_workers=int(body.get("validation_workers") or 0),
                baseline_parallel=int(body.get("baseline_parallel") or 0),
                make_jobs=int(body.get("make_jobs") or 0))
        if action == "stop":
            return ctl.stop_run()
        if action == "pause":
            return ctl.pause_run()
        if action == "resume":
            return ctl.resume_run()
        # Per-cell controls (project pages) — target ONE cell, not the whole run.
        if action == "cell_pause_toggle":
            return ctl.pause_toggle_cell(str(body.get("cell", "")))
        if action == "cell_stop":
            return ctl.stop_cell(str(body.get("cell", "")))
        if action == "cell_resume_fail":
            return ctl.resume_failed_cell(str(body.get("cell", "")))
        return {"ok": False, "error": f"unknown action {action!r}"}

    def _handle_preview(self, body):
        plan = ctl.plan_deletion(body)
        items = plan["items"]
        shown = items[:400]
        for i in shown:
            i["size_h"] = ctl.human_bytes(i.get("size_bytes", 0))
        return {"token": plan["token"], "count": plan["count"],
                "total_bytes": plan["total_bytes"],
                "total_h": ctl.human_bytes(plan["total_bytes"]),
                "docker_available": plan["docker_available"],
                "counts": plan["counts"], "notes": plan.get("notes", []),
                "truncated": len(items) > len(shown),
                "items": [{"kind": i["kind"], "label": i["label"],
                           "size_h": i["size_h"]} for i in shown]}

    def log_message(self, *a):
        pass


def main():
    global RUN_DIR
    args = sys.argv[1:]; run_dir = None; port = 8080; bind = "0.0.0.0"; i = 0
    while i < len(args):
        if args[i] == "--port": port = int(args[i + 1]); i += 2
        elif args[i] == "--bind": bind = args[i + 1]; i += 2
        else: run_dir = args[i]; i += 1
    if not run_dir:
        runs = sorted([d for d in glob.glob(os.path.join(HERE, "runs", "*"))
                       if os.path.isdir(d) and not d.endswith("latest")], reverse=True)
        run_dir = runs[0] if runs else None
    global RUN_DIR, _RUN_DIR_ARG
    if run_dir and not os.path.isdir(run_dir):
        print(f"Note: {run_dir!r} not found — grid will be empty until a run starts")
        _RUN_DIR_ARG = run_dir  # keep so _run_dir() can re-check once it exists
        run_dir = None
    else:
        _RUN_DIR_ARG = run_dir
    RUN_DIR = os.path.abspath(run_dir) if run_dir else None
    print(f"serving {RUN_DIR} on http://{bind}:{port}/")
    ThreadingHTTPServer((bind, port), H).serve_forever()


if __name__ == "__main__":
    main()
