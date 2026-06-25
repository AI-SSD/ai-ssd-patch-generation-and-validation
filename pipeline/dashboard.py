#!/usr/bin/env python3
"""Render a live status grid for a run_all.sh benchmark run.

Reads runs/<run_id>/cells/*.state (STATE|STAGE|STARTED|ENDED|EXIT|LOGFILE) and
prints a terminal table (--term) and/or writes runs/<run_id>/dashboard.html
(--html, auto-refreshing). With no run dir given, uses the newest under runs/.
"""
import sys, os, glob, time

RESET = "\033[0m"; BOLD = "\033[1m"
TCOL = {"DONE": "\033[32m", "FAILED": "\033[31m", "RUNNING": "\033[33m",
        "PENDING": "\033[90m", "SKIPPED": "\033[35m", "STALE": "\033[95m",
        "ABORTED": "\033[31m"}
HCOL = {"DONE": "#1b5e20", "FAILED": "#b71c1c", "RUNNING": "#f9a825",
        "PENDING": "#424242", "SKIPPED": "#6a1b9a", "STALE": "#8d6e63",
        "ABORTED": "#9e2a2b"}


def fmt_dur(sec):
    sec = int(sec); h, m, s = sec // 3600, (sec % 3600) // 60, sec % 60
    return f"{h}:{m:02d}:{s:02d}" if h else f"{m}:{s:02d}"


def last_log_line(path):
    try:
        with open(path, "rb") as f:
            f.seek(0, 2); end = f.tell(); f.seek(max(0, end - 4096))
            data = f.read().decode("utf-8", "replace")
        lines = [ln for ln in data.splitlines() if ln.strip()]
        return lines[-1][:90] if lines else ""
    except Exception:
        return ""


def load(run_dir):
    cells = []
    for f in sorted(glob.glob(os.path.join(run_dir, "cells", "*.state"))):
        try:
            parts = open(f).read().strip().split("|")
            state, stage, started, ended, exitc, logf = (parts + [""] * 6)[:6]
        except Exception:
            continue
        name = os.path.basename(f)[:-6]
        proj, _, prof = name.partition("__")
        cells.append(dict(name=name, proj=proj, prof=prof, state=state, stage=stage,
                          started=started, ended=ended, exitc=exitc, logf=logf))
    return sorted(cells, key=lambda c: (c["proj"], c["prof"]))


def elapsed_of(c, now):
    if not c["started"]:
        return ""
    try:
        st = int(c["started"]); en = int(c["ended"]) if c["ended"] else now
        return fmt_dur(en - st)
    except Exception:
        return ""


def disp_of(c, complete):
    # Once the run is COMPLETE, a cell still marked RUNNING was orphaned (its
    # process died before writing a terminal state). Show it STALE, not a phantom
    # whose elapsed climbs forever.
    if complete and c["state"] == "RUNNING":
        return "STALE"
    return c["state"]


def counts_of(cells):
    out = {}
    for c in cells:
        out[c.get("disp", c["state"])] = out.get(c.get("disp", c["state"]), 0) + 1
    return out


def render_term(run_dir, cells):
    now = int(time.time())
    print(f"{BOLD}AI-SSD benchmark — {os.path.basename(run_dir.rstrip('/'))}{RESET}"
          f"   {time.strftime('%Y-%m-%d %H:%M:%S')}"
          + ("   [COMPLETE]" if os.path.exists(os.path.join(run_dir, 'COMPLETE')) else ""))
    summ = "  ".join(f"{TCOL.get(k,'')}{k}={v}{RESET}" for k, v in sorted(counts_of(cells).items()))
    print(summ + "\n")
    print(f"{'PROJECT':9} {'PROFILE':31} {'STAGE':14} {'STATE':8} {'ELAPSED':8}  LAST LOG")
    print("-" * 118)
    for c in cells:
        ds = c.get("disp", c["state"])
        col = TCOL.get(ds, "")
        ll = last_log_line(c["logf"]) if ds in ("RUNNING", "FAILED", "STALE") else (
            "" if ds in ("PENDING", "SKIPPED") else f"exit {c['exitc']}")
        print(f"{c['proj']:9} {c['prof']:31} {(c['stage'] or '-'):14} "
              f"{col}{ds:8}{RESET} {elapsed_of(c, now):8}  {ll}")


def html_escape(s):
    return (s or "").replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def render_html(run_dir, cells):
    now = int(time.time())
    rows = ""
    for c in cells:
        ds = c.get("disp", c["state"])
        ll = last_log_line(c["logf"]) if ds == "RUNNING" else ""
        rows += (f"<tr><td>{c['proj']}</td><td>{c['prof']}</td><td>{c['stage']}</td>"
                 f"<td style='background:{HCOL.get(ds, '#333')};color:#fff;font-weight:700'>{ds}</td>"
                 f"<td>{elapsed_of(c, now)}</td><td><code>{html_escape(ll)}</code></td></tr>")
    summ = " &nbsp; ".join(f"{k}: <b>{v}</b>" for k, v in sorted(counts_of(cells).items()))
    done = os.path.exists(os.path.join(run_dir, "COMPLETE"))
    html = f"""<!doctype html><html><head><meta charset="utf-8">
<meta http-equiv="refresh" content="5"><title>AI-SSD benchmark</title>
<style>body{{font-family:system-ui,Segoe UI,monospace;background:#111;color:#eee;margin:1.5rem}}
table{{border-collapse:collapse;width:100%}}td,th{{padding:.35rem .6rem;border-bottom:1px solid #333;text-align:left;font-size:14px}}
th{{color:#9aa}}code{{color:#9cf}}h2 small{{color:#6c6;font-size:.6em}}</style></head><body>
<h2>AI-SSD benchmark — {os.path.basename(run_dir.rstrip('/'))} {'<small>COMPLETE</small>' if done else ''}</h2>
<p>updated {time.strftime('%Y-%m-%d %H:%M:%S')} &nbsp;|&nbsp; {summ}</p>
<table><tr><th>project</th><th>profile</th><th>stage</th><th>state</th><th>elapsed</th><th>last log</th></tr>
{rows}</table></body></html>"""
    with open(os.path.join(run_dir, "dashboard.html"), "w") as f:
        f.write(html)


def main():
    run_dir, term, html = None, False, False
    for a in sys.argv[1:]:
        if a == "--term": term = True
        elif a == "--html": html = True
        else: run_dir = a
    here = os.path.dirname(os.path.abspath(__file__))
    if not run_dir:
        runs = [d for d in sorted(glob.glob(os.path.join(here, "runs", "*")), reverse=True)
                if os.path.isdir(d) and not d.endswith("latest")]
        run_dir = runs[0] if runs else None
    if not run_dir or not os.path.isdir(run_dir):
        print("No run directory found (looked under runs/)."); return
    cells = load(run_dir)
    complete = os.path.exists(os.path.join(run_dir, "COMPLETE"))
    for c in cells:
        c["disp"] = disp_of(c, complete)
    if not term and not html:
        term = True
    if html: render_html(run_dir, cells)
    if term: render_term(run_dir, cells)


if __name__ == "__main__":
    main()
