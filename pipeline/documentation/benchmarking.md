# Benchmarking — run all projects × all profiles (`run_all.sh`)

One command runs the whole matrix (3 projects × 8 profiles) in a safe order on a
modest box and a single shared proxy GPU, with a global log, a live dashboard,
and a phone notification when it finishes.

## Quick start (on vm-dei)

```bash
cd ~/pipeline
tmux new -s benchmark                  # so it survives ssh disconnect
export NTFY_TOPIC=ai-ssd-tiago-7f3a    # optional push notify (see below)
./run_all.sh                           # kick it off, then Ctrl-B D to detach
```

Watch it (another tmux window / ssh session):

```bash
./dashboard.sh                         # live terminal grid, refreshes every 5s
```

When it ends you get a notification and `runs/<run_id>/COMPLETE` is created.

## What it does (3 stages)

1. **Baselines once** — Phase 0+1 per project under `BASELINE_PROFILE` (default
   `openai-fast`). The heavy compile happens **3×, not 24×**; the Docker images +
   `image_manifest.json` are then reused by every profile.
2. **OpenAI sweep** — Phase 2/3/4 for the OpenAI profiles, **in parallel**
   (`MAX_PARALLEL`, default 3). Safe to parallelize: each profile's patched Docker
   image tag is keyed by its (distinct) attempt-1 model, so they never collide.
3. **Ollama sweep** — Phase 2/3/4 for the Ollama profiles, **serialized**
   (`OLLAMA_PARALLEL`, default 1) because they share one proxy GPU.

Between stages it seeds each sweep profile's working dir with the once-built
baseline (CSV + manifest + PoCs), so Phase 2/3 finds its baseline.

## Where everything lands: `runs/<run_id>/`

| Path | What |
|------|------|
| `orchestrator.log` | global log — stage transitions, every cell start/end |
| `logs/<project>__<profile>.log` | full output of one cell (its whole pipeline) |
| `cells/<project>__<profile>.state` | machine-readable status (drives the dashboard) |
| `dashboard.html` | auto-refreshing browser view (written by the dashboard) |
| `COMPLETE` | created when the whole run finishes |

`runs/latest` symlinks the newest run. (Per-profile pipeline outputs still live in
`projects/<project>__<profile>/` as usual.)

## Dashboard

- **Terminal:** `./dashboard.sh` — a colored grid (project × profile) with state,
  elapsed time, and the last log line of each running cell. `REFRESH=2 ./dashboard.sh`
  for faster refresh. States: **PENDING** (queued), **RUNNING**, **DONE**, **FAILED**
  (non-zero exit), **SKIPPED** (baseline or seed failed — see below), **ABORTED**
  (you Ctrl-C'd the run), **STALE** (was RUNNING when the run ended — its process
  died without writing a final state).
- **Browser (with log viewer):** `./serve_dashboard.sh` runs `dashboard_server.py` —
  the grid where **each cell links to its full logs** (orchestration phase-flow +
  the detailed per-phase build/LLM output), ANSI-stripped and auto-refreshing so you
  can tail a running cell live or read a finished one. **vm-dei's host firewall
  (iptables, default-DROP) only allows inbound 22/80/443/8080**, so serve on **8080**
  for direct access — any other port is dropped (it "loads forever"):
  ```bash
  tmux new -d -s webdash './serve_dashboard.sh'        # 0.0.0.0:8080 by default
  # then open  http://10.3.3.13:8080/  (on the DEI network/VPN — no tunnel)
  ```
  Click a cell's profile → its logs → a log file (tail by default; "show full" for
  the whole file). Off-network, or for a non-allowed port, tunnel instead:
  `ssh -L 8080:localhost:8080 vm-dei` → `http://localhost:8080/`.
  ⚠️ `BIND=0.0.0.0` is unauthenticated (status + logs on the internal network). To
  open a different port permanently you'd add an iptables ACCEPT rule (needs sudo).

## Notifications — how

Set any of these env vars before `./run_all.sh`; you can set several. It pings on
run start, each stage end, every failed cell, and final completion.

- **ntfy (recommended, zero setup, free):** install the **ntfy** app on your phone,
  subscribe to a unique topic string, then `export NTFY_TOPIC=<that-topic>`. Done.
  Self-hosted server? add `export NTFY_SERVER=https://ntfy.yourhost`.
- **Slack:** `export SLACK_WEBHOOK=https://hooks.slack.com/services/...`
- **Discord:** `export DISCORD_WEBHOOK=https://discord.com/api/webhooks/...`

No var set → notifications are silently skipped (the run still logs everything).

## Knobs (env vars)

| Var | Default | Meaning |
|-----|---------|---------|
| `PROJECTS` | `glibc tcpdump openssl` | projects to run |
| `OPENAI_PROFILES` | the 4 openai-* | parallel sweep group |
| `OLLAMA_PROFILES` | the 4 ollama-proxy-* | serialized sweep group |
| `BASELINE_PROFILE` | `openai-fast` | builds Phase 0/1 once; all profiles reuse it |
| `MAX_PARALLEL` | `3` | OpenAI-sweep concurrency (tune to vCPU/RAM) |
| `OLLAMA_PARALLEL` | `1` | raise only if the proxy GPU has lots of VRAM |
| `SWEEP_PHASES` | `2 3 4` | phases per sweep cell |
| `BASELINE_PHASES` | `0 1` | phases for the baseline build |
| `RUN_ID` | timestamp | names `runs/<run_id>/` |

## Notes & sizing

- Run it inside **tmux** — it's a long job; detach and let it run.
- Sized for the current box (8 vCPU / 251 GB RAM): RAM is ample, and because
  baselines build once (warming the Docker cache) the sweep is LLM/IO-bound, not
  CPU-bound. The binding limit is the **proxy GPU** for the Ollama stage — hence
  `OLLAMA_PARALLEL=1`.
- Mind the OpenAI **1M-token/day flagship cap**: `openai-high`/`-mix`/`-codex`
  lean on it. Run those projects/profiles you care about, or spread across days.
- `manual_verification.auto_skip: true` in `config.yaml` keeps Phase 0 unattended
  (no manual-review pause). Leave it on for a hands-off run.
- A baseline failure for a project skips that project's whole sweep (logged +
  notified); other projects continue.
- **Seeding is verified, not silent:** before a profile's Phase 2/3 runs, the
  once-built baseline (CSV + manifest) is copied into its dir and the copy is
  checked (files present, sizes match the source). A partial/failed copy marks the
  cell **SKIPPED** rather than letting it run and report a bogus all-"No Phase 1
  Baseline" result. (A project that legitimately reproduces 0 CVEs has no manifest
  to copy — that's not a seed failure; its sweep runs and honestly reports none.)
- The venv is provisioned behind a `.deps-ready` sentinel + `flock`, so an
  interrupted/parallel provision can't hand cells a dependency-less venv. If you
  ever see `ModuleNotFoundError`, delete `.venv/.deps-ready` (or `.venv`) and re-run.
