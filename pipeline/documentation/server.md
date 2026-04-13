Run pipeline in background — quick reference
Date: 2026-04-13

Purpose:
Keep this file as a concise reminder for running the CVE pipeline on an Ubuntu server in a detached/backgrounded way, so you can exit SSH and let it continue.
Each project (glibc, tomcat, linux-kernel) runs in its own tmux session and
stores all output under its own directory:  projects/`<name>`/

1) Setup (one-time on the server)

```bash
# adjust /path/to to your server location
cd /path/to
# clone repo if needed
git clone <your-repo-url> pipeline
cd pipeline
# create and activate venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

2) Environment variables (do NOT commit secrets)

```bash
# export for the current session
export OPENAI_API_KEY="<your_openai_key>"
export NVD_API_KEY="<your_nvd_key>"
# or load from a file (safer):
# export OPENAI_API_KEY="$(cat /path/to/OPENAI_KEY_FILE)"
# export NVD_API_KEY="$(cat /path/to/NVD_API_KEY)"
```

3) Quick interactive test (always run this first)

```bash
source venv/bin/activate
# Run a single project to verify everything works:
./run_project.sh glibc
# Or manually:
python3 pipeline.py --phases 0 \
    --base-dir projects/glibc \
    --phase0-config cve_aggregator/glibc_config.yaml
```

4) Per-project tmux sessions (recommended)

Use the convenience script to launch each project in its own tmux session.
Each session is named after the project so you can attach with `tmux attach -t <name>`.

```bash
# install tmux if missing
sudo apt update && sudo apt install -y tmux

# --- Launch all three projects in parallel ---
./run_project.sh glibc
./run_project.sh tomcat
./run_project.sh linux-kernel

# --- Or run the full pipeline (all phases) ---
./run_project.sh glibc   --phases 0 1 2 3 4
./run_project.sh tomcat   --phases 0 1 2 3 4
./run_project.sh linux-kernel --phases 0 1 2 3 4

# --- Attach / detach ---
tmux attach -t glibc          # Ctrl-B then D to detach
tmux attach -t tomcat
tmux attach -t linux-kernel

# --- List all sessions ---
tmux ls

# --- Kill a session ---
tmux kill-session -t glibc
```

5) Manual tmux commands (without the convenience script)

```bash
PIPELINE_ROOT="/path/to/pipeline"
# Glibc
tmux new-session -d -s glibc bash -lc "cd $PIPELINE_ROOT && source venv/bin/activate && python3 pipeline.py --phases 0 --base-dir $PIPELINE_ROOT/projects/glibc --phase0-config $PIPELINE_ROOT/cve_aggregator/glibc_config.yaml 2>&1 | tee projects/glibc/logs/run.log; exec bash"

# Tomcat
tmux new-session -d -s tomcat bash -lc "cd $PIPELINE_ROOT && source venv/bin/activate && python3 pipeline.py --phases 0 --base-dir $PIPELINE_ROOT/projects/tomcat --phase0-config $PIPELINE_ROOT/cve_aggregator/tomcat_config.yaml 2>&1 | tee projects/tomcat/logs/run.log; exec bash"

# Linux Kernel
tmux new-session -d -s linux-kernel bash -lc "cd $PIPELINE_ROOT && source venv/bin/activate && python3 pipeline.py --phases 0 --base-dir $PIPELINE_ROOT/projects/linux-kernel --phase0-config $PIPELINE_ROOT/cve_aggregator/kernel_config.yaml 2>&1 | tee projects/linux-kernel/logs/run.log; exec bash"
```

6) Option B — nohup / setsid (minimal, no extra tools)

```bash
cd /path/to/pipeline
source venv/bin/activate
nohup python3 pipeline.py --phases 0 --base-dir projects/glibc --phase0-config cve_aggregator/glibc_config.yaml > projects/glibc/logs/run.log 2>&1 &
```

7) View logs & status

```bash
# Per-project file logs
tail -f projects/glibc/logs/run_*.log
tail -f projects/tomcat/logs/run_*.log
tail -f projects/linux-kernel/logs/run_*.log
```

8) Stop / restart

```bash
# tmux: attach then Ctrl-C or kill the session
tmux attach -t glibc  # then Ctrl-C
# kill session
tmux kill-session -t glibc
# nohup/setsid: kill the process by PID
ps aux | grep pipeline.py
kill <pid>
```

9) Project directory structure

Each project stores all its output under projects/`<name>`/:

  projects/
    glibc/
      logs/             — pipeline & aggregator logs
      results/          — JSON datasets, CSV, validation reports
      manual_supervision/ — PoCs flagged for manual review
      glibc/            — cloned source repo (auto-created on first run)
      exploits/         — extracted PoC files
      patches/          — generated patches (Phases 2+)
    tomcat/
      ...  (same structure)
    linux-kernel/
      ...  (same structure)

10) Notes & cautions

- Replace `/path/to/pipeline` and `youruser` with real server paths and usernames.
- The Linux kernel repo is large (several GB). Confirm available disk space before running phases that clone the kernel.
- Test interactively before backgrounding to ensure config paths and env vars are correct.
- Use `systemd` for unattended, auto-restarting runs; use `tmux` for ad-hoc interactive troubleshooting.
- Consider log rotation (`logrotate`) for long runs to avoid filling disk with logs.

Quick one-line tmux start (example):

```bash
# Glibc
./run_project.sh glibc
# Tomcat
./run_project.sh tomcat
# Linux Kernel
./run_project.sh linux-kernel
```

rsync (exclude per-project clones and output):

```bash
rsync -av --exclude='.venv' --exclude='exploit-database' \
  --exclude='projects/glibc/glibc/' \
  --exclude='projects/linux-kernel/linux/' \
  --exclude='projects/tomcat/tomcat/' \
  admin@10.17.0.151:/home/admin/pipeline/ \
  Downloads/pipeline

rsync -av --exclude='.venv' --exclude='exploit-database' --exclude='glibc' \
  --exclude='projects/*/results' --exclude='projects/*/logs' \
  --exclude='projects/*/manual_supervision' --exclude='projects/*/exploits' \
  Documents/Tese/ai-ssd-patch-generation-and-validation/pipeline/ \
  admin@10.17.0.151:/home/admin/pipeline/

rsync -av \
  --exclude='glibc/glibc/' \
  --exclude='linux-kernel/linux/' \
  --exclude='tomcat/tomcat/' \
  admin@10.17.0.151:/home/admin/pipeline/projects/ \
  Downloads/pipeline
```

Run script

```bash
# Launch all three projects in parallel:
./run_project.sh glibc
./run_project.sh tomcat
./run_project.sh linux-kernel

# Attach to any session:
tmux attach -t tomcat      # Ctrl-B then D to detach

# Full pipeline (all phases):
./run_project.sh glibc --phases 0 1 2 3 4
```
