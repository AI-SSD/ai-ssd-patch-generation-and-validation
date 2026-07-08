#!/usr/bin/env python3
"""Run a prompt/generation ablation sweep over a frozen reproducible subset.

Each variant (ablation/variants.yaml) is one pipeline run distinguished only by
the SSD_* env it exports (overlaid onto config.yaml by the config loader). Phase
0 (CVE aggregation) and Phase 1 (reproduction) are config-invariant for these
knobs and are REUSED from a completed base run — the sweep re-runs only Phase 2
(generation) + Phase 3 (validation) + the feedback loop per variant. The Phase 1
Docker images are daemon-global, so a per-variant base-dir can derive from them.

Usage:
  python3 run_ablation.py --base-run project-runs/glibc__openai --project glibc \
      [--variants ablation/variants.yaml] [--out ablation/runs] \
      [--phases 2 3] [--only baseline,no_poc] [--cve CVE-... ...] \
      [--skip-sast] [--max-retries 3] [--dry-run]

--dry-run prints the per-variant env + command without seeding or executing —
use it to sanity-check the sweep before committing compute. Requires Docker + an
LLM backend (like the main pipeline); intended to run on the Linux build host.
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List

PIPELINE_ROOT = Path(__file__).parent.resolve()
sys.path.insert(0, str(PIPELINE_ROOT))

from master_pipeline.ablation import (  # noqa: E402
    load_variants, parse_run_metrics, build_comparison_table, to_csv,
)


def build_plan(variants: List[Dict[str, Any]], out_dir: Path, project: str,
               phases: List[str], cves: List[str], skip_sast: bool,
               max_retries: int) -> List[Dict[str, Any]]:
    """Pure: turn variants into ``[{name, env, base_dir, cmd}]`` (no filesystem)."""
    plan = []
    for v in variants:
        vdir = out_dir / v["name"]
        cmd = [sys.executable, "pipeline.py",
               "--base-dir", str(vdir),
               "--project", project,
               "--phases", *[str(p) for p in phases]]
        if cves:
            cmd += ["--cve", *cves]
        if skip_sast:
            cmd.append("--skip-sast")
        if max_retries is not None:
            cmd += ["--max-retries", str(max_retries)]
        plan.append({
            "name": v["name"],
            "description": v.get("description", ""),
            "env": v["env"],
            "base_dir": str(vdir),
            "cmd": cmd,
        })
    return plan


# Phase 0/1 inputs reused by every variant. results/ is COPIED (Phase 3 may write
# alongside it) and exploits/ is SYMLINKED (read-only, possibly large).
_COPY_DIRS = ["results", "documentation", "manual_supervision"]
_LINK_DIRS = ["exploits"]


def seed_phase01(base_run: Path, vdir: Path) -> None:
    """Seed *vdir* with the base run's Phase 0/1 outputs so Phase 2/3 can reuse them."""
    vdir.mkdir(parents=True, exist_ok=True)
    for d in _COPY_DIRS:
        src = base_run / d
        if src.is_dir():
            dst = vdir / d
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(src, dst)
    for d in _LINK_DIRS:
        src = base_run / d
        dst = vdir / d
        if src.is_dir() and not dst.exists():
            dst.symlink_to(src.resolve())


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base-run", required=True,
                    help="Completed run dir with Phase 0/1 outputs to reuse")
    ap.add_argument("--project", required=True, help="Project name (e.g. glibc)")
    ap.add_argument("--variants", default=str(PIPELINE_ROOT / "ablation" / "variants.yaml"))
    ap.add_argument("--out", default=str(PIPELINE_ROOT / "ablation" / "runs"))
    ap.add_argument("--phases", nargs="+", default=["2", "3"])
    ap.add_argument("--cve", nargs="+", default=[], dest="cves")
    ap.add_argument("--only", default="", help="Comma-separated subset of variant names")
    ap.add_argument("--skip-sast", action="store_true")
    ap.add_argument("--max-retries", type=int, default=None)
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    base_run = Path(args.base_run).resolve()
    out_dir = Path(args.out).resolve()
    variants = load_variants(Path(args.variants))
    if args.only:
        wanted = {n.strip() for n in args.only.split(",") if n.strip()}
        variants = [v for v in variants if v["name"] in wanted]
        if not variants:
            print(f"No variants match --only={args.only!r}", file=sys.stderr)
            return 2

    plan = build_plan(variants, out_dir, args.project, args.phases,
                      args.cves, args.skip_sast, args.max_retries)

    print(f"Ablation sweep: {len(plan)} variant(s), project={args.project}, "
          f"phases={' '.join(args.phases)}, base-run={base_run}")
    for p in plan:
        envstr = " ".join(f"{k}={v}" for k, v in p["env"].items()) or "(none)"
        print(f"\n■ {p['name']} — {p['description']}")
        print(f"    env: {envstr}")
        print(f"    cmd: {' '.join(p['cmd'])}")

    if args.dry_run:
        print("\n[dry-run] no runs executed.")
        return 0

    if not base_run.is_dir():
        print(f"ERROR: --base-run {base_run} does not exist", file=sys.stderr)
        return 2

    rows: List[Dict[str, Any]] = []
    for p in plan:
        vdir = Path(p["base_dir"])
        print(f"\n===> {p['name']}: seeding Phase 0/1 from {base_run}")
        seed_phase01(base_run, vdir)
        env = dict(os.environ)
        env.update(p["env"])
        print(f"===> {p['name']}: running {' '.join(p['cmd'])}")
        rc = subprocess.call(p["cmd"], cwd=str(PIPELINE_ROOT), env=env)
        if rc != 0:
            print(f"!!! {p['name']}: pipeline exited {rc} (recording partial metrics)")
        rows.append(parse_run_metrics(vdir, p["name"]))

    table = build_comparison_table(rows)
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "comparison.md").write_text(table + "\n")
    (out_dir / "comparison.csv").write_text(to_csv(rows) + "\n")
    print("\n" + table)
    print(f"\nWrote {out_dir/'comparison.md'} and {out_dir/'comparison.csv'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
