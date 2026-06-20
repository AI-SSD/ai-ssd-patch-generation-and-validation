#!/usr/bin/env python3
"""Phase 1 ground-truth MECHANICAL runner.

Does only the tedious, judgment-free half of the ground-truth protocol
(pipeline/documentation/phase1-groundtruth-protocol.md):

  * reads results/image_manifest.json  -> the real Phase-1 set + real image tags
  * reads the /poc/.ssd_poc_uses_build linkage marker (C PoCs)
  * runs each CVE image 3x with the SAME limits Phase 1 uses (--memory=6g,
    --privileged for needs_privileged LPEs), capturing the raw exit codes
  * computes the >=2/3 "stable" signal (timeouts require all 3 to agree)
  * writes results/groundtruth/<CVE>.run{1,2,3}.log (full output, markers incl.)
  * writes results/phase1_groundtruth.csv with the mechanical columns filled

It DELIBERATELY leaves `gt_verdict`, `gt_baseline_exit` and
`agrees_with_pipeline` BLANK. You assign those by hand (protocol Step 3) so the
ground truth stays independent of the pipeline's own decision logic.

Run it ON THE VM, from /home/admin/pipeline, AFTER Phase 1 finishes:
    python3 documentation/phase1_groundtruth_run.py
    python3 documentation/phase1_groundtruth_run.py --cve CVE-2012-3480   # one CVE
    python3 documentation/phase1_groundtruth_run.py --runs 3 --memory 6g
"""
import argparse
import csv
import json
import os
import subprocess
import sys
from collections import Counter

RUN_TIMEOUT = 300  # seconds, matches orchestrator --run-timeout 300

COLS = ["cve", "poc_path", "ubuntu_version", "build_arch", "image_tag",
        "needs_privileged", "builds_ok", "links_project_build",
        "run1_exit", "run2_exit", "run3_exit", "stable", "observed_signal",
        "gt_verdict", "gt_baseline_exit",            # <- YOU fill these (Step 3)
        "pipeline_status", "pipeline_baseline", "pipeline_manual",
        "agrees_with_pipeline", "notes"]             # <- YOU fill agrees + notes


def docker(args, timeout=None):
    """Run a docker command, return (exit_code, combined_output)."""
    def _decode_stream(stream):
        if stream is None:
            return ""
        if isinstance(stream, bytes):
            return stream.decode(errors="replace")
        return str(stream)

    try:
        p = subprocess.run(["docker"] + args, capture_output=True, text=False,
                           timeout=timeout)
        return p.returncode, _decode_stream(p.stdout) + _decode_stream(p.stderr)
    except subprocess.TimeoutExpired as e:
        out = _decode_stream(e.stdout) + _decode_stream(e.stderr)
        return "TIMEOUT", out


def read_linkage(tag):
    """Read the baked-in /poc/.ssd_poc_uses_build marker. NA if absent (interpreted PoC)."""
    rc, out = docker(["run", "--rm", "--entrypoint", "cat", tag,
                      "/poc/.ssd_poc_uses_build"], timeout=60)
    if rc == 0:
        v = out.strip().splitlines()[-1].strip() if out.strip() else ""
        return v if v in ("yes", "no") else "NA"
    return "NA"  # marker file not present -> interpreted PoC


def signal_name(code):
    """Human label for an exit code (128+signal = crash)."""
    sig = {139: "SIGSEGV(11)", 134: "SIGABRT(6)", 136: "SIGFPE(8)",
           135: "SIGBUS(7)", 137: "SIGKILL/OOM(9)", 132: "SIGILL(4)",
           143: "SIGTERM(15)", 124: "timeout(coreutils)"}
    if code == "TIMEOUT":
        return "TIMEOUT"
    if code == 0:
        return "clean-0"
    if isinstance(code, int) and code in sig:
        return sig[code]
    if isinstance(code, int) and code > 128:
        return f"signal({code-128})"
    return f"exit-{code}"


def stable_signal(codes):
    """Return (stable_bool, dominant_code_or_signal). Timeouts need all-3; else >=2/3."""
    c = Counter(codes)
    timeouts = c.get("TIMEOUT", 0)
    if timeouts == len(codes):
        return True, "TIMEOUT"
    # ignore timeouts when checking numeric agreement
    numeric = [x for x in codes if x != "TIMEOUT"]
    if not numeric:
        return False, ""
    code, n = Counter(numeric).most_common(1)[0]
    return (n >= 2), code


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", default="results/image_manifest.json")
    ap.add_argument("--out", default="results/phase1_groundtruth.csv")
    ap.add_argument("--logdir", default="results/groundtruth")
    ap.add_argument("--cve", nargs="*", help="only these CVEs")
    ap.add_argument("--runs", type=int, default=3)
    ap.add_argument("--memory", default="6g")
    args = ap.parse_args()

    if not os.path.exists(args.manifest):
        sys.exit(f"ERROR: {args.manifest} not found. Has Phase 1 finished? "
                 f"(orchestrator.py writes it at the end.)")

    manifest = json.load(open(args.manifest))
    images = manifest.get("cve_images", [])
    if args.cve:
        want = set(args.cve)
        images = [i for i in images if i.get("cve") in want]
    if not images:
        sys.exit("No matching cve_images in manifest.")

    os.makedirs(args.logdir, exist_ok=True)
    rows = []
    print(f"Ground-truthing {len(images)} CVE image(s) "
          f"({args.runs}x each, --memory={args.memory})\n")

    for img in images:
        cve = img.get("cve")
        tag = img.get("tag", "")
        priv = bool(img.get("needs_privileged", False))
        print(f"=== {cve}  tag={tag}  privileged={priv} ===")

        # does the tag actually exist as an image?
        rc, _ = docker(["image", "inspect", tag], timeout=60)
        builds_ok = "yes" if rc == 0 else "no"
        if builds_ok == "no":
            print(f"  ! image not found ({tag}) -> unbuildable")

        links = read_linkage(tag) if builds_ok == "yes" else "NA"
        print(f"  links_project_build = {links}")

        run_args = ["run", "--rm", f"--memory={args.memory}"]
        if priv:
            run_args += ["--privileged",
                         "--security-opt", "seccomp=unconfined",
                         "--security-opt", "apparmor=unconfined"]
        run_args += [tag]

        codes = []
        if builds_ok == "yes":
            for i in range(1, args.runs + 1):
                rc, out = docker(run_args, timeout=RUN_TIMEOUT + 30)
                codes.append(rc)
                logf = os.path.join(args.logdir, f"{cve}.run{i}.log")
                with open(logf, "w") as fh:
                    fh.write(f"# tag={tag}\n# exit={rc}\n# privileged={priv}\n\n")
                    fh.write(out)
                print(f"  run {i}: exit={rc} ({signal_name(rc)})  -> {logf}")

        while len(codes) < args.runs:
            codes.append("NA")

        stable, dom = stable_signal([c for c in codes if c != "NA"]) if builds_ok == "yes" else (False, "")
        row = {
            "cve": cve, "poc_path": img.get("poc_path", ""),
            "ubuntu_version": img.get("ubuntu_version", ""),
            "build_arch": img.get("build_arch", ""),
            "image_tag": tag, "needs_privileged": priv,
            "builds_ok": builds_ok, "links_project_build": links,
            "run1_exit": codes[0], "run2_exit": codes[1], "run3_exit": codes[2],
            "stable": "yes" if stable else "no",
            "observed_signal": signal_name(dom) if stable else "UNSTABLE",
            "gt_verdict": "", "gt_baseline_exit": "",
            "pipeline_status": img.get("status", ""),
            "pipeline_baseline": img.get("baseline_exit_code", ""),
            "pipeline_manual": img.get("needs_manual_revision", ""),
            "agrees_with_pipeline": "", "notes": "",
        }
        rows.append(row)
        print(f"  stable={row['stable']}  observed={row['observed_signal']}  "
              f"pipeline_status={row['pipeline_status']} "
              f"pipeline_baseline={row['pipeline_baseline']}\n")

    with open(args.out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=COLS)
        w.writeheader()
        for r in rows:
            w.writerow(r)

    print(f"Wrote {args.out} ({len(rows)} rows) and per-run logs in {args.logdir}/")
    print("NEXT (by hand): open the CSV, read the run logs, fill gt_verdict / "
          "gt_baseline_exit / agrees_with_pipeline per protocol Step 3.")


if __name__ == "__main__":
    main()
