#!/usr/bin/env python3
"""Reconcile the pipeline's Phase-1 reproduction labels against an independent
ground-truth oracle, and emit a confusion matrix + precision/recall + the FP/FN
table described in documentation/groundtruth-validation-methodology.md.

This is the *comparison* half of the ground-truth work. It reads three things:
  1. results/image_manifest.json   -- the pipeline's Phase-1 label per CVE
  2. results/<project>_cve_poc_complete.csv  -- Phase-0 metadata (FIX_COMMIT, F_NAME...)
  3. groundtruth/<project>_groundtruth.json  -- the independent oracle's verdict per CVE
     (produced by run_groundtruth.py; schema documented below)

It is deliberately independent of the pipeline decision logic: it only joins labels.

Ground-truth JSON schema (list of objects), one per CVE the oracle attempted:
  {
    "cve": "CVE-2023-4911",
    "fix_commit": "...", "parent_commit": "...",
    "v_minus": {"exit": 1, "test": "FAIL", "sanitizer": "heap-buffer-overflow",
                 "top_frame": "elf/dl-tunables.c:__tunables_...", "build_ok": true},
    "v_plus":  {"exit": 0, "test": "PASS", "sanitizer": null,
                 "top_frame": null, "build_ok": true},
    "groundtruth": "CONFIRMED",   # CONFIRMED | REFUTED | UNCONFIRMABLE
    "reason": "fails+ASan at V-, clean at V+, frame matches F_NAME"
  }

Usage:
  python3 groundtruth/reconcile.py \
      --manifest projects/<dir>/results/image_manifest.json \
      --csv      projects/<dir>/results/<project>_cve_poc_complete.csv \
      --groundtruth groundtruth/<project>_groundtruth.json \
      --project glibc

If --groundtruth is omitted or a CVE is missing from it, that CVE's oracle verdict
is treated as PENDING and reported separately (so you can run the pipeline-side of
the table before the oracle has finished).
"""
import argparse
import csv
import json
import sys
from pathlib import Path

csv.field_size_limit(sys.maxsize)


def load_manifest_labels(path):
    """CVE -> True(reproduced) / False(needs manual) from the Phase-1 manifest."""
    m = json.loads(Path(path).read_text())
    labels = {}
    for c in m.get("cve_images", []):
        cve = c.get("cve")
        if not cve:
            continue
        reproduced = (
            c.get("baseline_exit_code") is not None
            and not c.get("needs_manual_revision")
        )
        labels[cve] = {
            "reproduced": reproduced,
            "baseline_exit_code": c.get("baseline_exit_code"),
            "status": c.get("status"),
            "poc_path": c.get("poc_path"),
        }
    return labels


def load_csv_meta(path):
    meta = {}
    if not path or not Path(path).exists():
        return meta
    with open(path, newline="") as fh:
        for r in csv.DictReader(fh):
            cve = r.get("CVE")
            if not cve:
                continue
            # keep the first non-empty row per CVE
            if cve in meta and meta[cve].get("FIX_COMMIT"):
                continue
            meta[cve] = {
                "FIX_COMMIT": (r.get("FIX_COMMIT") or "").strip(),
                "F_NAME": (r.get("F_NAME") or "").strip(),
                "FilePath": (r.get("FilePath") or "").strip(),
                "poc_language": (r.get("poc_language") or "").strip(),
            }
    return meta


def load_groundtruth(path):
    if not path or not Path(path).exists():
        return {}
    data = json.loads(Path(path).read_text())
    return {d["cve"]: d for d in data if d.get("cve")}


def classify(reproduced, gt_verdict):
    """Return one of TP/FP/FN/TN/PENDING/UNCONFIRMABLE."""
    if gt_verdict in (None, "PENDING"):
        return "PENDING"
    if gt_verdict == "UNCONFIRMABLE":
        return "UNCONFIRMABLE"
    confirmed = gt_verdict == "CONFIRMED"
    if reproduced and confirmed:
        return "TP"
    if reproduced and not confirmed:
        return "FP"
    if not reproduced and confirmed:
        return "FN"
    return "TN"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--manifest", required=True)
    ap.add_argument("--csv", default=None)
    ap.add_argument("--groundtruth", default=None)
    ap.add_argument("--project", default="project")
    ap.add_argument("--json-out", default=None, help="write full per-CVE join as JSON")
    args = ap.parse_args()

    labels = load_manifest_labels(args.manifest)
    meta = load_csv_meta(args.csv)
    gt = load_groundtruth(args.groundtruth)

    rows = []
    counts = {k: 0 for k in ("TP", "FP", "FN", "TN", "PENDING", "UNCONFIRMABLE")}
    for cve, lab in sorted(labels.items()):
        g = gt.get(cve, {})
        verdict = g.get("groundtruth", "PENDING")
        klass = classify(lab["reproduced"], verdict)
        counts[klass] += 1
        rows.append(
            {
                "cve": cve,
                "class": klass,
                "pipeline": "reproduced" if lab["reproduced"] else "manual",
                "baseline_exit": lab["baseline_exit_code"],
                "groundtruth": verdict,
                "reason": g.get("reason", ""),
                "F_NAME": meta.get(cve, {}).get("F_NAME", ""),
                "fix_commit": (meta.get(cve, {}).get("FIX_COMMIT", "")
                               or g.get("fix_commit", ""))[:12],
            }
        )

    tp, fp, fn = counts["TP"], counts["FP"], counts["FN"]
    prec = tp / (tp + fp) if (tp + fp) else float("nan")
    rec = tp / (tp + fn) if (tp + fn) else float("nan")

    print(f"\n===== {args.project}: Phase-1 reproduction vs. ground truth =====")
    print(f"  universe (CVEs with a Phase-1 label): {len(labels)}")
    print(f"  TP {tp}  FP {fp}  FN {fn}  TN {counts['TN']}"
          f"  | UNCONFIRMABLE {counts['UNCONFIRMABLE']}  PENDING {counts['PENDING']}")
    print(f"  reproduction precision = TP/(TP+FP) = {prec:.3f}")
    print(f"  reproduction recall    = TP/(TP+FN) = {rec:.3f}")

    fpfn = [r for r in rows if r["class"] in ("FP", "FN")]
    if fpfn:
        print("\n  --- disagreements (must be hand-explained) ---")
        for r in fpfn:
            print(f"   [{r['class']}] {r['cve']}  pipeline={r['pipeline']}"
                  f"  gt={r['groundtruth']}  fix={r['fix_commit']}"
                  f"  fn={r['F_NAME']}  :: {r['reason']}")

    if counts["PENDING"] == len(labels):
        print("\n  (no ground-truth file yet -> everything PENDING; run "
              "run_groundtruth.py first, then re-run this to fill the matrix.)")

    if args.json_out:
        Path(args.json_out).write_text(json.dumps(
            {"project": args.project, "counts": counts,
             "precision": prec, "recall": rec, "rows": rows}, indent=2))
        print(f"\n  wrote {args.json_out}")


if __name__ == "__main__":
    main()
