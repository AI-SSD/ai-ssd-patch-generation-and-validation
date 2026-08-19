#!/usr/bin/env python3
"""Reconcile the pipeline's Phase-1 reproduction labels against the independent
ground-truth oracle, producing the confusion matrix + precision/recall + the
enumerated FP/FN table (per project and pooled).

Input: one or more <project>_groundtruth.json files produced by run_groundtruth.py.
Each record already carries `pipeline_reproduced` (the Phase-1 label) and
`groundtruth` (the oracle verdict CONFIRMED/REFUTED/UNCONFIRMABLE), so no manifest
or CSV is needed here.

Confusion matrix (universe = CVEs the pipeline attempted in Phase 1):
                        oracle CONFIRMED   oracle REFUTED
  pipeline reproduced        TP                 FP
  pipeline manual/not        FN                 TN
UNCONFIRMABLE on either arm is reported separately (excluded from precision/recall).

  reproduction precision = TP / (TP + FP)
  reproduction recall    = TP / (TP + FN)

Usage:
  python3 reconcile_gt.py out/tcpdump_groundtruth.json out/openssl_groundtruth.json out/glibc_groundtruth.json
"""
import json, sys, os
from collections import Counter


def refuted_kind(rec):
    """Distinguish the two REFUTED sub-types:
      - 'nondiscrim': V- PASSes -> reverting the fix did NOT reintroduce a detectable
        failure -> the test genuinely does not discriminate the vuln (strong challenge).
      - 'vplus_fail': V- FAILs but V+ also FAILs -> the upstream fix's own test still
        aborts on the fixed tree (often a chained/latent bug or an incomplete single-commit
        fix, or ASan flagging unrelated old code) -> oracle INCONCLUSIVE, weaker signal.
    """
    vm = (rec.get("v_minus") or {}).get("result")
    vp = (rec.get("v_plus") or {}).get("result")
    if vm == "PASS":
        return "nondiscrim"
    if vp == "FAIL":
        return "vplus_fail"
    return "other"


def classify(rec):
    rep = bool(rec.get("pipeline_reproduced"))
    gt = rec.get("groundtruth")
    if gt == "UNCONFIRMABLE":
        return "UNCONF_repro" if rep else "UNCONF_manual"
    if gt == "CONFIRMED":
        return "TP" if rep else "FN"
    if gt == "REFUTED":
        return "FP" if rep else "TN"
    return "PENDING"


def report(project, records):
    counts = Counter(classify(r) for r in records)
    tp, fp = counts["TP"], counts["FP"]
    fn, tn = counts["FN"], counts["TN"]
    ur, um = counts["UNCONF_repro"], counts["UNCONF_manual"]
    # split the FP by REFUTED sub-type
    fps = [r for r in records if classify(r) == "FP"]
    fp_nondiscrim = [r for r in fps if refuted_kind(r) == "nondiscrim"]
    fp_vplusfail = [r for r in fps if refuted_kind(r) == "vplus_fail"]
    prec = tp / (tp + fp) if (tp + fp) else float("nan")          # strict: all REFUTED count against
    # lenient: only V- PASS (test truly doesn't discriminate) counts against; V+FAIL = inconclusive
    denom_len = tp + len(fp_nondiscrim)
    prec_len = tp / denom_len if denom_len else float("nan")
    rec_ = tp / (tp + fn) if (tp + fn) else float("nan")
    print(f"\n================ {project} ================")
    print(f"  attempted (universe): {len(records)}")
    print(f"  reproduced by pipeline: {sum(1 for r in records if r.get('pipeline_reproduced'))}")
    print(f"  TP={tp}  FP={fp} (nondiscrim={len(fp_nondiscrim)}, V+fail/inconclusive={len(fp_vplusfail)})  FN={fn}  TN={tn}")
    print(f"  UNCONFIRMABLE: {ur} (of reproduced) + {um} (of manual) = {ur+um}")
    print(f"  reproduction PRECISION strict   = TP/(TP+FP)            = {prec:.3f}")
    print(f"  reproduction PRECISION lenient  = TP/(TP+FP_nondiscrim) = {prec_len:.3f}   "
          f"(V+fail treated as inconclusive, not a pipeline error)")
    print(f"  reproduction RECALL             = TP/(TP+FN)            = {rec_:.3f}")
    if fps:
        print(f"  --- FP (pipeline reproduced, oracle REFUTED) — hand-audit ---")
        for r in fps:
            vm = r.get("v_minus") or {}; vp = r.get("v_plus") or {}
            print(f"     [{refuted_kind(r):10s}] {r['cve']:18s} V-={vm.get('result')} V+={vp.get('result')} "
                  f"fix={r.get('fix_commit','')[:10]}")
    fns = [r for r in records if classify(r) == "FN"]
    if fns:
        print(f"  --- FN (pipeline manual, oracle CONFIRMED) — missed reproductions ---")
        for r in fns:
            print(f"     {r['cve']:18s} :: {r.get('reason','')[:60]}")
    return {"project": project, "TP": tp, "FP": fp, "FN": fn, "TN": tn,
            "UNCONF": ur + um, "precision": prec, "precision_lenient": prec_len,
            "recall": rec_, "attempted": len(records)}


def main():
    files = sys.argv[1:]
    if not files:
        print("usage: reconcile_gt.py <groundtruth.json> ..."); sys.exit(1)
    pooled = []
    summaries = []
    for f in files:
        recs = json.load(open(f))
        proj = os.path.basename(f).replace("_groundtruth.json", "")
        summaries.append(report(proj, recs))
        pooled.extend(recs)
    if len(files) > 1:
        report("POOLED (all projects)", pooled)
    print("\n================ SUMMARY TABLE ================")
    print(f"{'project':22s} {'attempt':>7} {'TP':>4} {'FP':>4} {'FN':>4} {'TN':>4} {'UNCONF':>7} "
          f"{'precS':>6} {'precL':>6} {'recall':>6}")
    for s in summaries:
        print(f"{s['project']:22s} {s['attempted']:>7} {s['TP']:>4} {s['FP']:>4} {s['FN']:>4} "
              f"{s['TN']:>4} {s['UNCONF']:>7} {s['precision']:>6.3f} {s['precision_lenient']:>6.3f} {s['recall']:>6.3f}")


if __name__ == "__main__":
    main()
