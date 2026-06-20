---
name: phase1-runtime-bottleneck
description: Measured Phase 1 runtime bottleneck — hang-PoC baselines, NOT glibc builds; ccache rejected
metadata:
  type: project
---

2026-06-20 runtime measurement (full VM run, glibc). **The Phase 1 cost is PoC
baseline execution of `-1`/hang baselines, NOT image builds.** Evidence from
`orchestrator_20260620_113743.log`: CVE-2009-5029 (hang, `-1`) took **923.8s =
88% of Phase 1's 1052.6s**; it pays `baseline_runs(3) × run_timeout(300s) = 900s`
because the determinism guard requires *unanimity* for a hang (can't early-stop;
crash baselines like CVE-2012-3480 early-stop at 3.8s). CVE-image "builds" were
**0.7s / 3.5s / 0.3s** — Docker's **layer cache** already serves the glibc compile
(same base+commit+configure/make = cached layer), so the compile is effectively free
on warm runs.

**ccache REJECTED** (was the candidate optimization): compile already layer-cached;
buildable set tiny + version-fragmented (8 buildable CVEs / 22, 5 versions, 3
singletons) so cross-CVE reuse ceiling ~nil; would add BuildKit dep + perturb the
baseline build for ~zero gain. See [[exploitdb-only-funnel]].

**Real fix, ranked (benefit ÷ danger):**
1. **Baseline memoization** (most beneficial, least dangerous): cache
   `baseline_exit_code` keyed on the existing `poc_signature`; skip re-running on
   warm re-runs (the 923.8s hang was RE-MEASURED on a warm run where the image was
   cache-identical — pure waste). Safe: identical image ⇒ identical already-established
   baseline. **Correctness requirement:** cache key MUST also include `run_timeout` +
   `docker.memory_limit` (not in `poc_signature` today) — changing timeout can flip
   hang↔completion. Add `--force-baseline` escape hatch.
2. **Concurrent hang-confirmation** (helps only the COLD first measurement): run the
   independent determinism repeats concurrently → 3×300s becomes ~300s. RISK: **VM has
   only 9 GB RAM**, `memory_limit` is 6 GB/container → 3 concurrent = 18 GB ceiling;
   safe form caps at 2 concurrent / lower per-run ceiling. Hanging PoCs use little real
   memory so usually fine, not zero-risk.

**Why:** measuring before implementing killed a plausible-but-wrong optimization
(ccache) and found the real one (baseline re-measurement waste).
**How to apply:** project-agnostic — the cost driver is `baseline_runs × run_timeout`
for hang PoCs in ANY project, and Docker layer caching makes builds cheap on warm
re-runs regardless of project. Related: [[run-environment]] [[phase1-and-feedback-improvements]].
