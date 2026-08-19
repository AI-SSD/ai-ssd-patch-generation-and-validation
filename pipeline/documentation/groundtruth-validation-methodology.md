# Ground-truth validation of Phase 0/1 (reproduction) results

**Purpose.** Answer the thesis critique: *"How do you know the exploit really triggers the
vulnerability, and that the vulnerability is really present in the vulnerable build and
absent after the fix?"* The pipeline's own Phase 1 verdict cannot answer this on its own,
because Phase 1 builds the code **and** judges the result — it is self-referential. Ground
truth is an **independent** check of the same fact, using a source of truth the pipeline
never consults: the upstream maintainers' own fixing commit and their own regression test.

This document defines that independent oracle, explains why it is defensible, says what to
automate vs. do by hand, and specifies the comparison (Phase 0/1 vs. ground truth) to report.

---

## 1. What "reproduction" currently means, and why the critique is valid

For the three campaign projects, almost every Phase-1 "reproduction" is the **in-tree
regression-test path** (`poc_language = intree-test`), not a native ExploitDB exploit:

| Project  | Reproduced (baseline set) | via native PoC | via in-tree test | Signal recorded |
|----------|---------------------------|----------------|------------------|-----------------|
| glibc    | 27 / 61                   | 1 (`CVE-2012-4412`, exit 139 = SIGSEGV) | 26 (`.test0.c`) | exit code (mostly `1`) |
| openssl  | 15 / 35                   | 0              | 15 (`.test0.c`)  | exit `1` |
| tcpdump  | 123 / 142                 | 0              | 123 (`.test0.pcap`, ASan build) | exit `1` |

The oracle is **fail-to-pass**: harvest the regression test the fixing commit ships, run it
on the vulnerable build; if it *fails*, the CVE is "reproduced" (baseline success code
captured), and Phase 3 later requires the patched build to make it *pass*.

The critique bites because the recorded signal is a **generic non-zero exit code**. An exit
`1` on the vulnerable build could come from the test genuinely detecting the vulnerable
behaviour — or from a build/link mismatch, an era mismatch, a harness quirk, an unrelated
assertion, a missing fixture, etc. Nothing independent confirms that (a) the test actually
exercises the CVE's vulnerable code, (b) the "vulnerable" build is truly vulnerable, and
(c) the official fix truly removes the behaviour. Ground truth supplies exactly that.

---

## 2. The ground-truth oracle: an independent differential on the upstream fix commit

For each CVE, build **two** unmodified upstream trees and run the **same** PoC/test on both:

- **V− (vulnerable)** = parent of the fixing commit: `git checkout <FIX_COMMIT>^`
- **V+ (patched)**   = the fixing commit itself: `git checkout <FIX_COMMIT>` (upstream's
  official patch, *no LLM anywhere*)

Both `FIX_COMMIT` and `TEST_PATH` are already present in the Phase-0 CSV for every reproduced
CVE (glibc 661/712 rows, openssl 86/237, tcpdump 403/434 — 100 % of the `intree-test` rows),
so the inputs exist. The regression test ships **with** the fix, so at V− the test file is
absent: copy the test (and only the test-registration metadata) from `FIX_COMMIT` onto the
V− tree before building — this is the standard SWE-bench / fail-to-pass construction.

**Verdict per CVE (the discriminating-oracle test):**

| V− result | V+ result | Ground truth |
|-----------|-----------|--------------|
| FAIL / crash | PASS / clean | **CONFIRMED** — PoC genuinely discriminates the CVE |
| PASS / clean | PASS / clean | **REFUTED** — PoC does not exercise the vuln (spurious) |
| FAIL / crash | FAIL / crash | **REFUTED** — fix commit or test is wrong for this CVE |
| build error at V−/V+ | —      | **UNCONFIRMABLE** — record separately, don't count as pass/fail |

Only **CONFIRMED** means the reproduction is genuine ground truth.

### Why this is defensible in a defence
- The fix commit is ground truth *by construction*: it is the maintainers' own patch, and the
  regression test is the maintainers' own encoding of "the vulnerability is gone."
- It is **independent of the pipeline**: a separate harness that only checks out, builds, and
  runs — it never calls `poc_analyzer`, the negative filter, the era gates, or the manifest
  logic. So it is not the pipeline grading itself.
- It is the established methodology in the vuln-reproduction / APR literature (fail-to-pass
  differential over vulnerable vs. fixed revisions, à la SWE-bench / ARVO / vulnerability PoV
  datasets) — citable, not ad hoc.

### Strengthen the signal beyond a bare exit code
Replace "exit ≠ 0" with **specific, CVE-aligned evidence** so a CONFIRMED verdict means the
*right* thing broke:

- **glibc / openssl (in-tree C tests):** build V− with **`-fsanitize=address,undefined`**.
  A memory-safety CVE should produce an actual ASan/UBSan report (`heap-buffer-overflow`,
  `stack-buffer-overflow`, etc.) at V−, not a generic assertion. Also capture the test
  framework's own PASS/FAIL line, not just the process exit code.
- **tcpdump (pcap tests):** the Phase-1 build is already ASan. Require a real
  **AddressSanitizer report** at V− and a clean run at V+, and **match the crash frame's
  file/function to Phase 0's `FilePath` / `F_NAME`** for that CVE. That cross-check ties the
  crash to the code the CVE is actually about, which is the single most convincing artifact
  for a slide.
- **glibc native PoC (`CVE-2012-4412`):** V− must crash with the CVE's signal (here SIGSEGV
  /139), V+ must exit cleanly. This is the cleanest case — audit it fully by hand.

Record, per CVE: `fix_commit`, `parent_commit`, V− outcome (exit, PASS/FAIL, sanitizer
class + top frame), V+ outcome, and the derived `groundtruth ∈ {CONFIRMED, REFUTED,
UNCONFIRMABLE}` plus a one-line reason.

---

## 3. Automate, or do it by hand? — Hybrid (recommended)

**Automate the differential oracle for all CVEs.** It is fully deterministic (checkout →
build → run → compare) and there are ~165 reproduced CVEs × 2 builds = ~330 builds; by-hand
is infeasible and *less* reproducible, not more. The one rule: the harness must be an
**independent implementation** — it may reuse the *build recipes* (compiler flags, configure
lines) but must **not** reuse the pipeline's reproduction *decision logic*, or you are again
checking the pipeline against itself.

**Audit a stratified sample by hand** for credibility (this is what convinces a committee):
1. **Every native ExploitDB PoC** — glibc's single `CVE-2012-4412` (read the advisory, the
   PoC, confirm the SIGSEGV is the documented bug).
2. **Every disagreement** between the pipeline label and the automated oracle (all FPs and
   FNs, see §4) — read the CVE advisory + fix commit + test and explain each. These are the
   scientifically interesting cases; they *must* be hand-explained, not just counted.
3. **A ~10–15 % random sample of the agreeing in-tree cases** — open the harvested test,
   confirm it actually exercises the vulnerable function (`F_NAME`), not an adjacent one.

Report it exactly as this hybrid: "automated differential oracle over N CVEs, with a
human-audited sample of M (100 % of native PoCs, 100 % of oracle/pipeline disagreements,
and 12 % of agreements), inter-rater agreement X %." That is both scalable and trustworthy.

---

## 4. The comparison to report: Phase 0/1 vs. ground truth

Treat the pipeline's Phase-1 label as a *classifier* of "is this CVE genuinely reproducible"
and score it against the ground-truth oracle. **Universe** = CVEs that entered Phase 1 (had a
PoC or a harvested test — i.e. a row with a candidate reproducer).

| | Ground truth CONFIRMED | Ground truth REFUTED |
|---|---|---|
| **Pipeline reproduced** (baseline_exit_code set) | **TP** — genuine reproduction | **FP** — spurious reproduction |
| **Pipeline not reproduced** (needs_manual_revision) | **FN** — over-conservative miss | **TN** — correctly excluded |

Report per project **and** pooled:

- **Reproduction precision = TP / (TP + FP)** — *"of the CVEs the pipeline claims to
  reproduce, what fraction are confirmed by an independent upstream oracle."* This single
  number is the direct answer to the critique.
- **Reproduction recall = TP / (TP + FN)** — how many genuinely-reproducible CVEs the pipeline
  found (bounds the honesty gate's conservatism).
- **A full table of every FP and FN with a one-line root cause** (e.g. "FP: test fails at V−
  and V+ alike → era mismatch, not the CVE"; "FN: honesty gate routed to manual because PoC
  linked system libs, but oracle confirms"). Enumerating and explaining these *is* the
  contribution — it converts the critique into a measured, bounded property of the method.
- **UNCONFIRMABLE** CVEs (build failed under the oracle) are reported as a separate row, never
  silently folded into pass or fail.

Optionally extend the same oracle to **Phase 3**: the ground-truth patch is the upstream fix,
so "does the LLM patch match the upstream fix's behaviour on the PoC" reuses the identical V+
run — giving a patch-correctness ground truth for free.

---

## 5. Execution plan

1. **Do not run on the VM while a campaign is active** (as of this writing a Stage-2 OpenAI
   sweep is running Phases 2/3/4 on glibc/openssl rep2). ~330 sanitizer builds would contend
   for Docker/CPU and could corrupt the run. Run the oracle on a free VM window or a separate
   box with the same Docker base images.
2. `groundtruth/run_groundtruth.py` (independent harness): for each reproduced CVE, clone the
   project once, `git worktree` V− and V+, apply the per-project build recipe (from the config)
   with sanitizers, copy the harvested test onto V−, run the test on both, parse the outcome,
   emit `groundtruth/<project>_groundtruth.json`.
3. `groundtruth/reconcile.py` (already provided): join that JSON with the Phase-1
   `image_manifest.json` + Phase-0 CSV → the confusion matrix, precision/recall, and the
   FP/FN table above, per project and pooled. Runs against existing artifacts today.
4. Hand-audit the sample in §3; record verdicts + inter-rater notes.
5. Write the results section: precision/recall table + the enumerated, root-caused FP/FN list.

Cost sketch: tcpdump builds are cheap (single ASan binary), openssl medium, glibc expensive
(full libc, minutes each). Budget the glibc 27 first as a pilot to validate the harness, then
scale to openssl (15) and tcpdump (123).
