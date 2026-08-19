# Ground-truth validation of Phase-0/1 reproduction

An **independent** oracle that checks, per CVE, whether the pipeline's Phase-1
"reproduction" is genuine — i.e. whether the harvested PoC/test really discriminates
the vulnerability. It anchors on the **upstream fixing commit** and is deliberately
independent of the pipeline's reproduction *decision* logic.

See `../documentation/groundtruth-validation-methodology.md` for the full rationale.
This README documents what was actually implemented and how to run it.

## The differential (what makes it trustworthy)

For each CVE, two source trees are materialised from the upstream repo as clean,
`.git`-free snapshots (`git archive`), and the **same** harvested regression test is run
on both, **in the same era container** (build environment held constant):

- **V+** = `FIX_COMMIT` — upstream's official fix, unmodified.
- **V−** = `FIX_COMMIT` with only the **vulnerable source files reverted** to `FIX_COMMIT^`.
  "Source" = files the fix changed with a code extension (`.c/.h/.S/…`) that are **not**
  test artifacts. The test, its expected output, and its build-registration (Makefiles /
  `build.info` / `TESTLIST`) are kept from the fix, so the test always compiles and
  registers identically on both arms — the only difference between V− and V+ is the
  vulnerable code. A pass→fail flip is therefore attributable to the vulnerability alone.

**Verdict:**
| V− | V+ | verdict | meaning |
|----|----|---------|---------|
| FAIL | PASS | **CONFIRMED** | PoC genuinely discriminates the CVE |
| PASS | PASS | **REFUTED** (`nondiscrim`) | reverting the fix did not reintroduce a detectable failure — the test does not exercise the vuln |
| FAIL | FAIL | **REFUTED** (`vplus_fail`) | the fix's own test still fails on the fixed tree — chained/latent bug or incomplete single-commit fix → oracle *inconclusive* |
| build/runtime fails, or fix has no source/test | — | **UNCONFIRMABLE** | cannot construct the differential |

Why this is independent of the pipeline: the pipeline's Phase 1 only ever builds/judges
V− and records "test fails ⇒ reproduced"; it **never** builds the upstream-patched tree to
confirm the test passes there. That V+ arm is the oracle's novel signal. The harness does
not import `orchestrator.py`/`poc_analyzer.py`; it reuses only the containerised build
environment (toolchain), which is held constant across both arms by design.

## Per-project test oracle (upstream's own verdict)

- **tcpdump** — build with AddressSanitizer, run `tcpdump <flags> -r <fix's pcap>`; exit 0 =
  PASS, ASan-abort/crash/non-zero = FAIL. Flags + pcap are recovered from the `TESTLIST`
  line the fix added. Evidence captured: ASan class + top stack frame, matched against the
  CVE's `F_NAME`/`FilePath` (e.g. CVE-2017-13011 → `global-buffer-overflow` in
  `bittok2str_internal` at `util-print.c:542`).
- **openssl** — `./config … && make build_sw && make test/<name>`; run the test binary
  through the freshly built libs. exit 0 = PASS.
- **glibc** — out-of-tree `configure && make`, then `make test t=<subdir>/<name>` and read
  glibc's own `<name>.test-result` (`PASS`/`FAIL`); standalone-compile fallback runs the
  test through the *build* loader (never the host libc).

## Files

| file | role |
|------|------|
| `run_groundtruth.py` | the oracle harness (host does git/snapshots; containers only build+run) |
| `reconcile_gt.py` | joins oracle verdicts with the pipeline label → confusion matrix, precision/recall, FP/FN table |
| `reconcile.py` | variant that reads the Phase-1 manifest + Phase-0 CSV separately |
| `inputs/<project>.json` | per-CVE oracle inputs (fix commit, test path, era, `pipeline_reproduced`), extracted from the manifests |
| `out/<project>_groundtruth.json` | oracle results |

## Running (on a Docker host, e.g. vm-campos)

```bash
# base images: glibc reuses ai-ssd/glibc-base:ubuntu-<era>; openssl/tcpdump derive
# gt/<project>-base:<era> = that base + project build deps.
python3 run_groundtruth.py --project tcpdump --repo <clone> \
    --inputs inputs/tcpdump.json --out out/tcpdump_groundtruth.json --workdir work/tcpdump \
    --jobs 6 --build-jobs 4 --run-timeout 30 --min-free-gb 12
python3 reconcile_gt.py out/tcpdump_groundtruth.json out/openssl_groundtruth.json out/glibc_groundtruth.json
```

Resumable: re-running skips CVEs already in the output JSON.

## Disk-safety (learned the hard way)

Some tcpdump CVEs are **infinite-loop / very-verbose** PoCs; unbounded, `tcpdump -v`
writes gigabytes before any timeout and can fill the host disk (one container's log layer
hit 18 GB and deadlocked at 0 free space). The harness therefore:
- routes all container logs to a **RAM tmpfs** (`--tmpfs /tmp:size=128m`) — runaway output
  is capped in memory and **never touches the host disk**;
- sets a hard `ulimit -f` per-file cap and a short run timeout as backstops;
- names every container and force-removes it on timeout (no orphans);
- honours a `--min-free-gb` disk guard and cleans each CVE's trees immediately.

## Results (final — see `out/FINAL_REPORT.txt`)

| project | attempted | reproduced | TP | FP | FN | UNCONF | precision strict | precision lenient | recall |
|---------|-----------|-----------|----|----|----|--------|------------------|-------------------|--------|
| tcpdump | 142 | 127 | 122 | 3 | 0 | 13 | 0.976 | **1.000** | **1.000** |
| openssl | 35 | 15 | 3 | 8 | 2 | 17 | 0.273 | 0.600 | 0.600 |
| glibc | 61 | 27 | 13 | 11 | 1 | 31 | 0.542 | 0.929 | 0.929 |
| **pooled** | **238** | **169** | **138** | **22** | **3** | **61** | **0.863** | **0.979** | **0.979** |

**Reading the FP column is the whole point.** Of the 22 pooled FP (pipeline reproduced,
oracle did not confirm), only **3 are `nondiscrim`** — the strong case, where reverting the
fix source did NOT reintroduce a test failure, so the test genuinely does not exercise the
vuln (openssl CVE-2016-7053, CVE-2026-9076; glibc CVE-2016-1234). The other **19 are
`vplus_fail`**: the upstream fix's *own* regression test still fails on the upstream-fixed
tree. That is an oracle-inconclusive outcome (chained/unrelated failures, or a test the
independent harness can't run as cleanly as the project's full CI), **not** evidence the
reproduction is spurious. Hence the two precision columns: strict counts all `vplus_fail`
against the pipeline; lenient treats them as inconclusive. So **only 3 of 169 reproductions
(1.8%) are positively contradicted**, and lenient precision is 0.979.

tcpdump — whose reproducer is an **ASan crash** — is the cleanest signal (1.000 lenient and
1.000 recall, 0 `nondiscrim`); openssl/glibc use assertion-based regression tests with no ASan, so their
`vplus_fail` rate (and thus the strict/lenient gap) is higher. **3 false negatives** are
reproductions the pipeline conservatively routed to manual that the oracle *confirms* are
genuine (openssl CVE-2021-3711 and CVE-2023-0217, glibc CVE-2012-3480). `UNCONFIRMABLE` = the oracle could not
construct the differential (fix has no source/test, or old-glibc/openssl builds the
independent harness couldn't reproduce); these do not count for or against the pipeline.
