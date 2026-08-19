# AI-SSD Pipeline

Automated vulnerability reproduction, patching, and validation pipeline. It is **project-agnostic** and configuration-driven — targeting a new C/C++ project needs only a YAML config (configs ship for glibc, the Linux kernel, OpenSSL, FFmpeg, libxml2, libtiff, pcre2, expat, gnutls, tcpdump, file, libtasn1, plus a Java config for Apache Tomcat). The pipeline is composed of 5 phases that run sequentially with an optional self-healing feedback loop.

## Phases

| Phase | Script | Description |
|-------|--------|-------------|
| **0 – Data Aggregation** | `cve_aggregator/` | Scrape NVD/CVE.org, cross-reference ExploitDB, extract PoCs — or, for CVEs without a public PoC, harvest the fixing commit's own regression test — validate syntax, attempt LLM-based repair of invalid PoCs, and export datasets. Produces `<project>_cve_poc_complete.csv`. |
| **1 – Reproduction** | `orchestrator.py` | Build era-matched Docker images per CVE and reproduce each vulnerability — running its ExploitDB PoC, or its harvested regression test — capturing a **deterministic baseline** in `image_manifest.json`. |
| **2 – Patch Generation** | `patch_generator.py` | Generate candidate patches with an LLM, as minimal SEARCH/REPLACE edits. |
| **3 – Patch Validation** | `patch_validator.py` | Rebuild the patched source incrementally from the Phase 1 image, re-run the exploit/test against the baseline, and run host-side SAST (gating only on patch-introduced findings). |
| **4 – Reporting** | `reporter.py` | Collect results and generate final report. |

## Host requirements (kernel) — important for old-glibc CVEs

Phase 1 reproduces a CVE by building the project from source and then either
running its ExploitDB PoC or its in-tree regression test against that build. For
glibc this exposes a **host-kernel constraint** that is easy to miss because the
pipeline runs in Docker.

**Docker isolates userspace, not the kernel.** Every container shares the *host's*
single Linux kernel — there is no kernel inside an image. The pipeline can (and does)
build each CVE on an era-matched Ubuntu userspace (Gate B picks the base from the
checked-out tree's glibc version), but the kernel underneath is always the host's.

**The incompatibility is one-directional:**

| Combination | Result |
|---|---|
| New glibc on an **old** kernel | ✅ works (glibc is backward-compatible down to a low minimum kernel) |
| Old glibc on a **new** kernel | ❌ the dynamic loader (`ld.so`) **SIGSEGVs at process startup** |

The crash is in glibc's loader ↔ kernel interface: old glibc (≤ ~2.34) resolves a
vDSO symbol (e.g. `__vdso_clock_gettime`) against a newer kernel's vDSO than it was
written for, and faults in `setup_vdso_pointers` *before* the test's `main()` runs.
The exit code looks like a test failure but has nothing to do with the CVE. Observed
cutoff: glibc **≤ 2.34 crash on kernel 5.15 / 6.8**; **≥ 2.36 work**. (Note: CVE
*date* is not a proxy for glibc version — e.g. CVE-2024-2961 is a backport to the
glibc 2.31 release branch, so it is "old glibc" despite the recent ID.)

**Gate A (runtime sanity check)** detects this automatically: before recording an
in-tree baseline it verifies the *built* runtime can start a trivial process; if not,
the CVE is routed to manual revision instead of recording a false "reproduced."

**Deployment recommendation:** to reproduce old-glibc CVEs, run the pipeline on a host
with an **era-appropriate (older) kernel** — e.g. **Ubuntu 20.04 (kernel 5.4)**. Because
the incompatibility is one-directional, a single old-kernel host runs **both** old and
new glibc, so no per-CVE host routing is required. On a modern-kernel host (5.15 / 6.8)
the old-glibc CVEs are correctly flagged by Gate A but cannot be reproduced. This is a
host/infra choice, not a code change — the pipeline itself stays project-agnostic.

*Caveats (kernel-independent, not fixed by an older host):* tests that pass on the
vulnerable build (non-discriminating / wrong fixing commit), CVEs with no PoC or no
recorded fixing commit, and the very oldest glibc (2.15/2.19) which may need a kernel
older than 5.4.

## Quick-Start

```bash
# Install dependencies
pip install -r requirements.txt

# Verify Docker, glibc repo, etc.
bash setup/verify_setup.sh
```

### Run the full pipeline (all phases)

```bash
python3 pipeline.py
```

### Run Phase 0 only (data aggregation)

```bash
python3 pipeline.py --phases 0
```

After Phase 0 completes, the pipeline produces `<project>_cve_poc_complete.csv`. CVEs whose PoC had syntax issues and could not be auto-repaired are flagged with `manual_review_required=True`. **By default (`manual_verification.auto_skip: true`) these pending CVEs are automatically excluded** so unattended runs never block; they can be reviewed and re-run later. To review them interactively, set `auto_skip: false` (or pass `--auto-skip-manual` off) to get a review menu after Phase 0, then either:

- **Edit the CSV directly**: set `manual_verified` to `done` for reviewed CVEs, or
- **Create marker files**: `mkdir -p manual_supervision && touch manual_supervision/CVE-XXXX-YYYY.ok`

### Re-run skipped CVEs

```bash
python3 pipeline.py --cves CVE-2015-7547,CVE-2014-5119
```

### Dry run (no Docker builds)

```bash
python3 pipeline.py --dry-run
```

### Manual verification mode

By default (`manual_verification.auto_skip: true` in `config.yaml`) the pipeline never blocks — pending CVEs are auto-excluded and can be re-run later. To review them interactively instead, set `manual_verification.auto_skip: false` in `config.yaml`; Phase 0 then presents a review menu. The skipped CVEs can always be re-run on their own:

```bash
python3 pipeline.py --cves CVE-2015-7547,CVE-2014-5119
```

## Phase 1: Optimized Image Workflow

When Phase 0's CSV (`<project>_cve_poc_complete.csv`) is detected, Phase 1 uses an optimized workflow:

1. **Pre-update glibc** — `git fetch --all && git pull` once (fail-fast).
2. **Build base images** — One per `ubuntu_version` (e.g., `ai-ssd/glibc-base:ubuntu-16.04`). Reused across CVEs.
3. **Build CVE images** — Lightweight derived images (`FROM base`) with `git checkout <commit>`, glibc build, and PoC copy. Tagged `ai-ssd/glibc-cve:CVE-XXXX-YYYY-16.04`.
4. **Persist images** — Images are **not** deleted; they are reused by Phase 3 for patched validation.
5. **Write manifest** — `image_manifest.json` tracks all base/CVE images with metadata.

If Phase 0 CSV is not found, Phase 1 falls back to the legacy per-CVE Dockerfile workflow.

Phase 1 uses a **deterministic-baseline** reproduction model (methodology v2/v3). The container wrapper does not judge success itself — it runs the PoC and exits with the exploit's *own* exit code. On the known-vulnerable build that exit code, validated across multiple runs to filter out non-deterministic crashes, is captured as the vulnerability's **baseline signature** in `image_manifest.json`, and Phase 3 later judges a patch by comparison against it. Two gates guard the baseline's integrity:

1. **Build-linkage (honesty) gate** — a linkage probe confirms the compiled PoC actually exercises the project's *own* build rather than the system libraries; if not, the case is routed to manual revision, after first attempting recovery rebuilds on the previous era's toolchain and then on a 32-bit (i386) toolchain.
2. **Negative filter** — the PoC's output is scanned (an LLM with a deterministic regex fallback) for explicit evidence the exploit did *not* work; a flagged run is routed to manual revision instead of recording a false baseline.

> The earlier two-gate exit-`42`/`43` wrapper design has been retired and archived under `deprecated/` (`orchestrator_phase1_gates.py`, `poc_analyzer.py`).

### Run Phase 1 standalone

```bash
python3 orchestrator.py                             # auto-detects Phase 0 CSV
python3 orchestrator.py --phase0-csv /path/to/csv   # explicit path
python3 orchestrator.py --cve CVE-2015-7547         # single CVE
python3 orchestrator.py --dry-run                   # print plan without building
python3 orchestrator.py --cleanup --verbose          # cleanup containers (not images)
python3 orchestrator.py --skip-cves CVE-A,CVE-B     # skip specific CVEs
```

## Tests

```bash
cd pipeline
python3 -m pytest tests/ -v
```

## Project Structure

```
pipeline/
├── pipeline.py                  # Entry point (wraps master_pipeline)
├── master_pipeline/             # Core orchestrator package (phases 0–4 coordination)
│   ├── config.py                # Shared configuration loader
│   ├── executor.py              # Phase executor with idle-watchdog
│   ├── orchestrator.py          # Master orchestrator (phase sequencing + feedback loop)
│   ├── feedback.py              # Feedback-loop context assembly
│   ├── intree.py                # Container-timeout policy for in-tree regression tests
│   ├── contamination.py         # Training-data contamination filter (Phase 2 scope gate)
│   └── candidates.py            # Candidate fan-out framework (over-generate-and-validate)
├── cve_aggregator/              # Phase 0: Data aggregation package
│   ├── modules/                 # Aggregator pipeline modules
│   └── utils/                   # Shared utilities
│       ├── build_lock.py        # Host-global build semaphore (flock-based)
│       ├── gpu_lock.py          # Host-global GPU serialization (multi-slot semaphore)
│       ├── gpu_monitor.py       # Remote Ollama GPU residency gate (evict/wait/off)
│       └── gpu_slots.py         # Multi-GPU slot detection and live polling
├── orchestrator.py              # Phase 1: Docker env build + PoC execution
├── patch_generator.py           # Phase 2: LLM patch generation
├── patch_validator.py           # Phase 3: Patch validation
├── reporter.py                  # Phase 4: Reporting
├── cleanup.py                   # Artifact cleanup utility
├── config.yaml                  # Pipeline configuration
├── requirements.txt             # Python dependencies
├── profiles/                    # LLM model profiles (.env files)
├── groundtruth/                 # Independent reproduction oracle (V−/V+ differential)
│   ├── run_groundtruth.py       # Oracle harness
│   ├── reconcile_gt.py          # Verdict reconciliation → confusion matrix
│   └── inputs/                  # Per-project oracle inputs
├── setup/                       # Environment setup utilities
│   ├── setup.sh                 # Environment setup
│   ├── verify_setup.sh          # Setup verification
│   └── fix_containerd.sh        # Docker/containerd recovery helper
├── run_all.sh                   # Multi-project benchmark runner (pipelined sweep mode)
├── run_project.sh               # Single-project tmux launcher
├── glibc/                       # Local glibc repository
├── exploit-database/            # Local ExploitDB clone
├── exploits/                    # PoC exploit files (approved from manual_supervision)
├── manual_supervision/          # PoC files pending manual review + .ok marker files
├── documentation/               # Reference data and methodology docs
│   ├── file-function.csv        # Vulnerable function→file mapping (used by phases 2–3)
│   ├── groundtruth-validation-methodology.md  # Ground-truth oracle methodology
│   ├── groundtruth-validation-results.md      # Ground-truth validation results
│   ├── module_descriptions.txt  # Phase 0 module descriptions
│   ├── image.png                # Pipeline diagram image
│   ├── methodology.xml          # CVE aggregator methodology diagram
│   ├── phase0-methodology.xml   # Phase 0 methodology diagram
│   ├── phase0-methodology-v2.*  # Phase 0 methodology v2 (XML + PDF)
│   └── proposal-technical.pdf   # Technical proposal document
├── results/                     # All generated outputs from pipeline runs
│   ├── glibc_cve_poc_complete.csv        # Phase 0 primary output (input to Phase 1)
│   ├── glibc_cve_poc_map.json            # Full CVE dataset (Phase 0)
│   ├── glibc_cve_poc_map_filtered.json   # Filtered CVE dataset (Phase 0)
│   ├── image_manifest.json               # Docker image registry (Phase 1)
│   ├── syntax_validation_report.json     # PoC syntax validation results
│   ├── poc_repair_report.json            # LLM PoC repair results
│   ├── manual_review_queue.json          # PoCs queued for manual review
│   └── pipeline_run_*.json               # Per-run execution summaries
├── logs/                        # Pipeline log files
├── tests/                       # Unit and integration tests
└── deprecated/                  # Archived files not part of the active execution flow
    ├── glibc_cve_aggregator.py  # Empty; replaced by cve_aggregator/ package
    ├── llm-endpoint.py          # Standalone LLM test script
    ├── random.txt               # Ad-hoc command notes
    ├── docker-debug.txt         # Docker troubleshooting notes
    └── implementation/          # Implementation plan documents
```

## Configuration

Key settings in `config.yaml` or CLI args:

| Setting | Default | Description |
|---------|---------|-------------|
| `--phases` | `0 1 2 3 4` | Which phases to run |
| `--manual-verify-timeout` | `1800` | Manual-review timeout (auto-skip is the default; see *Manual verification mode*) |
| `--manual-verify-poll` | `30` | Seconds between marker-file checks |
| `--build-timeout` | `3600` | Docker build timeout per image |
| `--run-timeout` | `300` | Container execution timeout |
| `--dry-run` | `False` | Print plan without executing |
| `--cleanup` | `False` | Remove containers after execution (images preserved) |
| `contamination_filter.enabled` | `true` | Restrict Phase 2 to post-training-cutoff CVEs (env: `SSD_CONTAMINATION_FILTER=1\|0`) |
| `llm.gpu_exclusive` | `evict` | GPU residency gate mode: `evict`, `wait`, or `off` (env: `SSD_GPU_EXCLUSIVE`) |
| `llm.gpu_slots` | `auto` | Number of concurrent GPU slots (env: `SSD_GPU_SLOTS`) |
| `SSD_BUILD_SLOTS` | *(unset)* | Cap concurrent Docker builds host-wide (env only; 0/unset = unbounded) |

