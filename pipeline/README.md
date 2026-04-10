# AI-SSD Pipeline

Automated vulnerability reproduction pipeline for glibc CVEs. The pipeline is composed of 5 phases that run sequentially with an optional feedback loop.

## Phases

| Phase | Script | Description |
|-------|--------|-------------|
| **0 – Data Aggregation** | `cve_aggregator/` | Scrape NVD/CVE.org, cross-reference ExploitDB, extract PoCs, validate syntax, attempt LLM-based repair of invalid PoCs, and export datasets. Produces `glibc_cve_poc_complete.csv` for manual review. |
| **1 – Docker Env Build** | `orchestrator.py` | Build Docker images per CVE and execute PoC exploits to reproduce vulnerabilities. |
| **2 – Patch Generation** | `patch_generator.py` | Generate candidate patches using LLM. |
| **3 – Patch Validation** | `patch_validator.py` | Apply patches inside Docker and validate via test execution. |
| **4 – Reporting** | `reporter.py` | Collect results and generate final report. |

## Quick-Start

```bash
# Install dependencies
pip install -r requirements.txt

# Verify Docker, glibc repo, etc.
bash verify_setup.sh
```

### Run the full pipeline (all phases)

```bash
python3 pipeline.py
```

### Run Phase 0 only (data aggregation)

```bash
python3 pipeline.py --phases 0
```

After Phase 0 completes, the pipeline produces `glibc_cve_poc_complete.csv`. CVEs whose PoC had syntax issues are flagged with `manual_review_required=True`. You have **30 minutes** (configurable) to review them before the pipeline continues:

- **Edit the CSV directly**: set `manual_verified` to `done` for reviewed CVEs.
- **Create marker files**: `mkdir -p manual_supervision && touch manual_supervision/CVE-XXXX-YYYY.ok`

CVEs not verified within the timeout are skipped and can be re-run later.

### Re-run skipped CVEs

```bash
python3 pipeline.py --cves CVE-2015-7547,CVE-2014-5119
```

### Dry run (no Docker builds)

```bash
python3 pipeline.py --dry-run
```

### Adjust manual verification timeout

```bash
python3 pipeline.py --manual-verify-timeout 3600   # 60 min
python3 pipeline.py --manual-verify-poll 60          # poll every 60s
```

## Phase 1: Optimized Image Workflow

When Phase 0's CSV (`glibc_cve_poc_complete.csv`) is detected, Phase 1 uses an optimized workflow:

1. **Pre-update glibc** — `git fetch --all && git pull` once (fail-fast).
2. **Build base images** — One per `ubuntu_version` (e.g., `ai-ssd/glibc-base:ubuntu-16.04`). Reused across CVEs.
3. **Build CVE images** — Lightweight derived images (`FROM base`) with `git checkout <commit>`, glibc build, and PoC copy. Tagged `ai-ssd/glibc-cve:CVE-XXXX-YYYY-16.04`.
4. **Persist images** — Images are **not** deleted; they are reused by Phase 3 for patched validation.
5. **Write manifest** — `image_manifest.json` tracks all base/CVE images with metadata.

If Phase 0 CSV is not found, Phase 1 falls back to the legacy per-CVE Dockerfile workflow.

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
├── cve_aggregator/              # Phase 0: Data aggregation package
├── orchestrator.py              # Phase 1: Docker env build + PoC execution
├── patch_generator.py           # Phase 2: LLM patch generation
├── patch_validator.py           # Phase 3: Patch validation
├── reporter.py                  # Phase 4: Reporting
├── cleanup.py                   # Artifact cleanup utility
├── config.yaml                  # Pipeline configuration
├── requirements.txt             # Python dependencies
├── setup.sh                     # Environment setup
├── verify_setup.sh              # Setup verification
├── glibc/                       # Local glibc repository
├── exploit-database/            # Local ExploitDB clone
├── exploits/                    # PoC exploit files (approved from manual_supervision)
├── manual_supervision/          # PoC files pending manual review + .ok marker files
├── documentation/               # Reference data and methodology docs
│   ├── file-function.csv        # Vulnerable function→file mapping (used by phases 2–3)
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
| `--manual-verify-timeout` | `1800` (30 min) | Seconds to wait for manual CSV review |
| `--manual-verify-poll` | `30` | Seconds between marker-file checks |
| `--build-timeout` | `3600` | Docker build timeout per image |
| `--run-timeout` | `300` | Container execution timeout |
| `--dry-run` | `False` | Print plan without executing |
| `--cleanup` | `False` | Remove containers after execution (images preserved) |
