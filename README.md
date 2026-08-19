# AI-SSD Patch Generation & Validation Pipeline

An automated, end-to-end pipeline designed to reproduce, patch, and validate security vulnerabilities (CVEs) across software projects. While initially developed for `glibc`, the pipeline is **project-agnostic** and configuration-driven: targeting a new C/C++ project requires only a YAML config (configs ship for glibc, the Linux kernel, OpenSSL, FFmpeg, libxml2, and others). Its Phase 0 data aggregation additionally handles multiple languages, and a Java configuration (Apache Tomcat) is included.

This repository was created as part of the AI-SSD research project by the [Department of Computer Engineering at the Faculty of Sciences and Technology](https://www.uc.pt/fctuc/dei/), [University of Coimbra](https://www.uc.pt/).

## 🌟 Overview

The pipeline operates in five sequential phases, orchestrated by a central module, with a self-healing LLM feedback loop to iteratively improve generated patches.

| Phase             | Component              | Description                                                                                                                                                                                                                                                            |
| ----------------- | ---------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Phase 0** | `cve_aggregator/`    | **Data Aggregation**: Scrapes NVD/CVE.org, cross-references ExploitDB, extracts Proofs-of-Concept (PoCs) — or, for CVEs with no public PoC, harvests the fixing commit's own regression test — validates syntax, attempts LLM-based repair of invalid PoCs, and exports normalized datasets (CSV/JSON).                                               |
| **Phase 1** | `orchestrator.py`    | **Vulnerability Reproduction**: Builds Docker environments tailored to the target project (matching the appropriate Ubuntu version and compiler era), compiles the vulnerable code, and reproduces the issue via the PoC exploit or the regression test, capturing a deterministic baseline signature for later comparison.                      |
| **Phase 2** | `patch_generator.py` | **Patch Generation**: Uses local (Ollama) or external (OpenAI) LLMs to generate candidate patches for the vulnerable functions. A per-model training-data contamination filter restricts generation to CVEs published after the model's knowledge cutoff, and CWE-aware spear prompts tailor the system prompt to each vulnerability's weakness class.                                                                                                                                  |
| **Phase 3** | `patch_validator.py` | **Patch Validation**: Rebuilds the patched source incrementally from the Phase 1 image, re-executes the exploit/test and compares against the Phase 1 baseline to confirm mitigation, and runs host-side Static Application Security Testing (SAST) with a configurable, per-project tool set (for C: Cppcheck, Clang-Tidy, Semgrep, Flawfinder; for Java: Semgrep, PMD), failing a patch only when it introduces *new* findings. |
| **Phase 4** | `reporter.py`        | **Automated Reporting**: Aggregates all execution results, generates comprehensive Markdown reports, and produces Matplotlib visualizations comparing model performances.                                                                                        |

## ⚙️ Prerequisites & Setup

### 1. System Requirements

- **OS:** Linux or macOS (Validation runs best on Linux due to Docker requirements)
- **Docker:** Must be installed and running.
- **Python:** 3.10+
- **LLM Provider:**
  - **Local:** [Ollama](https://ollama.ai/) with models pulled (e.g., `qwen2.5-coder:7b`, `devstral:32k`).
  - **Cloud:** OpenAI API key (if using GPT models).

### 2. Installation

Clone the repository and run the automated setup script to install dependencies, SAST tools, and configure the workspace:

```bash
git clone <repository_url>
cd ai-ssd-patch-generation-and-validation/pipeline
sudo ./setup/setup.sh
```

*(Alternatively, you can manually install the Python dependencies using `pip install -r requirements.txt` inside a virtual environment).*

### 3. Verify Setup

Run the verification script to ensure all tools, directories, and dependencies are correctly configured:

```bash
./setup/verify_setup.sh
```

## 🚀 Running the Pipeline

You can run the entire pipeline autonomously using the master orchestrator, or you can run individual phases.

### Master Pipeline Execution

To run all phases sequentially with the self-healing feedback loop enabled:

```bash
cd pipeline
python3 -m master_pipeline
# Or using the wrapper:
python3 pipeline.py
```

### Running with tmux (Recommended for Long Runs)

For long-running executions, it is highly recommended to use `tmux` so that the pipeline continues running even if your SSH session disconnects. A helper script `run_project.sh` is provided to easily launch the pipeline for a specific project within its own `tmux` session.

To run the pipeline using `tmux`:

```bash
cd pipeline
# Usage: ./run_project.sh <project_name> [extra pipeline.py flags...]
./run_project.sh glibc --phases 0 1 2 3 4
```

To re-attach to the session later:

```bash
tmux attach -t glibc
```

*(To detach from the session and leave it running in the background, press `Ctrl-B` then `D`)*.

### Configuration

Global settings for timeouts, LLM models, and directories are managed in `pipeline/config.yaml`.
Project-specific configurations (e.g., for `glibc`, `linux-kernel`, `tomcat`) are managed in Phase 0 YAML configs like `pipeline/cve_aggregator/glibc_config.yaml`.

You can specify which Phase 0 config to use for your run:

```bash
python3 pipeline.py --phase0-config cve_aggregator/tomcat_config.yaml
```

### Running Specific Phases

You can limit the execution to specific phases using the `--phases` argument:

**Run pipeline on tmux:**

```
tmux new-session -s pipeline
tmux a -t pipeline
```

To exit tmux `Ctrl + B` then press `d`

To kill tmux `tmux kill-session`

**Run only Phase 0 (Data Aggregation):**

```bash
python3 pipeline.py --phases 0
```

Note: Phase 0 may flag some PoCs for manual review. By default (`manual_verification.auto_skip: true`) these are automatically excluded so unattended runs do not block, and can be re-run later; set `manual_verification.auto_skip: false` in `config.yaml` for an interactive review of `pipeline/manual_supervision/` instead.

**Run Patch Generation & Validation (Phases 2 and 3) for a specific CVE:**

```bash
python3 pipeline.py --phases 2 3 --cve CVE-2015-7547
```

### Self-Healing Feedback Loop

When Phase 3 determines that a generated patch failed to block the exploit or introduced new SAST findings, the pipeline can automatically cycle back to Phase 2. The LLM is provided with the specific failure context (build errors, PoC output, SAST warnings) to iteratively generate a better patch.

- To configure max retries: `python3 pipeline.py --max-retries 5`
- To disable feedback loop: `python3 pipeline.py --no-feedback-loop`

### Dry Run

To see what the pipeline *would* do without building images, executing code, or making API calls:

```bash
python3 pipeline.py --dry-run
```

## 🧹 Cleanup

To clean up generated artifacts (Docker images, containers, logs, results, patches):

```bash
cd pipeline
python3 cleanup.py --interactive
# Or clean everything forcefully:
python3 cleanup.py --force --all
```

## 📁 Key Directories

- `pipeline/cve_aggregator/`: Source code for Phase 0 and project configurations.
- `pipeline/master_pipeline/`: Source code for the orchestrator and feedback loop.
- `pipeline/groundtruth/`: Independent ground-truth reproduction oracle (V−/V+ differential validation).
- `pipeline/exploits/`: Verified PoC exploit scripts ready for execution.
- `pipeline/manual_supervision/`: PoCs needing human validation before proceeding.
- `pipeline/patches/`: LLM-generated source code patches.
- `pipeline/results/` & `pipeline/validation_results/`: JSON outputs and datasets from pipeline runs.
- `pipeline/reports/`: Final Markdown reports and charts from Phase 4.
- `pipeline/profiles/`: LLM model profiles (`.env` files) for benchmark campaigns.

## ⚠️ Warning

This pipeline executes downloaded Proof-of-Concept exploits. **It is strongly recommended to run all test cases inside isolated containers or virtualized environments.** The pipeline leverages Docker to isolate execution, but you must ensure your Docker daemon and host system are securely configured.
