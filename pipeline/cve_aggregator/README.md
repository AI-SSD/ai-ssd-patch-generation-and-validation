# CVE Aggregator (Phase 0)

The **CVE Aggregator** is the foundational "Phase 0" module of the AI-SSD Patch Generation & Validation Pipeline. It is a highly modular, project-agnostic framework designed to automatically construct a high-quality dataset of security vulnerabilities mapped directly to their corresponding git commits and Proof-of-Concept (PoC) exploit scripts.

## 🎯 Purpose

To train or validate AI models for automated vulnerability repair, you need three critical pieces of data for every vulnerability:
1. **Metadata:** What is the vulnerability? (CVE ID, CVSS, CWE, Description)
2. **Context:** What code was changed to fix it? (The vulnerable function and the patched function from the project's source code history)
3. **Validation:** How do we prove it exists? (A functional PoC script that triggers the vulnerability — or, when no public PoC exists, the regression test the fixing commit itself introduces)

The CVE Aggregator automates the collection, validation, and structuring of this triad.

## 🏗️ Architecture & Modules

The aggregator operates as a sequence of discrete, decoupled modules. They communicate by passing a shared `context` dictionary sequentially from one module to the next.

1. **`CVEFetcher`**: Queries the NVD 2.0 API (and optionally CVE.org) using project-specific keywords to retrieve base CVE metadata. It deduplicates and filters out irrelevant results (e.g., look-alike projects).
2. **`CommitDiscovery`**: Clones the target project's Git repository and searches the commit history to find the exact commit that fixed the CVE. It then extracts the parent (vulnerable) commit and the specific C/C++/Java/C# functions that were modified.
3. **`PoCMapper`**: Clones the [Exploit Database](https://github.com/offensive-security/exploitdb) and maps CVEs to available PoC scripts. It extracts the full source code of the exploit.
4. **`DataAggregator`**: Merges all fetched metadata, git state, and PoC data into a unified, version-controlled JSON structure (`Dataset`).
5. **`SyntaxValidator`**: Analyzes the extracted PoC scripts using language-native tools (`gcc`/`g++ -fsyntax-only`, `javac`, Mono `mcs`, `py_compile`, `bash -n`, `ruby -c`, `perl -c`, `php -l`). Invalid scripts are automatically flagged for manual review.
6. **`PoCRepairLLM`**: Uses an LLM (Ollama or OpenAI) to automatically repair syntax errors and scraping artifacts in invalid PoC scripts.
7. **`OutputGenerator`**: Exports the final, clean data into a global JSON file, a filtered JSON file, a structured CSV (`cve_poc_complete.csv`), and standalone exploit files (`exploits/`).

### Shared Utilities (`cve_aggregator/utils/`)

In addition to the core pipeline modules, the aggregator package contains shared utilities consumed by the wider pipeline:

- **`build_lock`**: Host-global flock-based counting semaphore that caps concurrent Docker builds (`SSD_BUILD_SLOTS`). Crash-safe — the OS frees slots on process exit.
- **`gpu_lock`**: Host-global GPU serialization (multi-slot semaphore) ensuring concurrent cells don't thrash the shared Ollama model.
- **`gpu_monitor`**: Remote Ollama GPU residency gate (`evict`/`wait`/`off` modes) — ensures a model is only loaded when a GPU is free, preventing CPU offload.
- **`gpu_slots`**: Multi-GPU slot detection and live polling — probes how many GPUs are available and publishes slot counts for all GPU-aware components.

## ⚙️ Configuration

The aggregator is entirely driven by YAML configuration files. This allows you to point the pipeline at any open-source project without changing Python code.

Configurations are stored in `pipeline/cve_aggregator/`. Thirteen project configs ship today (12 C/C++ projects plus Apache Tomcat for Java), alongside a generic `aggregator_config.yaml` template; for example:
- `glibc_config.yaml` (GNU C Library)
- `kernel_config.yaml` (Linux Kernel)
- `openssl_config.yaml`, `ffmpeg_config.yaml`, `libxml2_config.yaml`, … (further C/C++ projects)
- `tomcat_config.yaml` (Apache Tomcat — Java)

### Creating a Custom Configuration
To adapt the aggregator to a new project, duplicate `aggregator_config.yaml` and update the relevant sections:
- `project.name`: The project slug.
- `cve_fetcher.keywords`: The terms used to search NVD.
- `commit_discovery.repo_url`: The Git URL of the source code.
- `phase1.*`: Define how the downstream Docker reproduction container should be built (build system, source directory, etc.).

## 🚀 Usage

You can run the CVE Aggregator independently from the main pipeline.

### Full Execution
```bash
cd pipeline
python3 -m cve_aggregator --config cve_aggregator/glibc_config.yaml
```

### Partial Execution (Skip Modules)
If you already fetched data from NVD and only want to re-run the commit discovery and subsequent steps:
```bash
python3 -m cve_aggregator --config cve_aggregator/glibc_config.yaml --skip CVEFetcher
```

### Fast Data Re-Export
If you only want to regenerate the output CSV or PoC files from the existing `results/cve_poc_map.json` without re-running any data collection or validation logic:
```bash
# Re-export both CSV and PoC files
python3 -m cve_aggregator --config cve_aggregator/glibc_config.yaml --export-csv

# Re-export only PoC files
python3 -m cve_aggregator --config cve_aggregator/glibc_config.yaml --export-poc
```

## 📁 Outputs

All outputs are generated in the `pipeline/results/` directory (or wherever configured).

- **`*_cve_poc_complete.csv`**: The primary tabular output. Each row represents a vulnerable code unit mapped to a specific PoC. This is the main input file for the downstream `orchestrator.py` (Phase 1).
- **`*_cve_poc_map.json`**: The complete, un-filtered dataset containing every CVE fetched from NVD.
- **`*_cve_poc_map_filtered.json`**: A pruned dataset containing only CVEs that successfully mapped to *both* a Git commit and a PoC.
- **`pipeline/exploits/`**: Directory containing the successfully validated and extracted standalone PoC scripts (e.g., `CVE-2015-7547.c`).
- **`pipeline/manual_supervision/`**: Directory containing PoCs that failed automated syntax validation and could not be repaired by the LLM. These require human review.

## 🛠️ Manual Supervision Workflow

Because ExploitDB PoCs are often scraped from PDFs or websites, they frequently contain prose, missing preprocessor directives, or formatting errors. 

1. If a PoC fails automated validation (Module 5) and LLM repair (Module 6), it is placed in `pipeline/manual_supervision/`.
2. By default the master pipeline auto-excludes these pending CVEs (re-runnable later); set `manual_verification.auto_skip: false` in `config.yaml` for an interactive review menu, or simply inspect the files yourself.
3. Fix the syntax errors in the script.
4. From the main pipeline interactive menu, you can approve the CVE, which moves the fixed PoC to `pipeline/exploits/` and updates the CSV. Alternatively, you can drop an empty `.ok` file next to it (e.g., `CVE-2015-7547.ok`) and the pipeline will automatically process it on the next run.