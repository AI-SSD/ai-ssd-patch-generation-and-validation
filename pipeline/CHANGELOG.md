# Changelog

All notable changes to the AI-SSD Patch Generation & Validation Pipeline will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project loosely adheres to Semantic Versioning principles.

## [0.3.3] - 2026-04-10

### Added

- **Alternative PoC fallback for Phase 1**: `CVEImageBuilder.build_cve_image()` now discovers alternative PoC files matching `{CVE}_*{ext}` and copies them into the Docker build context; `_generate_alt_poc_section()` was added to generate a Dockerfile fallback section that attempts multiple gcc variants for each alternative PoC.

### Fixed

- **CVE-2017-1000366 reproduction**: Primary PoC compilation failures (missing generated headers and broken preprocessor directives) are now handled gracefully — when alternatives exist the Dockerfile emits a warning instead of `exit 1` and tries alternative PoCs.
- **`main()` wrapper detection**: Broadened the `grep` used to detect `main()` to avoid injecting duplicate `main()` functions in wrappers.
- **i386 pattern fix**: corrected `%%eax` → `%eax` in i386 grep logic.
- **COMPILE_OK guard**: Replaced subshell-guard logic with file-based checks (`[ -f /poc/exploit ]`) to avoid race/exit issues.
- **Strategy precedence**: Fixed grouping for Strategy 5 so compound commands are evaluated correctly.
- **Container timeout semantics**: Container run timeouts now return `True` when a hang is observed (DoS reproduction), so the pipeline records hang-based successes correctly.
- **Dockerfile ordering bug**: Ensured the alternative PoC section is inserted before `ENV`/`CMD` lines in generated Dockerfiles.

### Changed

- `orchestrator.py`: `_generate_dockerfile()` now accepts `alt_poc_filenames`; new `_generate_alt_poc_section()` added; `build_cve_image()` discovers and copies alternative PoCs.
- **Tests/verification**: Local Docker build for `CVE-2017-1000366` shows the primary PoC fails (as expected) and the alternative `CVE-2017-1000366_poc1.c` compiles successfully; image exports cleanly.
- **Syntax check**: `orchestrator.py` passes `py_compile` checks (no syntax errors).

### Impact

- These changes increase Phase 1 PoC reproduction robustness and should improve the overall success rate (observed 5/6 → expected 6/6 for current test set).

## [0.3.2] - 2026-04-02

### Changed

- **Unified runtime configuration for Phases 1-4**: Consolidated pipeline runtime settings into a single `config.yaml` source of truth, replacing scattered per-file constants and fallback values.
- **Central config loader introduced**: `master_pipeline/config.py` now provides shared config accessors (`load_pipeline_config`, `get_config`, `cfg_section`, `reload_config`) and module-level defaults derived directly from `config.yaml`.
- **Master pipeline defaults now config-driven**:
  - `master_pipeline/cli.py` argparse defaults (`--phase0-config`, `--build-timeout`, `--run-timeout`) are loaded from `config.yaml`.
  - `master_pipeline/executor.py` phase timeouts and output directory discovery now use `config.yaml` sections (`phase_timeouts`, `paths`).
  - `master_pipeline/orchestrator.py` LLM endpoint resolution and health-check payload settings now read from the `llm` section in `config.yaml`.
- **Phase scripts aligned to shared config**:
  - `patch_generator.py` now initializes endpoint, models, timeouts, context size, GPU wait timeout, and output/input paths from shared config loading.
  - `patch_validator.py` now loads OS mappings, CVE mappings, timeout defaults, and key paths from `config.yaml`.
  - `reporter.py` now resolves reports/results/patches/validation/logs directories from `config.yaml`.
- **Schema expansion in `config.yaml`**: Added/standardized sections for `phase_timeouts`, `paths`, `llm.health_check`, `validation`, `feedback_loop`, `manual_verification`, and `cve_mappings` to support end-to-end modular configuration.

### Fixed

- **Config drift between code and YAML defaults**: Eliminated mismatches where Python defaults diverged from YAML values (for example retry/timeouts/model-related parameters) by enforcing centralized config reads.
- **Hardcoded directory and endpoint usage**: Removed repeated hardcoded directory names and endpoint assumptions in Phase 1-4 code paths in favor of config-backed resolution.

### Verified

- **Refactor integrity checks passed**: Updated modules were validated with Python AST parse checks and an end-to-end config load/import verification to confirm values are correctly read from `config.yaml`.

## [0.3.1] - 2026-04-02

### Changed

- **Codebase cleanup & deprecation**: Traced the full execution flow from the `python3 pipeline` entry point and built a dependency graph of all actively used modules, scripts, configs, and data files. Moved the following unused files and directories into a new `deprecated/` folder inside `pipeline/`:
  - `glibc_cve_aggregator.py` — empty file, superseded by the `cve_aggregator/` package.
  - `llm-endpoint.py` — standalone LLM test script, not imported or called by any active module.
  - `random.txt` — ad-hoc command-line notes.
  - `docker-debug.txt` — Docker troubleshooting notes.
  - `implementation/` — implementation plan documents (`phase1_implementation.md` through `phase4_implementation.md`, `pipeline_implementation.md`); not referenced by any runtime code.
- **Directory reorganization**:
  - Non-code methodology and documentation files (`image.png`, `methodology.xml`, `phase0-methodology.xml`, `phase0-methodology-v2.xml`, `phase0-methodology-v2.pdf`, `module_descriptions.txt`) were moved from `cve_aggregator/` (a Python package) into `documentation/`.
  - All Phase 0 and Phase 1 generated output files (`glibc_cve_poc_complete.csv`, `glibc_cve_poc_map.json`, `glibc_cve_poc_map_filtered.json`, `image_manifest.json`, `manual_review_queue.json`, `poc_repair_report.json`, `syntax_validation_report.json`) were moved from the pipeline root into `results/`. Updated `cve_aggregator/glibc_config.yaml` and the `orchestrator.py` default constant to write these files to `results/` on subsequent runs.
- **README updated**: Revised the project structure diagram to reflect the streamlined layout.

## [0.3.0] - 2026-04-01

### Added

- **Phase 0 → Phase 1 transition**: Analysed output/input contract between phases; `OutputGenerator` now emits `glibc_version` and `poc_index` columns so Phase 1's `Phase0CSVParser` can resolve Ubuntu build versions without falling back to undefined values.
- **Fully project-agnostic pipeline**: Removed every glibc-specific constant from `orchestrator.py` (`GLIBC_LOCAL_PATH`, `GLIBC_REMOTE_URL`, `PHASE0_CSV_PATH`, `BASE_IMAGE_PREFIX`, `GLIBC_TO_UBUNTU_MAP`, `GLIBC_COMMIT_ERA_MAP`, `COMMIT_OS_MAPPING`, `CVE_YEAR_HINTS`). All project-specific settings (repo URL, Docker image prefix, source/build/install dir names, commit-era→Ubuntu map) now live exclusively in the project YAML config under a `phase1:` block. Switching projects requires only a new YAML file, zero Python changes.
- **`phase1:` config section** added to `cve_aggregator/glibc_config.yaml` and `cve_aggregator/aggregator_config.yaml` with `project_repo_local_path`, `project_repo_remote_url`, `docker_base_image_prefix`, `docker_cve_image_prefix`, `source_dir_name`, `build_dir_name`, `install_prefix`, and `commit_era_map`.
- **GPU/CPU acceleration detection**: Both `cve_aggregator/modules/poc_repair.py` and `patch_generator.py` now call Ollama's `GET /api/ps` endpoint at startup and after the first successful inference. Warnings are emitted for CPU-only (`size_vram == 0`) or partially GPU-accelerated models, including a remediation hint. Models already at full VRAM are confirmed with a success log.
- **Prompt engineering improvements for PoC repair**:
  - Language mismatch detector (`_detect_language_mismatch`) skips files that are clearly prose or shell scripts mislabelled as C, avoiding wasted LLM calls.
  - Error classifier (`_classify_errors`) categorises compiler errors into scraping damage, missing declarations, platform mismatches, and other; the prompt now includes a targeted "ERROR ANALYSIS" section.
  - LLM preamble stripper (`_strip_llm_preamble`) post-processes responses to remove `# FIX:` / `// FIX:` lines that the model adds despite instructions.
  - Cross-platform awareness added: prompts now note that validation runs on macOS while PoCs target Linux, with guidance to use `#ifdef` stubs for Linux-only symbols.
  - Header-addition policy relaxed from "never add headers" to "may add standard library headers when clearly missing; do not add third-party dependencies".
  - Temperature escalation per retry reduced from +0.2 (cap 0.9) to +0.1 (cap 0.5) to prevent hallucination at high temperatures.
- **`poc_index` and `glibc_version` columns** added to `csv_fields` in both YAML configs.
- **Repaired PoC language update**: `PoCRepairLLM` now updates `exploit.language` in-place when the original language was `"unknown"` or `"text"`, so downstream modules see the correct language after repair.

### Fixed

- **Ollama health check**: Both `poc_repair.py` and `patch_generator.py` were POSTing to `/api/chat` as a health check. On CPU inference this always timed out (>30 s), falsely reporting the server as unreachable. Health check now uses `GET /api/tags`, which responds in microseconds regardless of inference load.
- **Repaired PoCs incorrectly listed as needing manual review**: `OutputGenerator._build_csv_row` now consults `poc_repair_report` as an authoritative override; a successfully repaired PoC forces `needs_manual = False` regardless of `syntax_results`.
- **`"text"` language not treated as auto-detectable**: `OutputGenerator` only auto-detected language for `"unknown"` exploits, not `"text"`. Files with `language="text"` therefore always received `.txt` extension and were unconditionally marked `needs_manual = True`, overriding the repair. Now `"unknown"` and `"text"` are both treated as auto-detectable.
- **Repaired PoCs remaining in `manual_supervision/`**: `PoCRepairLLM` cleanup now removes both the indexed pattern (`{cve_id}_{idx}{ext}`) created by `SyntaxValidator` **and** the bare pattern (`{cve_id}{ext}`) created by the master pipeline's `_generate_syntax_report`, along with `.validation.json` and `.ok` marker files.
- **Approved PoCs not moved to `exploits/`**: `master_pipeline/orchestrator.py`'s `_approve_cves` and `_check_marker_files` now copy PoC source files from `manual_supervision/` to `exploits/` and remove all related `manual_supervision/` files for approved CVEs. Only CVEs excluded via option `[E]` retain files in `manual_supervision/`.
- **`DictWriter` crash on `manual_verified_at`**: Both CSV write-back paths in `master_pipeline/orchestrator.py` now use `extrasaction='ignore'` to prevent `ValueError` when the extra `manual_verified_at` field was added to rows without updating `fieldnames`.
- **`# FIX:` comment causing self-inflicted syntax errors**: The retry prompt previously instructed the LLM to start its response with `# FIX: previous attempt...`. In C, `#` starts a preprocessor directive, so every retry's first line was an invalid directive. Retry prompt no longer includes this instruction.

### Changed

- **`BaseImageBuilder` and `CVEImageBuilder`**: Dockerfile templates now use `{source_dir}`, `{build_dir}`, and `{install_prefix}` placeholders instead of hardcoded `glibc-src`, `glibc-build`, and `/opt/glibc-vulnerable`. Values are injected from the project YAML at build time.
- **`GlibcRepoManager` renamed to `ProjectRepoManager`**: Log messages now use `self.repo_path.name` dynamically.
- **`resolve_build_ubuntu_version`**: Now accepts an explicit `commit_era_map` argument sourced from YAML; year bounds clamp to the map's actual min/max instead of hardcoded values.
- **`api_timeout` reverted to 120 s** (from 600 s CPU workaround) now that GPU inference is restored.
- **`num_ctx` and `max_poc_chars`** config knobs reverted to `0` (server defaults / no truncation) as GPU inference handles full context natively.

## [0.2.0] - 2026-03-26

### Added

- **LLM PoC Repair (Module 6)**: Integrated a new automated repair stage using Ollama-compatible LLMs to fix syntax errors in PoCs before output generation.
- **Domain-Specific Prompt Engineering**: Implemented advanced, context-aware prompts for Module 6 that handle common ExploitDB scraping artifacts (prose noise, missing preprocessor '#' characters, HTML entities) and include language-specific guidance for C, Python, Shell, Ruby, Perl, and PHP.

### Fixed

- **Module 6 Robustness**: Enhanced LLM output parsing to handle stray markdown fences and added a reasoning-based retry loop that surfaces previous failures to the model.

## [0.1.0] - 2026-03-22

### Added

- **Dynamic Phase 0 Configuration**: Master pipeline now accepts a `--phase0-config` argument (defaulting to `cve_aggregator/glibc_config.yaml`) to decouple Phase 0 execution from hardcoded paths.
- **Enhanced DRY_RUN Logs**: Master pipeline configuration logs and `--dry-run` headers now explicitly print the active Phase 0 config path.

### Fixed

- **Duplicate CVE Reports**: Fixed a presentation bug in the master pipeline interactive menu (`_get_pending_manual_cves`) where duplicate CVE IDs were printed when the CVE mapped to multiple exploits.
- **Validation Report Integration**: Updated the master pipeline's `_generate_missing_reports`, `_show_syntax_reports`, and `_interactive_view_report` methods to natively parse and display the `*.validation.json` files generated by the modular `cve_aggregator`, preventing the generation of redundant "MISSING POC" default text files.

### Changed

- **Pipeline Architecture**: Successfully modularized the legacy monolithic `pipeline.py` script into the organized `master_pipeline` Python package, mirroring the modular standard set by the `cve_aggregator`.
