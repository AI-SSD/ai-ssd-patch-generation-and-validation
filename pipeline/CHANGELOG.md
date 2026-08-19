# Changelog

All notable changes to the AI-SSD Patch Generation & Validation Pipeline will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project loosely adheres to Semantic Versioning principles.

## [Unreleased]

### Fixed

- **In-tree hangs are no longer silently dropped.** A CWE-835 infinite-loop CVE reproduces by *hanging*: the in-tree recipes bound themselves with `timeout` and map any non-zero rc (including 124) to `SSD_TEST_RESULT=FAIL`, which is the reproduction. Three defects stopped that ever working, and together they cost four tcpdump CVEs (`CVE-2017-12989`/`-12990`/`-12997`/`-13003`) in **all 19** tcpdump cells of the `2026-07-26_uniform-single-model-matrix` campaign — the campaign credited **zero** timeouts, in-tree or PoC.
  1. Every recipe called bare `timeout`, which only sends `SIGTERM`. A process spinning inside a parser ignores it, so the recipe's own budget was unenforceable. All 17 invocations across the 10 project configs now use `timeout -k 10`, escalating to `SIGKILL`.
  2. The container ceiling was a flat `run_timeout` (300 s) that sat **below** what nine of ten recipes declare (glibc's three-strategy cascade declares 320+320+320+1500), so Docker killed the shell before it could print any marker — for those projects an in-tree hang could *never* self-report. The ceiling is now derived per project as `sum(recipe-declared budgets) + margin`, clamped to `[intree_container_floor, intree_container_cap]` (new `master_pipeline/intree.py`; knobs in `config.yaml`). Nothing project-specific enters the Python: the budgets are parsed out of whatever recipe the YAML supplies, so a new project is covered as soon as its recipe is written.
  3. With no marker, Phase 1 filed the hang as an anonymous "build/run error". A container-ceiling hang is now labelled as such (new `ExecutionResult.timed_out`). It still routes to manual revision — once the ceiling wins there is no way to tell a hung test from a hung harness — but it is no longer invisible.
- **Phases 1 and 3 now run the in-tree test on the same clock.** Phase 1 used `run_timeout` (300 s) and Phase 3 `max(run_timeout, 600)`; a fail-to-pass oracle is only sound if the vulnerable and patched runs get the same budget. Both derive the identical number from the same recipe.
- **`failure_breakdown.timeouts` is no longer structurally zero.** It counted `ExecutionStatus.TIMEOUT`, which nothing in the tree assigns, so it read `0` while real hangs sat unlabelled inside `needs_manual_revision` — across the 57 archived cells it reports `0` against 95 timed-out runs. It now counts the `timed_out` flag for **non-reproduced** runs only, which keeps the breakdown a partition of the corpus (a hang the DoS branch credits is a success, not a failure). The memoized-baseline path derives the flag from the `-1` sentinel so a warm re-run reports the same figures as the cold run it reuses.
- **Both reproducer paths now detect a hang the same way.** The in-tree test and the ExploitDB PoC hit the identical container timeout, but each read it ad hoc, which is how they drifted apart. A single contract (`_timeout_banner` / `is_timeout_run` / `strip_timeout_banner`) now serves every site, and a regression test fails the build if any site re-derives it. Two PoC-path sites were silently uncovered and are now fixed: the **non-deterministic-baseline** branch (a hang that did not reach unanimity yields no baseline and was dropped into that bucket unlabelled) and the **i386 arch-fallback re-run** (a full PoC execution that can hang like any other, and which was still feeding the raw banner to the negative filter). The predicate also now requires the banner rather than trusting a bare `-1`, so an infrastructure error — image missing, daemon refused the run — is no longer mistaken for a hang.
- **The negative filter no longer judges the harness's own diagnostic.** On a PoC-path timeout the logs are prefixed with `TIMEOUT after Ns (PoC caused hang/deadlock). Partial output: …`; that banner was handed to the LLM negative filter, which read it as evidence the exploit failed and short-circuited the chain *before* the branch that credits a stable unanimous hang as a DoS reproduction — so that branch had never once fired. The banner is now stripped (on the main path and on the i386 re-run) and the explicit timeout policy decides. Observed outcomes are unchanged on the one archived case (glibc `CVE-2009-5029` is `poc_category=RCE`, outside the credited set, so it still routes to manual revision — with an accurate reason string).
- **The idle watchdog no longer guillotines a healthy in-tree run.** An in-tree test is a detached container the phase waits on in silence, so its whole ceiling is one quiet stretch; glibc's 2520 s ceiling would have tripped the 2400 s cap. Phases 1 and 3 raise their idle cap to `ceiling + intree_idle_build_allowance` (`master_pipeline/executor.py`). Projects with no in-tree recipe, and projects whose ceiling already fits, keep the tight cap unchanged.

> **Operational note:** the recipe text is hashed into `ai-ssd.intree_signature`, so adding `-k` invalidates every cached in-tree image; the next Phase 1 rebuilds them.

## [0.4.3] - 2026-06-27

Host-global GPU serialization, context-fit guards, and per-cell execution controls for the results dashboard, enabling safe multi-cell parallel execution.

### Added

- **Host-Global GPU Mutex (`gpu_lock`).** Implemented cross-process POSIX `flock` serialization around GPU-bound inference (Phase 2 generation and the iterative feedback loop). When running multiple concurrent projects/cells on a host, this prevents weight thrashing and VRAM contention on the shared local Ollama instance. Enabled via `gpu_lock: true` under `llm` in `config.yaml`, with overrides for remote OpenAI backends.
- **In-process Heartbeat Pulser.** Introduced a background thread `_HeartbeatPulser` in Phase 2 (`patch_generator.py`) to periodically refresh the live progress heartbeat during long-running LLM API calls, preventing the idle watchdog from false-killing healthy tasks.
- **Context-Fit Guard for PoC Repair.** Added checks querying Ollama's `/api/show` to find actual model context windows. Automatically skips repair attempts and advances to the next model in the ramp schedule if the combined prompt and expected output size exceed the usable context.
- **Separate-Commit Test Harvesting.** Added `find_cve_referencing_commits` to harvest regression tests from separate/sibling commits referencing the same CVE (e.g. OpenSSL CVE-2016-7055).
- **Per-Cell Dashboard Control.** Added project-level controls (Pause/Resume, Stop, and "Resume run" to restart failed/aborted cells) on the dashboard page, backed by subtree PID signal management and persistent control event auditing (`control_audit.log`).
- **Funnel Metrics Reconciliation.** Integrated new dashboard metrics (`task_cves`, `funnel_reproduced`, `skipped_distinct`) and detailed validation failure breakdowns (`failed_both`, `failed_poc_only`, `failed_sast_only`) to trace Phase 1 → Phase 2 → Phase 3 transitions accurately.

### Changed

- **Primary-Fix Selection Tier Scoring.** Introduced `_commit_fix_tier` in `git_utils.py` to scoring candidate commits so that test-only/doc-only commits do not outrank the actual code fix (preventing "patched tree parent" errors).
- **Test-Only Commits Safety Net.** Updated `output_generator.py` to record test-only commits as "no-patchable-function" to bypass useless generation attempts while keeping the test as the Phase 1 reproducer.
- **Run Script Default Cleanup.** Added the `--cleanup` flag by default in `pipeline/run_project.sh`.

## [0.4.2] - 2026-06-26

Runtime optimizations and a one-click run archiver, implemented after the first full-scale (0.4.1) run. The two concurrency controls are opt-in and default to the prior sequential behaviour, so a default-settings run is byte-for-byte identical to 0.4.1 — making that first run a clean pre-optimization runtime baseline (archived under `run-archives/2026-06-25_pre-optimization-baseline/`) for a before/after comparison.

### Added

- **Phase 1 concurrent baseline capture (`baseline_max_parallel`).** The repeated baseline PoC runs used to confirm a deterministic reproduction signature can now execute concurrently instead of one after another. This is decisive for the weakest, hang/timeout signal, which requires *unanimity* (every run must reach `run_timeout`): running them in parallel collapses `baseline_runs × run_timeout` of pure waiting into approximately one `run_timeout`. Implemented via new `_run_baseline_once` / `_finalize_baseline` helpers and a `ThreadPoolExecutor` path in `_capture_baseline` (`orchestrator.py`); each concurrent run gets a unique container suffix so they never collide. Defaults to `1` (sequential with early-stop — byte-for-byte the previous behaviour) when the setting is absent from `config.yaml`.
- **Phase 3 concurrent patch validation (`--max-workers` / `max_workers`).** Independent candidate patches can now be validated in parallel, each an isolated Docker rebuild + PoC re-run + host-side SAST on image/container/build-dir names unique to `(cve, model)`, with results merged on the main thread (`patch_validator.py`). Defaults to `1` (sequential) — raise it on a multi-core host with enough RAM, since each validation is a full project rebuild.
- **Dashboard "Download Results" archiver.** A new `GET /api/download?cell=<project>__<profile>` endpoint streams a single ZIP bundling everything needed to archive one pipeline execution — `results/`, `logs/`, `reports/`, metrics, `patches/`, `validation_results/` (+ `validation_builds/`), `exploits/`, `manual_supervision/` — plus the config that produced it (`config.yaml`, the project Phase-0 YAML, the profile `.env`) and a generated `MANIFEST.txt`. Backed by `dashboard_control.build_cell_archive()` (validates the cell name, refuses path traversal, compresses with `ZIP_DEFLATED`, builds to a temp file that the web layer streams and then deletes); the endpoint is localhost-only, consistent with the existing security model. A "⬇ zip" link is added to every grid row and a "⬇ download results (ZIP)" link to each cell page (`dashboard_server.py`, `dashboard_control.py`).

### Changed

- **libtiff in-tree reproduction recipe rewritten to a shipped-test oracle** (`cve_aggregator/libtiff_config.yaml`, `phase1.intree_test`). Empirically (validated on the fax3 *bug54* fix, commit `a566b83b`: shipped test `make check` **FAILs** on the vulnerable build and **PASSes** on the patched build) libtiff CVE fixes ship **golden-output comparison** tests (`test/<name>.sh` + `refs/o-<name>.tiff`, wired via `add_convert_test`/`add_reader_test` as e.g. `tiffcp -c none img` then diff vs the reference), **not** crashes. The previous recipe only replayed the crafted TIFF through the CLI tools under ASan and so reproduced **none** of libtiff's harness tests (golden-output mismatch is invisible to a crash oracle, and tools like `tiffcrop` abort on *both* builds from unrelated bugs, polluting the signal). The new primary path builds libtiff with ASan and runs `make check TESTS="<the .sh the fix added>"` as the fail-to-pass oracle; the crafted-TIFF ASan replay is retained as a fallback for pure memory-safety CVEs that ship no harness test, ahead of the built-binary / standalone-`.c` fallbacks. **Yield ceiling is structural, not recipe-bound:** across all libtiff history only ~23 fix commits ship a `test/*.sh` harness test and ~20 add a crafted `test/images/*.tif` fixture (31 test images total), versus tcpdump's 785 committed `.pcap` fixtures — libtiff CVEs are mostly validated via OSS-Fuzz reproducers stored *outside* the repo, so the in-tree path can only ever reach the small in-repo corpus.
- **Clearer per-CVE and per-retry logging** in Phase 2 generation, the iterative feedback loop and the master-pipeline feedback driver (`patch_generator.py`, `master_pipeline/feedback.py`, `master_pipeline/orchestrator.py`): boxed/indented headers and ✓/✗ status markers. Formatting only — no behavioural change.

## [0.4.1]- 2026-06-25

Consolidates all work since 0.3.7: the methodology v2/v3 deterministic-baseline reproduction model, multi-project expansion, configurable SAST, benchmarking/provider infrastructure, dashboard, notifications, and Phase 0 parallelization.

### Added

- **Multi-project support (12 C/C++ projects + Apache Tomcat/Java).** New Phase 0 configs for `expat`, `ffmpeg`, `file`, `gnutls`, `libtasn1`, `libtiff`, `libxml2`, `openssl`, `pcre2`, and `tcpdump`, plus `tomcat` (Apache Tomcat, Java) alongside `glibc` and `kernel` (a generic `aggregator_config.yaml` template is also provided). Targeting a new project needs only a YAML config — no Python changes.
- **Dual reproduction oracle (`reproduction_strategy`).** Besides ExploitDB PoCs, Phase 0 can harvest the regression test the fixing commit ships and use it as a reproduction artefact; Phases 1 and 3 then validate via a *fail-to-pass* oracle (the test fails on the vulnerable build and must pass on the patched build). Most shipped configs set `reproduction_strategy: [exploitdb, intree]`.
- **Configurable, per-project SAST.** The Phase 3 tool list is declared in each project's YAML `sast:` section and executed by a tool-/format-agnostic runner (cppcheck-xml / flawfinder / SARIF / regex parsers). C projects use cppcheck + clang-tidy + semgrep + flawfinder; Tomcat (Java) uses semgrep + PMD. SAST also runs in Phase 1 to record an unpatched baseline.
- **Benchmarking & provider infrastructure.** LLM provider profiles under `profiles/`, batch runners (`run_matrix.sh` / `run_all.sh`), and supporting docs (`documentation/benchmarking.md`).
- **Results dashboard** (`dashboard.py` / `dashboard_server.py` / `dashboard.sh`):
  - Per-phase live-progress cards updated in real time via per-phase `.live_progress_p{N}.json` heartbeat files (`cve_aggregator/utils/live_progress.py`); the overlay prefers the heartbeat over stale/absent final artifacts by mtime.
  - Per-phase manual-review UI (`/manual` route): edit/approve/discard/retry/proceed workflow; the Start form enables or skips manual review independently per phase. Marker-file IPC drives a polling orchestrator gate; live-run-safe defaults (`auto_skip=true`, `phase1_gate=false`) via ENV transport.
  - Run control: start/stop/pause via PGID signals to `run_all.sh` (`dashboard_control.py`).
  - Selective data and Docker deletion scoped to project × profile × phase, with a preview→token→apply fail-safe.
  - nginx basic-auth + CSRF/localhost gate.
- **Push notifications (`master_pipeline/notify.py`).** ntfy-based two-layer system: `run_all.sh` (run/stage/project/cell) and `master_pipeline/notify.py` (per-phase). Granularity toggles and issue-always-send behavior driven by one `config.yaml notifications:` block.
- **LLM compatibility layer (`cve_aggregator/utils/llm_compat.py`).** Centralizes provider-specific parameter normalization (e.g., stripping `temperature` for gpt-5/o-series models that reject non-default values). Wired into `poc_repair.py` and `poc_analyzer.py`.
- **Phase 1 readiness utility (`cve_aggregator/utils/phase1_readiness.py`).** Checks that Phase 0 artifacts are present and well-formed before Phase 1 is launched.
- **Vulnerable-commit metadata in Phase 0 CSV.** Phase 0 now records `V_COMMIT_TIMESTAMP` and `V_COMMIT_YEAR` so later phases can reuse commit-era information without re-querying git.
- **In-memory commit message index** (`build_commit_message_index` in `cve_aggregator/utils/git_utils.py`): avoids repeated `git log --grep` subprocesses, dramatically reducing commit-search latency on large repos.
- **Setup utilities reorganized under `pipeline/setup/`** (`setup.sh`, `verify_setup.sh`, `fix_containerd.sh`); scripts now resolve the pipeline root correctly after the move.
- **API key fallback loading.** `NVD_API_KEY` / `OPENAI_API_KEY` are loaded from repo-root secret files (`pipeline/API-openai-key`, `pipeline/API-nvd-key`) when environment variables and YAML values are absent.

### Changed

- **Phase 1 reproduction model (methodology v2/v3).** Replaced the two-gate exit-`42`/`43` wrapper with a **deterministic-baseline** model: the wrapper propagates the PoC's own exit code, captured across multiple runs as the baseline signature in `image_manifest.json`, against which Phase 3 compares the patched build. A **build-linkage honesty gate** (with previous-era and 32-bit/i386 recovery rebuilds) and an **LLM negative filter** (regex fallback) guard the baseline. The legacy gate design was archived under `deprecated/` (`orchestrator_phase1_gates.py`, `poc_analyzer.py`).
- **Era-by-version base-image selection (Gate B).** The Docker base is chosen from the checked-out tree's actual version (`version_era_map`), with the commit-date map as a fallback, so back-ported fixes build on an era-matched toolchain.
- **SAST gating is baseline-relative.** A patch fails only on findings it *introduces* (new vs. the Phase 1 baseline); pre-existing project debt is documented but never gates.
- **Phase 2 emits minimal SEARCH/REPLACE edits**, with per-project language and prompts (`phase2.language`, `system_prompt`).
- **Phase 3 verdict mirrors Phase 1.** Patched-image output now passes through the same negative filter used for Phase 1 baselines; `POC_HANG` exit class is retryable; crash-class/137 exit hardening added for consistency across both phases.
- **Phase 2 and Phase 3 consume the Phase 0 CSV path from the active configuration** instead of hardcoded `documentation/file-function.csv` paths, including master pipeline and feedback-loop wiring.
- **`Phase0CSVParser` and `resolve_build_ubuntu_version()`** now use commit-year metadata from Phase 0 when available, improving Ubuntu-era selection; `commit_era_map` extended back to 1995.
- **Parallelized `CommitDiscovery`**: processes CVEs via a configurable `ThreadPoolExecutor` (`commit_discovery.max_workers`).
- **Parallelized `PoCRepairLLM`**: runs independent LLM repair calls concurrently with a configurable worker pool (`poc_repair.max_repair_workers`).
- **Configurable performance knobs**: `commit_discovery.commit_index_timeout`, `poc_repair.local_token_rate`, `poc_repair.openai_token_rate`, and other LLM/timeout parameters; defaults preserved for backward compatibility.
- **Cleanup coverage** now includes Phase 0 artifacts and project workspaces, with updated Docker image prefixes for the new project layout.
- **Manual review flow** now offers a continue/skip-all option for remaining pending CVEs.
- **Documentation cleanup**: removed stale analysis/design documents (`poc_flag_analysis.md`, `documentation/poc-validation-report.md`, `documentation/provider-profiles-design.md`, `documentation/non-c-adaptation-inventory.md`, `docs/MODULARIZATION_PLAN.md`, `docs/STAGE4_TOMCAT_DESIGN.md`).

### Fixed

- **Phase 3 `--phase0-config` not forwarded.** `executor.py` did not pass `--phase0-config` to `patch_validator.py`, so non-glibc Phase 3 runs silently read the glibc manifest path and returned "No Phase 1 Baseline" for every CVE. Fixed in `executor.py` and `patch_validator.py` (manifest path + SAST config resolution).
- **Phase 2 PoC-source path.** `_find_poc_source` now resolves the exploits directory against the active `--base-dir` (a rebased `EXPLOITS_DIR`) in both the subprocess and the in-process feedback paths, so multi-project runs include the exploit in the generation prompt instead of silently dropping it.
- **gpt-5/o-series temperature rejection.** Models in the o-series/gpt-5 family reject non-default `temperature` values; now handled centrally in `llm_compat.py` and wired into `poc_repair.py` and `poc_analyzer.py`.
- **NVD/OpenAI key loading** now works from the relocated root secret files in addition to environment variables and config values.
- **Master pipeline preflight** no longer requires the legacy CSV path when Phase 0 is part of the current run.
- **Variable reference bug in failed PoC repair output**: corrected a `NameError` when writing failed PoC repairs to `manual_supervision/` (`original_code` was referenced instead of the undefined `content`), preventing empty manual-review artifacts.

## [0.3.7] - 2026-04-14

### Fixed

- `cve_aggregator/modules/poc_mapper.py`: strict CVE parsing when reading ExploitDB CSVs — the CSV `codes` field is now parsed using the regex match group (`m.group(0)`) and the extracted value is used as the canonical CVE identifier. This prevents malformed keys from dirty CSV tokens (for example, `CVE-2017-18344.`) and avoids creating duplicate filenames such as `CVE-2017-18344..c`.

### Reverted

- Reverted a proposed tightening of reverse-search content filtering that could have excluded legitimate dual-project CVEs. Reverse-search behavior remains permissive so CVEs that legitimately affect multiple projects are preserved.

### Notes

- This update is defensive: it corrects parsing of noisy ExploitDB CSV entries without changing PoC-to-CVE attribution or cross-project mappings.

## [0.3.6] - 2026-04-13

### Added

- C++ and C# language support across Phase 0 modules: language detection, syntax validation, and code parsing. C++ validation uses `g++ -fsyntax-only -std=c++17`; C# validation uses Mono `mcs` with a structural fallback when the compiler or project references are missing.
- C# method extractor (`extract_csharp_methods`) and `extract_all_csharp_units` in `cve_aggregator/utils/code_parser.py`.
- Language-specific repair guidance and comment-prefix mappings for `cpp` and `csharp` in `cve_aggregator/modules/poc_repair.py`.

### Changed

- `cve_aggregator/utils/file_utils.py`: added mappings and heuristics for `.cpp/.cc/.cxx/.hpp/.hxx` and `.cs` extensions and improved detection order to avoid Java/Python misclassification.
- `cve_aggregator/modules/syntax_validator.py`: added C++ and C# validators, updated comment-prefix entries, and improved code-anchor heuristics.
- `cve_aggregator/modules/poc_repair.py`: added C++/C# repair guidance to `_LANG_GUIDANCE` and `_COMMENT_PREFIX`.
- `cve_aggregator/utils/code_parser.py`: added C# extractor, updated `_infer_language` and dispatch logic to support `cpp` and `csharp`; C++ reuses the existing C function/macro extractor.

### Fixed

- Resolved Java/Python detection edge-case by reordering detection logic and tightening the Python import regex so Java `import` lines are not misclassified as Python.

### Notes

- C# detection prefers realistic multi-line source files; very short single-line snippets may still be classified as `unknown`.
- Validation continues to run on macOS for local checks; some Linux-specific headers may require small guarded stubs when compiling locally.

## [0.3.5] - 2026-04-13

### Added

- **Config knob:** `poc_repair.allow_repair_without_commit` (default: `true`) to control whether `PoCRepairLLM` attempts repairs for CVEs without associated commits, decoupling repair gating from `SyntaxValidator`'s `allow_manual_without_commit`.

### Changed

- **Module 6 (PoCRepairLLM):** Now attempts repair on invalid PoCs independent of commit history when enabled, and updates `syntax_results` in-memory on success so downstream modules see fixes immediately.
- **Manual supervision artifacts:** When the LLM cannot repair a PoC, `PoCRepairLLM` now writes the source copy and a companion validation JSON into `manual_supervision/` using the same naming convention as `SyntaxValidator` (`{cve_id}_{exploit_idx}{ext}` and `{cve_id}_{exploit_idx}.validation.json`). This ensures `OutputGenerator` and the master orchestrator can find and present manual review items.

### Fixed

- **Orchestrator artifact fabrication reverted:** Removed a temporary change that emitted synthetic `.validation.json` files from `master_pipeline/orchestrator.py` outside Phase 0; validation artifacts are produced by Phase 0 modules to preserve modular boundaries.
- **Manual-review gap closed:** Fixed the mismatch where CVEs flagged for manual review by Phase 0 were not present in `manual_supervision/`, preventing orphaned reports and ensuring consistent pipeline behavior.

### Notes

- These changes keep Phase 0 self-contained and preserve modular separation between the `cve_aggregator` pipeline and the master orchestrator. To opt out of repairing CVEs without commits, set `poc_repair.allow_repair_without_commit: false` in your aggregator config.

## [0.3.4] - 2026-04-11

### Added

- **OpenAI LLM provider:** Added support for OpenAI as an alternative LLM backend. New `provider`/`openai_model`/`openai_api_key` options were added to `config.yaml` and the `cve_aggregator` configs; `patch_generator.py` and `cve_aggregator/modules/poc_repair.py` dispatch between Ollama and OpenAI backends. The project now depends on `openai>=1.0.0` (recorded in `requirements.txt`).

### Changed

- **Provider-aware token budgeting:** PoC repair token/time estimates are now provider-aware (OpenAI uses a faster estimate), avoiding unnecessary skips for large PoCs when using OpenAI.
- **PoC ordering:** When a CVE's primary PoC (index 0) is invalid but a secondary PoC is valid, the valid PoC is promoted to primary so downstream tools see the best exploit first; the (now secondary) invalid PoC is still queued for LLM repair. This change updates `syntax_results` and the in-memory repair queue to keep indexes consistent.
- **LLM call refactor:** `patch_generator.py` and `poc_repair.py` were refactored to split LLM calls into `_call_ollama_api` and `_call_openai_api` with a provider dispatch layer.
- **Reproduction detection:** `orchestrator.py` CVE-specific detection blocks no longer short-circuit to False; generic heuristics were improved (PoC diagnostic-output detection and an exit-code-1 heuristic) so environment-mismatch diagnostics still count as evidence the PoC exercised the target code path.

### Fixed

- **_repair_loop parameter bug:** Fixed `NameError` by adding missing `provider`, `openai_model`, and `openai_api_key` parameters to `_repair_loop` and its call sites.
- **Removed hardcoded secrets:** Removed an accidentally committed OpenAI API key from `cve_aggregator/glibc_config.yaml`; the code now prefers `OPENAI_API_KEY` env var with YAML fallback.
- **Dependency installation:** `openai` installed into the project's virtual environment; note the pipeline should be run with the project's `.venv` Python interpreter so the package is available.

### Security

- Removed sensitive API key from repository and recommend using the `OPENAI_API_KEY` environment variable.

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
