# Pipeline Modularization Plan

**Goal:** make the pipeline *fully modular and project-agnostic* — no project-specific
build/compile/run/test commands anywhere in the Python. Everything project-specific lives
only in the project YAML (`cve_aggregator/<project>_config.yaml`), as it already does for
Phase 0, `base_packages`, the `sast:` section, and the (dormant) `intree_test` path.

**Status legend:** ☐ not started · ◐ in progress · ☑ done · ⊘ won't do / out of scope

**Overall status:** ☑ Stage 1 · ☑ Stage 2 · ☑ Stage 3 (3a/3b/3c code done; 3a+3c VM-smoke-tested) · ☐ Stage 4 (tomcat reproduction methodology / kernel build-only)

**Phase 1 & Phase 3 are now fully project-agnostic:** the orchestrator/validator carry NO
glibc build/compile/run commands. Everything project-specific is config: `phase1.build_script`
(build), `poc_prepare_script` (PoC compile + honesty), `poc_launch_script` (run/loader),
`patch_rebuild_script` (Phase 3 rebuild), plus `base_packages`, `poc_run_env`, era maps, SAST,
and `phase2:` prompts/language. Remaining = Stage 4 (NEW methodology for non-shared-lib
projects), not refactoring.

> **Decision (Stage 1 close):** tomcat/kernel `build_script`+`base_packages` are **deferred
> to Stage 3** — on their own they only make the image *compile*; Phase 1's baseline/honesty
> gate is still Axis-B (glibc) shaped, and they need Docker (VM) to iterate. The tomcat recipe
> will be written alongside its Stage 3 reproduction model; kernel stays build-only/⊘.

---

## 1. Audit — where project-specific logic lives today

Leakage is concentrated in **Phase 1's build/PoC/run model, which Phase 3 inherits**.
Phases 0 and 4 are already clean.

| Phase / file | Status | Couplings (file:line at time of audit) |
|---|---|---|
| 0 — `cve_aggregator/` | ✅ Agnostic | Fully config-driven. Remaining gaps are *config*, not code (see `PHASE0_CONFIG_FIXES` below). |
| 1 — `orchestrator.py` | ❌ Coupled | `CVE_DOCKERFILE_HEADER` hardcodes glibc `configure`×3 + `_begin` rtld fix + `make`/`make install` + `localedef` (`1290–1412`). `CVE_DOCKERFILE_C` links PoC against `{install_prefix}/lib/libc.so.6`, 5 gcc strategies, i386 detect (`1444–1528`). Honesty gate `poc_uses_project_build` = "PoC links project libc" (`1539–1547`). `LD_LIBRARY_PATH={install_prefix}/lib` on every language template (`1549,1570,1599,1618,1633,1653`). |
| 2 — `patch_generator.py` | ⚠️ Language-coupled | `SYSTEM_PROMPT`/`FEEDBACK_SYSTEM_PROMPT` hardcode "expert C … glibc" (`175,181`). `GLIBC_INTERNAL_HEADERS` (`1364–1367`). GCC `.c` syntax validation (`1479–1525`). `.c`/`_function_only.c` naming. |
| 3 — `patch_validator.py` | ❌ Inherits Phase 1 | Rebuild = `make`/`make install` (`593–596`). Honesty re-check = `ld.so --library-path … ldd` (`614–621`). Image tag `glibc-patch/…` (`206`). `patched_source.c`, `.c`-only object check (`585,659`). SAST itself ✅ config-driven. |
| 4 — `reporter.py` | ✅ Agnostic | None. |
| feedback — `master_pipeline/feedback.py` | ⚠️ Language-coupled | Patch globs `*_function_only.c`, `*.c` (`299–304`). |

---

## 2. Key insight — two independent axes

- **Axis A — build model** ("compile the project at the vulnerable commit"). Cleanly
  refactorable. The dormant intree path already proves the pattern: `COPY build.sh` →
  `RUN bash build.sh` + generic `ENV` contract, zero build verbs in Python
  (`orchestrator.py:2185–2191`). glibc already has a working (currently unread)
  `phase1.build_script`. **Low risk; glibc stays byte-identical.**

- **Axis B — reproduction-proof model** ("prove the bug fired, and that the patch stops
  it"). Today = *compile a C PoC, link it against the project shared libc, run it, compare
  exit codes; honesty = PoC resolved the project libc.* Valid **only for shared-library
  projects** (glibc). Tomcat's proof = request against a running server; kernel's = LPE
  against a booted kernel (**infeasible in plain Docker**). Generalizing B is *new
  methodology*, not refactoring, and cannot make kernel reproduction work regardless.

---

## 3. Generic contract (design)

Extend the intree pattern to the standard path. Every CVE Dockerfile exports one ENV
contract; every project-specific action becomes a `COPY`'d script. New optional keys under
`phase1:` (absent ⇒ capability unavailable ⇒ route to manual, exactly like intree today):

```yaml
phase1:
  # Axis A — build (glibc already has this; make the code READ it)
  build_script: |            # replaces CVE_DOCKERFILE_HEADER configure/make
    ...                      # env: SOURCE_DIR BUILD_DIR INSTALL_PREFIX COMMIT_HASH BUILD_ARCH

  # Axis B — reproduction proof (glibc bodies are lift-outs of today's code)
  poc_prepare_script: |      # replaces CVE_DOCKERFILE_C gcc-link block + honesty gate;
    ...                      #   builds /poc/exploit, writes /poc/.ssd_poc_uses_build (yes/no)
  poc_run_cmd: [...]         # replaces per-language CMD + LD_LIBRARY_PATH
  patch_rebuild_script: |    # Phase 3: replaces make/make install + honesty re-check
    ...
```

**ENV contract** (superset of what intree exports): `SOURCE_DIR`, `BUILD_DIR`,
`INSTALL_PREFIX`, `COMMIT_HASH`, `BUILD_ARCH`, `POC_DIR=/poc`, `POC_FILE`, plus
`poc_run_env`. Python only: checks out the commit, exports the contract, `COPY`s+`RUN`s the
scripts, reads markers (`/poc/.ssd_poc_uses_build`, baseline exit code). No build/compile/run
verbs remain in Python.

**Interpreter templates** (Python/Ruby/Perl/Shell/PHP, `1553–1655`) are already nearly
generic — only the harmless `LD_LIBRARY_PATH` is glibc-flavored. So Axis B's real work is
only the **C compile + honesty gate** and **Phase 3 rebuild**.

---

## 4. Staged execution

Acceptance test for every stage: **the generated Dockerfile for a glibc CVE must diff empty**
(behavior identical) after the lift-out. Lift the glibc body verbatim into YAML; make the
code read it.

### Stage 1 — Axis A: build layer  ◐
- [x] `orchestrator.py`: replaced `CVE_DOCKERFILE_HEADER` build body with `COPY build.sh; RUN bash /build.sh` + ENV contract (`SOURCE_DIR/BUILD_DIR/INSTALL_PREFIX/COMMIT_HASH/BUILD_ARCH`).
- [x] Read `phase1.build_script` into `_p1`; thread through `CVEImageBuilder(build_script=…)`; write `build.sh` into the CVE build context (loud-failure stub when unconfigured).
- [x] `glibc_config.yaml:phase1.build_script` verified to mirror the old hardcoded body (critic_missing sed, `_begin` fix, 3 configure strategies, make/install, all 3 markers, localedef; superset = native `$BUILD_ARCH` i386).
- [x] i386 arch fallback for the BUILD now handled by build_script via `$BUILD_ARCH` (removed the Python configure-flag string-replace); PoC-compile `-m32` rewrite intentionally left for Stage 3.
- [x] Cache invalidation: `build_script` hashed into `poc_signature` + `WRAPPER_CONTRACT_VERSION` → `v15`.
- [x] Neutralized the build marker name `PROJECT_LIBC_INSTALLED` → `PROJECT_BUILD_INSTALLED` (generic name in code; the `libc.so.6` check stays in the glibc YAML). Read at `orchestrator.py:4248`, written by each project's `build_script`.
- [x] Local verification: `py_compile` OK; header renders with all placeholders; no inline configure/make remains on the standard path.
- [ ] **VM verification (needs Docker):** a glibc Phase 1 run still reproduces the same baselines (the real acceptance test — can't run on macOS host).
- [→] tomcat/kernel `base_packages` + `build_script` — **moved to Stage 3** (see decision banner at top).

> **Stage 1 learning:** the orchestrator refactor *fully achieves the project-agnostic
> build* (no build commands in Python; glibc behavior unchanged). But adding tomcat/kernel
> build recipes now only gets the image to *compile* — Phase 1's baseline/honesty gate is
> still Axis-B (glibc shared-lib) shaped, so those CVEs still route to manual until Stage 3.
> Recommend doing the tomcat recipe together with Stage 3 (its reproduction model), and
> treating kernel as build-only. Recipes also need Docker (VM) to iterate, unavailable on
> the macOS host.

### Stage 2 — Phase 2 + feedback language-parameterization  ☑ (code; VM run pending)
- [x] `patch_generator.py`: prompts now `phase2.system_prompt`/`feedback_system_prompt` (role preamble); code keeps only GENERIC defaults + the fixed SEARCH/REPLACE format (parser contract) + feedback tail. glibc's exact wording moved to its YAML → byte-identical (verified).
- [x] Gated GCC syntax-validation behind `phase2.language` (`c` → gcc+structural; else → structural brace check only). `GLIBC_INTERNAL_HEADERS` moved out of code → `phase2.internal_headers` (`INTERNAL_HEADERS` global; generic `fatal error: *.h` regex is the primary arbiter).
- [x] Patch artifact extension derived from the vuln file at both write sites (`_invalid{ext}`, `_function_only{ext}`); temp gcc file stays `.c` (C-only path).
- [x] `feedback.py`: globs generalized to `*_function_only.*` + any non-sidecar source file (extension-agnostic).
- [x] Added `phase2:` to glibc (c, exact prompts, 44 internal_headers), tomcat (java), kernel (c).
- [x] Plumbing: new `config.project_section()`/`resolve_phase0_config_path()`; `patch_generator` takes `--phase0-config` and re-applies phase2 in `main()`; `executor.py` passes `--phase0-config` to Phase 2 (it previously couldn't tell which project).
- [x] Local verify: `py_compile` clean (no SyntaxWarning); glibc prompt == old text; isolated assembly/gate logic correct.
- [ ] **VM run pending:** a glibc Phase 2 run produces the same patches (full import needs `pandas`, VM-only).

### Stage 3 — Axis B: PoC prepare/run/honesty + Phase 3 rebuild  ◐
- [x] **3b** `patch_validator.py`: replaced hardcoded `make`/`make install` + obj-check + ld.so honesty re-check with a config-driven `phase1.patch_rebuild_script` (COPY `patch_rebuild.sh` + RUN; reuses the Phase 1 image's `SOURCE_DIR/BUILD_DIR/INSTALL_PREFIX` env + new `VULN_FILE`; writes the 4 `/tmp/ssd_*` markers). Image tag `glibc-patch/` → `ai-ssd-patch/`. glibc script = verbatim lift-out (verified: markers + env). Loud-failure stub when unconfigured.
- [x] **3a** `orchestrator.py`: extracted `CVE_DOCKERFILE_C` gcc compile + alt-PoC fallback + companion build + i386 + honesty marker → `phase1.poc_prepare_script` (COPY `poc_prepare.sh` + RUN, env `INSTALL_PREFIX`/`BUILD_ARCH`/`POC_ALTS`/`POC_COMPANIONS`). Deleted `_generate_alt_poc_section`/`_generate_companion_section` + the i386/alt string-transforms; `_generate_dockerfile` now just stages files + fills COPY lines. glibc script = faithful port. Contract `v16`; poc_prepare_script hashed into signature. **VM-smoke-tested:** amd64→64-bit ELF, i386→32-bit ELF, both honesty=`yes` (matches old). Loud-failure stub when unconfigured.
- [x] **3c** `orchestrator.py`: moved the glibc loader-prefix/`LD_LIBRARY_PATH` launch logic out of `_build_run_wrapper` into `phase1.poc_launch_script` (sets `$SSD_EXEC_PREFIX`/`$SSD_LD_LIBRARY_PATH`; absent → direct run with `LD_LIBRARY_PATH=$RUN_LIB`). Contract `v17`; hashed into signature. The per-language CMD map stays in code on purpose — it's *language*-generic (python→python3), not project-specific. **VM-smoke-tested:** CVE-2012-3480 launch resolves "run directly" (binary embeds project interp) and the PoC exits **139 = the recorded baseline**. glibc snippet = faithful port.
- [ ] glibc bodies are lift-outs → glibc unchanged. Verify diff-empty / same baselines on VM.
- [ ] **tomcat** (moved from Stage 1): `base_packages` (JDK+Ant) + `build_script` (`ant deploy`/`dist`) + the new prepare/run/honesty hooks for a server-up + HTTP-PoC proof.
- [ ] **kernel** (moved from Stage 1): `base_packages` + `build_script` (`make defconfig && make`) = build-only; reproduction ⊘.

### Stage 4 — New reproduction methodology  ◐ (scoped — see `docs/STAGE4_TOMCAT_DESIGN.md`)
- [x] Scoped the Tomcat reproduction model + honest feasibility (full design: `docs/STAGE4_TOMCAT_DESIGN.md`).
- Key finding: the **architecture** extends cleanly (one project-level `service_start_script`/`service_stop_script` seam in the run wrapper + honesty-via-readiness through the Stage-3c `poc_launch_script` seam). The **methodology** does NOT generalise for free — Tomcat repro is blocked by the no-per-CVE-config rule (Ghostcat/PUT-RCE etc. need CVE-specific server config) + thin/MSF/target-parameterised ExploitDB PoCs.
- **Recommended deliverable:** Tomcat (and kernel) as **patch-gen + build + SAST validation** targets (PoC-independent), enabled by a small "static-validation mode" letting Phase 2/3 run on CVEs with **no Phase 1 baseline** (patch compiles + SAST gate). HTTP-PoC reproduction = best-effort for the few default-config CVEs.
- [ ] **Next (cheap reality check):** run Tomcat **Phase 0** to measure the real runnable-PoC funnel before investing in repro.
- [ ] Implement `service_start_script` seam + static-validation mode (see design doc task list).
- [ ] Kernel: ⊘ document as build-only / reproduction unsupported in Docker.

---

## 5. Per-project end state

| Project | Build (A) | Reproduction (B) |
|---|---|---|
| glibc | unchanged (lift-out) | unchanged (lift-out) — **zero regression is the safety property** |
| tomcat | JDK+Ant `build_script` | needs Stage 4 server-up proof |
| kernel | `make defconfig && make` | ⊘ out of scope in Docker |

---

## 6. Honest limits

- Agnostic *code* ≠ reproducible *project*. Tomcat needs a new proof model; the kernel
  likely can't be reproduced in Docker at all. The refactor makes these **expressible**,
  not free.
- `poc_uses_project_build` is intrinsically a shared-library notion; non-lib projects must
  redefine it (Stage 3/4 design, not a mechanical move).

---

## Appendix — PHASE0_CONFIG_FIXES (config-only, independent of the refactor)

These are YAML fixes from the earlier config review; they don't need code changes.
- [ ] Add `cve_fetcher.cpe_match` to tomcat (`cpe:2.3:a:apache:tomcat`) and kernel (`cpe:2.3:o:linux:linux_kernel`).
- [ ] Fix `poc_mapper.exploitdb_path` in tomcat/kernel: `../../exploit-database` → `../exploit-database` (paths resolve vs pipeline-root CWD, not `projects/<name>/`; current value re-clones ExploitDB to the wrong place).
- [ ] Consider `repo_local_path` `../tomcat` / `../linux` (sibling, persistent) to match glibc's convention; kernel clone is 4–5 GB.
