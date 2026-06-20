# Stage 4 — Tomcat reproduction model (design / scoping)

Stages 1–3 made the pipeline **code** project-agnostic by lifting glibc's build/compile/run
into config hooks. Stage 4 is different: it is **new methodology**, because Tomcat's
*reproduction proof* is structurally unlike glibc's. This doc scopes what's needed, what's
feasible, and what isn't — before any code is written.

## 1. The structural mismatch

| | glibc (works today) | Tomcat |
|---|---|---|
| Project artifact | a shared library (`libc.so.6`) | a running **HTTP server** |
| PoC shape | self-contained C program; triggers the bug in the linked libc | a client that sends crafted **HTTP requests** to a live server |
| Reproduction signal | the PoC's **exit code** (e.g. 139 SIGSEGV) vs baseline | the **HTTP response** (e.g. `/etc/passwd` body, command output, 200 vs 403) |
| "Honesty" gate | does the PoC link the project build? (`ld.so --list`) | is the **server under test** the project build? |
| Pre-PoC state | none — PoC is standalone | the **server must be started + ready** first |

The pipeline's contract is *"run a self-contained PoC, read its exit code, compare to
baseline."* Tomcat needs *"start the build's server, drive an HTTP PoC against it, read the
response."* The build/compile/launch hooks from Stages 1–3 cover building Tomcat and running
an interpreted PoC, but **two pieces are missing**:

1. a **project-level service-start + readiness** step before the PoC runs;
2. a **reproduction signal** suited to HTTP (positive proof in output, not just exit code),
   and a **redefined honesty** gate ("server under test = patched build").

## 2. Proposed architecture extension (one new hook + redefinitions)

Reuse everything from Stages 1–3; add the minimum:

```yaml
phase1:
  base_packages: [default-jdk, ant]          # build + run a JVM
  build_script: |                            # ant build → $INSTALL_PREFIX + deploy webapp
    ...
  # NEW — project-level service-under-test. Started (backgrounded) and polled for
  # readiness BEFORE the PoC runs; torn down after. Env: INSTALL_PREFIX, plus a
  # well-known target the PoC can hit (SSD_TARGET=http://127.0.0.1:8080).
  service_start_script: |
    "$INSTALL_PREFIX"/bin/catalina.sh start
    for i in $(seq 1 60); do curl -fsS http://127.0.0.1:8080/ >/dev/null 2>&1 && break; sleep 1; done
  service_stop_script: |
    "$INSTALL_PREFIX"/bin/catalina.sh stop || true
  # honesty for a service project = "the build's server is up and is the one under test"
  # (poc_launch_script writes /poc/.ssd_poc_uses_build=yes iff readiness succeeded).
  poc_launch_script: |
    curl -fsS http://127.0.0.1:8080/ >/dev/null 2>&1 && echo yes > /poc/.ssd_poc_uses_build || echo no > /poc/.ssd_poc_uses_build
    export SSD_TARGET=http://127.0.0.1:8080
  patch_rebuild_script: |                    # ant recompile patched class + redeploy + restart
    ...
```

- **Where service-start plugs in:** the run wrapper already has a *"Step 1: setup (root)"*
  slot. Add a project-level `service_start_script` run there (before the per-PoC
  `setup_command`), and a `service_stop_script` in teardown. Generic: the wrapper just runs
  whatever the project gives — no Tomcat knowledge in code, same pattern as every Stage 1–3
  hook.
- **Honesty redefinition:** `poc_uses_project_build` becomes "service readiness passed."
  Already expressible via `poc_launch_script` writing the marker (Stage 3c gave us that seam).
- **The PoC itself** uses the existing interpreted templates (python/ruby) — no new code.

So the **code change is small and clean** (one service-start/stop seam in the wrapper). The
hard part is not the architecture.

## 3. The hard limits (why this yields few/no reproduced CVEs)

These are methodology realities, not code problems:

1. **No-per-CVE-config rule excludes the famous CVEs.** The pipeline forbids per-CVE config
   anywhere. But most high-impact Tomcat CVEs need **CVE-specific server config**:
   - CVE-2017-12615 / -12617 (PUT-JSP RCE): needs `readonly=false` on `DefaultServlet`.
   - CVE-2020-1938 (Ghostcat): needs the **AJP connector** enabled/exposed in `server.xml`.
   - deserialization / session CVEs: need specific `PersistentManager`/`Store` config.
   A single generic out-of-the-box config only reproduces the CVE subset that fires against
   **default** config — a minority.
2. **ExploitDB Tomcat PoCs are thin and target-parameterised.** Most are **Metasploit
   modules** (the pipeline explicitly *can't* run these — `CVE_DOCKERFILE_RUBY` writes a
   failure wrapper for MSF) or scripts that take `RHOST`/`RPORT` args. The pipeline runs the
   PoC with **no args**, so it won't hit `127.0.0.1:8080` unless the PoC self-targets. After
   the `require_verified` + `filtered_require_poc` funnel, the runnable set is near-empty.
3. **Server repro is flaky / setup-heavy** vs glibc's deterministic compile+run (startup
   timing, port, webapp deploy, the vuln must be on the deployed path).
4. **Indirect vuln↔PoC link.** Phase 0 extracts the patched Java *method*; the PoC triggers
   it only via a specific request to a specific endpoint. Exit-code/output comparison still
   works *if* the PoC reliably reaches that method — often it doesn't without setup.

## 4. Recommended scoping (the honest call)

- **Treat Tomcat primarily as a patch-generation + static-validation target, not a
  reproduction target.** Phases 0 (dataset) + 2 (LLM patch) + 3-**SAST** (semgrep/PMD, already
  configured) + 3-**build** (ant compiles the patch) are all **PoC-independent** and work for
  Tomcat today *except* one blocker: Phase 2/3 currently **require a Phase 1 baseline** (CVEs
  without one are skipped as "No Phase 1 Baseline"). 
  - **Small enabling change:** allow Phase 2/3 to run on CVEs with **no Phase 1 baseline** in a
    "static-validation mode" (patch must compile + pass SAST; no exit-code comparison). This
    unlocks Tomcat patch-gen/validation **without** solving reproduction.
- **Implement the `service_start_script` hook anyway** (small, clean) so the *few* default-
  config, self-targeting Tomcat PoCs CAN reproduce — but set expectations at "a handful, maybe
  zero," and `log()` the funnel honestly (don't present static-only validation as reproduction).
- **Kernel: build-only / reproduction ⊘.** Booting a custom kernel + running an LPE needs a VM,
  not a container. Same recommendation: patch-gen + build + SAST validation, no Phase 1 repro.

## 5. Implementation tasks (if we proceed)

- [ ] Run Tomcat **Phase 0** to see the real funnel (how many CVEs have a fix commit + extracted
      Java method + a runnable, verified, non-MSF PoC). This number decides how much repro work
      is worth it. **Do this first — it's the cheap reality check.**
- [ ] Add `phase1.service_start_script` / `service_stop_script` seam to the run wrapper +
      teardown (generic; ~30 lines, mirrors Stage 1–3 hooks).
- [ ] Redefine honesty for service projects via `poc_launch_script` (readiness → marker) —
      already supported by the Stage 3c seam; just supply Tomcat's snippet.
- [ ] **Static-validation mode:** let Phase 2/3 process CVEs with no Phase 1 baseline (patch
      compiles + SAST gate only). This is the high-value, reproduction-independent win.
- [ ] Tomcat `build_script` (ant) + `base_packages` (JDK/ant) + deploy a generic webapp.
- [ ] Document Tomcat/kernel as static-validation targets; reproduction best-effort/out-of-scope.

## 6. One-line summary

The **architecture** extends cleanly (one service-start seam). The **methodology** does not
generalise for free: Tomcat reproduction is gated by the no-per-CVE-config rule and thin
ExploitDB coverage, so the realistic, honest Stage-4 deliverable is **Tomcat/kernel as
patch-generation + build + SAST validation targets**, with HTTP-PoC reproduction as a
best-effort extra for the few default-config CVEs.
