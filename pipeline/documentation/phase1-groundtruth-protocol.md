# Phase 1 Ground-Truth Protocol

**Goal.** Produce a *human-verified* reference of what each PoC actually does on the
known-vulnerable build — does it run, and with what exit code — so the pipeline's
automated Phase 1 output (`results/image_manifest.json`) can be scored against reality
(precision/recall, false "reproduced", false "manual revision").

**Scope.** Only the CVEs that *reach Phase 1* — i.e. CVEs from the Phase 0 CSV that have
at least one runnable ExploitDB PoC. These are exactly the entries that appear under
`cve_images` in `results/image_manifest.json` after a Phase 1 run. (A CVE whose every PoC
is still pending manual review never reaches Phase 1 and is out of scope — see
`master_pipeline/orchestrator.py:475` `_get_pending_manual_cves`.)

---

## Why run inside the pipeline's CVE image (not on the host)

A PoC's exit code is only meaningful if it executed against the **correctly-built
vulnerable glibc** — same Ubuntu era, linked against the project build, not the host
libc. Reproducing that environment by hand is exactly what Phase 1 already automates
(era-by-version gate, honesty/`ldd` gate). So we **reuse the per-CVE image as the
environment** — but we read the raw exit code and **assign the verdict ourselves**. The
baked-in wrapper only *measures* (it exits with the PoC's own code and prints markers); it
never *judges*. Using `docker run <cve-image>` is therefore legitimate ground-truth data,
independent of the pipeline's decision logic and negative filter.

> If you judged a PoC on the host instead, a binary that silently linked the host libc
> would give a false exit code — the precise linkage bug the honesty gate exists to catch.

---

## Step 0 — Build the Phase 1 images

On the VM (`ssh vm-dei`, `/home/admin/pipeline`):

```bash
# Build only — produce the vulnerable CVE images + manifest, no verdict needed from us
python3 orchestrator.py                       # all Phase-1-ready CVEs
python3 orchestrator.py --cve CVE-2012-3480   # or one at a time
```

This writes `results/image_manifest.json`. The `cve_images` list **is** the Phase-1 set —
the rows you must ground-truth. Confirm the exact image tags Docker actually built:

```bash
docker images | grep glibc-cve
# tag layout: ai-ssd/glibc-cve:<CVE>-<ubuntu_version>   e.g. ai-ssd/glibc-cve:CVE-2012-3480-12.04
# NOTE: an era fallback may build on a different Ubuntu version than the CSV's,
# and 32-bit PoCs add a -i386 suffix. Do NOT reconstruct the tag from <cve>-<ver>;
# read the real "tag" field from results/image_manifest.json (the skeleton below does).
```

(Regenerate the template skeleton straight from a fresh manifest — see the one-liner at the
bottom — so the row set always matches the current run.)

---

## Step 1 — Per CVE: verify linkage (C PoCs only)

The exit code is only trustworthy if the compiled PoC links the *project* build. Read the
marker baked into the image:

```bash
TAG=ai-ssd/glibc-cve:CVE-2012-3480-12.04
docker run --rm --entrypoint cat "$TAG" /poc/.ssd_poc_uses_build   # prints: yes | no
```

- `yes` → linkage OK, exit code is meaningful.
- `no`  → PoC linked the **system** libc; **no source patch can change its behavior**.
  Record `links_project_build=no` and `gt_verdict=links-system-libc` regardless of exit code.
- (interpreted PoCs — `.rb/.sh/.php/.pl/.py` — have no marker; leave `links_project_build=NA`.)

---

## Step 2 — Per CVE: run the PoC 3× and capture exit codes

Match Phase 1's determinism policy (`baseline_runs: 3`, `baseline_min_agree: 2` in
`config.yaml`) and its container limits (6 GB) so you don't manufacture a spurious OOM
(137) the pipeline wouldn't see:

```bash
TAG=ai-ssd/glibc-cve:CVE-2012-3480-12.04
for i in 1 2 3; do
  docker run --rm --memory=6g "$TAG" >/tmp/out.$i 2>&1
  echo "run $i  exit=$?"
done
# inspect the PoC's own stdout (between the markers) for one run:
sed -n '/--- BEGIN POC OUTPUT ---/,/--- END POC OUTPUT ---/p' /tmp/out.1
grep '^SSD_RESULT:' /tmp/out.1     # category=... exit_code=...
```

**Privileged PoCs** (namespace/setuid LPEs — e.g. CVE-2014-5119, CVE-2017-1000366). If
`docker run` reports it cannot create a user namespace or the PoC says it can't drop
privileges, match what Phase 1 grants source-detected PoCs:

```bash
docker run --rm --memory=6g --privileged \
  --security-opt seccomp=unconfined --security-opt apparmor=unconfined "$TAG"; echo "exit=$?"
```

**To poke around by hand** (read the PoC, run it step by step, check `echo $?`):

```bash
docker run --rm -it --entrypoint /bin/bash "$TAG"
#  inside:  /poc/exploit ; echo $?     (C)
#           python3 /poc/exploit.py ; echo $?   (etc.)
```

---

## Step 3 — Assign the ground-truth verdict (your judgment)

Read the 3 exit codes + the PoC output, then pick **one** verdict. This mirrors Phase 1's
decision logic (`orchestrator.py:4302-4466`) but **you** decide — that independence is the
whole point.

| What you observed (3 runs)                                              | `gt_verdict`           | `gt_baseline_exit` |
|-------------------------------------------------------------------------|------------------------|--------------------|
| Same crash signal ≥2/3, e.g. 139 SIGSEGV / 134 SIGABRT / 136 SIGFPE; output shows the vuln path | `reproduces`           | that exit code     |
| Clean `0` every run, no crash, no DoS                                   | `clean-exit`           | NA                 |
| Hangs / times out every run **and** PoC is DoS / format-string          | `reproduces-dos`       | -1                 |
| `137` (SIGKILL) — almost always container OOM, not a bug                | `oom`                  | NA (raise memory)  |
| Exit codes differ across the 3 runs (no ≥2/3 agreement)                 | `non-deterministic`    | NA                 |
| Output says "not vulnerable" / "not setuid" / "error while loading shared libraries" / "command not found" | `env-error`            | NA                 |
| `links_project_build=no` (C PoC linked system libc)                     | `links-system-libc`    | NA                 |
| Image failed to build / tag absent                                      | `unbuildable`          | NA                 |

Notes:
- A crash code is `> 128` (128 + signal number). `0`–`127` clean exits are **not** a
  reproduction unless the PoC deliberately returns a chosen non-zero code (rare; note it).
- "≥2/3 agreement" = the `baseline_min_agree` rule; timeouts require **all 3** to agree.

---

## Step 4 — Record and score

Fill one row per CVE in `results/phase1_groundtruth.csv` (copy the template). Then paste the
pipeline's own answer next to yours and mark agreement:

```bash
# pull the pipeline's verdict per CVE from the manifest
python3 - <<'PY'
import json
m=json.load(open("results/image_manifest.json"))
for i in m["cve_images"]:
    print(i["cve"], i.get("status"), "baseline="+str(i.get("baseline_exit_code")),
          "manual="+str(i.get("needs_manual_revision")), "uses_build="+str(i.get("poc_uses_project_build")))
PY
```

`agrees_with_pipeline = yes` when (your `gt_verdict` is a reproduce-class **and** the
pipeline reproduced with the same baseline exit code) **or** (both say not-reproduced). Any
mismatch is a finding — a false positive or false negative in Phase 1 — and is the actual
output of this exercise.

---

## Generate the template skeleton from a fresh manifest

So the row set always matches the current Phase-1 run:

```bash
python3 - <<'PY'
import json
m=json.load(open("results/image_manifest.json"))
cols=["cve","poc_path","ubuntu_version","image_tag","builds_ok","links_project_build",
      "run1_exit","run2_exit","run3_exit","stable","observed_signal","gt_verdict",
      "gt_baseline_exit","pipeline_status","pipeline_baseline","agrees_with_pipeline","notes"]
print(",".join(cols))
for i in m["cve_images"]:
    cve=i["cve"]; ver=i.get("ubuntu_version",""); poc=i.get("poc_path","")
    tag=i.get("tag","")   # the REAL built tag (handles era-fallback / -i386); do not reconstruct
    row={"cve":cve,"poc_path":poc,"ubuntu_version":ver,"image_tag":tag,
         "pipeline_status":i.get("status",""),"pipeline_baseline":i.get("baseline_exit_code","")}
    print(",".join(str(row.get(c,"")) for c in cols))
PY
```
