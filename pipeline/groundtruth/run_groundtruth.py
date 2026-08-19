#!/usr/bin/env python3
"""Independent ground-truth oracle for Phase-1 reproduction claims.

For each CVE it builds TWO trees from the *upstream* repo and runs the SAME
harvested regression test on both, in the SAME era container (environment held
constant), reading each project's OWN test verdict:

  V+  = FIX_COMMIT                       (upstream's official fix, unmodified)
  V-  = FIX_COMMIT with the vulnerable   (the fix reverted -> vulnerable again,
        SOURCE files reverted to FIX^     but the test + its registration kept)

Verdict (the discriminating-oracle test):
  CONFIRMED     : test FAILs at V-  AND  PASSes at V+   (PoC genuinely discriminates)
  REFUTED       : test PASSes at V- (doesn't detect the vuln)  OR  FAILs at V+ (fix/test wrong)
  UNCONFIRMABLE : either arm produced no runnable build / no test result

This is INDEPENDENT of the pipeline's reproduction *decision* logic: it never
imports orchestrator.py / poc_analyzer.py, it anchors on the upstream fix commit,
and its novel signal is the V+ arm (the pipeline only ever builds/judges V-).
The build/run *environment* is deliberately shared and held constant across the
two arms so a PASS->FAIL flip isolates the reverted source change.

Runs on a Docker host (vm-campos). Host does ALL git ops (snapshots via
`git archive`, so the container source tree has no .git); containers only build
and run. Output: out/<project>_groundtruth.json  (schema consumed by reconcile.py).

Usage:
  python3 run_groundtruth.py --project tcpdump --repo ~/gt/repos/tcpdump \
      --inputs ~/gt/tcpdump.json --out ~/gt/out/tcpdump_groundtruth.json \
      --workdir ~/gt/work --jobs 6 [--only CVE-2017-13011,CVE-...] [--reproduced-only]
"""
import argparse, json, os, re, shutil, subprocess, sys, time
from concurrent.futures import ThreadPoolExecutor, as_completed

# ---------------------------------------------------------------- helpers
CODE_EXT = (".c", ".h", ".cc", ".cpp", ".cxx", ".S", ".sym", ".s")

def is_test_path(path):
    p = path.lower(); base = os.path.basename(p)
    if p.startswith(("test/", "tests/")) or "/test/" in p or "/tests/" in p:
        return True
    if base.startswith(("tst-", "test-", "test_", "test.")):
        return True
    if base.endswith(("_test.c", "-test.c", "_test.h")):
        return True
    if p.endswith((".pcap", ".pcapng", ".cap", ".out", ".err", ".expected")):
        return True
    if base in ("testlist", "testlist.in"):
        return True
    return False

def git(repo, *args, check=True):
    r = subprocess.run(["git", "-C", repo, *args], text=True,
                       stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if check and r.returncode != 0:
        raise RuntimeError(f"git {' '.join(args)} failed: {r.stderr.strip()}")
    return r.stdout

def changed_files(repo, commit):
    out = git(repo, "diff-tree", "--no-commit-id", "--name-only", "-r", commit)
    return [f for f in out.split("\n") if f.strip()]

def revert_set(files):
    return [f for f in files if f.endswith(CODE_EXT) and not is_test_path(f)]

def snapshot(repo, commit, dest, revert_files=None, parent="^"):
    """Materialize `commit` into dest (no .git); optionally revert given files to commit^."""
    os.makedirs(dest, exist_ok=True)
    p1 = subprocess.Popen(["git", "-C", repo, "archive", commit], stdout=subprocess.PIPE)
    subprocess.run(["tar", "-x", "-C", dest], stdin=p1.stdout, check=True)
    p1.wait()
    for f in (revert_files or []):
        # extract the file's PARENT version over the snapshot (makes it vulnerable)
        p = subprocess.Popen(["git", "-C", repo, "archive", commit + parent, "--", f],
                             stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        subprocess.run(["tar", "-x", "-C", dest], stdin=p.stdout, check=False)
        p.wait()

def free_gb(path="/"):
    st = os.statvfs(path)
    return st.f_bavail * st.f_frsize / (1024 ** 3)

def era_image(project, era):
    if project == "glibc":
        # pipeline's prebuilt base images
        return f"ai-ssd/glibc-base:ubuntu-{era}"
    return f"gt/{project}-base:{era}"

# ---------------------------------------------------------------- in-container runners
# Each prints CONFIGURE_OK/FAIL and exactly one 'RESULT=PASS|FAIL|NORESULT' line,
# plus optional ASAN_CLASS= / TOPFRAME= evidence. They are git-free and symmetric.

RUNNERS = {
"tcpdump": r'''#!/bin/bash
ulimit -f 131072 2>/dev/null || true
cd /src
export CFLAGS="-fsanitize=address -fno-omit-frame-pointer -g -O0 -w"
export LDFLAGS="-fsanitize=address"
if [ ! -x ./configure ]; then (./autogen.sh || autoreconf -fi) >/tmp/agen.log 2>&1 || true; fi
./configure >/tmp/cfg.log 2>&1 && echo CONFIGURE_OK || { echo CONFIGURE_FAIL; tail -15 /tmp/cfg.log; echo "RESULT=NORESULT"; exit 0; }
make -j"${JOBS:-4}" >/tmp/make.log 2>&1 || make -k >/tmp/make.log 2>&1
[ -x ./tcpdump ] || { echo NO_BINARY; tail -15 /tmp/make.log; echo "RESULT=NORESULT"; exit 0; }
CAP="tests/$GT_PCAP"; [ -f "$CAP" ] || CAP="$GT_PCAP"
[ -f "$CAP" ] || { echo "RESULT=NORESULT"; echo "no pcap $GT_PCAP"; exit 0; }
export ASAN_OPTIONS="abort_on_error=1:exitcode=99:detect_leaks=0:halt_on_error=1"
FLAGS="${GT_FLAGS:--nn -v}"
echo "--- ./tcpdump $FLAGS -r $CAP ---"
timeout "${RUN_TIMEOUT:-120}" ./tcpdump $FLAGS -r "$CAP" >/tmp/run.log 2>&1; rc=$?
echo "EXIT=$rc"
grep -m1 -oE "(heap-buffer-overflow|stack-buffer-overflow|global-buffer-overflow|heap-use-after-free|SEGV|stack-overflow|use-after-poison)" /tmp/run.log | sed "s/^/ASAN_CLASS=/"
grep -E "#[0-9]+ .* in .*\.(c|h)" /tmp/run.log | head -1 | sed "s/^/TOPFRAME=/"
# arg-parse rejection => dissector never reached => not a valid result
if grep -qiE "syntax error|^Usage:|invalid option|unrecognized option" /tmp/run.log \
   && ! grep -qiE "reading from file|AddressSanitizer|ABORTING|Segmentation|runtime error" /tmp/run.log; then
  echo "RESULT=NORESULT (tcpdump rejected args)"; exit 0
fi
[ "$rc" -eq 0 ] && echo "RESULT=PASS" || echo "RESULT=FAIL"
exit 0
''',

"openssl": r'''#!/bin/bash
ulimit -f 262144 2>/dev/null || true
cd /src
( ./config --prefix=/opt/pfx shared -w -Wno-error 2>&1 && echo CONFIGURE_OK ) >/tmp/cfg.log 2>&1 || true
grep -q CONFIGURE_OK /tmp/cfg.log && echo CONFIGURE_OK || { echo CONFIGURE_FAIL; tail -20 /tmp/cfg.log; }
make depend >/tmp/dep.log 2>&1 || true
( make -j"${JOBS:-4}" build_sw 2>/dev/null || make -j"${JOBS:-4}" -k ) >/tmp/make.log 2>&1
make -j"${JOBS:-4}" "test/$GT_TESTNAME" >>/tmp/make.log 2>&1 || true
if ! ls /src/libssl.so* /opt/pfx/lib/libssl.so* /opt/pfx/lib64/libssl.so* 2>/dev/null | grep -q .; then
  echo "RESULT=NORESULT (no libssl)"; tail -15 /tmp/make.log; exit 0; fi
export LD_LIBRARY_PATH="/src:/opt/pfx/lib:/opt/pfx/lib64"
# Prefer openssl's OWN perl test harness: it sets up the cert/key fixtures and env the
# standalone test binary needs. Running the raw binary misses its fixtures and fails
# spuriously on BOTH arms. Discover the recipe that drives this binary generically:
# grep test/recipes/*.t for the binary name -> recipe "test_<x>" (strip NN- prefix).
REC=$(grep -lE "(^|[^A-Za-z0-9_])${GT_TESTNAME}([^A-Za-z0-9_]|\$)" test/recipes/*.t 2>/dev/null | head -1)
if [ -n "$REC" ]; then
  TESTS=$(basename "$REC" .t | sed 's/^[0-9]*-//')
  echo "--- make test TESTS=$TESTS (perl harness) ---"
  timeout "${RUN_TIMEOUT:-400}" make test TESTS="$TESTS" HARNESS_VERBOSE=yes >/tmp/mt.log 2>&1; rc=$?
  tail -30 /tmp/mt.log
  grep -m1 -oE "(heap-buffer-overflow|stack-buffer-overflow|heap-use-after-free|SEGV|stack-overflow)" /tmp/mt.log | sed "s/^/ASAN_CLASS=/"
  if grep -qiE "(^|[^a-z])not ok|FAILED|Dubious|ERROR IN|Result: FAIL" /tmp/mt.log; then echo "RESULT=FAIL"; exit 0; fi
  if grep -qiE "Result: PASS|All tests successful" /tmp/mt.log && [ "$rc" -eq 0 ]; then echo "RESULT=PASS"; exit 0; fi
  [ "$rc" -eq 0 ] && { echo "RESULT=PASS"; exit 0; } || { echo "RESULT=FAIL"; exit 0; }
fi
# fallback: no recipe found -> run the raw binary
TBIN="/src/test/$GT_TESTNAME"
if [ -x "$TBIN" ]; then
  echo "--- run raw test/$GT_TESTNAME (no recipe) ---"
  timeout "${RUN_TIMEOUT:-300}" "$TBIN" >/tmp/it.log 2>&1; rc=$?
  tail -20 /tmp/it.log
  grep -m1 -oE "(heap-buffer-overflow|stack-buffer-overflow|heap-use-after-free|SEGV|stack-overflow)" /tmp/it.log | sed "s/^/ASAN_CLASS=/"
  echo "EXIT=$rc"; [ "$rc" -eq 0 ] && echo "RESULT=PASS" || echo "RESULT=FAIL"; exit 0
fi
echo "RESULT=NORESULT (no recipe, no test binary)"; exit 0
''',

"glibc": r'''#!/bin/bash
ulimit -f 524288 2>/dev/null || true
SRC=/src; BD=/build; PFX=/opt/pfx; CC=gcc   # era-matched gcc (from the era base image)
mkdir -p "$BD" "$PFX"
# relax old configure version gates (newer binutils/sed rejected as "too old")
sed -i 's/test -n "$critic_missing"/false/g; s/test "x$critic_missing" != x/false/g' "$SRC/configure" 2>/dev/null || true
# _begin linker-script compat for old trees (binutils >= 2.21) so ld.so links
if grep -q 'GL(dl_rtld_map).l_map_start = (ElfW(Addr)) _begin;' "$SRC/elf/rtld.c" 2>/dev/null; then
  sed -i -e 's|GL(dl_rtld_map).l_map_start = (ElfW(Addr)) _begin;|GL(dl_rtld_map).l_map_start = (ElfW(Addr)) GL(dl_rtld_map).l_addr;|' \
         -e 's|= (ElfW(Ehdr) \*) \&_begin;|= (ElfW(Ehdr) *) bootstrap_map.l_addr;|' "$SRC/elf/rtld.c" 2>/dev/null
fi
cd "$BD"; rm -rf ./* 2>/dev/null
# 3 escalating configure strategies (mirrors the pipeline's proven glibc build)
CFG=0
"$SRC"/configure --prefix="$PFX" --disable-werror --disable-sanity-checks --disable-profile --enable-obsolete-rpc \
  CC="$CC -fno-stack-protector -fgnu89-inline" CFLAGS="-O2 -g -fno-stack-protector -Wno-error -w -U_FORTIFY_SOURCE" >/tmp/cfg.log 2>&1 && CFG=1
if [ $CFG -eq 0 ]; then cd "$BD"; rm -rf ./*; "$SRC"/configure --prefix="$PFX" --disable-werror --disable-sanity-checks --disable-profile --disable-nscd --without-selinux --without-gd \
  CC="$CC -fgnu89-inline" CFLAGS="-O1 -g -w -U_FORTIFY_SOURCE -fno-stack-protector -Wno-error" >/tmp/cfg.log 2>&1 && CFG=1; fi
if [ $CFG -eq 0 ]; then cd "$BD"; rm -rf ./*; "$SRC"/configure --prefix="$PFX" --disable-werror --disable-sanity-checks --disable-profile --disable-nscd \
  CC="$CC" CFLAGS="-O0 -g -w -U_FORTIFY_SOURCE -fno-stack-protector -Wno-error -std=gnu99 -fgnu89-inline -fno-strict-aliasing" >/tmp/cfg.log 2>&1 && CFG=1; fi
[ $CFG -eq 1 ] && echo CONFIGURE_OK || { echo CONFIGURE_FAIL; tail -25 /tmp/cfg.log; echo "RESULT=NORESULT"; exit 0; }
make -j"${JOBS:-6}" -k >/tmp/make.log 2>&1
LOADER=$(ls "$BD"/elf/ld-*.so* 2>/dev/null | head -1); LIBC=$(ls "$BD"/libc.so.6 "$BD"/libc.so 2>/dev/null | head -1)
if [ -z "$LOADER" ] || [ -z "$LIBC" ]; then echo "RESULT=NORESULT (no runtime)"; tail -25 /tmp/make.log; exit 0; fi
TR="$BD/$GT_SUBDIR/$GT_TESTNAME.test-result"; rm -f "$TR"
timeout "${RUN_TIMEOUT:-320}" make test "t=$GT_SUBDIR/$GT_TESTNAME" >/tmp/mt.log 2>&1
if [ -f "$TR" ]; then
  cat "$TR"
  grep -qE '^PASS' "$TR" && { echo "RESULT=PASS"; exit 0; }
  grep -qE '^(FAIL|ERROR|UNRESOLVED)' "$TR" && { echo "RESULT=FAIL"; exit 0; }
fi
# fallback: standalone compile + run through the BUILD runtime (never host libc)
LIBP="$BD"; for d in "$BD"/*/; do LIBP="$LIBP:${d%/}"; done
"$CC" -O2 -D_GNU_SOURCE "-DTEST_DATA_LIMIT=(3UL<<30)" "$SRC/$GT_TESTPATH" -o /tmp/itest -lpthread -lm 2>/tmp/cc.log \
  || "$CC" -O2 -D_GNU_SOURCE "$SRC/$GT_TESTPATH" -o /tmp/itest 2>>/tmp/cc.log
if [ -x /tmp/itest ]; then
  GCONV_PATH="$BD/iconvdata" timeout "${RUN_TIMEOUT:-320}" "$LOADER" --library-path "$LIBP" /tmp/itest >/tmp/it.log 2>&1; rc=$?
  tail -15 /tmp/it.log
  grep -m1 -oE "(Segmentation|Aborted|buffer overflow|stack smashing|corrupt)" /tmp/it.log | sed "s/^/CRASH=/"
  echo "EXIT=$rc"; [ "$rc" -ne 0 ] && echo "RESULT=FAIL" || echo "RESULT=PASS"; exit 0
fi
echo "standalone compile failed:"; tail -8 /tmp/cc.log 2>/dev/null
echo "RESULT=NORESULT"; exit 0
''',
}

# ---------------------------------------------------------------- tcpdump pcap/flags from the fix
def tcpdump_pcap_flags(repo, fix):
    """Return (pcap_basename, flags) for the capture the fix added under tests/."""
    files = changed_files(repo, fix)
    pcaps = [f for f in files if f.lower().endswith((".pcap", ".pcapng", ".cap"))]
    pcap = os.path.basename(pcaps[0]) if pcaps else ""
    flags = "-nn -v"
    # recover flags from the TESTLIST line the fix added, if any
    try:
        diff = git(repo, "show", fix, "--", "tests/TESTLIST", check=False)
        stem = os.path.splitext(pcap)[0] if pcap else ""
        for line in diff.splitlines():
            if line.startswith("+") and pcap and pcap in line:
                cols = line[1:].split()
                # name  pcap  out  <flags...>
                if len(cols) >= 4:
                    flags = " ".join(cols[3:]); break
    except Exception:
        pass
    return pcap, flags

# ---------------------------------------------------------------- per-CVE oracle
def run_container(project, arm_dir, era, env, runner_path, timeout, name, extra_mounts=None):
    img = era_image(project, era)
    # /tmp is a RAM tmpfs so runaway logs (infinite-loop / very verbose PoCs)
    # are capped in memory and can NEVER fill the host disk; --memory bounds RAM.
    cmd = ["docker", "run", "--rm", "--name", name,
           "--tmpfs", "/tmp:rw,exec,size=128m",
           # glibc's parallel build peaks well above 8G; cap generously (host has 62G,
           # and only a few builds run at once) so builds aren't OOM-killed into NORESULT.
           "--memory", "16g", "--memory-swap", "16g",
           "-v", f"{arm_dir}:/src",
           "-v", f"{runner_path}:/runner.sh:ro"]
    for hostp, contp in (extra_mounts or []):
        cmd += ["-v", f"{hostp}:{contp}"]
    for k, v in env.items():
        cmd += ["-e", f"{k}={v}"]
    cmd += [img, "bash", "/runner.sh"]
    try:
        r = subprocess.run(cmd, text=True, stdout=subprocess.PIPE,
                           stderr=subprocess.STDOUT, timeout=timeout)
        return r.stdout
    except subprocess.TimeoutExpired as e:
        # kill the container so it can't linger and keep writing
        subprocess.run(["docker", "rm", "-f", name],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        return (e.output or "") + "\nRESULT=NORESULT (container timeout)\n"

def parse_arm(out):
    res = "NORESULT"
    m = re.findall(r"^RESULT=(PASS|FAIL|NORESULT)", out, re.M)
    if m:
        res = m[-1]
    asan = (re.search(r"ASAN_CLASS=(\S+)", out) or [None, None])[1]
    crash = (re.search(r"CRASH=(.+)", out) or [None, None])[1]
    frame = (re.search(r"TOPFRAME=(.+)", out) or [None, None])[1]
    exit_m = re.search(r"EXIT=(-?\d+)", out)
    cfg_fail = "CONFIGURE_FAIL" in out and "CONFIGURE_OK" not in out
    return {"result": res, "asan": asan, "crash": crash, "top_frame": frame,
            "exit": int(exit_m.group(1)) if exit_m else None, "configure_failed": cfg_fail}

def derive_verdict(vminus, vplus):
    a, b = vminus["result"], vplus["result"]
    if a == "NORESULT" or b == "NORESULT":
        return "UNCONFIRMABLE", f"V-={a}, V+={b} (build/runtime failure on an arm)"
    if a == "FAIL" and b == "PASS":
        return "CONFIRMED", "test fails on vulnerable tree, passes on upstream-fixed tree"
    if a == "PASS":
        return "REFUTED", "test passes even on the vulnerable tree (does not exercise the vuln)"
    if b == "FAIL":
        return "REFUTED", "test still fails on the upstream-fixed tree (fix/test mismatch)"
    return "UNCONFIRMABLE", f"V-={a}, V+={b}"

def process_cve(project, repo, cve_obj, workdir, runner_path, jobs_per_build, run_timeout, min_free_gb):
    cve = cve_obj["cve"]; fix = cve_obj.get("FIX_COMMIT", "").strip()
    era = cve_obj.get("ubuntu_version") or "22.04"
    rec = {"cve": cve, "fix_commit": fix, "parent_commit": (fix + "^") if fix else "",
           "era": era, "pipeline_reproduced": cve_obj.get("pipeline_reproduced"),
           "F_NAME": cve_obj.get("F_NAME", ""), "FilePath": cve_obj.get("FilePath", "")}
    if not fix:
        rec.update(groundtruth="UNCONFIRMABLE", reason="no FIX_COMMIT recorded"); return rec
    if free_gb() < min_free_gb:
        rec.update(groundtruth="UNCONFIRMABLE", reason=f"disk guard (<{min_free_gb}GB free)"); return rec
    try:
        files = changed_files(repo, fix)
    except Exception as e:
        rec.update(groundtruth="UNCONFIRMABLE", reason=f"commit not found: {e}"); return rec
    rev = revert_set(files)
    if not rev:
        rec.update(groundtruth="UNCONFIRMABLE", reason="no source file to revert (fix touches only tests/meta)",
                   revert_files=[]); return rec
    rec["revert_files"] = rev
    base = os.path.join(workdir, cve)
    safe = cve.replace(".", "_")
    vminus_dir, vplus_dir = base + "__vminus", base + "__vplus"
    bminus, bplus = base + "__bminus", base + "__bplus"   # glibc out-of-tree build dirs (host)
    cleanup_dirs = [vminus_dir, vplus_dir, bminus, bplus]
    for d in cleanup_dirs:
        shutil.rmtree(d, ignore_errors=True)
    # env per project
    env = {"JOBS": str(jobs_per_build), "RUN_TIMEOUT": str(run_timeout)}
    if project == "tcpdump":
        pcap, flags = tcpdump_pcap_flags(repo, fix)
        env["GT_PCAP"] = pcap; env["GT_FLAGS"] = flags
        rec["pcap"] = pcap; rec["flags"] = flags
    elif project == "openssl":
        tp = cve_obj.get("TEST_PATH", "")
        env["GT_TESTNAME"] = os.path.splitext(os.path.basename(tp))[0] if tp else ""
    elif project == "glibc":
        tp = cve_obj.get("TEST_PATH", "")
        env["GT_TESTPATH"] = tp
        env["GT_TESTNAME"] = os.path.splitext(os.path.basename(tp))[0] if tp else ""
        env["GT_SUBDIR"] = cve_obj.get("TEST_SUBDIR", "") or "misc"
    mounts_minus = mounts_plus = None
    if project == "glibc":
        os.makedirs(bminus, exist_ok=True); os.makedirs(bplus, exist_ok=True)
        mounts_minus = [(bminus, "/build")]; mounts_plus = [(bplus, "/build")]
    ctimeout = run_timeout + 2400   # container-level cap: build (up to ~40min) + run
    try:
        snapshot(repo, fix, vplus_dir)               # V+ : untouched fix
        snapshot(repo, fix, vminus_dir, revert_files=rev)   # V- : fix with source reverted
        out_minus = run_container(project, vminus_dir, era, env, runner_path, ctimeout,
                                  f"gt_{project}_{safe}_m", mounts_minus)
        out_plus = run_container(project, vplus_dir, era, env, runner_path, ctimeout,
                                 f"gt_{project}_{safe}_p", mounts_plus)
        vminus, vplus = parse_arm(out_minus), parse_arm(out_plus)
        verdict, reason = derive_verdict(vminus, vplus)
        rec.update(v_minus=vminus, v_plus=vplus, groundtruth=verdict, reason=reason)
    except Exception as e:
        rec.update(groundtruth="UNCONFIRMABLE", reason=f"harness error: {e}")
    finally:
        for d in cleanup_dirs:
            shutil.rmtree(d, ignore_errors=True)
        # Docker writes build artifacts as root; a non-sudo host cleanup (above) leaves
        # root-owned remnants. Remove them via a throwaway root container so the workdir
        # cannot accumulate and fill the disk.
        remnants = [os.path.basename(d) for d in cleanup_dirs if os.path.exists(d)]
        if remnants:
            try:
                subprocess.run(["docker", "run", "--rm", "-v", f"{os.path.abspath(workdir)}:/w",
                                "ubuntu:22.04", "bash", "-c", "cd /w && rm -rf " + " ".join(remnants)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120)
            except Exception:
                pass
    return rec

# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--project", required=True, choices=list(RUNNERS))
    ap.add_argument("--repo", required=True)
    ap.add_argument("--inputs", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--workdir", required=True)
    ap.add_argument("--jobs", type=int, default=4, help="concurrent CVEs")
    ap.add_argument("--build-jobs", type=int, default=6, help="make -j inside each build")
    ap.add_argument("--run-timeout", type=int, default=180)
    ap.add_argument("--min-free-gb", type=float, default=12.0)
    ap.add_argument("--only", default="", help="comma-separated CVE allowlist")
    ap.add_argument("--reproduced-only", action="store_true")
    args = ap.parse_args()

    os.makedirs(args.workdir, exist_ok=True)
    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    runner_path = os.path.join(args.workdir, f"{args.project}_runner.sh")
    with open(runner_path, "w") as fh:
        fh.write(RUNNERS[args.project])

    data = json.load(open(args.inputs))
    if args.reproduced_only:
        data = [o for o in data if o.get("pipeline_reproduced")]
    if args.only:
        allow = set(args.only.split(","))
        data = [o for o in data if o["cve"] in allow]
    # resume: skip CVEs already in the output
    done = {}
    if os.path.exists(args.out):
        try:
            done = {r["cve"]: r for r in json.load(open(args.out))}
        except Exception:
            done = {}
    todo = [o for o in data if o["cve"] not in done]
    print(f"[{args.project}] {len(data)} CVEs, {len(done)} cached, {len(todo)} to run, "
          f"{args.jobs}-way, free={free_gb():.1f}GB", flush=True)

    results = list(done.values())
    def flush():
        json.dump(sorted(results, key=lambda r: r["cve"]), open(args.out, "w"), indent=1)
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=args.jobs) as ex:
        futs = {ex.submit(process_cve, args.project, args.repo, o, args.workdir,
                          runner_path, args.build_jobs, args.run_timeout, args.min_free_gb): o["cve"]
                for o in todo}
        n = 0
        for fut in as_completed(futs):
            rec = fut.result(); results.append(rec); n += 1
            print(f"  [{n}/{len(todo)}] {rec['cve']:20s} {rec.get('groundtruth','?'):13s} "
                  f"free={free_gb():.1f}GB  {rec.get('reason','')[:60]}", flush=True)
            flush()
    flush()
    from collections import Counter
    c = Counter(r["groundtruth"] for r in results)
    print(f"[{args.project}] done in {(time.time()-t0)/60:.1f}min: {dict(c)}", flush=True)

if __name__ == "__main__":
    main()
