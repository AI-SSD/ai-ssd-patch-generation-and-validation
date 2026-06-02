# PoC Success-Flag Analysis — Phase 1.3 Replication Verification

**Author:** AI-SSD Security Analysis  
**Date:** 2026-06-02  
**Scope:** `poc_analyzer.py`, `orchestrator.py` (`_interpret_exit_code`, `_generate_dockerfile`)

---

## 1. Classification of Current PoC Flags

The pipeline currently detects success through two independent but layered mechanisms: the **dynamic wrapper** (inside the container) and the **host-side interpreter** (`_interpret_exit_code`).

### 1.1 Wrapper-Level Flags (inside the container, `wrapper.sh`)

| Exit Code | Meaning | Source |
|-----------|---------|--------|
| `42` | Vulnerability confirmed — `verify_cmd` exited 0 | `CVEImageBuilder._generate_dockerfile` |
| `43` | PoC ran but `verify_cmd` exited non-zero | Same |
| Any other | Wrapper did not reach the verification step | Crash, env failure, missing binary |

The `verify_cmd` is generated per-category by `PoCAnalyzer.analyze_poc()` (LLM primary, `_heuristic_analysis` fallback). Category → default verification mapping:

| Category | Default Verification Strategy |
|----------|-------------------------------|
| `LPE` | `grep -qiE 'uid=0\(root\)|^\[+\].*[Ss]hell|Launching shell' /tmp/out` |
| `FORMAT_STRING` | Crash signal OR SUID artifact OR root-shell string in /tmp/out |
| `DOS` | Exit code 139/134/≥128 OR crash string in /tmp/out |
| `SUID_DROPPER` | `find /tmp /var/tmp -perm /4000` OR specific artifact `[ -u /tmp/xp ]` |
| `INFO_LEAK` | `grep -qE 'root:.*:0:0:'` in /tmp/out |
| `METASPLOIT` | Stubbed — always exits 43 (framework not installed) |
| `RCE` | Specific diagnostic strings from ld.so |
| `ARB_FILE_WRITE` | `grep -q "pwned" /etc/passwd` |

### 1.2 Host-Side Interpreter Flags (`_interpret_exit_code`)

The interpreter runs **only when the wrapper does not return 42/43** (i.e., the container crashed before reaching the verification block). It operates in four sequential phases:

| Phase | Signal Type | Examples |
|-------|-------------|---------|
| **Phase 1** | Environment rejection | exit 127 (binary not found), `exec format error`, missing shared lib, missing Ruby/Python module |
| **Phase 2** | Vulnerability crash signals | exit 139 (SIGSEGV), 134 (SIGABRT), 135 (SIGBUS), heap corruption strings, sanitizer reports, FORTIFY_SOURCE |
| **Phase 3** | CVE-specific overrides | `CVE-2012-3480` strtod output, `CVE-2015-7547` getaddrinfo, `CVE-2014-5119` `__gconv_translit_find`, `CVE-2017-1000366` ld.so hwcap |
| **Phase 4** | Default fallback | Log "Could not confirm" and return False |

---

## 2. Identified Gaps and Weak Detections

### 2.1 Silent Success (PoC works but produces no stdout proof)

**Problem:** Several PoC categories succeed without emitting `uid=0(root)` or any other grep-able string to `/tmp/out`.

**Affected scenarios:**
- `CVE-2001-0169` (tcsh/LD_PRELOAD) — creates `/var/tmp/.nothing` with chmod 6755, then exits. The success proof is the SUID file on disk, *not* stdout. Currently the heuristic routes this to `LPE` (rule 3, LD_PRELOAD signal), but `verify_cmd` only greps `/tmp/out` for shell-spawn strings that will never appear.
- `CVE-2010-3856` (shell script, `ld.so` audit) — succeeds by creating a root-owned SUID binary. Stdout is not captured in the standard `/tmp/out` because the wrapper may spawn a subshell.
- Any LPE that uses `execve("/bin/sh", ...)` without piping `id\n` to stdin will hang waiting for interactive input, causing a timeout (which is currently treated as success — a correct result for the wrong reason).

**Current weakness:** The wrapper script does not probe the filesystem for artifacts after executing the exploit. It only reads `/tmp/out`.

### 2.2 Crash Ambiguity (Generic Crash vs. Vulnerability-Triggered Crash)

**Problem:** The host-side interpreter returns `True` for virtually any crash signal (exit 139, 134, any 128+N). This is correct for `DOS` PoCs but causes false positives for other categories.

**Affected scenarios:**
- A `LPE` PoC that crashes due to a null dereference in its *own* setup code (missing `/etc/ld.so.conf.d/` file, wrong glibc version) will be reported as "reproduced" even though the vulnerable code path was never reached.
- A `FORMAT_STRING` PoC that exits 134 because `abort()` was called by FORTIFY_SOURCE *inside the PoC's own `printf` call* (not the target's) is indistinguishable from a genuine format string exploitation.
- The catch-all `128 < exit_code < 192` block (line 2232 of orchestrator.py) accepts signals 1–63, including `SIGHUP`, `SIGPIPE`, `SIGTERM` — all of which can be triggered by routine infrastructure events, not a vulnerability.

**Root cause:** No distinction between the *source* of the crash (vulnerable library code path vs. PoC infrastructure code).

### 2.3 Multi-Stage PoC Execution

**Problem:** Some PoCs require a second stage to confirm exploitation.

**Affected scenarios:**
- `CVE-2001-0169`: Stage 1 creates `/var/tmp/.nothing`. Stage 2 would be running `.nothing` as root. The current wrapper only runs stage 1.
- `CVE-2000-0844` PoC family (10 variants): Multiple PoCs target different paths in the same vulnerability. Only the primary file is tried; alt fallbacks attempt compilation only, not semantic diversity.
- Metasploit modules (`CVE-2010-3847`, `CVE-2015-0235`): Require a live target service. The current stub always exits 43, which is correct but provides no partial reproduction signal.

### 2.4 Filesystem State Probing

**Problem:** The current wrapper never checks filesystem state directly. The only artifact checks are inside the LLM-generated `verify_cmd`, which may not probe the correct path.

Missing probes:
- `/var/tmp/.nothing` — specific to CVE-2001-0169 style SUID droppers
- `/tmp/kidd0`, `/tmp/r00t` — common PoC artifact names
- `/etc/passwd`, `/etc/shadow` modification timestamps
- `dmesg` entries (kernel messages from syscall abuse)
- Writable file in a normally root-owned directory (ARB_FILE_WRITE proof)

### 2.5 `_heuristic_analysis` False Positives and Misroutes

| PoC | Expected Category | Actual Routing | Issue |
|-----|-------------------|----------------|-------|
| CVE-2001-0169 (LD_PRELOAD, tcsh) | `SUID_DROPPER` | `LPE` (rule 3: LD_PRELOAD) | Rule 3 fires before rule 4 (SUID_DROPPER); verify_cmd checks for root shell text instead of SUID file |
| CVE-2000-0844 (FORMAT_STRING, gettext) | `FORMAT_STRING` | `FORMAT_STRING` (correctly) | verify_cmd relies on crash OR SUID artifact but never checks `/var/tmp/.nothing` specifically |
| Any PoC with `// shadow copy` comment | `INFO_LEAK` | `INFO_LEAK` (false) | Rule 5 matches `shadow` string anywhere, including comments |
| DOS PoC with memcpy+argv but usage line that references a binary name | `DOS` custom argv | `DOS` with `usage_command` = correct binary | Correct, but the wrapper exits 43 if the target binary isn't at the usage-derived path |

### 2.6 Metasploit Module Verification

**Problem:** All `.rb` Metasploit modules are wrapped in a stub that exits 43. There is no partial-verification signal even when the module CAN be structurally validated (e.g., correct protocol output, connection attempt logged).

For network-based exploits like `CVE-2015-0235` (GHOST), the container has `network_disabled=True`, so even if `msfconsole` were installed the exploit would fail. This is architecturally correct but means these CVEs will never be reproduced in Phase 1.

---

## 3. Proposed Modular Success Verification Engine

The proposed architecture adds a **three-layer verification model** that decouples *what to check* from *how to check it*.

```
┌─────────────────────────────────────────────────────────┐
│  PoCAnalyzer  (LLM + heuristics)                        │
│  → produces VerificationSpec (structured, not a string) │
└────────────────────┬────────────────────────────────────┘
                     │ VerificationSpec
                     ▼
┌─────────────────────────────────────────────────────────┐
│  WrapperBuilder                                         │
│  → serialises VerificationSpec into wrapper.sh          │
│  → checks are ordered and labeled                       │
└────────────────────┬────────────────────────────────────┘
                     │ wrapper.sh (multi-probe)
                     ▼
┌─────────────────────────────────────────────────────────┐
│  Container execution                                    │
│  → exit 42 = proven, exit 43 = ran/not proven           │
│  → JSON proof record written to /tmp/ssd_proof.json     │
└────────────────────┬────────────────────────────────────┘
                     │ exit code + logs + /tmp/ssd_proof.json
                     ▼
┌─────────────────────────────────────────────────────────┐
│  ResultInterpreter  (replaces _interpret_exit_code)     │
│  → reads proof record, applies per-category confidence  │
│  → returns (verified: bool, confidence: float, reason)  │
└─────────────────────────────────────────────────────────┘
```

### 3.1 VerificationSpec — Structured Contract

Replace the raw `verification_command` string with a structured object:

```python
@dataclass
class VerificationSpec:
    category: str               # LPE | DOS | FORMAT_STRING | etc.
    confidence_threshold: float # 0.0–1.0 required to call it reproduced
    checks: List[VerificationCheck]

@dataclass
class VerificationCheck:
    kind: str          # "stdout_grep" | "suid_file" | "file_exists" | "exit_code" | "dmesg_grep"
    params: dict       # kind-specific parameters
    weight: float      # contribution to confidence score
    required: bool     # if True, failure immediately disqualifies
```

**Example — CVE-2001-0169 (SUID dropper):**

```python
VerificationSpec(
    category="SUID_DROPPER",
    confidence_threshold=0.6,
    checks=[
        VerificationCheck(
            kind="suid_file",
            params={"paths": ["/var/tmp/.nothing", "/tmp/xp", "/tmp/kidd0", "/tmp/r00t"]},
            weight=1.0,
            required=False,
        ),
        VerificationCheck(
            kind="find_suid",
            params={"search_dirs": ["/tmp", "/var/tmp"], "min_count": 1},
            weight=0.8,
            required=False,
        ),
        VerificationCheck(
            kind="stdout_grep",
            params={"pattern": r"uid=0\(root\)|SUID|setuid"},
            weight=0.3,
            required=False,
        ),
    ],
)
```

**Example — CVE-2011-2702 (DOS / memcpy argv):**

```python
VerificationSpec(
    category="DOS",
    confidence_threshold=0.5,
    checks=[
        VerificationCheck(
            kind="exit_code",
            params={"codes": [139, 134], "interpretation": "crash_signal"},
            weight=1.0,
            required=False,
        ),
        VerificationCheck(
            kind="exit_code_range",
            params={"min": 129, "max": 159, "exclude": [130, 131]},  # exclude Ctrl-C/Ctrl-Z
            weight=0.6,
            required=False,
        ),
        VerificationCheck(
            kind="stdout_grep",
            params={"pattern": r"segmentation fault|buffer overflow|core dumped|stack smashing"},
            weight=0.4,
            required=False,
        ),
    ],
)
```

### 3.2 Enhanced `wrapper.sh` Template

The wrapper should emit a machine-readable proof record so the host-side interpreter has structured data, not just raw log text.

```bash
#!/bin/bash
set -o pipefail
CATEGORY="{category}"
PROOF_FILE="/tmp/ssd_proof.json"

# Initialize proof record
echo '{"category":"'"$CATEGORY"'","checks":[],"confirmed":false}' > "$PROOF_FILE"

append_check() {
    local name="$1" result="$2" detail="$3"
    python3 -c "
import json, sys
p = json.load(open('$PROOF_FILE'))
p['checks'].append({'name':'$name','result':'$result','detail':'$detail'})
json.dump(p, open('$PROOF_FILE','w'))
" 2>/dev/null || true
}

# ── 1. Setup ──────────────────────────────────────────────────────────────────
{setup_command}

# ── 2. Execution ──────────────────────────────────────────────────────────────
{execution_wrapper}
exit_code=$?
append_check "exit_code" "$exit_code" "process exit code"

# ── 3. Stdout/stderr checks ───────────────────────────────────────────────────
if [ -f /tmp/out ]; then
    # Check for root shell proof
    if grep -qiE 'uid=0\(root\)|^\s*root\s*$|\[+\].*[Ss]hell' /tmp/out 2>/dev/null; then
        append_check "root_shell_stdout" "pass" "found in /tmp/out"
    fi
    # Check for crash strings
    if grep -qiE 'segmentation fault|core dumped|stack smashing|heap corruption' /tmp/out 2>/dev/null; then
        append_check "crash_string_stdout" "pass" "found in /tmp/out"
    fi
fi

# ── 4. Filesystem artifact checks ─────────────────────────────────────────────
SUID_ARTIFACTS=( /tmp/xp /tmp/r00t /tmp/kidd0 /var/tmp/.nothing /tmp/rootshell )
for artifact in "${SUID_ARTIFACTS[@]}"; do
    if [ -u "$artifact" ] 2>/dev/null; then
        append_check "suid_artifact" "pass" "$artifact has SUID bit"
    fi
done

# Generic SUID search in world-writable dirs
FOUND_SUID=$(find /tmp /var/tmp -perm /4000 2>/dev/null | head -3)
if [ -n "$FOUND_SUID" ]; then
    append_check "suid_find" "pass" "$FOUND_SUID"
fi

# ARB_FILE_WRITE: check if normally-root-owned files were modified
if [ -f /etc/passwd ] && grep -q 'pwned\|hacked\|ssd_test' /etc/passwd 2>/dev/null; then
    append_check "arb_write_passwd" "pass" "/etc/passwd modified"
fi

# ── 5. Crash-signal verification (DOS / FORMAT_STRING only) ───────────────────
if [ "$CATEGORY" = "DOS" ] || [ "$CATEGORY" = "FORMAT_STRING" ]; then
    if [ "$exit_code" -eq 139 ] || [ "$exit_code" -eq 134 ]; then
        append_check "crash_signal" "pass" "exit_code=$exit_code"
    elif [ "$exit_code" -ge 128 ] && [ "$exit_code" -le 159 ] \
         && [ "$exit_code" -ne 130 ] && [ "$exit_code" -ne 131 ]; then
        append_check "crash_signal_generic" "pass" "exit_code=$exit_code signal=$((exit_code-128))"
    fi
fi

# ── 6. INFO_LEAK checks ───────────────────────────────────────────────────────
if [ "$CATEGORY" = "INFO_LEAK" ]; then
    if grep -qE 'root:.*:0:0:|daemon:.*:1:1:|^root:' /tmp/out 2>/dev/null; then
        append_check "shadow_leak" "pass" "shadow/passwd content in output"
    fi
    if grep -qiE '0x[0-9a-f]{8,16}' /tmp/out 2>/dev/null; then
        append_check "address_leak" "pass" "hex address in output"
    fi
fi

# ── 7. Final verdict (category-aware) ─────────────────────────────────────────
CONFIRMED=false
PASS_COUNT=$(python3 -c "
import json
p = json.load(open('$PROOF_FILE'))
print(sum(1 for c in p['checks'] if c['result']=='pass'))
" 2>/dev/null || echo 0)

case "$CATEGORY" in
    LPE)
        python3 -c "
import json
p = json.load(open('$PROOF_FILE'))
names = [c['name'] for c in p['checks'] if c['result']=='pass']
sys.exit(0 if any(n in names for n in ['root_shell_stdout','suid_artifact','suid_find']) else 1)
" 2>/dev/null && CONFIRMED=true ;;
    DOS|FORMAT_STRING)
        python3 -c "
import json,sys
p = json.load(open('$PROOF_FILE'))
names = [c['name'] for c in p['checks'] if c['result']=='pass']
sys.exit(0 if any(n in names for n in ['crash_signal','crash_signal_generic','crash_string_stdout','suid_artifact']) else 1)
" 2>/dev/null && CONFIRMED=true ;;
    SUID_DROPPER)
        python3 -c "
import json,sys
p = json.load(open('$PROOF_FILE'))
names = [c['name'] for c in p['checks'] if c['result']=='pass']
sys.exit(0 if any(n in names for n in ['suid_artifact','suid_find']) else 1)
" 2>/dev/null && CONFIRMED=true ;;
    INFO_LEAK)
        python3 -c "
import json,sys
p = json.load(open('$PROOF_FILE'))
names = [c['name'] for c in p['checks'] if c['result']=='pass']
sys.exit(0 if any(n in names for n in ['shadow_leak','address_leak']) else 1)
" 2>/dev/null && CONFIRMED=true ;;
    *)
        # Generic: any check passed with exit 0, or crash for OTHER
        [ "$PASS_COUNT" -ge 1 ] && CONFIRMED=true ;;
esac

# Write final verdict to proof file
python3 -c "
import json
p = json.load(open('$PROOF_FILE'))
p['confirmed'] = $([ "$CONFIRMED" = "true" ] && echo true || echo false)
p['exit_code'] = $exit_code
json.dump(p, open('$PROOF_FILE','w'), indent=2)
" 2>/dev/null || true

if [ "$CONFIRMED" = "true" ]; then
    echo "--- VERIFICATION SUCCESS: Vulnerability Confirmed (category=$CATEGORY) ---"
    exit 42
else
    echo "--- VERIFICATION FAILED: Not Reproduced (category=$CATEGORY, exit=$exit_code, checks_passed=$PASS_COUNT) ---"
    exit 43
fi
```

### 3.3 Enhanced `_interpret_exit_code` — Structured Proof Reader

Replace the current log-scanning function with one that reads the JSON proof record first:

```python
def _interpret_exit_code(self, vuln, exit_code: int, logs: str) -> bool:
    """Read structured proof record first; fall back to log scanning."""

    # -- Primary: structured proof record ------------------------------------
    proof = self._extract_proof_record(logs)
    if proof:
        if exit_code == 42 or proof.get("confirmed"):
            self.logger.info(f"{vuln.cve}: Confirmed via proof record: "
                             f"{[c['name'] for c in proof.get('checks',[]) if c['result']=='pass']}")
            return True
        if exit_code == 43:
            self.logger.warning(f"{vuln.cve}: Not reproduced (exit 43). Proof: {proof.get('checks')}")
            return False

    # -- Secondary: legacy signal scanning (unchanged for compatibility) -----
    # ... existing Phase 1/2/3/4 logic ...

def _extract_proof_record(self, logs: str) -> Optional[dict]:
    """Extract the JSON proof record embedded in container logs."""
    import json
    # The proof file content may be echoed to stdout at the end of the wrapper
    for line in reversed(logs.splitlines()):
        line = line.strip()
        if line.startswith('{"category":'):
            try:
                return json.loads(line)
            except json.JSONDecodeError:
                continue
    return None
```

### 3.4 Category-Specific Improvements to `_heuristic_analysis`

#### Fix: LD_PRELOAD/LD_AUDIT PoC should route to SUID_DROPPER when SUID signals are present

```python
# In _heuristic_analysis, rule 3 (LD_AUDIT / LD_PRELOAD):
# Add a SUID-dropper check BEFORE the generic LPE assignment
_linker_with_suid = any(sig in content_lower for sig in _linker_signals) and any(
    re.search(p, content, re.IGNORECASE) for p in [
        r'chmod\s+[46]7[0-7][0-7]',
        r'/var/tmp/\.nothing',
        r'/tmp/kidd0',
        r'suid',
    ]
)
if _linker_with_suid:
    meta["poc_category"] = "SUID_DROPPER"
    # ... SUID_DROPPER verification ...
    return meta
elif any(sig in content_lower for sig in _linker_signals):
    # existing LPE logic
```

#### Fix: Tighten INFO_LEAK signal to avoid matching comments

```python
# OLD (rule 5):
_info_leak_env_signals = ["resolv_host_conf", "/etc/shadow", "shadow"]

# NEW: require the signal to appear in a non-comment context
def _has_info_leak_signal(content: str) -> bool:
    code_lines = [l for l in content.splitlines() if not l.strip().startswith(('/*', '//', '#', '*'))]
    code = "\n".join(code_lines).lower()
    return any(s in code for s in ["resolv_host_conf", "/etc/shadow"]) \
        or bool(re.search(r'\bshadow\b', code))
```

#### Fix: Crash signal filtering — exclude setup crashes for non-DOS categories

```python
# In _interpret_exit_code Phase 2, add category guard:
poc_category = vuln_metadata.get("poc_category", "OTHER")  # need to pass this in

if exit_code in (139, 134, 135, 136):
    # For LPE/INFO_LEAK, a crash before producing any output is likely a
    # setup error, not a successful exploitation
    if poc_category in ("LPE", "INFO_LEAK", "ARB_FILE_WRITE") and not logs.strip():
        self.logger.warning(f"{vuln.cve}: Crash with empty output for {poc_category} "
                            "category — likely setup/env failure, not exploitation")
        return False
    self.logger.info(f"{vuln.cve}: Crash signal (exit {exit_code}) — exploitation likely")
    return True
```

#### Fix: Exclude benign POSIX signals from the 128+N catch-all

```python
BENIGN_SIGNALS = {
    1,   # SIGHUP  — terminal hangup (container teardown)
    2,   # SIGINT  — Ctrl+C (user interrupt)
    13,  # SIGPIPE — broken pipe (normal for clients)
    15,  # SIGTERM — graceful shutdown
    17,  # SIGCHLD — child state change (not a crash)
}

if exit_code > 128 and exit_code < 192:
    signal_num = exit_code - 128
    if signal_num in BENIGN_SIGNALS:
        self.logger.debug(f"{vuln.cve}: Exit {exit_code} (signal {signal_num}) is benign — not a crash")
    else:
        self.logger.info(f"{vuln.cve}: Killed by signal {signal_num} (exit {exit_code})")
        return True
```

---

## 4. New Verification Patterns and Regex

### 4.1 SUID Artifact Detection (wrapper.sh bash)

```bash
# Extended SUID artifact probe with common PoC-authored paths
SUID_PROBE_PATHS=(
    /tmp/xp /tmp/r00t /tmp/rootshell /tmp/kidd0 /tmp/backdoor
    /var/tmp/.nothing /var/tmp/rootshell /tmp/.hidden_shell
)
for path in "${SUID_PROBE_PATHS[@]}"; do
    if [ -f "$path" ] && [ "$(stat -c %a "$path" 2>/dev/null)" = "4755" -o \
                          "$(stat -c %a "$path" 2>/dev/null)" = "6755" -o \
                          "$(stat -c %a "$path" 2>/dev/null)" = "4777" ]; then
        echo "SUID_ARTIFACT_FOUND: $path"
    fi
done
```

### 4.2 Shadow/Passwd Leak Pattern (verification_command)

```bash
# More permissive: also catches partial leaks
grep -qE \
    'root:[^:]*:[0-9]+:[0-9]+:|daemon:[^:]*:[0-9]+:|nobody:[^:]*:[0-9]+:' \
    /tmp/out 2>/dev/null
```

### 4.3 Root Shell Proof (LPE category)

```bash
# Capture id output if a subshell was spawned
grep -qiE \
    'uid=0\(root\)|euid=0|gid=0\(root\)|^\s*root\s*$|\[\+\].*(shell|root|escalat)' \
    /tmp/out 2>/dev/null
```

### 4.4 Differentiating Vulnerability-Triggered Crash from Setup Crash

```bash
# Heuristic: if the exploit produced ≥10 lines of output before crashing,
# the crash likely happened inside the vulnerable code path
output_lines=$(wc -l < /tmp/out 2>/dev/null || echo 0)
if [ "$exit_code" -eq 139 ] && [ "$output_lines" -lt 2 ]; then
    echo "CRASH_LIKELY_SETUP: only $output_lines lines before SIGSEGV"
    exit 43  # inconclusive
fi
```

### 4.5 dmesg Kernel Signal Detection

```bash
# After execution, check dmesg for crash markers (requires privileged container)
dmesg 2>/dev/null | tail -20 | grep -qiE \
    'general protection fault|kernel BUG|BUG:|Oops:|segfault at|invalid opcode' \
    && echo "KERNEL_CRASH_IN_DMESG"
```

### 4.6 Improved Exploit-Intent Patterns for `validate_poc_static`

```python
# Additions to _EXPLOIT_INTENT_PATTERNS in poc_analyzer.py

# TIOCSTI terminal injection
re.compile(r'TIOCSTI|0x5412', re.IGNORECASE),

# ptrace-based privilege escalation
re.compile(r'\bptrace\s*\(|PTRACE_ATTACH|PTRACE_POKETEXT', re.IGNORECASE),

# /proc/self/mem write (LPE via mem overwrite)
re.compile(r'/proc/self/mem|/proc/\d+/mem'),

# Dirty COW style signals
re.compile(r'madvise\s*\(.*MADV_DONTNEED|MAP_PRIVATE.*PROT_WRITE', re.IGNORECASE),

# Namespace escape
re.compile(r'unshare\s*\(|clone\s*\(.*CLONE_NEWUSER|setns\s*\(', re.IGNORECASE),

# ARB_FILE_WRITE via symlink
re.compile(r'symlink\s*\(|readlink\s*\(.*race|TOCTOU', re.IGNORECASE),
```

---

## 5. Metasploit Module Handling Recommendation

Metasploit modules cannot be verified without the framework and a live target, but they can be structurally evaluated:

```python
def _validate_msf_module(self, content: str, cve: str) -> dict:
    """Structural validation for Metasploit modules (no execution)."""
    signals = {
        "has_target_definition": bool(re.search(r"'Targets'\s*=>", content)),
        "has_payload_reference": bool(re.search(r"payload\.(encoded|raw|generate)", content)),
        "targets_glibc": bool(re.search(r"glibc|gethostbyname|getaddrinfo|stack.*overflow", content, re.IGNORECASE)),
        "has_reliability_rank": bool(re.search(r"(Great|Excellent|Normal)Ranking", content)),
        "cve_mentioned": cve.upper() in content.upper(),
    }
    score = sum(signals.values()) / len(signals)
    return {
        "poc_category": "METASPLOIT",
        "structural_validity_score": score,
        "structural_signals": signals,
        "reproduction_status": "requires_framework",
        "confidence": "medium" if score >= 0.6 else "low",
    }
```

This turns a binary "cannot run" into a graded confidence score that Phase 4 reporting can use.

---

## 6. Implementation Priority

| Priority | Change | Effort | Impact |
|----------|--------|--------|--------|
| 1 (Critical) | Add filesystem artifact probes to `wrapper.sh` (SUID find, specific paths) | Low | Fixes CVE-2001-0169 class |
| 2 (High) | Fix LD_PRELOAD routing: route to `SUID_DROPPER` when chmod/SUID signals present | Low | Fixes misrouting of 3+ CVEs |
| 3 (High) | Filter benign POSIX signals from 128+N catch-all in `_interpret_exit_code` | Low | Reduces false positives |
| 4 (High) | Add empty-output guard for LPE crash signals | Low | Prevents setup-crash false positives |
| 5 (Medium) | Replace raw `verify_cmd` string with `VerificationSpec` struct | High | Enables weighted multi-probe verification |
| 6 (Medium) | Emit `/tmp/ssd_proof.json` from wrapper.sh and read it on host | Medium | Structured audit trail for all results |
| 7 (Medium) | Tighten INFO_LEAK shadow detection to exclude comments | Low | Reduces false positives for commented PoCs |
| 8 (Low) | Metasploit structural validation score | Medium | Partial signal for network exploits |
| 9 (Low) | dmesg probe in wrapper (requires `--privileged` container) | Medium | Kernel-level crash detection |
