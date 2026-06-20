"""
DEPRECATED — Phase 1 two-gate verification logic (reference snapshot).

This module is a verbatim archive of the Phase 1 "Gate 1 / Gate 2" verification
code that used to live in ``orchestrator.py``. It is kept for historical
reference only and is NOT imported or executed by the pipeline.

It was superseded (methodology v2, Phase 1 redesign) by a deterministic
baseline-exit-code approach with an LLM-assisted negative filter:

  * Gate 1 (negative filter, in-wrapper grep)   -> moved host-side, now an
                                                    LLM negative filter with a
                                                    deterministic regex fallback
                                                    (``PoCAnalyzer.negative_filter``).
  * Gate 2 (positive proof: SUID probes, crash   -> removed. Success is now
            signals, LLM verify_cmd, SSD_PROOF)     established by matching the
                                                    baseline exit code captured
                                                    from a known-vulnerable run.

The methods below referenced ``self`` on ``CVEImageBuilder`` /
``DockerManager`` and the module-level helpers ``get_negative_grep_pattern``
(see ``deprecated/poc_analyzer.py``). They are reproduced here unmodified.

Original location: pipeline/orchestrator.py
Archived: 2026-06-04
"""

# ---------------------------------------------------------------------------
# CVEImageBuilder._generate_dockerfile — wrapper.sh construction (gate portion)
# ---------------------------------------------------------------------------
#
#         # Gate 1 negative-signal grep pattern (language/category-agnostic).
#         # Embedded verbatim in the wrapper; if any alternative matches the
#         # runtime output, the wrapper exits 43 immediately without evaluating
#         # the positive checks (Gate 2).
#         from poc_analyzer import get_negative_grep_pattern
#         neg_grep = poc_metadata.get(
#             "negative_signal_filter",
#             get_negative_grep_pattern()
#         ) if poc_metadata else get_negative_grep_pattern()
#         # Escape single-quotes so the pattern is safe inside bash single-quoted string
#         neg_grep_safe = neg_grep.replace("'", "'\\''")
#
#         # -----------------------------------------------------------------------
#         # Wrapper script: two-gate verification design
#         #
#         # Gate 1 (negative filter): checks runtime output for explicit
#         #   "did not exploit" self-reports, language-agnostic.  If it fires,
#         #   the wrapper exits 43 (ran but unproven) immediately.
#         #
#         # Gate 2 (positive proof): only runs when Gate 1 is clear.  Checks
#         #   filesystem artifacts, category-specific crash signals, and the
#         #   LLM/heuristic verification command.  Any single passing check
#         #   exits 42 (confirmed exploitation).
#         #
#         # Structured SSD_PROOF line is always emitted for host-side parsing.
#         # -----------------------------------------------------------------------
#         wrapper_sh = [
#             "#!/bin/bash",
#             "set -o pipefail 2>/dev/null || true",
#             f"CATEGORY='{poc_category}'",
#             "_PASS_COUNT=0",
#             "_PROOF_CHECKS=''",
#             "_NEGATIVE_GATE=0",
#             '_record_pass() { _PASS_COUNT=$((_PASS_COUNT + 1)); _PROOF_CHECKS="${_PROOF_CHECKS}|$1"; }',
#             "",
#             f"echo '--- Executing dynamic wrapper for category: {poc_category} ---'",
#             "",
#             "# 1. Setup",
#             setup_cmd,
#             "",
#             "# 2. Execution",
#             "echo '--- Running exploit ---'",
#             exec_wrap,
#             "exit_code=$?",
#             'echo "--- Exploit finished (exit=$exit_code) ---"',
#             "",
#             "# ── Gate 1: Negative signal filter ─────────────────────────────────",
#             'if [ -f /tmp/out ] && grep -qiE \'' + neg_grep_safe + '\' /tmp/out 2>/dev/null; then',
#             '    _NEGATIVE_GATE=1',
#             '    echo "NEGATIVE_GATE_FIRED: Explicit non-exploitation signal found in output"',
#             'fi',
#             "",
#             "# ── Gate 2: Positive proof checks (only when Gate 1 is clear) ───────",
#             'if [ "$_NEGATIVE_GATE" -eq 0 ]; then',
#             "    # 3. Filesystem artifact probes — silent SUID droppers produce no stdout",
#             '    for _p in /tmp/xp /tmp/r00t /tmp/rootshell /tmp/kidd0 /tmp/backdoor /var/tmp/.nothing /var/tmp/rootshell; do',
#             '        if [ -u "$_p" ] 2>/dev/null; then',
#             '            echo "SUID_ARTIFACT_FOUND: $_p"',
#             '            _record_pass "suid_artifact:$_p"',
#             '        fi',
#             '    done',
#             '    _FOUND_SUID=$(find /tmp /var/tmp -perm /4000 2>/dev/null | head -3)',
#             '    if [ -n "$_FOUND_SUID" ]; then',
#             '        echo "SUID_FIND_RESULT: $_FOUND_SUID"',
#             '        _record_pass "suid_find"',
#             '    fi',
#             "    # 4. Category-specific crash acceptance (DOS / FORMAT_STRING only).",
#             f"    if [ \"$CATEGORY\" = 'DOS' ] || [ \"$CATEGORY\" = 'FORMAT_STRING' ]; then",
#             '        if [ "$exit_code" -eq 139 ] || [ "$exit_code" -eq 134 ]; then',
#             '            _record_pass "crash_signal:$exit_code"',
#             '        elif [ "$exit_code" -ge 132 ] && [ "$exit_code" -le 159 ] \\',
#             '             && [ "$exit_code" -ne 141 ] && [ "$exit_code" -ne 143 ]; then',
#             '            _record_pass "crash_signal_generic:$exit_code"',
#             '        fi',
#             '    fi',
#             "    # 5. LPE setup-crash guard",
#             "    if [ \"$CATEGORY\" = 'LPE' ] && [ \"$exit_code\" -eq 139 ]; then",
#             '        _output_lines=0',
#             '        [ -f /tmp/out ] && _output_lines=$(wc -l < /tmp/out 2>/dev/null || echo 0)',
#             '        if [ "$_output_lines" -lt 2 ]; then',
#             '            echo "CRASH_LIKELY_SETUP: SIGSEGV with only $_output_lines output lines"',
#             '        fi',
#             '    fi',
#             "    # 6. Category-specific positive verification command (LLM / heuristic)",
#             f'    if eval "{verify_cmd}" 2>/dev/null; then',
#             '        _record_pass "verify_cmd"',
#             '    fi',
#             'fi  # end Gate 2',
#             "",
#             'echo "SSD_PROOF: category=$CATEGORY exit_code=$exit_code pass_count=$_PASS_COUNT checks=$_PROOF_CHECKS negative_gate=$_NEGATIVE_GATE"',
#             "",
#             'if [ "$_NEGATIVE_GATE" -eq 1 ]; then',
#             "    echo '--- NEGATIVE GATE FIRED: PoC explicitly confirmed non-exploitation ---'",
#             '    exit 43',
#             f'elif [ "$_PASS_COUNT" -gt 0 ]; then',
#             "    echo '--- VERIFICATION SUCCESS: Vulnerability Confirmed ---'",
#             '    exit 42',
#             'else',
#             "    echo '--- VERIFICATION FAILED: Not Reproduced ---'",
#             '    exit $exit_code',
#             'fi',
#         ]


# ---------------------------------------------------------------------------
# DockerManager._extract_proof_record
# ---------------------------------------------------------------------------
def _extract_proof_record(self, logs):
    """Parse the SSD_PROOF line written by the enhanced wrapper.sh.

    Returns a dict with at minimum ``category``, ``exit_code``, and
    ``pass_count`` keys, or None if no proof line was found.
    """
    for line in reversed(logs.splitlines()):
        line = line.strip()
        if not line.startswith("SSD_PROOF:"):
            continue
        payload = line[len("SSD_PROOF:"):].strip()
        record = {}
        for token in payload.split():
            if "=" in token:
                k, _, v = token.partition("=")
                record[k] = v
        if record:
            try:
                record["pass_count"] = int(record.get("pass_count", 0))
            except ValueError:
                record["pass_count"] = 0
            return record
    return None


# ---------------------------------------------------------------------------
# DockerManager._interpret_exit_code
# ---------------------------------------------------------------------------
def _interpret_exit_code(self, vuln, exit_code, logs):
    """Interpret container exit code and logs to determine if vulnerability
    was triggered (two-gate era).

    Distinguishes:
      1. True vulnerability reproduction (crash, overflow, corruption)
      2. Environment/setup failures (missing libs, wrong arch, missing deps)
      3. Inconclusive results (PoC ran but can't confirm vuln was triggered)
    """
    logs_lower = logs.lower()

    if exit_code == 42:
        self.logger.info(f"{vuln.cve}: PoC wrapper exited with 42 - vulnerability confirmed")
        return True
    if exit_code == 43:
        if "NEGATIVE_GATE_FIRED" in logs:
            self.logger.warning(
                f"{vuln.cve}: PoC wrapper exited 43 — Gate 1 fired: PoC output "
                "contained an explicit non-exploitation signal"
            )
        else:
            self.logger.warning(
                f"{vuln.cve}: PoC wrapper exited 43 — PoC ran but did not prove exploitation"
            )
        return False

    proof = self._extract_proof_record(logs)
    if proof is not None:
        if proof.get("negative_gate", "0") == "1":
            self.logger.warning(
                f"{vuln.cve}: SSD_PROOF negative_gate=1 — Gate 1 fired inside wrapper "
                f"(category={proof.get('category')}, exit={exit_code})"
            )
            return False
        if proof.get("pass_count", 0) == 0:
            self.logger.warning(
                f"{vuln.cve}: SSD_PROOF present but pass_count=0 — wrapper ran, "
                f"no positive check passed (category={proof.get('category')}, exit={exit_code})"
            )
            return False

    # PHASE 1: Reject known environment/setup failures
    if "no such file or directory" in logs_lower and exit_code == 127:
        return False
    if "exec format error" in logs_lower:
        return False
    if "permission denied" in logs_lower and exit_code == 126:
        return False
    if "error while loading shared libraries" in logs_lower:
        return False
    if "version `glibc_" in logs_lower and "not found" in logs_lower:
        return False
    if "cannot load such file" in logs_lower or "loaderror" in logs_lower:
        return False
    if "modulenotfounderror" in logs_lower or "importerror" in logs_lower:
        return False
    if "can't locate" in logs_lower and ".pm" in logs_lower:
        return False
    if "msf/core" in logs_lower or "metasploit" in logs_lower:
        if "cannot load" in logs_lower or "require" in logs_lower:
            return False

    # PHASE 2: Detect clear vulnerability reproduction signals
    if "crash_likely_setup" in logs_lower:
        return False
    if exit_code == 139 or "segmentation fault" in logs_lower or "sigsegv" in logs_lower:
        return True
    if exit_code == 134 or "sigabrt" in logs_lower:
        return True
    if exit_code == 135:
        return True
    if exit_code == 136:
        return True
    if exit_code > 128 and exit_code < 192:
        signal_num = exit_code - 128
        _BENIGN_SIGNALS = {1, 2, 3, 13, 15, 17}
        if signal_num not in _BENIGN_SIGNALS:
            return True
    if "stack smashing" in logs_lower or "stack buffer overflow" in logs_lower:
        return True
    if any(indicator in logs_lower for indicator in [
        'heap corruption', 'double free', 'corrupted size',
        'corrupted double-linked list', 'free(): invalid',
        'malloc(): corrupted', 'munmap_chunk(): invalid',
        'realloc(): invalid'
    ]):
        return True
    if any(indicator in logs_lower for indicator in [
        'buffer overflow', 'overflow detected', 'corrupted',
        'out of bounds', 'use after free', 'use-after-free'
    ]):
        return True
    if 'addresssanitizer' in logs_lower or 'ubsan' in logs_lower or 'sanitizer' in logs_lower:
        return True
    if '*** buffer overflow detected ***' in logs or 'fortify_fail' in logs_lower:
        return True

    # PHASE 3: CVE-specific detection logic (return True only on positive match)
    if vuln.cve == "CVE-2012-3480":
        if "0x" in logs and "p" in logs:
            return True
        if logs.strip() and exit_code == 0:
            return True
    if vuln.cve == "CVE-2015-7547":
        if exit_code != 0 or "getaddrinfo" in logs_lower:
            return True
    if vuln.cve == "CVE-2014-5119":
        if "double-linked" in logs_lower or "corrupted" in logs_lower:
            return True
        if "__gconv_translit_find" in logs_lower or "translit" in logs_lower:
            return True
    if vuln.cve == "CVE-2017-1000366":
        if any(marker in logs_lower for marker in [
            "num_important_hwcaps", "probability 1/", "ld_hwcap_mask=",
            "target 0 ", "target 1 ",
            "executing new program: /bin/sh", "/bin/dash",
        ]):
            return True
        if "usage:" in logs_lower or "target binary" in logs_lower:
            return False
    if "usage:" in logs_lower and exit_code in (0, 1):
        return False

    # PHASE 4: Default — not reproduced
    return False
