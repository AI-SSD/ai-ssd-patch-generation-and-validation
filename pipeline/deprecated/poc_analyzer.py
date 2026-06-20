import json
import logging
import os
import re
from pathlib import Path
from typing import Dict, Any, Optional

try:
    from openai import OpenAI
except ImportError:
    OpenAI = None

# ---------------------------------------------------------------------------
# Gate 1 — Negative signal patterns.
#
# These are compiled regexes matched against RUNTIME OUTPUT (not source).
# If any fires, the PoC has explicitly printed a message confirming it did
# NOT exploit the target. The wrapper script converts this to exit 43
# ("ran but did not prove exploitation") without evaluating Gate 2 at all.
#
# Rationale: false positives (blocking a real success) are always worse than
# false negatives here, so patterns are kept conservative and anchored to
# explicit phrases that exploits print when they self-report failure.
# ---------------------------------------------------------------------------
_NEGATIVE_RUNTIME_PATTERNS = [
    # Explicit "not vulnerable" self-reports
    re.compile(r'\bnot\s+vuln(?:erable)?\b', re.IGNORECASE),
    re.compile(r'\btarget\s+is\s+(?:not\s+)?safe\b', re.IGNORECASE),
    re.compile(r'\balready\s+patch(?:ed)?\b', re.IGNORECASE),
    re.compile(r'\bnot\s+exploitable\b', re.IGNORECASE),
    # Metasploit CheckCode / fail_with logged messages
    re.compile(r'CheckCode::Safe', re.IGNORECASE),
    re.compile(r'Failure::NotVulnerable', re.IGNORECASE),
    re.compile(r'Failure::NotFound', re.IGNORECASE),
    re.compile(r'\[-\]\s+Exploit\s+failed', re.IGNORECASE),
    re.compile(r'\[-\].*\bfailed\b.*(not vulnerable|not found|bad config)', re.IGNORECASE),
    # Precondition self-checks printed by the PoC
    re.compile(r'\bnot\s+setuid\b|\bis\s+NOT\s+setuid\b', re.IGNORECASE),
    re.compile(r'NOT setuid on this system'),             # CVE-2001-0170 shell exact phrase
    re.compile(r'\bno\s+offsets?\s+for\s+this\s+version\b', re.IGNORECASE),
    re.compile(r'unprivileged user namespaces are not permitted', re.IGNORECASE),
    re.compile(r'\bGNU C Library version .* is not vulnerable\b', re.IGNORECASE),
    re.compile(r'\bLinux kernel version .* is not vulnerable\b', re.IGNORECASE),
    # Our own MSF stub wrapper message
    re.compile(r'Metasploit module detected'),
    re.compile(r'Phase 1 requires an explicit shell'),
]

# Single grep-compatible ERE string built once — used verbatim inside wrapper.sh.
# Each alternative is escaped so it is safe to embed in a double-quoted bash string.
_NEGATIVE_GREP_PATTERN = (
    r'not vuln(erable)?'
    r'|target is (not )?safe'
    r'|already patch(ed)?'
    r'|not exploitable'
    r'|CheckCode::Safe'
    r'|Failure::NotVulnerable'
    r'|Failure::NotFound'
    r'|\[-\] Exploit failed'
    r'|NOT setuid on this system'
    r'|not setuid'
    r'|is NOT setuid'
    r'|no offsets for this version'
    r'|unprivileged user namespaces are not permitted'
    r'|GNU C Library version .* is not vulnerable'
    r'|Linux kernel version .* is not vulnerable'
    r'|Metasploit module detected'
    r'|Phase 1 requires an explicit shell'
)

# ---------------------------------------------------------------------------
# Static exploit-intent signals used by both validate_poc_static() and
# _heuristic_analysis(). Compiled once at import time for performance.
# ---------------------------------------------------------------------------
_EXPLOIT_INTENT_PATTERNS = [
    re.compile(r'setuid\s*\(\s*0\s*\)', re.IGNORECASE),
    re.compile(r'setgid\s*\(\s*0\s*\)', re.IGNORECASE),
    re.compile(r'execve?\s*\(\s*["\']?/bin/(sh|bash|dash)', re.IGNORECASE),
    re.compile(r'system\s*\(\s*["\']?/bin/(sh|bash|dash)', re.IGNORECASE),
    re.compile(r'/bin/(sh|bash|dash)\b', re.IGNORECASE),   # shell reference anywhere
    re.compile(r'chmod\s+[46]7[0-7][0-7]'),
    re.compile(r'char\s+(shellcode|sc)\s*\['),
    re.compile(r'(?:\\x[0-9a-fA-F]{2}){4,}'),             # shellcode bytes
    re.compile(r'\bLD_AUDIT\b|\bLD_PRELOAD\b|\bRESOLV_HOST_CONF\b|\bPCPROFILE_OUTPUT\b'),
    re.compile(r'\bgettext\b|\bcatopen\b|\bdcgettext\b|\bdgettext\b'),
    re.compile(r'Msf::Exploit|def exploit|fail_with\s+Failure'),
    re.compile(r'%\d+\$n|printf.*%n'),
    re.compile(r'overflow|heap.corrupt|double.free|use.after.free', re.IGNORECASE),
    re.compile(r'crash|stack.exhaustion|denial.of.service|regcomp\s*\(|getaddrinfo\s*\(', re.IGNORECASE),
    re.compile(r'get_sp\s*\(\)|__asm__.*esp|ret2libc|return.address', re.IGNORECASE),
    re.compile(r'/bin/su\b|/bin/ping\b|/usr/bin/passwd\b|/bin/mount\b'),
    re.compile(r'chown\s+root|chmod\s+4777|chmod\s+6755'),
    re.compile(r'\bsegfault\b|\bsigsegv\b|\bsigabrt\b', re.IGNORECASE),
    re.compile(r'\bfork\s*\(\s*\)|\bexecve\s*\('),
    re.compile(r'memcpy\s*\(.*argv', re.IGNORECASE),       # argv-driven memory copy
    re.compile(r'jump.table|signedness.bug|signed.*unsigned', re.IGNORECASE),
    # ptrace-based LPE (e.g. hijack another process's memory)
    re.compile(r'\bptrace\s*\(|PTRACE_ATTACH|PTRACE_POKETEXT', re.IGNORECASE),
    # /proc/self/mem write — common LPE via anonymous mapping overwrite
    re.compile(r'/proc/self/mem|/proc/\d+/mem'),
    # Dirty-COW style (madvise + mmap race)
    re.compile(r'madvise\s*\(.*MADV_DONTNEED|MAP_PRIVATE.*PROT_WRITE', re.IGNORECASE),
    # User-namespace escape
    re.compile(r'unshare\s*\(|CLONE_NEWUSER|setns\s*\(', re.IGNORECASE),
    # Symlink/TOCTOU race
    re.compile(r'symlink\s*\(|readlink\s*\(.*race|TOCTOU', re.IGNORECASE),
]


def get_negative_grep_pattern() -> str:
    """Return the ERE pattern string used by wrapper.sh Gate 1 negative filter."""
    return _NEGATIVE_GREP_PATTERN


class PoCAnalyzer:
    """Analyzes PoC source code using LLM to determine execution strategy and success conditions."""

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.api_key = self._get_openai_key()
        self.model = "gpt-4o-mini"
        if OpenAI and self.api_key:
            self.client = OpenAI(api_key=self.api_key)
        else:
            self.client = None
            self.logger.warning("OpenAI client not available for PoC analysis. Falling back to heuristics.")

    def _get_openai_key(self) -> str:
        api_key = os.environ.get("OPENAI_API_KEY")
        if not api_key:
            key_file = Path("API-openai-key")
            if key_file.exists():
                api_key = key_file.read_text().strip()
        return api_key

    # =========================================================================
    # Step 1 — Static pre-flight validation
    # =========================================================================

    def validate_poc_static(self, poc_path: Path, cve: str = "") -> Dict[str, Any]:
        """Pre-flight static validation before attempting to run a PoC.

        Implements the three static checks from the analysis:
          1. File type classification and entrypoint detection
          2. CVE identifier anchoring
          3. Exploit-intent signal scanning

        Returns a dict with:
            is_valid      – True if the file should be executed
            reason        – Human-readable explanation
            file_type     – c / shell / ruby_msf / ruby / python / php / unknown
            has_exploit_intent – at least one exploitation primitive found
            has_entrypoint    – recognisable execution entry point present
            cve_match         – CVE string found in file body
            min_size_ok       – file has at least 15 non-empty lines
        """
        result: Dict[str, Any] = {
            "is_valid": False,
            "reason": "",
            "file_type": "unknown",
            "has_exploit_intent": False,
            "has_entrypoint": False,
            "cve_match": False,
            "min_size_ok": False,
        }

        if not poc_path or not poc_path.exists():
            result["reason"] = "File does not exist"
            return result

        try:
            content = poc_path.read_text(errors="ignore")
        except Exception as e:
            result["reason"] = f"Cannot read file: {e}"
            return result

        non_empty_lines = [l for l in content.splitlines() if l.strip()]
        result["min_size_ok"] = len(non_empty_lines) >= 15

        ext = poc_path.suffix.lower()

        # ---- file type + entrypoint -----------------------------------------
        if ext == ".c":
            result["file_type"] = "c"
            result["has_entrypoint"] = bool(
                re.search(r"^\s*(int|void)?\s*main\s*\(", content, re.MULTILINE)
            )
        elif ext == ".sh":
            result["file_type"] = "shell"
            # .sh extension is sufficient — not all shell scripts have a shebang
            result["has_entrypoint"] = True
        elif ext == ".rb":
            if "class MetasploitModule" in content or re.search(r"class Metasploit\d", content):
                result["file_type"] = "ruby_msf"
                result["has_entrypoint"] = "def exploit" in content
            else:
                result["file_type"] = "ruby"
                result["has_entrypoint"] = True
        elif ext == ".php":
            # CVE-2001-0169 is a tcsh script saved with .php extension
            if content.lstrip().startswith("#!/bin/tcsh") or "#!/bin/tcsh" in content[:80]:
                result["file_type"] = "shell"
                result["has_entrypoint"] = True
            else:
                result["file_type"] = "php"
                result["has_entrypoint"] = True
        elif ext == ".py":
            result["file_type"] = "python"
            result["has_entrypoint"] = True
        elif ext == ".pl":
            result["file_type"] = "perl"
            result["has_entrypoint"] = True
        else:
            # Plain shebang detection for unknown extensions
            if re.search(r"^#!\s*/", content):
                result["file_type"] = "shell"
                result["has_entrypoint"] = True

        # ---- CVE match ------------------------------------------------------
        cve_upper = cve.upper()
        result["cve_match"] = bool(
            (cve_upper and cve_upper in content.upper())
            or re.search(r"CVE-\d{4}-\d+", content, re.IGNORECASE)
        )

        # ---- exploit intent -------------------------------------------------
        result["has_exploit_intent"] = any(
            pat.search(content) for pat in _EXPLOIT_INTENT_PATTERNS
        )

        # ---- final verdict --------------------------------------------------
        if not result["min_size_ok"]:
            result["reason"] = (
                f"File too small ({len(non_empty_lines)} non-empty lines, need ≥15)"
            )
        elif not result["has_entrypoint"]:
            result["reason"] = "No recognisable entry point (main / def exploit / shebang)"
        elif not result["has_exploit_intent"]:
            result["reason"] = "No exploit-intent signals detected"
        else:
            result["is_valid"] = True
            result["reason"] = f"Valid {result['file_type']} PoC"
            if not result["cve_match"] and cve:
                result["reason"] += f" (warning: '{cve}' not found in body)"

        return result

    # =========================================================================
    # Step 2 — Full analysis (LLM primary, heuristics fallback)
    # =========================================================================

    def analyze_poc(self, poc_path: Path) -> Dict[str, Any]:
        """Analyse the PoC file to determine exploit type and success conditions."""
        default_meta = {
            "poc_category": "OTHER",
            "setup_command": "",
            "execution_wrapper": "./exploit",
            "verification_command": (
                "grep -qiE "
                "'uid=0\\(root\\)|meterpreter|session opened|root shell|"
                "vulnerable|success|pwned|exploit worked' /tmp/out"
            ),
            "negative_signal_filter": _NEGATIVE_GREP_PATTERN,
        }

        if not poc_path or not poc_path.exists():
            return default_meta

        try:
            content = poc_path.read_text(errors="ignore")
        except Exception as e:
            self.logger.error(f"Failed to read PoC file {poc_path}: {e}")
            return default_meta

        # Metasploit fast-path (heuristic — no LLM needed)
        if poc_path.suffix == ".rb" and re.search(r"class Metasploit", content):
            return {
                "poc_category": "METASPLOIT",
                "setup_command": "",
                "execution_wrapper": "./exploit > /tmp/out 2>&1",
                "verification_command": (
                    "grep -qiE "
                    "'meterpreter|session opened|shell|uid=0\\(root\\)|root shell' "
                    "/tmp/out"
                ),
                "negative_signal_filter": _NEGATIVE_GREP_PATTERN,
            }

        if not self.client:
            return self._heuristic_analysis(content)

        if len(content) > 16000:
            content = content[:16000]

        prompt = f"""
Analyze the following exploit source code and determine how to automatically execute and verify it.
You MUST output a valid JSON object.

The goal is to generate a wrapper script executed in a Docker container.
The exploit binary will be named `./exploit` (or the appropriate script name).

Return a JSON object with this schema:
{{
  "poc_category": "LPE | FORMAT_STRING | DOS | INFO_LEAK | METASPLOIT | SUID_DROPPER | ARB_FILE_WRITE | RCE | OTHER",
  "setup_command": "Any bash commands to run BEFORE the exploit (e.g. 'echo -e \\"id\\\\nexit\\\\n\\" > /tmp/cmds.txt'), or '' if none",
  "execution_wrapper": "Command to run the exploit. Default './exploit > /tmp/out 2>&1'. For LPE that reads stdin: 'cat /tmp/cmds.txt | ./exploit > /tmp/out 2>&1'. For DOS: './exploit > /tmp/out 2>&1'.",
  "verification_command": "Bash command that exits 0 ONLY if exploit succeeded. Examples:
    - LPE/FORMAT_STRING spawning shell: 'grep -qE \\"uid=0\\\\(root\\\\)|^root$\\" /tmp/out'
    - SUID_DROPPER (creates /tmp/xp): '[ -u /tmp/xp ] || [ -u /var/tmp/.nothing ] || find /tmp /var/tmp -perm /4000 2>/dev/null | grep -q .'
    - DOS (crash): '[ $exit_code -eq 139 ] || [ $exit_code -eq 134 ] || [ $exit_code -ge 128 ]'
    - INFO_LEAK (shadow): 'grep -qE \\"root:.*:0:0:\\" /tmp/out'
    - ARB_FILE_WRITE: 'grep -q \\"pwned\\" /etc/passwd'
    - FORMAT_STRING (crash + optional SUID): '[ $exit_code -eq 139 ] || [ $exit_code -eq 134 ] || [ -u /tmp/xp ] || grep -qiE \\"uid=0\\\\(root\\\\)|\\\\[\\\\+\\\\].*shell\\" /tmp/out'
   "
}}

Source Code:
```
{content}
```
"""
        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a security expert generating bash wrapper scripts "
                            "for exploit verification. Output strictly JSON."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0.0,
                response_format={"type": "json_object"},
            )
            result_str = response.choices[0].message.content
            meta = json.loads(result_str)
            meta.setdefault("negative_signal_filter", _NEGATIVE_GREP_PATTERN)
            self.logger.info(f"LLM PoC Analysis for {poc_path.name}: {meta}")
            return meta
        except Exception as e:
            self.logger.error(f"LLM analysis failed for {poc_path.name}: {e}")
            return self._heuristic_analysis(content)

    # =========================================================================
    # Step 3 — Heuristic fallback analysis
    # =========================================================================

    def _extract_usage_example(self, content: str) -> Optional[str]:
        """Extract a concrete usage example from a PoC source file."""
        for line in content.splitlines():
            match = re.search(r"\busage:\s*(.+)", line, re.IGNORECASE)
            if not match:
                continue
            usage = match.group(1).strip().strip("\"';)")
            if not usage:
                continue
            usage_lower = usage.lower()
            if any(token in usage_lower for token in ("%s", "target binary", "<", "binary")):
                continue
            return usage
        return None

    def _normalize_exploit_command(self, usage: str) -> str:
        """Rewrite a usage example so it runs the container's exploit binary."""
        parts = usage.split()
        if not parts:
            return "./exploit"
        parts[0] = "./exploit"
        return " ".join(parts)

    def _heuristic_analysis(self, content: str) -> Dict[str, Any]:
        """Fallback analysis when LLM is unavailable.

        Category priority order (first match wins):
          1. Metasploit module
          2. FORMAT_STRING (glibc locale exploitation)
          3. LD_AUDIT / LD_PRELOAD linker-based LPE
          4. SUID_DROPPER (creates setuid-root binary)
          5. INFO_LEAK (reads privileged files via environment)
          6. DoS-with-explicit-argv pattern (e.g. CVE-2011-2702)
          7. ld.so hwcap diagnostic PoC (e.g. CVE-2017-1000366)
          8. LPE (generic shell spawn)
          9. DOS (crash/overflow)
         10. INFO_LEAK (generic)
         11. OTHER
        """
        meta: Dict[str, Any] = {
            "poc_category": "OTHER",
            "setup_command": "",
            "execution_wrapper": "./exploit > /tmp/out 2>&1",
            "verification_command": (
                "grep -qiE "
                "'uid=0\\(root\\)|meterpreter|session opened|root shell|"
                "vulnerable|success|pwned|exploit worked' /tmp/out"
            ),
            "negative_signal_filter": _NEGATIVE_GREP_PATTERN,
        }
        content_lower = content.lower()
        usage_example = self._extract_usage_example(content)
        usage_command = (
            self._normalize_exploit_command(usage_example) if usage_example else None
        )

        # Concrete usage example overrides bare ./exploit
        if usage_command:
            meta["execution_wrapper"] = f"{usage_command} > /tmp/out 2>&1"

        # ------------------------------------------------------------------
        # 1. Metasploit modules
        # ------------------------------------------------------------------
        if "metasploitmodule" in content_lower or "msf/core" in content_lower:
            meta["poc_category"] = "METASPLOIT"
            meta["execution_wrapper"] = "./exploit > /tmp/out 2>&1"
            meta["verification_command"] = (
                "grep -qiE "
                "'meterpreter|session opened|shell|uid=0\\(root\\)|root shell' "
                "/tmp/out"
            )
            return meta

        # ------------------------------------------------------------------
        # 2. FORMAT_STRING — glibc locale / message-catalogue exploitation
        #    Signal: actual gettext/catopen/dcgettext CALLS (not path strings)
        #    plus at least one exploitation primitive (shellcode or %n)
        #    Outcome: crash (SIGSEGV) or SUID artifact
        # ------------------------------------------------------------------
        _fs_locale_calls = bool(
            re.search(r'\b(gettext|catopen|dcgettext|dgettext|catgets)\s*\(', content)
            or re.search(r'locale subsystem|format string bug', content_lower)
            or re.search(r'lc_messages.*\bexploit\b', content_lower)   # word-boundary: avoids "ExploitData"
            or "dopercentn" in content_lower
            or "nsfocus" in content_lower
        )
        _format_string_primitives = [
            re.search(r'%\d+\$n', content) is not None,
            re.search(r'printf.*%n', content, re.IGNORECASE) is not None,
            re.search(r'\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}.*\\x[0-9a-fA-F]{2}', content) is not None,
            "shellcode" in content_lower,
            "%08x" in content,
        ]
        if _fs_locale_calls and any(_format_string_primitives):
            meta["poc_category"] = "FORMAT_STRING"
            # Setup: some PoCs need a writable /tmp and a locale dir
            meta["setup_command"] = "mkdir -p /tmp/LC_MESSAGES 2>/dev/null; chmod 777 /tmp 2>/dev/null; true"
            meta["execution_wrapper"] = "./exploit > /tmp/out 2>&1"
            # Success: crash (SIGSEGV/SIGABRT) OR SUID artifact created OR root shell
            meta["verification_command"] = (
                "[ $exit_code -eq 139 ] || [ $exit_code -eq 134 ] || "
                "[ $exit_code -ge 128 ] || "
                "[ -u /tmp/xp ] || [ -u /var/tmp/.nothing ] || "
                "grep -qiE 'uid=0\\(root\\)|\\[\\+\\].*shell|root shell|"
                "stack smashing|segmentation fault|abort|fortify' /tmp/out"
            )
            return meta

        # ------------------------------------------------------------------
        # 3. LD_AUDIT / LD_PRELOAD linker-based LPE
        #    Signal: LD_AUDIT, libpcprofile, PCPROFILE_OUTPUT, LD_PRELOAD
        #    Two sub-cases:
        #      3a. SUID dropper — uses LD_PRELOAD to trigger a signal handler
        #          that creates a setuid-root artifact (e.g. CVE-2001-0169).
        #          Success proof is a file on disk, NOT a shell prompt.
        #      3b. Shell spawn — LD_PRELOAD/LD_AUDIT constructor calls
        #          setuid(0) + execve("/bin/sh").  Success proof is stdout.
        # ------------------------------------------------------------------
        _linker_signals = [
            "ld_audit", "ld_preload", "libpcprofile", "pcprofile_output",
            "ldaudit", "ldpreload",
        ]
        if any(sig in content_lower for sig in _linker_signals):
            # Detect SUID-dropper sub-case: chmod/SUID artifact signals present
            _linker_suid_signals = [
                bool(re.search(r'chmod\s+[46]7[0-7][0-7]', content, re.IGNORECASE)),
                bool(re.search(r'/var/tmp/\.nothing|/tmp/xp\b|/tmp/kidd0|/tmp/r00t', content)),
                "segfault_output_name" in content_lower,
                "libsegfault" in content_lower,
            ]
            if any(_linker_suid_signals):
                meta["poc_category"] = "SUID_DROPPER"
                meta["setup_command"] = "chmod 777 /tmp /var/tmp 2>/dev/null; true"
                meta["execution_wrapper"] = "./exploit > /tmp/out 2>&1 || true"
                _la = []
                for _ar in [r'/tmp/xp\b', r'/var/tmp/\.nothing', r'/tmp/kidd0', r'/tmp/r00t']:
                    if re.search(_ar, content, re.IGNORECASE):
                        _la.append(re.sub(r'\\b', '', _ar).replace(r'\.', '.').strip())
                if _la:
                    meta["verification_command"] = (
                        " || ".join(f"[ -u {p} ]" for p in _la) +
                        " || find /tmp /var/tmp -perm /4000 2>/dev/null | grep -q ."
                    )
                else:
                    meta["verification_command"] = (
                        "find /tmp /var/tmp -perm /4000 2>/dev/null | grep -q ."
                    )
                return meta

            # Sub-case 3b: genuine shell-spawn via LD_PRELOAD constructor
            meta["poc_category"] = "LPE"
            meta["setup_command"] = "echo -e 'id\\nwhoami\\nexit\\n' > /tmp/cmds.txt"
            meta["execution_wrapper"] = "./exploit > /tmp/out 2>&1 || true"
            meta["verification_command"] = (
                "grep -qiE "
                "'uid=0\\(root\\)|\\[\\+\\].*[Ll]aunch|\\[\\+\\].*[Ss]hell|"
                "Launching shell|root shell' /tmp/out"
            )
            return meta

        # ------------------------------------------------------------------
        # 4. SUID_DROPPER — creates a setuid-root binary as proof
        #    Signal: chmod 4777 / chmod 6755 / chown root /tmp/
        # ------------------------------------------------------------------
        _suid_dropper_signals = [
            re.search(r'chmod\s+[46]7[0-7][0-7]\s+/tmp/', content, re.IGNORECASE),
            re.search(r'chmod\s+[46]7[0-7][0-7]\s+/var/tmp/', content, re.IGNORECASE),
            re.search(r'chown\s+root\s+/tmp/', content, re.IGNORECASE),
            "suid" in content_lower and "dropper" in content_lower,
        ]
        # Detect the specific artifact path used by this PoC
        _artifact_paths = []
        for artifact_re in [r'/tmp/xp\b', r'/var/tmp/\.nothing', r'/tmp/kidd0', r'/tmp/r00t']:
            if re.search(artifact_re, content, re.IGNORECASE):
                _artifact_paths.append(re.sub(r'\\b', '', artifact_re).strip())
        if any(_suid_dropper_signals):
            meta["poc_category"] = "SUID_DROPPER"
            meta["setup_command"] = "chmod 777 /tmp 2>/dev/null; true"
            meta["execution_wrapper"] = "./exploit > /tmp/out 2>&1"
            if _artifact_paths:
                checks = " || ".join(f"[ -u {p} ]" for p in _artifact_paths)
                meta["verification_command"] = (
                    f"{checks} || "
                    "find /tmp /var/tmp -perm /4000 2>/dev/null | grep -q ."
                )
            else:
                meta["verification_command"] = (
                    "find /tmp /var/tmp -perm /4000 2>/dev/null | grep -q . || "
                    "grep -qiE 'uid=0\\(root\\)|root shell' /tmp/out"
                )
            return meta

        # ------------------------------------------------------------------
        # 5. INFO_LEAK via privileged environment variables
        #    Signal: RESOLV_HOST_CONF, /etc/shadow, shadow file reading
        #    Checked against non-comment lines only to prevent false matches
        #    on innocuous strings like "// the shadow copy" in comments.
        # ------------------------------------------------------------------
        _non_comment_lines = [
            l for l in content.splitlines()
            if not re.match(r'\s*(/\*|//|#|\*)', l)
        ]
        _content_nocomment = "\n".join(_non_comment_lines).lower()
        _info_leak_env_signals = ["resolv_host_conf", "/etc/shadow"]
        _info_leak_shadow_match = (
            re.search(r'\bshadow\b', _content_nocomment) is not None
            and ("/etc/" in _content_nocomment or "getenv" in _content_nocomment
                 or "resolv" in _content_nocomment)
        )
        if any(sig in _content_nocomment for sig in _info_leak_env_signals) or _info_leak_shadow_match:
            meta["poc_category"] = "INFO_LEAK"
            meta["execution_wrapper"] = "./exploit > /tmp/out 2>&1"
            meta["verification_command"] = (
                "grep -qE 'root:.*:0:0:|daemon:.*:1:1:' /tmp/out || "
                "grep -qiE 'shadow|passwd|resolv' /tmp/out"
            )
            return meta

        # ------------------------------------------------------------------
        # 6. DoS with explicit argv (e.g. CVE-2011-2702 memcpy pattern)
        # ------------------------------------------------------------------
        if "memcpy(buf, argv[1], atoi(argv[2]))" in content_lower:
            meta["poc_category"] = "DOS"
            if usage_command:
                meta["execution_wrapper"] = f"{usage_command} > /tmp/out 2>&1"
            else:
                meta["execution_wrapper"] = "./exploit A 3492348247 > /tmp/out 2>&1"
            meta["verification_command"] = (
                "[ $exit_code -eq 139 ] || [ $exit_code -eq 134 ] || "
                "[ $exit_code -ge 128 ] || "
                "grep -qiE 'segmentation fault|core dumped|stack smashing|"
                "abort|invalid' /tmp/out"
            )
            return meta

        # ------------------------------------------------------------------
        # 7. ld.so hwcap diagnostic PoC (e.g. CVE-2017-1000366)
        # ------------------------------------------------------------------
        if (
            "target binary" in content_lower
            and "num_important_hwcaps" in content_lower
            and "ld_hwcap_mask" in content_lower
        ):
            meta["poc_category"] = "RCE"
            meta["execution_wrapper"] = "./exploit 0 /bin/ls > /tmp/out 2>&1"
            meta["verification_command"] = (
                "grep -qiE "
                "'num_important_hwcaps|probability 1/|Target [0-9]+|"
                "executing new program: /bin/sh|/bin/dash|uid=0\\(root\\)|root shell' "
                "/tmp/out"
            )
            return meta

        # ------------------------------------------------------------------
        # 7b. Terminal injection (TIOCSTI) — injects input into another tty
        #     Signal: ioctl with TIOCSTI (0x5412) to hijack terminal
        # ------------------------------------------------------------------
        if re.search(r'ioctl\s*\(.*(?:TIOCSTI|0x5412)', content, re.IGNORECASE):
            meta["poc_category"] = "LPE"
            meta["setup_command"] = ""
            meta["execution_wrapper"] = "./exploit /dev/tty > /tmp/out 2>&1 || ./exploit > /tmp/out 2>&1"
            meta["verification_command"] = (
                "grep -qiE 'it worked|uid=0|root|huhuhu' /tmp/out || "
                "[ $exit_code -eq 0 ]"
            )
            return meta

        # ------------------------------------------------------------------
        # 8. LPE — generic shell spawn (setuid + execve/system + /bin/sh)
        # ------------------------------------------------------------------
        if "/bin/sh" in content and any(
            x in content for x in ["system", "execve", "setuid", "pty"]
        ):
            meta["poc_category"] = "LPE"
            meta["setup_command"] = "echo -e 'id\\nwhoami\\nexit\\n' > /tmp/cmds.txt"
            meta["execution_wrapper"] = "cat /tmp/cmds.txt | ./exploit > /tmp/out 2>&1"
            meta["verification_command"] = (
                "grep -qiE 'uid=0\\(root\\)|^root$|\\[\\+\\].*shell|Launching shell' /tmp/out"
            )
            return meta

        # ------------------------------------------------------------------
        # 9. DOS — memory corruption / crash signals
        # ------------------------------------------------------------------
        _dos_signals = [
            "overflow", "crash", "segfault", "memory exhaust",
            "sigsegv", "sigabrt", "corruption",
        ]
        if any(x in content_lower for x in _dos_signals):
            meta["poc_category"] = "DOS"
            meta["execution_wrapper"] = "./exploit > /tmp/out 2>&1"
            meta["verification_command"] = (
                "[ $exit_code -eq 139 ] || [ $exit_code -eq 134 ] || "
                "[ $exit_code -ge 128 ] || "
                "grep -qiE "
                "'segmentation fault|buffer overflow|core dumped|crash|"
                "fortify|asan|ubsan' /tmp/out"
            )
            return meta

        # ------------------------------------------------------------------
        # 10. INFO_LEAK — generic (address leak)
        # ------------------------------------------------------------------
        if "leak" in content_lower and "address" in content_lower:
            meta["poc_category"] = "INFO_LEAK"
            meta["execution_wrapper"] = "./exploit > /tmp/out 2>&1"
            meta["verification_command"] = (
                "grep -qiE '0x[0-9a-f]{8,16}|leak|leaked|address' /tmp/out"
            )
            return meta

        # ------------------------------------------------------------------
        # 11. OTHER — default
        # ------------------------------------------------------------------
        return meta
