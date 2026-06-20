"""PoC analysis for Phase 1 (methodology v2 — deterministic baseline design).

This module replaces the previous two-gate verification brain (archived at
``deprecated/poc_analyzer.py``). Under the new methodology, Phase 1 establishes
vulnerability reproduction by:

  1. Capturing the PoC exit code from a *known-vulnerable* build (the baseline
     "success code"). This is deterministic and is done by the orchestrator.
  2. Running an **LLM-assisted negative filter** over the PoC's stdout/stderr to
     detect explicit failure messages. This filter is the only place the LLM is
     used in Phase 1, and it can only *flag* a run for manual revision — it can
     never assert success. A deterministic regex fallback is used when no LLM is
     available.

Accordingly, this analyzer no longer synthesizes positive "verification
commands", crash-signal heuristics, or SUID probes. ``PoCAnalyzer`` now provides:

  * ``validate_poc_static``  — static pre-flight (file type, entry point,
                               exploit-intent, CVE anchoring). Unchanged in
                               spirit; still used to skip non-runnable files.
  * ``analyze_poc``          — execution strategy only (how to *run* the PoC:
                               setup command, execution wrapper, category for
                               logging). No verification logic.
  * ``negative_filter``      — the new LLM/regex negative filter.
"""

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
# Negative-signal patterns — the deterministic fallback for the negative filter.
#
# These regexes match RUNTIME OUTPUT (not source). If any fires, the PoC has
# explicitly printed a message confirming it did NOT exploit the target. Under
# the v2 methodology this no longer runs inside the container wrapper; it is the
# host-side fallback used by ``PoCAnalyzer.negative_filter`` when an LLM is not
# available.
#
# Rationale: keep patterns conservative and anchored to explicit phrases that
# exploits print when they self-report failure, so a flag genuinely means
# "send to manual revision" rather than noise.
# ---------------------------------------------------------------------------
_NEGATIVE_RUNTIME_PATTERNS = [
    re.compile(r'\bnot\s+vuln(?:erable)?\b', re.IGNORECASE),
    # "target is safe" == not vulnerable. NOTE: deliberately NOT matching
    # "target is not safe" (which means the opposite — vulnerable), so a genuine
    # reproduction printing "not safe" is never mis-flagged.
    re.compile(r'\btarget\s+is\s+safe\b', re.IGNORECASE),
    re.compile(r'\balready\s+patch(?:ed)?\b', re.IGNORECASE),
    re.compile(r'\bnot\s+exploitable\b', re.IGNORECASE),
    re.compile(r'CheckCode::Safe', re.IGNORECASE),
    re.compile(r'Failure::NotVulnerable', re.IGNORECASE),
    re.compile(r'Failure::NotFound', re.IGNORECASE),
    re.compile(r'\[-\]\s+Exploit\s+failed', re.IGNORECASE),
    re.compile(r'\[-\].*\bfailed\b.*(not vulnerable|not found|bad config)', re.IGNORECASE),
    re.compile(r'\bnot\s+setuid\b|\bis\s+NOT\s+setuid\b', re.IGNORECASE),
    re.compile(r'NOT setuid on this system'),
    re.compile(r'\bno\s+offsets?\s+for\s+this\s+version\b', re.IGNORECASE),
    re.compile(r'unprivileged user namespaces are not permitted', re.IGNORECASE),
    re.compile(r'\bGNU C Library version .* is not vulnerable\b', re.IGNORECASE),
    re.compile(r'\bLinux kernel version .* is not vulnerable\b', re.IGNORECASE),
    re.compile(r'Metasploit module detected'),
    re.compile(r'Phase 1 requires an explicit shell'),
    # Environment / "the program never executed" failures. These can NEVER be a
    # genuine reproduction (the PoC binary/interpreter did not run), so flagging
    # them as failure → manual revision prevents recording a meaningless baseline
    # when no LLM is configured to catch them. High-precision phrases only — a
    # real crash (SIGSEGV/abort) does not print any of these.
    re.compile(r'error while loading shared libraries', re.IGNORECASE),
    re.compile(r'\bexec format error\b', re.IGNORECASE),
    re.compile(r'cannot execute binary file', re.IGNORECASE),
    re.compile(r'\bcommand not found\b', re.IGNORECASE),
]

# Single grep-compatible ERE string (kept for backward compatibility / tooling).
_NEGATIVE_GREP_PATTERN = (
    r'not vuln(erable)?'
    r'|target is safe'
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
    r'|error while loading shared libraries'
    r'|exec format error'
    r'|cannot execute binary file'
    r'|command not found'
)

# ---------------------------------------------------------------------------
# Static exploit-intent signals used by validate_poc_static(). Compiled once.
# ---------------------------------------------------------------------------
_EXPLOIT_INTENT_PATTERNS = [
    re.compile(r'setuid\s*\(\s*0\s*\)', re.IGNORECASE),
    re.compile(r'setgid\s*\(\s*0\s*\)', re.IGNORECASE),
    re.compile(r'execve?\s*\(\s*["\']?/bin/(sh|bash|dash)', re.IGNORECASE),
    re.compile(r'system\s*\(\s*["\']?/bin/(sh|bash|dash)', re.IGNORECASE),
    re.compile(r'/bin/(sh|bash|dash)\b', re.IGNORECASE),
    re.compile(r'chmod\s+[46]7[0-7][0-7]'),
    re.compile(r'char\s+(shellcode|sc)\s*\['),
    re.compile(r'(?:\\x[0-9a-fA-F]{2}){4,}'),
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
    re.compile(r'memcpy\s*\(.*argv', re.IGNORECASE),
    re.compile(r'jump.table|signedness.bug|signed.*unsigned', re.IGNORECASE),
    re.compile(r'\bptrace\s*\(|PTRACE_ATTACH|PTRACE_POKETEXT', re.IGNORECASE),
    re.compile(r'/proc/self/mem|/proc/\d+/mem'),
    re.compile(r'madvise\s*\(.*MADV_DONTNEED|MAP_PRIVATE.*PROT_WRITE', re.IGNORECASE),
    re.compile(r'unshare\s*\(|CLONE_NEWUSER|setns\s*\(', re.IGNORECASE),
    re.compile(r'symlink\s*\(|readlink\s*\(.*race|TOCTOU', re.IGNORECASE),
]


def get_negative_grep_pattern() -> str:
    """Return the ERE pattern string used by the deterministic negative filter."""
    return _NEGATIVE_GREP_PATTERN


def regex_negative_match(output: str) -> Optional[str]:
    """Return the first negative-signal phrase found in *output*, or None.

    Used as the deterministic fallback for :meth:`PoCAnalyzer.negative_filter`.
    """
    if not output:
        return None
    for pat in _NEGATIVE_RUNTIME_PATTERNS:
        m = pat.search(output)
        if m:
            return m.group(0)
    return None


def is_unreadable_output(text: str) -> bool:
    """True when *text* is binary / a memory dump rather than readable status.

    Such output (raw bytes, fill patterns like ``AAAA…``) carries no
    human-readable failure message, so the LLM negative filter can only guess
    at it.  When this holds we abstain and defer to the deterministic baseline
    exit code (methodology v2) instead of risking a false "failure" verdict.
    """
    if not text:
        return False
    # Control bytes (excluding tab/newline/CR) indicate a binary/memory dump.
    ctrl = sum(1 for ch in text if ord(ch) < 32 and ch not in "\t\n\r")
    if ctrl >= 16 or (len(text) >= 200 and ctrl / len(text) > 0.02):
        return True
    # A long run of one repeated non-space char is a memory-fill pattern, not a
    # status message (e.g. an overflow PoC echoing its "AAAA…" payload).
    if re.search(r"([^\s])\1{199,}", text):
        return True
    return False


def looks_like_payload_generator(content: str) -> bool:
    """Heuristic: the PoC only EMITS a crafted payload to stdout and never feeds
    it into a vulnerable code path (no self-trigger / consume behaviour).

    Such PoCs exercise *nothing* of the target library on their own — they just
    print bytes (e.g. CVE-2009-5029 dumps a malicious tzfile and exits). A
    baseline captured from one is meaningless and no source patch can change it.
    Detecting this lets Phase 1 synthesize a consumer/driver instead.
    """
    if not content:
        return False
    emits = bool(
        re.search(r'printf\s*\(\s*"%c"', content)
        or re.search(r'\bputchar\s*\(', content)
        or re.search(r'\bfputc\s*\(', content)
        or re.search(r'\bfwrite\s*\([^;]*\bstdout\b', content)
        or re.search(r'\bwrite\s*\(\s*(?:1|STDOUT_FILENO)\s*,', content)
    )
    if not emits:
        return False
    # Self-trigger / consume signals: if the PoC drives the vulnerability itself
    # (spawns a process, sets an env var the library reads, or calls a library
    # entry point that reaches the bug) it is NOT a bare generator.
    consumes = bool(
        re.search(r'\b(system|popen|execve?|execl\w*|execvp?|posix_spawn)\s*\(', content)
        or re.search(r'\b(setenv|putenv)\s*\(', content)
        or re.search(r'\bfork\s*\(', content)
        or re.search(
            r'\b(localtime|localtime_r|mktime|ctime|strftime|tzset|'
            r'getaddrinfo|gethostby\w+|setlocale|newlocale|regcomp|regexec|'
            r'catopen|catgets|dlopen|iconv_open|fnmatch|glob|wordexp|'
            r'realpath|getcwd|nl_langinfo|gettext|dcgettext)\s*\(',
            content,
        )
    )
    return not consumes


class PoCAnalyzer:
    """Determines how to *run* a PoC and applies the LLM-assisted negative filter.

    This class no longer produces positive verification logic. Success in Phase 1
    is decided by the orchestrator via baseline-exit-code matching; this analyzer
    only (a) decides the execution strategy and (b) flags explicit failures.
    """

    def __init__(self, logger: logging.Logger, model: str = "gpt-4.1-mini"):
        self.logger = logger
        self.api_key = self._get_openai_key()
        self.model = model
        if OpenAI and self.api_key:
            self.client = OpenAI(api_key=self.api_key)
        else:
            self.client = None
            self.logger.warning(
                "OpenAI client not available — negative filter will use the "
                "deterministic regex fallback."
            )

    def _get_openai_key(self) -> str:
        api_key = os.environ.get("OPENAI_API_KEY")
        if api_key:
            return api_key
        # Resolve the key file relative to THIS module, not the CWD. Phase 1/3
        # run as subprocesses whose CWD is the pipeline root, so a bare
        # Path("API-openai-key") worked there — but the feedback loop runs Phase 3
        # validation IN-PROCESS inside the master pipeline, whose CWD may be
        # elsewhere, which silently dropped us to the weak regex fallback.
        for key_file in (Path(__file__).resolve().parent / "API-openai-key",
                         Path("API-openai-key")):
            try:
                if key_file.exists():
                    return key_file.read_text().strip()
            except OSError:
                continue
        return api_key

    # =========================================================================
    # Step 1 — Static pre-flight validation (unchanged in spirit)
    # =========================================================================

    def validate_poc_static(self, poc_path: Path, cve: str = "") -> Dict[str, Any]:
        """Pre-flight static validation before attempting to run a PoC.

        Returns a dict with:
            is_valid, reason, file_type, has_exploit_intent, has_entrypoint,
            cve_match, min_size_ok
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
        if ext in (".c", ".cpp", ".cc", ".cxx", ".c++"):
            result["file_type"] = "c" if ext == ".c" else "cpp"
            result["has_entrypoint"] = bool(
                re.search(r"^\s*(int|void)?\s*main\s*\(", content, re.MULTILINE)
            )
        elif ext == ".sh":
            result["file_type"] = "shell"
            result["has_entrypoint"] = True
        elif ext == ".rb":
            if "class MetasploitModule" in content or re.search(r"class Metasploit\d", content):
                result["file_type"] = "ruby_msf"
                result["has_entrypoint"] = "def exploit" in content
            else:
                result["file_type"] = "ruby"
                result["has_entrypoint"] = True
        elif ext == ".php":
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
    # Step 2 — Execution strategy (how to RUN the PoC; no verification logic)
    # =========================================================================

    def analyze_poc(self, poc_path: Path, cve: str = "",
                    vuln_function: str = "", vuln_file: str = "") -> Dict[str, Any]:
        """Determine how to execute the PoC.

        Uses a three-stage approach:
          1. Fast heuristic pass — covers the majority of common exploit patterns
             (linker-based LPE, format-string, DOS, SUID-dropper, etc.).
          2. Payload-generator driver synthesis — when the PoC merely PRINTS a
             crafted payload and never feeds it into the vulnerable code path
             (so it exercises nothing on its own), ask the LLM to synthesize a
             consumer/driver that feeds the payload into the vulnerable
             subsystem. Needs the vulnerable-function context + an LLM.
          3. LLM fallback — when the heuristic returns the generic ``OTHER``
             category, the LLM derives an execution strategy from the source.

        ``cve`` / ``vuln_function`` / ``vuln_file`` give stage 2 the context it
        needs (which library entry point to drive); they are optional so other
        callers keep working.

        Returns a dict with:
            poc_category    – coarse class, for logging/metadata only
            setup_command   – bash to run before the exploit ('' if none)
            execution_wrapper – command to launch the exploit, writing combined
                                stdout/stderr to /tmp/out

        NOTE: No ``verification_command`` is returned. Success is decided by the
        orchestrator via baseline-exit-code matching + the negative filter.
        """
        default_meta = {
            "poc_category": "OTHER",
            "setup_command": "",
            "execution_wrapper": "./exploit > /tmp/out 2>&1",
        }

        if not poc_path or not poc_path.exists():
            return default_meta

        try:
            content = poc_path.read_text(errors="ignore")
        except Exception as e:
            self.logger.error(f"Failed to read PoC file {poc_path}: {e}")
            return default_meta

        meta = self._strategy_from_content(content)

        # Stage 2: payload-generator → driver. A PoC that only prints a payload
        # and never triggers the bug yields a meaningless baseline (no patch can
        # change it). When we can (LLM available), synthesize a driver that
        # actually feeds the payload into the vulnerable subsystem. Only for C/C++
        # PoCs: the driver is compiled to /poc/exploit and run through the
        # project loader, which is the C-PoC execution path.
        _is_c = poc_path.suffix.lower() in (".c", ".cpp", ".cc", ".cxx", ".c++")
        if self.client and _is_c and looks_like_payload_generator(content):
            gen = self._llm_generator_strategy(
                content, poc_path.name, cve, vuln_function, vuln_file
            )
            if gen:
                self.logger.info(
                    f"PoC {poc_path.name} looks like a payload generator — using a "
                    f"synthesized driver that feeds the payload into "
                    f"{vuln_function or 'the vulnerable subsystem'}."
                )
                return gen
            self.logger.warning(
                f"PoC {poc_path.name} looks like a payload generator but driver "
                f"synthesis failed — it may not exercise the vulnerable code path."
            )

        # Stage 3: when the heuristic couldn't classify the PoC beyond "OTHER",
        # ask the LLM to derive the correct execution strategy from the source.
        if meta["poc_category"] == "OTHER" and self.client:
            meta = self._llm_execution_strategy(content, poc_path.name) or meta

        return meta

    def _llm_generator_strategy(self, content: str, filename: str, cve: str,
                                vuln_function: str, vuln_file: str
                                ) -> Optional[Dict[str, Any]]:
        """Synthesize a driver for a payload-generator PoC.

        The compiled generator lives at ``/poc/exploit`` and prints its crafted
        payload to stdout. We need a *consumer* that feeds that payload into the
        vulnerable code path and is itself runnable as ``/poc/exploit`` — because
        the run wrapper executes ``/poc/exploit`` through the project's own glibc
        loader (so the consumer is tested against the patched/vulnerable build).

        Returns a strategy dict (setup_command builds the driver, overwriting
        /poc/exploit; execution_wrapper runs it) or None on failure.
        """
        snippet = content[:12000]
        vf = vuln_function or "the vulnerable library function"
        vfile = f" (defined in {vuln_file})" if vuln_file else ""
        prompt = f"""You are automating vulnerability reproduction for {cve or 'a CVE'} in the
GNU C Library (glibc). The proof-of-concept below is a PAYLOAD GENERATOR: when
run it only PRINTS a crafted payload to stdout and never feeds that payload into
the vulnerable code path, so on its own it exercises nothing.

The vulnerable function is `{vf}`{vfile}. Your job is to produce a small C
DRIVER that actually triggers the bug, by feeding the generator's payload into
the glibc entry point that reaches `{vf}`.

Runtime contract (read carefully):
- The compiled generator is at /poc/exploit and writes its payload to stdout.
- The glibc under test is installed at /opt/project-build and the driver will be
  run THROUGH that build's dynamic loader, so it WILL use the build's glibc — do
  NOT add special link flags or rpath; compile normally.
- Whatever ends up at /poc/exploit is what gets tested, so your driver must be
  compiled to /poc/exploit (overwriting the generator).
- The driver must just trigger the code path and return 0 on normal completion.
  Do NOT make it print "vulnerable"/"safe" or choose its own exit codes — on a
  vulnerable build the bug will crash it (the harness captures that); on a fixed
  build it should return cleanly. The DIFFERENCE in exit code is the signal.

Return ONLY a JSON object:
{{
  "poc_category": "DOS | RCE | INFO_LEAK | OTHER",
  "setup_command": "bash, runs as root BEFORE execution",
  "execution_wrapper": "bash command to run the driver, all output to /tmp/out"
}}

setup_command MUST (robust, use '|| true' where sensible, no 'set -e'):
  1. Preserve and run the generator to capture its payload to a file, e.g.:
       cp /poc/exploit /poc/.gen 2>/dev/null; /poc/.gen > /poc/payload.bin 2>/dev/null || true
  2. Write the driver C source to /poc/driver.c using a QUOTED heredoc
     delimiter (e.g. cat > /poc/driver.c <<'DRIVER_EOF' ... DRIVER_EOF) so the C
     is written verbatim without shell expansion. The driver reads
     /poc/payload.bin and feeds it into the glibc entry point reaching `{vf}`
     (e.g. for a tzfile payload: write it to a file, point TZ at that file with
     a leading ':' or install it under a TZ name, then call tzset()/localtime();
     for a locale payload: install it and call setlocale()/newlocale(); etc.).
  3. Compile it OVERWRITING the generator:
       gcc -O0 -g -w -o /poc/exploit /poc/driver.c 2>/poc/driver_build.log || \\
       gcc -O0 -g -w -std=gnu99 -o /poc/exploit /poc/driver.c 2>>/poc/driver_build.log || true

execution_wrapper MUST run ./exploit and redirect ALL output to /tmp/out, e.g.:
  "./exploit > /tmp/out 2>&1"
It MUST NOT append '|| true' (the driver's real exit code is the signal).

Generator source ({filename}):
```
{snippet}
```"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a security automation expert. Output strictly JSON."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.0,
                response_format={"type": "json_object"},
            )
            result = json.loads(response.choices[0].message.content)
            if not isinstance(result, dict) or not result.get("execution_wrapper"):
                self.logger.error(f"Driver synthesis for {filename} returned no execution_wrapper")
                return None
            result.setdefault("poc_category", "OTHER")
            result.setdefault("setup_command", "")
            self.logger.info(f"Synthesized driver strategy for {filename}: {result}")
            return result
        except Exception as e:
            self.logger.error(f"Driver synthesis failed for {filename}: {e}")
            return None

    def _llm_execution_strategy(self, content: str, filename: str) -> Optional[Dict[str, Any]]:
        """Ask the LLM to derive an execution strategy for an unrecognised PoC.

        Called only when the heuristic returned ``OTHER`` and a client is
        available. The LLM is given the PoC source and asked to produce the
        minimal shell commands needed to trigger the vulnerability.
        """
        snippet = content[:12000]

        prompt = f"""You are a security engineer automating exploit reproduction.
Analyse the following PoC source file ({filename}) and determine how to execute
it inside a Docker container to trigger the vulnerability.

The exploit binary (or script) will already be compiled/copied to /poc/ and
named 'exploit' (with the appropriate extension). The vulnerable library is
installed at /opt/project-build/lib.

Return ONLY a valid JSON object with these fields:
{{
  "poc_category": "DOS | LPE | FORMAT_STRING | INFO_LEAK | SUID_DROPPER | RCE | OTHER",
  "setup_command": "bash commands to run BEFORE the exploit, or empty string",
  "execution_wrapper": "exact bash command to run the exploit, redirecting ALL output to /tmp/out"
}}

Rules:
- execution_wrapper MUST redirect stdout AND stderr to /tmp/out
- If the PoC writes binary data to stdout (payload generator), the wrapper must
  feed that output into the vulnerable subsystem (e.g. pipe to a consumer, write
  to a file the library will read, etc.)
- If the PoC needs arguments, include them in execution_wrapper
- setup_command may install packages with apt-get if the wrapper needs tools
  not in the base image (e.g. gcc for inline C triggers)
- Keep commands simple and robust; prefer '|| true' over set -e

Source:
```
{snippet}
```"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {"role": "system", "content": "You are a security automation expert. Output strictly JSON."},
                    {"role": "user", "content": prompt},
                ],
                temperature=0.0,
                response_format={"type": "json_object"},
            )
            result = json.loads(response.choices[0].message.content)
            self.logger.info(f"LLM execution strategy for {filename}: {result}")
            return result
        except Exception as e:
            self.logger.error(f"LLM execution strategy failed for {filename}: {e}")
            return None

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

    def _strategy_from_content(self, content: str) -> Dict[str, Any]:
        """Heuristically determine category + setup + execution wrapper.

        Categories are advisory metadata only (no behavioural gating). The
        execution strategy still matters: some PoCs need arguments or stdin to
        exercise the vulnerable code path at all.
        """
        meta: Dict[str, Any] = {
            "poc_category": "OTHER",
            "setup_command": "",
            "execution_wrapper": "./exploit > /tmp/out 2>&1",
        }
        content_lower = content.lower()
        usage_example = self._extract_usage_example(content)
        usage_command = (
            self._normalize_exploit_command(usage_example) if usage_example else None
        )
        if usage_command:
            meta["execution_wrapper"] = f"{usage_command} > /tmp/out 2>&1"

        # Metasploit modules
        if "metasploitmodule" in content_lower or "msf/core" in content_lower:
            meta["poc_category"] = "METASPLOIT"
            meta["execution_wrapper"] = "./exploit > /tmp/out 2>&1"
            return meta

        # FORMAT_STRING — glibc locale / message-catalogue exploitation
        _fs_locale_calls = bool(
            re.search(r'\b(gettext|catopen|dcgettext|dgettext|catgets)\s*\(', content)
            or re.search(r'locale subsystem|format string bug', content_lower)
            or re.search(r'lc_messages.*\bexploit\b', content_lower)
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
            meta["setup_command"] = "mkdir -p /tmp/LC_MESSAGES 2>/dev/null; chmod 777 /tmp 2>/dev/null; true"
            meta["execution_wrapper"] = "./exploit > /tmp/out 2>&1"
            return meta

        # ld.so hwcap diagnostic PoC — MUST come before generic LD_PRELOAD / LPE
        # checks because CVE-2017-1000366 contains LD_PRELOAD/LD_LIBRARY_PATH
        # references that would otherwise trigger the linker-LPE branch first,
        # running the PoC bare with no arguments and printing a usage banner.
        if (
            "target binary" in content_lower
            and "num_important_hwcaps" in content_lower
            and ("ld_hwcap_mask" in content_lower or "LD_HWCAP_MASK" in content)
        ):
            meta["poc_category"] = "RCE"
            meta["execution_wrapper"] = "./exploit 0 /bin/ls > /tmp/out 2>&1"
            return meta

        # LD_AUDIT / LD_PRELOAD linker-based LPE / SUID dropper
        _linker_signals = [
            "ld_audit", "ld_preload", "libpcprofile", "pcprofile_output",
            "ldaudit", "ldpreload",
        ]
        if any(sig in content_lower for sig in _linker_signals):
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
                return meta
            meta["poc_category"] = "LPE"
            meta["setup_command"] = "echo -e 'id\\nwhoami\\nexit\\n' > /tmp/cmds.txt"
            meta["execution_wrapper"] = "./exploit > /tmp/out 2>&1 || true"
            return meta

        # SUID_DROPPER — creates a setuid-root binary as proof
        _suid_dropper_signals = [
            re.search(r'chmod\s+[46]7[0-7][0-7]\s+/tmp/', content, re.IGNORECASE),
            re.search(r'chmod\s+[46]7[0-7][0-7]\s+/var/tmp/', content, re.IGNORECASE),
            re.search(r'chown\s+root\s+/tmp/', content, re.IGNORECASE),
            "suid" in content_lower and "dropper" in content_lower,
        ]
        if any(_suid_dropper_signals):
            meta["poc_category"] = "SUID_DROPPER"
            meta["setup_command"] = "chmod 777 /tmp 2>/dev/null; true"
            meta["execution_wrapper"] = "./exploit > /tmp/out 2>&1"
            return meta

        # INFO_LEAK via privileged environment variables
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
            return meta

        # DoS with explicit argv (e.g. CVE-2011-2702 memcpy pattern)
        if "memcpy(buf, argv[1], atoi(argv[2]))" in content_lower:
            meta["poc_category"] = "DOS"
            meta["execution_wrapper"] = (
                f"{usage_command} > /tmp/out 2>&1" if usage_command
                else "./exploit A 3492348247 > /tmp/out 2>&1"
            )
            return meta

        # Terminal injection (TIOCSTI)
        if re.search(r'ioctl\s*\(.*(?:TIOCSTI|0x5412)', content, re.IGNORECASE):
            meta["poc_category"] = "LPE"
            meta["execution_wrapper"] = "./exploit /dev/tty > /tmp/out 2>&1 || ./exploit > /tmp/out 2>&1"
            return meta

        # LPE — generic shell spawn (setuid + execve/system + /bin/sh)
        # NOTE: must come AFTER the hwcap check above — the CVE-2017-1000366 PoC
        # contains /bin/sh, system, and setuid but is an ld.so hwcap exploit that
        # requires positional arguments; matching LPE here would run it bare.
        if "/bin/sh" in content and any(
            x in content for x in ["system", "execve", "setuid", "pty"]
        ):
            meta["poc_category"] = "LPE"
            meta["setup_command"] = "echo -e 'id\\nwhoami\\nexit\\n' > /tmp/cmds.txt"
            meta["execution_wrapper"] = "cat /tmp/cmds.txt | ./exploit > /tmp/out 2>&1"
            return meta

        # DOS — memory corruption / crash signals
        _dos_signals = [
            "overflow", "crash", "segfault", "memory exhaust",
            "sigsegv", "sigabrt", "corruption",
        ]
        if any(x in content_lower for x in _dos_signals):
            meta["poc_category"] = "DOS"
            meta["execution_wrapper"] = "./exploit > /tmp/out 2>&1"
            return meta

        # INFO_LEAK — generic (address leak)
        if "leak" in content_lower and "address" in content_lower:
            meta["poc_category"] = "INFO_LEAK"
            meta["execution_wrapper"] = "./exploit > /tmp/out 2>&1"
            return meta

        return meta

    # =========================================================================
    # Step 3 — LLM-assisted negative filter (the only LLM use in Phase 1)
    # =========================================================================

    def negative_filter(
        self,
        output: str,
        exit_code: int,
        cve: str = "",
        poc_category: str = "OTHER",
    ) -> Dict[str, Any]:
        """Decide whether the PoC runtime output indicates an explicit failure.

        This is a *negative* filter only: it can flag a run for manual revision,
        but it never asserts success. When the LLM is unavailable (or errors out)
        the deterministic regex fallback is used.

        Returns a dict:
            failed  – True if the output indicates the exploit did NOT work
            reason  – short human-readable justification
            source  – "llm" | "regex" | "regex-fallback"
        """
        # Deterministic regex pre-check: an explicit self-reported failure is
        # authoritative regardless of the LLM, and cheap to detect.
        regex_hit = regex_negative_match(output)

        # Binary / memory-dump output has no readable failure message; the LLM
        # would only guess (observed: CVE-2009-5029 emits raw tzfile bytes +
        # an "AAAA…" fill and was wrongly flagged). Abstain and defer to the
        # deterministic baseline — unless regex already saw explicit failure text.
        if not regex_hit and is_unreadable_output(output):
            return {
                "failed": False,
                "reason": "Output is binary/non-textual — deferring to deterministic baseline",
                "source": "binary-abstain",
            }

        if not self.client:
            if regex_hit:
                return {
                    "failed": True,
                    "reason": f"Deterministic negative signal: {regex_hit!r}",
                    "source": "regex",
                }
            return {
                "failed": False,
                "reason": "No deterministic negative signal (LLM unavailable)",
                "source": "regex",
            }

        # LLM path. Truncate output to keep the request small and bounded.
        snippet = output or ""
        if len(snippet) > 8000:
            snippet = snippet[:4000] + "\n...[truncated]...\n" + snippet[-4000:]

        prompt = f"""You are a security analyst reviewing the runtime output of an exploit
proof-of-concept (PoC) that was executed against a build KNOWN to be vulnerable
to {cve or 'the target CVE'} (category: {poc_category}).

Your ONLY job is to decide whether the output contains explicit evidence that
the exploit FAILED or did not work — for example: "not vulnerable", "target is
safe", "already patched", "no offsets for this version", "NOT setuid", a
Metasploit CheckCode::Safe / Failure::NotVulnerable, a usage/help banner printed
instead of running, or a clear environment/setup error that prevented the
exploit from running (missing library, wrong architecture, interpreter error).

Do NOT try to confirm success. If the output looks like a successful or
plausibly successful exploitation, or is ambiguous/empty, answer failed=false.
Only answer failed=true when there is clear evidence of failure.

Process exit code: {exit_code}

Output:
```
{snippet}
```

Respond with a strict JSON object: {{"failed": true|false, "reason": "<short>"}}"""

        try:
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[
                    {
                        "role": "system",
                        "content": (
                            "You are a precise security analyst. You only detect "
                            "explicit exploitation FAILURE. Output strictly JSON."
                        ),
                    },
                    {"role": "user", "content": prompt},
                ],
                temperature=0.0,
                response_format={"type": "json_object"},
            )
            data = json.loads(response.choices[0].message.content)
            failed = bool(data.get("failed", False))
            reason = str(data.get("reason", "")).strip() or "(no reason given)"
            # The deterministic signal is authoritative: if regex saw an explicit
            # failure phrase, honour it even if the LLM disagreed.
            if regex_hit and not failed:
                return {
                    "failed": True,
                    "reason": f"Deterministic negative signal overrides LLM: {regex_hit!r}",
                    "source": "regex",
                }
            return {"failed": failed, "reason": reason, "source": "llm"}
        except Exception as e:
            self.logger.error(f"LLM negative filter failed for {cve}: {e}")
            if regex_hit:
                return {
                    "failed": True,
                    "reason": f"LLM error; deterministic negative signal: {regex_hit!r}",
                    "source": "regex-fallback",
                }
            return {
                "failed": False,
                "reason": f"LLM error ({e}); no deterministic negative signal",
                "source": "regex-fallback",
            }
