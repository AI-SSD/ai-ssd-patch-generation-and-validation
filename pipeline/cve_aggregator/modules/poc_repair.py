"""
LLM PoC Repair module (Module 6).

Takes Proof-of-Concept scripts that failed syntax validation (Module 5),
sends them to an LLM for repair, re-validates the output using the same
Module 5 logic, and either saves the fixed PoC to ``exploits/`` or flags
it for manual supervision.

The LLM API integration follows the same Ollama-compatible pattern used
in Phase 2 (``patch_generator.py``).
"""

from __future__ import annotations

import json
import logging
import re
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

from ..models import CVEEntry, Dataset, SyntaxValidationResult
from ..utils.file_utils import get_file_extension_for_language
from .base import PipelineModule
from .syntax_validator import SyntaxValidator

logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════
# Prompt Templates
# ═══════════════════════════════════════════════════════════════════════

# --- Comment-prefix per language (used in retry prompts) ---
_COMMENT_PREFIX: Dict[str, str] = {
    "c": "//", "cpp": "//", "csharp": "//", "java": "//",
    "python": "#", "shell": "#", "ruby": "#",
    "perl": "#", "php": "//",
}

# --- Language-specific guidance injected into prompts ---
_LANG_GUIDANCE: Dict[str, str] = {
    "c": (
        "C-SPECIFIC RULES:\n"
        "  • Preprocessor directives missing the leading '#' (e.g. 'include <stdio.h>' → '#include <stdio.h>')\n"
        "  • Bare numeric tokens on their own line (OCR/scraping noise) — comment them out with '//'\n"
        "  • Plain-English prose lines embedded in code — comment them out with '//'\n"
        "  • Unbalanced braces or parentheses from truncated scraping\n"
        "  • Missing 'int main()' or function return types stripped during extraction\n"
        "  • If an error says 'undeclared identifier' for a well-known POSIX/Linux symbol\n"
        "    (e.g. environ, O_RDONLY, PAGE_SIZE, SOMAXCONN, socklen_t), add the STANDARD\n"
        "    header that declares it (e.g. <unistd.h>, <fcntl.h>, <sys/socket.h>).\n"
        "    These headers were almost certainly in the original code and were stripped during scraping.\n"
        "  • If the file appears to be a SHELL SCRIPT or prose write-up (contains '$', 'mkdir',\n"
        "    'ln /bin/', 'exec 3<', 'whoami', etc. but NO #include directives and NO function\n"
        "    definitions), do NOT try to convert it to C. Instead, wrap the ENTIRE content\n"
        "    in a block comment /* ... */ so it compiles as an empty C translation unit.\n"
        "\n"
        "  IMPORTANT: Validation runs on macOS with Xcode's clang, NOT Linux gcc.\n"
        "  Some Linux-only headers (e.g. <sys/mount.h> fields, <asm/..., linux/...)>\n"
        "  may produce 'undeclared identifier' errors that are FALSE POSITIVES.\n"
        "  For those, add a minimal stub definition guarded by #ifndef, e.g.:\n"
        "    #ifndef PAGE_MASK\n"
        "    #define PAGE_MASK (~(PAGE_SIZE - 1))\n"
        "    #endif\n"
        "  This preserves compilation on both macOS and Linux."
    ),
    "cpp": (
        "C++-SPECIFIC RULES:\n"
        "  • All C rules apply (preprocessor, prose, undeclared identifiers, etc.)\n"
        "  • Missing namespace qualifiers (std::) — add 'using namespace std;' or qualify names\n"
        "  • Missing C++ standard headers (<iostream>, <string>, <vector>, <memory>, etc.)\n"
        "  • Template syntax errors from HTML entity corruption (e.g. &lt; → <)\n"
        "  • C++11/14/17 features that may need 'auto', 'nullptr', range-for, etc.\n"
        "  • Class/struct declarations with missing closing braces or semicolons\n"
        "  • Do NOT downgrade C++ to C — preserve the original coding style\n"
        "  • Validation uses g++ with -std=c++17"
    ),
    "csharp": (
        "C#-SPECIFIC RULES:\n"
        "  • Prose/description lines embedded in code — comment them out with '//'\n"
        "  • Missing 'using' directives for standard namespaces\n"
        "    (e.g. using System; using System.IO; using System.Net;) — add them\n"
        "  • Unresolved project-specific references (e.g. custom NuGet packages)\n"
        "    are expected for standalone PoC files — do NOT remove the using directives\n"
        "  • Missing semicolons at end of statements stripped during scraping\n"
        "  • Truncated class/method declarations from line-wrap during extraction\n"
        "  • Unbalanced braces from incomplete class or method bodies\n"
        "  • Attribute syntax errors ([Attribute]) — ensure they are on their own line\n"
        "  • String interpolation syntax ($\"...\") that may have been corrupted\n"
        "  • Do NOT change the namespace or class name\n"
        "  • Validation uses the Mono mcs compiler if available"
    ),
    "python": (
        "PYTHON-SPECIFIC RULES:\n"
        "  • Python 2 syntax that is not valid Python 3 (print statement, except E, e: syntax)\n"
        "  • Indentation errors caused by HTML-to-text conversion (tabs vs spaces mixed)\n"
        "  • Prose/description lines inserted between code sections — comment them out with '#'\n"
        "  • Truncated string literals or unclosed parentheses from line-wrap during scraping\n"
        "  • Missing colons at the end of def/class/if/for/while lines (stripped by scrapers)"
    ),
    "shell": (
        "SHELL-SPECIFIC RULES:\n"
        "  • Missing shebang line (add '#!/bin/bash' or '#!/bin/sh' if absent)\n"
        "  • Prose/description lines not commented out — prefix them with '#'\n"
        "  • Broken heredoc syntax from scraping (EOF markers not on their own line)\n"
        "  • Unmatched quotes or unclosed subshell expressions '$(...)'\n"
        "  • Variable assignments with spaces around '=' (bash requires no spaces)"
    ),
    "ruby": (
        "RUBY-SPECIFIC RULES:\n"
        "  • Prose lines without comment markers — prefix with '#'\n"
        "  • Missing 'end' keywords from truncated scraping\n"
        "  • Require statements with incorrect string quoting from HTML entities\n"
        "  • Unbalanced do/end or begin/rescue/end blocks"
    ),
    "perl": (
        "PERL-SPECIFIC RULES:\n"
        "  • Missing 'use strict;' / 'use warnings;' is OK — do not add them\n"
        "  • Prose lines not commented — prefix with '#'\n"
        "  • Broken heredoc markers\n"
        "  • Missing semicolons at end of statements stripped during scraping"
    ),
    "php": (
        "PHP-SPECIFIC RULES:\n"
        "  • Missing '<?php' opening tag — add if absent\n"
        "  • Prose lines inside code blocks — comment out with '//'\n"
        "  • HTML entity artefacts (&lt; &gt; &amp;) that should be < > &\n"
        "  • Missing semicolons at end of PHP statements"
    ),
    "java": (
        "JAVA-SPECIFIC RULES:\n"
        "  • Prose/description lines embedded in code — comment them out with '//'\n"
        "  • Missing import statements for standard JDK classes\n"
        "    (e.g. java.io.*, java.net.*, java.util.*) — add them\n"
        "  • Unresolved project-specific imports (e.g. org.apache.*, javax.servlet.*)\n"
        "    are expected for standalone PoC files — do NOT remove them\n"
        "  • Missing semicolons at end of statements stripped during scraping\n"
        "  • Truncated class/method declarations from line-wrap during extraction\n"
        "  • Unbalanced braces from incomplete class or method bodies\n"
        "  • Annotation syntax errors (@Override, @Test) — ensure they are on\n"
        "    their own line before the method or class declaration\n"
        "  • If the file has no public class matching the filename, that is OK —\n"
        "    standalone PoC files are compiled with javac directly\n"
        "  • Generics syntax errors from HTML entity corruption\n"
        "    (e.g. List&lt;String&gt; → List<String>)\n"
        "  • Do NOT change the package declaration or class name\n"
    ),
}

_DEFAULT_LANG_GUIDANCE = (
    "COMMON SCRAPING CORRUPTION PATTERNS TO FIX:\n"
    "  • Prose/description lines embedded in code — comment them out\n"
    "  • Truncated lines or missing closing delimiters from line-wrap\n"
    "  • HTML entity artefacts (&lt; &gt; &amp;) that should be < > &\n"
    "  • Unbalanced brackets or block delimiters"
)


# ── Error classification helpers ─────────────────────────────────────
# Used to give the LLM targeted hints about what kind of errors it faces.

def _classify_errors(errors: List[str], language: str) -> Dict[str, List[str]]:
    """Classify compiler/validator errors into actionable categories.

    Returns a dict with keys: 'scraping', 'missing_decl', 'platform', 'other'.
    """
    cats: Dict[str, List[str]] = {
        "scraping": [], "missing_decl": [], "platform": [], "other": [],
    }
    if language != "c":
        cats["other"] = list(errors)
        return cats

    for e in errors:
        lower = e.lower()
        if "invalid preprocessing directive" in lower:
            cats["scraping"].append(e)
        elif "expected ';' after top level declarator" in lower and "from:" in lower:
            cats["scraping"].append(e)
        elif any(p in lower for p in [
            "unknown type name", "use of undeclared identifier",
            "no member named", "expected expression",
        ]):
            cats["missing_decl"].append(e)
        elif "xcode" in lower or "macosx" in lower or "xcrun" in lower:
            cats["platform"].append(e)
        else:
            cats["other"].append(e)
    return cats


def _build_error_summary(cats: Dict[str, List[str]]) -> str:
    """Build a human-readable summary of classified errors for the prompt."""
    parts = []
    if cats["scraping"]:
        parts.append(
            f"  SCRAPING DAMAGE ({len(cats['scraping'])} errors):\n"
            f"    Prose lines, missing '#' on preprocessor directives, HTML artefacts.\n"
            f"    → Comment out prose with '//', restore '#' on directives."
        )
    if cats["missing_decl"]:
        parts.append(
            f"  MISSING DECLARATIONS ({len(cats['missing_decl'])} errors):\n"
            f"    Undeclared identifiers, unknown types, missing struct members.\n"
            f"    → If it's a standard POSIX/Linux symbol, add the missing #include.\n"
            f"    → If it's a project-specific constant (e.g. PAGE_MASK), add a\n"
            f"      guarded #define stub. Do NOT remove the code that uses it."
        )
    if cats["platform"]:
        parts.append(
            f"  PLATFORM MISMATCH ({len(cats['platform'])} errors):\n"
            f"    Errors from compiling Linux-targeted code on macOS.\n"
            f"    → Add #ifdef/#ifndef guards or stub definitions as needed."
        )
    if cats["other"]:
        parts.append(
            f"  OTHER ({len(cats['other'])} errors):\n"
            f"    General compilation errors — fix as needed."
        )
    return "\n".join(parts)

SYSTEM_PROMPT = """\
You are a senior security researcher and expert programmer.\
 Your task is to repair COMPILATION/SYNTAX errors in a Proof-of-Concept (PoC)\
 exploit script that was automatically scraped from ExploitDB.

CONTEXT — WHY THESE FILES HAVE ERRORS:
These PoC scripts were scraped from web pages and PDF files.\
 During extraction, the following corruption routinely occurs:
  • Prose/description text is mixed into the source code without comment markers.
  • Preprocessor directives lose their leading character (e.g. '#' in C).
  • Lines get truncated, merged, or duplicated by HTML-to-text converters.
  • HTML entities (&lt; &gt; &amp;) replace real characters.
  • Indentation is garbled (tabs replaced by spaces inconsistently).
  • Numeric labels or line numbers from listings are left as bare tokens.
  • Standard #include headers may have been accidentally stripped.

ADDITIONAL CONTEXT — CROSS-PLATFORM VALIDATION:
The validator may run on macOS (clang/Xcode) but the PoC targets Linux.\
 Some Linux-only symbols (PAGE_MASK, SOMAXCONN, environ, etc.) will appear\
 as 'undeclared identifier' errors. These are NOT real bugs in the PoC.\
 Fix them by adding the correct standard header or a guarded #define stub.

YOUR RULES:
  1. Fix ALL errors reported by the validator so the code compiles cleanly.
  2. Treat the EXPLOIT LOGIC as sacred — never change what the script does.
  3. Do NOT rewrite, optimise, or modernise the code beyond what is needed.
  4. You MAY add standard library #include headers if the errors clearly show\
 they are missing (e.g. <unistd.h> for environ, <fcntl.h> for O_RDONLY).\
 Do NOT add third-party dependencies.
  5. Comment out (do NOT delete) any prose lines that cannot be valid code.
  6. Return ONLY the complete, corrected source code — no markdown fences,\
 no explanations, no preamble, no leading comment about what you fixed.

OUTPUT FORMAT:
Start directly with the first line of the source file (e.g. '#include <stdio.h>',\
 '#!/usr/bin/env python3', '<?php', etc.).\
 Do NOT wrap the code in triple backticks or any other delimiters.\
 Do NOT start with a comment describing your fix.\
"""

RETRY_SYSTEM_PROMPT = """\
You are a senior security researcher and expert programmer.\
 Your previous attempt to repair a scraped PoC exploit script FAILED validation.\
 You must analyse your mistake and produce a corrected version.

CONTEXT — WHY THESE FILES HAVE ERRORS:
These PoC scripts were scraped from ExploitDB web pages and PDFs.\
 Common corruption: prose lines mixed into code without comment markers,\
 missing preprocessor '#' characters, truncated lines, HTML entities,\
 garbled indentation, and bare numeric line-number artefacts.\
 Standard #include headers may also have been stripped during scraping.

ADDITIONAL CONTEXT — CROSS-PLATFORM VALIDATION:
The validator may run on macOS (clang/Xcode) but the PoC targets Linux.\
 Fix Linux-only symbols by adding the correct standard header or a stub #define.

YOUR RULES:
  1. Study BOTH the original errors AND the new errors from your previous attempt.
  2. Your previous repair introduced NEW errors or failed to fix the originals — fix them.
  3. Treat the EXPLOIT LOGIC as sacred — never change what the script does.
  4. You MAY add standard library #include headers when they are clearly missing.\
 Do NOT add third-party or non-standard dependencies.
  5. Comment out (do NOT delete) any prose lines that cannot be valid code.
  6. Return ONLY the complete, corrected source code — no markdown fences,\
 no explanations, no preamble, no leading comment about what you fixed.

CRITICAL — DO NOT REPEAT THESE COMMON MISTAKES:
  • Do NOT start your output with '# FIX: ...' — in C, '#' begins a preprocessor\
 directive and '# FIX:' is an invalid directive that creates a new error.
  • Do NOT generate code in a DIFFERENT language than requested.\
 If the file is labelled C, output only C code.
  • Do NOT hallucinate new functionality — only fix what is broken.

OUTPUT FORMAT:
Start directly with the first line of the source file.\
 Do NOT wrap the code in triple backticks or any other delimiters.\
 Do NOT start with a comment describing your fix.\
"""


def _build_repair_prompt(
    poc_code: str,
    language: str,
    errors: List[str],
) -> str:
    """Build the initial user prompt for PoC repair.

    Includes language-specific guidance, classified error analysis, and
    the exact validator error messages to target.
    """
    lang_guidance = _LANG_GUIDANCE.get(language, _DEFAULT_LANG_GUIDANCE)
    error_block = "\n".join(f"  [{i+1}] {e}" for i, e in enumerate(errors))

    # Classify errors and build targeted guidance
    cats = _classify_errors(errors, language)
    error_summary = _build_error_summary(cats)

    parts = [
        f"LANGUAGE: {language.upper()}\n",
        f"{lang_guidance}\n",
    ]

    if error_summary:
        parts.append(
            f"══════════════════════════════════════════════════════════\n"
            f"ERROR ANALYSIS (categorised for you):\n"
            f"══════════════════════════════════════════════════════════\n"
            f"{error_summary}\n"
        )

    parts.extend([
        f"══════════════════════════════════════════════════════════\n"
        f"RAW ERRORS REPORTED BY VALIDATOR:\n"
        f"══════════════════════════════════════════════════════════\n"
        f"{error_block}\n",
        f"══════════════════════════════════════════════════════════\n"
        f"POC SOURCE CODE (scraped — may contain corruption):\n"
        f"══════════════════════════════════════════════════════════\n"
        f"{poc_code}\n"
        f"══════════════════════════════════════════════════════════\n",
        f"TASK: Fix the {len(errors)} error(s) listed above while\n"
        f"preserving all exploit logic.\n"
        f"Return the complete corrected source file — nothing else.",
    ])

    return "\n".join(parts)


def _build_retry_prompt(
    original_code: str,
    previous_attempt: str,
    language: str,
    new_errors: List[str],
    attempt_number: int,
) -> str:
    """Build a retry prompt that surfaces the failed attempt and new errors.

    Uses error classification and language-aware comment prefix to avoid
    the LLM introducing new errors (e.g. ``# FIX:`` in C files).
    """
    lang_guidance = _LANG_GUIDANCE.get(language, _DEFAULT_LANG_GUIDANCE)
    error_block = "\n".join(f"  [{i+1}] {e}" for i, e in enumerate(new_errors))

    # Classify errors for targeted guidance
    cats = _classify_errors(new_errors, language)
    error_summary = _build_error_summary(cats)

    parts = [
        f"RETRY ATTEMPT #{attempt_number} — LANGUAGE: {language.upper()}\n",
        f"{lang_guidance}\n",
    ]

    if error_summary:
        parts.append(
            f"══════════════════════════════════════════════════════════\n"
            f"ERROR ANALYSIS (categorised for you):\n"
            f"══════════════════════════════════════════════════════════\n"
            f"{error_summary}\n"
        )

    parts.extend([
        f"══════════════════════════════════════════════════════════\n"
        f"YOUR PREVIOUS REPAIR ATTEMPT (STILL INVALID):\n"
        f"══════════════════════════════════════════════════════════\n"
        f"{previous_attempt}\n",
        f"══════════════════════════════════════════════════════════\n"
        f"NEW ERRORS FROM YOUR PREVIOUS ATTEMPT:\n"
        f"══════════════════════════════════════════════════════════\n"
        f"{error_block}\n",
        f"══════════════════════════════════════════════════════════\n"
        f"ORIGINAL SCRAPED POC (for reference):\n"
        f"══════════════════════════════════════════════════════════\n"
        f"{original_code}\n"
        f"══════════════════════════════════════════════════════════\n",
        f"TASK: Fix the {len(new_errors)} remaining error(s) in your previous\n"
        f"attempt. Start your output directly with the first line of code.\n"
        f"Return the complete corrected source file — nothing else.",
    ])

    return "\n".join(parts)


# ═══════════════════════════════════════════════════════════════════════
# Helper: strip markdown fences from LLM output
# ═══════════════════════════════════════════════════════════════════════

def strip_markdown_fences(code: str) -> str:
    """Remove markdown code fences that LLMs sometimes add despite instructions."""
    if not code:
        return ""
    # Opening fence with optional language tag
    code = re.sub(r"^\s*```[a-zA-Z0-9+#]*\s*[\r\n]+", "", code)
    # Closing fence
    code = re.sub(r"[\r\n]+\s*```\s*$", "", code)
    # Standalone fence lines
    code = re.sub(r"^\s*```[a-zA-Z0-9+#]*\s*$", "", code, flags=re.MULTILINE)
    return code.strip()


def _strip_llm_preamble(code: str, language: str) -> str:
    """Remove leading '# FIX: ...' or '// FIX: ...' comment lines.

    LLMs often add a self-reflective comment at the top despite being told
    not to.  In C, '# FIX:' is an invalid preprocessor directive, so this
    must be stripped before validation.
    """
    if not code:
        return code
    prefix = _COMMENT_PREFIX.get(language, "//")
    lines = code.split("\n")
    # Strip up to 3 leading preamble lines (# FIX:, // FIX:, etc.)
    stripped = 0
    while stripped < min(3, len(lines)):
        line = lines[stripped].strip()
        if not line:
            stripped += 1
            continue
        # Match '# FIX:', '// FIX:', '/* FIX:', etc.
        if re.match(r"^(#\s*FIX\b|//\s*FIX\b|/\*\s*FIX\b)", line, re.IGNORECASE):
            stripped += 1
            continue
        break
    if stripped:
        return "\n".join(lines[stripped:])
    return code


# ═══════════════════════════════════════════════════════════════════════
# Module class
# ═══════════════════════════════════════════════════════════════════════

class PoCRepairLLM(PipelineModule):
    """Pipeline module: *LLM PoC Repair* (Module 6).

    Reads ``context["syntax_results"]`` and ``context["dataset"]`` to
    identify invalid PoCs, attempts to repair each via an LLM, re-validates
    with :class:`SyntaxValidator`, and writes results back into the context.
    """

    # ----- main entry point -----

    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        cfg = self.config.get("poc_repair", {})

        # Configuration knobs
        provider: str = cfg.get("provider", "ollama").lower()
        api_endpoint: str = cfg.get("api_endpoint", "http://10.3.2.171:80/api/chat")
        model: str = cfg.get("model", "qwen2.5-coder:7b")
        openai_model: str = cfg.get("openai_model", "gpt-4.1-mini")
        # API key: env var takes precedence over config value
        import os as _os
        openai_api_key: str = _os.environ.get("OPENAI_API_KEY") or str(cfg.get("openai_api_key", ""))
        max_attempts: int = cfg.get("max_repair_attempts", 3)
        api_timeout: int = cfg.get("api_timeout", 600)
        num_ctx: int = cfg.get("num_ctx", 0)          # 0 = use server default
        max_poc_chars: int = cfg.get("max_poc_chars", 0)  # 0 = no truncation
        temperature: float = cfg.get("temperature", 0.2)
        report_path = Path(cfg.get("report_path", "poc_repair_report.json"))
        manual_queue_path = Path(cfg.get("manual_review_queue_path", "manual_review_queue.json"))
        poc_dir = Path(self.config.get("output", {}).get("poc_dir", "exploits"))
        manual_dir = Path(
            self.config.get("syntax_validator", {}).get("manual_supervision_dir", "manual_supervision")
        )

        poc_dir.mkdir(parents=True, exist_ok=True)

        # Read inputs from earlier pipeline stages
        syntax_results: Dict[str, Dict] = context.get("syntax_results", {})
        dataset: Dataset = context.get("dataset", Dataset())

        if not syntax_results:
            self.logger.info("No syntax results found – skipping PoC repair.")
            return context

        # Identify invalid PoCs that need repair.
        # By default, PoCRepairLLM attempts repair on ALL invalid PoCs
        # regardless of whether the CVE has commits.  The commit-gating
        # in SyntaxValidator controls which files are *copied* to
        # manual_supervision/ for human review; it should not prevent
        # LLM repair attempts.  Use poc_repair.allow_repair_without_commit
        # (default True) to control this independently.
        repair_allow = cfg.get(
            "allow_repair_without_commit", True
        )
        invalid_pocs = self._collect_invalid_pocs(
            syntax_results, dataset, allow_without_commit=repair_allow
        )
        if not invalid_pocs:
            self.logger.info("All PoCs passed validation – nothing to repair.")
            return context

        self.logger.info(
            "Found %d invalid PoC(s) to attempt LLM repair.", len(invalid_pocs)
        )

        # Pre-flight: check API health
        if not self._check_api_health(
            api_endpoint, model,
            provider=provider, openai_api_key=openai_api_key, openai_model=openai_model,
        ):
            if provider == "openai":
                self.logger.error("OpenAI API key not configured – skipping PoC repair.")
            else:
                self.logger.error(
                    "LLM API at %s is not reachable – skipping PoC repair.", api_endpoint
                )
            return context

        if provider == "openai":
            # No GPU or model pre-loading needed for OpenAI
            pass
        else:
            # GPU availability gate: wait up to gpu_wait_timeout seconds for a
            # free GPU.  When the timeout expires, skip repairs entirely to avoid
            # wasting hours on CPU-only inference.
            gpu_wait_timeout: int = cfg.get("gpu_wait_timeout", 120)
            if gpu_wait_timeout > 0 and not self._wait_for_gpu(
                api_endpoint, timeout=gpu_wait_timeout
            ):
                self.logger.warning(
                    "GPU not available after %d s — skipping PoC repair. "
                    "Set poc_repair.gpu_wait_timeout to 0 to disable this check.",
                    gpu_wait_timeout,
                )
                return context

            # Pre-load the model before starting repairs.
            # Ollama lazy-loads models on the first inference call; for large
            # models like devstral (~14 GiB) this cold-start can take several
            # minutes, exceeding api_timeout and causing every initial request
            # to time out.  We trigger loading explicitly here and wait until
            # the model is confirmed to be in GPU VRAM before continuing.
            model_load_timeout: int = cfg.get("model_load_timeout", 300)
            if not self._preload_model(api_endpoint, model, timeout=model_load_timeout):
                self.logger.warning(
                    "Model '%s' did not reach GPU VRAM within %d s — "
                    "inference may be slow or time out.",
                    model, model_load_timeout,
                )

        # Instantiate a SyntaxValidator to reuse Module 5 validation logic
        syntax_validator = SyntaxValidator(self.config)
        sv_cfg = self.config.get("syntax_validator", {})

        # Track results
        repair_report: Dict[str, Any] = {}
        manual_queue: List[Dict[str, Any]] = []
        repaired_count = 0
        failed_count = 0

        # Build a set of CVE IDs that already have at least one valid PoC.
        cves_with_valid_poc: set = set()
        for sr_key, sr_val in syntax_results.items():
            if sr_val.get("is_valid"):
                sr_cve, _, _ = sr_key.partition(":")
                cves_with_valid_poc.add(sr_cve)

        # ── Promote valid PoC to primary position ──
        # If a CVE's primary PoC (index 0) is invalid but a secondary PoC is
        # valid, swap them so downstream tools always see the best exploit
        # first.  The swapped (invalid) PoC is still queued for LLM repair.
        for cve_id_swap in list(cves_with_valid_poc):
            entry_swap = dataset.cves.get(cve_id_swap)
            if not entry_swap or not entry_swap.exploits:
                continue
            primary_key = f"{cve_id_swap}:0"
            if syntax_results.get(primary_key, {}).get("is_valid"):
                continue  # Primary is already valid — nothing to do
            # Find the first valid secondary PoC
            valid_idx: Optional[int] = None
            for idx in range(1, len(entry_swap.exploits)):
                if syntax_results.get(f"{cve_id_swap}:{idx}", {}).get("is_valid"):
                    valid_idx = idx
                    break
            if valid_idx is None:
                continue
            # Swap exploits in the dataset
            entry_swap.exploits[0], entry_swap.exploits[valid_idx] = (
                entry_swap.exploits[valid_idx], entry_swap.exploits[0]
            )
            self.logger.info(
                "CVE %s: promoted valid PoC (idx %d) to primary — "
                "invalid PoC moved to idx %d.",
                cve_id_swap, valid_idx, valid_idx,
            )
            # Swap the corresponding syntax_results entries
            sr_primary = dict(syntax_results.get(primary_key, {}))
            sr_valid = dict(syntax_results.get(f"{cve_id_swap}:{valid_idx}", {}))
            if primary_key in syntax_results:
                syntax_results[primary_key] = sr_valid
            if f"{cve_id_swap}:{valid_idx}" in syntax_results:
                syntax_results[f"{cve_id_swap}:{valid_idx}"] = sr_primary
            # Update exploit_idx in the already-collected invalid_pocs list
            for item_swap in invalid_pocs:
                if item_swap["cve_id"] != cve_id_swap:
                    continue
                if item_swap["exploit_idx"] == 0:
                    item_swap["exploit_idx"] = valid_idx
                elif item_swap["exploit_idx"] == valid_idx:
                    item_swap["exploit_idx"] = 0

        # ── Phase A: Pre-checks (fast, sequential) ──
        # Separate items into those that need LLM repair vs those skipped.
        items_to_repair: List[Dict[str, Any]] = []

        for item in invalid_pocs:
            cve_id = item["cve_id"]
            exploit_idx = item["exploit_idx"]
            original_code = item["content"]
            language = item["language"]
            errors = item["errors"]
            key = f"{cve_id}:{exploit_idx}"

            # ── Pre-check: estimate token budget ──
            est_output_tokens = len(original_code) // 4
            # Token generation rates (tok/s) — configurable per provider
            local_tok_rate = cfg.get("local_token_rate", 3)
            openai_tok_rate = cfg.get("openai_token_rate", 150)
            if provider != "openai":
                est_generation_secs = est_output_tokens / local_tok_rate
            else:
                est_generation_secs = est_output_tokens / openai_tok_rate
            if est_generation_secs > api_timeout * 0.8:
                skip_msg = (
                    f"PoC too large for LLM repair (~{est_output_tokens} output "
                    f"tokens, ~{est_generation_secs:.0f}s estimated vs "
                    f"{api_timeout}s timeout)"
                )
                self.logger.warning(
                    "Skipping PoC %s — %s. Flagging for manual review.",
                    key, skip_msg,
                )
                failed_count += 1
                repair_report[key] = {
                    "repaired": False,
                    "fixed_code": None,
                    "attempts": 0,
                    "last_errors": errors,
                    "attempt_history": [],
                    "skip_reason": skip_msg,
                }
                manual_queue.append({
                    "cve_id": cve_id,
                    "exploit_idx": exploit_idx,
                    "language": language,
                    "original_errors": errors,
                    "last_errors": errors,
                    "attempts": 0,
                    "skip_reason": skip_msg,
                    "flagged_at": datetime.now().isoformat(),
                })
                continue

            # ── Pre-check: detect obvious language mismatch ──
            mismatch = self._detect_language_mismatch(original_code, language)
            if mismatch:
                self.logger.warning(
                    "Skipping PoC %s — %s. Flagging for manual review.",
                    key, mismatch,
                )
                failed_count += 1
                repair_report[key] = {
                    "repaired": False,
                    "fixed_code": None,
                    "attempts": 0,
                    "last_errors": errors,
                    "attempt_history": [],
                    "skip_reason": mismatch,
                }
                manual_queue.append({
                    "cve_id": cve_id,
                    "exploit_idx": exploit_idx,
                    "language": language,
                    "original_errors": errors,
                    "last_errors": errors,
                    "attempts": 0,
                    "skip_reason": mismatch,
                    "flagged_at": datetime.now().isoformat(),
                })
                continue

            items_to_repair.append(item)

        # ── Phase B: Parallel LLM repair (I/O-bound) ──
        max_repair_workers = cfg.get("max_repair_workers", 3)
        from concurrent.futures import ThreadPoolExecutor, as_completed

        def _run_repair(item: Dict[str, Any]) -> Dict[str, Any]:
            """Run a single repair loop — safe to call from a worker thread."""
            return {
                "item": item,
                "result": self._repair_loop(
                    original_code=item["content"],
                    language=item["language"],
                    errors=item["errors"],
                    max_attempts=max_attempts,
                    api_endpoint=api_endpoint,
                    model=model,
                    api_timeout=api_timeout,
                    num_ctx=num_ctx,
                    max_poc_chars=max_poc_chars,
                    temperature=temperature,
                    syntax_validator=syntax_validator,
                    sv_cfg=sv_cfg,
                    provider=provider,
                    openai_model=openai_model,
                    openai_api_key=openai_api_key,
                ),
            }

        self.logger.info(
            "Starting LLM repair for %d PoC(s) with %d worker(s) …",
            len(items_to_repair), max_repair_workers,
        )

        repair_results: List[Dict[str, Any]] = []
        with ThreadPoolExecutor(max_workers=max_repair_workers) as executor:
            futures = {
                executor.submit(_run_repair, item): item
                for item in items_to_repair
            }
            for future in as_completed(futures):
                try:
                    repair_results.append(future.result())
                except Exception as exc:
                    failed_item = futures[future]
                    key = f"{failed_item['cve_id']}:{failed_item['exploit_idx']}"
                    self.logger.error("Repair thread failed for %s: %s", key, exc)
                    repair_results.append({
                        "item": failed_item,
                        "result": {
                            "repaired": False,
                            "fixed_code": None,
                            "attempts": 0,
                            "last_errors": failed_item["errors"],
                            "attempt_history": [],
                        },
                    })

        # ── Phase C: Apply results (sequential) ──
        for rr in repair_results:
            item = rr["item"]
            result = rr["result"]
            cve_id = item["cve_id"]
            exploit_idx = item["exploit_idx"]
            original_code = item["content"]
            language = item["language"]
            errors = item["errors"]
            key = f"{cve_id}:{exploit_idx}"

            repair_report[key] = result

            if result["repaired"]:
                repaired_count += 1
                fixed_code = result["fixed_code"]

                # ── Update the dataset in-place so OutputGenerator sees the fix
                entry = dataset.cves.get(cve_id)
                if entry and exploit_idx < len(entry.exploits):
                    entry.exploits[exploit_idx].source_code_content = fixed_code
                    if entry.exploits[exploit_idx].language in ("unknown", "text"):
                        entry.exploits[exploit_idx].language = language

                # ── Update syntax_results so OutputGenerator no longer flags it
                if key in syntax_results:
                    syntax_results[key]["is_valid"] = True
                    syntax_results[key]["needs_manual_review"] = False
                    syntax_results[key]["errors"] = []
                    syntax_results[key].setdefault("warnings", []).append(
                        "llm_repaired"
                    )

                # ── Save the repaired PoC directly to exploits/
                ext = get_file_extension_for_language(language)
                poc_filename = f"{cve_id}{ext}" if exploit_idx == 0 else f"{cve_id}_poc{exploit_idx}{ext}"
                poc_path = poc_dir / poc_filename
                try:
                    poc_path.write_text(fixed_code, encoding="utf-8")
                    self.logger.info("Saved repaired PoC → %s", poc_path)
                except IOError as exc:
                    self.logger.warning(
                        "Failed to save repaired PoC %s: %s", key, exc
                    )

                # ── Remove stale manual_supervision/ files for this PoC ──
                if manual_dir.exists():
                    stale_candidates = [
                        manual_dir / f"{cve_id}_{exploit_idx}{ext}",
                        manual_dir / f"{cve_id}_{exploit_idx}.validation.json",
                    ]
                    stale_candidates.extend(manual_dir.glob(f"{cve_id}{ext}"))
                    stale_candidates.extend(manual_dir.glob(f"{cve_id}_syntax_report.txt"))
                    stale_candidates.extend(manual_dir.glob(f"{cve_id}.ok"))
                    for stale in stale_candidates:
                        stale_path = Path(stale)
                        if stale_path.exists():
                            try:
                                stale_path.unlink()
                                self.logger.info(
                                    "Removed stale manual supervision file: %s",
                                    stale_path,
                                )
                            except OSError as exc:
                                self.logger.warning(
                                    "Could not remove %s: %s", stale_path, exc
                                )
            else:
                failed_count += 1
                manual_queue.append({
                    "cve_id": cve_id,
                    "exploit_idx": exploit_idx,
                    "language": language,
                    "original_errors": errors,
                    "last_errors": result["last_errors"],
                    "attempts": result["attempts"],
                    "flagged_at": datetime.now().isoformat(),
                })

                if manual_dir.exists():
                    ext = get_file_extension_for_language(language)
                    src_dest = manual_dir / f"{cve_id}_{exploit_idx}{ext}"
                    meta_dest = manual_dir / f"{cve_id}_{exploit_idx}.validation.json"
                    try:
                        src_dest.write_text(original_code, encoding="utf-8")
                        meta_dest.write_text(json.dumps({
                            "is_valid": False,
                            "language": language,
                            "errors": result.get("last_errors", errors),
                            "warnings": [
                                f"llm_repair_failed_after_{result['attempts']}_attempts"
                            ],
                            "needs_manual_review": True,
                        }, indent=2), encoding="utf-8")
                        self.logger.debug(
                            "Flagged failed repair for manual review: %s", src_dest,
                        )
                    except Exception as exc:
                        self.logger.warning(
                            "Could not flag %s for manual review: %s", cve_id, exc,
                        )

        # ── Persist reports ──
        self._save_report(repair_report, report_path)
        self._save_manual_queue(manual_queue, manual_queue_path)

        self.logger.info(
            "PoC Repair complete: %d repaired, %d still invalid (flagged for manual review).",
            repaired_count, failed_count,
        )

        context["poc_repair_report"] = repair_report
        return context

    # ------------------------------------------------------------------
    # Collect invalid PoCs from syntax results
    # ------------------------------------------------------------------

    @staticmethod
    def _collect_invalid_pocs(
        syntax_results: Dict[str, Dict],
        dataset: Dataset,
        allow_without_commit: bool = True,
    ) -> List[Dict[str, Any]]:
        """Return a list of dicts describing each invalid PoC.

        Only includes PoCs that were actually flagged for manual review
        by the syntax validator.  When *allow_without_commit* is False
        (which mirrors ``syntax_validator.allow_manual_without_commit``),
        CVEs without associated commits are skipped — exactly as Module 5
        does when deciding which files to copy to ``manual_supervision/``.
        """
        invalid: List[Dict[str, Any]] = []

        for key, sr in syntax_results.items():
            if sr.get("is_valid"):
                continue
            if not sr.get("needs_manual_review"):
                continue

            parts = key.split(":", 1)
            if len(parts) != 2:
                continue
            cve_id, idx_str = parts
            try:
                exploit_idx = int(idx_str)
            except ValueError:
                continue

            entry = dataset.cves.get(cve_id)
            if not entry or exploit_idx >= len(entry.exploits):
                continue

            # Mirror Module 5's commit-gating: skip CVEs without commits
            # when the config says so (allow_manual_without_commit=false).
            if not allow_without_commit and not entry.has_commits:
                continue

            exploit = entry.exploits[exploit_idx]
            content = exploit.source_code_content
            if not content:
                continue

            language = sr.get("language", exploit.language)
            errors = sr.get("errors", [])

            # Skip PoCs whose only error is "unrecognised_language" — no point
            # in asking the LLM to fix something we can't validate.
            if errors == ["unrecognised_language"]:
                continue

            invalid.append({
                "cve_id": cve_id,
                "exploit_idx": exploit_idx,
                "content": content,
                "language": language,
                "errors": errors,
            })

        return invalid

    # ------------------------------------------------------------------
    # Language mismatch detection
    # ------------------------------------------------------------------

    @staticmethod
    def _detect_language_mismatch(content: str, language: str) -> Optional[str]:
        """Detect obvious language misidentification.

        Returns a warning string if the content is clearly NOT the labelled
        language, or None if it looks plausible.  This prevents the LLM from
        wasting attempts trying to make prose/shell into valid C.
        """
        if language != "c":
            return None

        lines = content.split("\n")
        total = len(lines)
        if total < 5:
            return None

        c_anchors = 0
        prose_lines = 0
        shell_lines = 0
        for line in lines:
            s = line.strip()
            if not s:
                continue
            # Strong C indicators
            if re.match(r"^#\s*(include|define|if|ifdef|ifndef|elif|else|endif|pragma)\b", s):
                c_anchors += 1
            elif re.match(r"^(typedef|struct|union|enum|static|extern|void|char|int|long|float|double|unsigned|signed)\b", s):
                c_anchors += 1
            elif re.match(r"^(return|for|while|if|else|switch|case|break|continue)\b", s):
                c_anchors += 1
            # Shell indicators
            elif re.match(r"^\$\s", s) or re.match(r"^(mkdir|ln |rm |ls |cat |exec |chmod |export )\b", s):
                shell_lines += 1
            # Prose indicators (5+ words, no code punctuation)
            elif not any(ch in s for ch in (";", "{", "}", "(", ")", "#")):
                words = re.findall(r"[A-Za-z]+", s)
                if len(words) >= 6:
                    prose_lines += 1

        non_blank = sum(1 for l in lines if l.strip())
        if non_blank == 0:
            return None

        # If <5% of lines look like C and >30% look like prose/shell, it's mislabeled
        c_ratio = c_anchors / non_blank
        prose_shell_ratio = (prose_lines + shell_lines) / non_blank

        if c_ratio < 0.05 and prose_shell_ratio > 0.30:
            return (
                f"Content appears to be prose/shell (C anchors: {c_ratio:.0%}, "
                f"prose+shell: {prose_shell_ratio:.0%}) — likely mislabeled as C"
            )
        return None

    # ------------------------------------------------------------------
    # Core LLM repair loop
    # ------------------------------------------------------------------

    def _repair_loop(
        self,
        *,
        original_code: str,
        language: str,
        errors: List[str],
        max_attempts: int,
        api_endpoint: str,
        model: str,
        api_timeout: int,
        num_ctx: int = 0,
        max_poc_chars: int = 0,
        temperature: float = 0.2,
        syntax_validator: "SyntaxValidator",
        sv_cfg: Dict,
        provider: str = "ollama",
        openai_model: str = "",
        openai_api_key: str = "",
    ) -> Dict[str, Any]:
        """Try up to *max_attempts* LLM repairs, re-validating each time.

        Returns a dict with keys: repaired, fixed_code, attempts, last_errors,
        and attempt_history.
        """
        current_errors = list(errors)
        previous_attempt: Optional[str] = None
        attempt_history: List[Dict[str, Any]] = []

        # Truncate PoC code to avoid exceeding the model's context window.
        # The truncation notice lets the LLM know the file was cut, so it
        # doesn't hallucinate a complete file from a partial one.
        if max_poc_chars and len(original_code) > max_poc_chars:
            truncated_chars = len(original_code) - max_poc_chars
            prompt_code = (
                original_code[:max_poc_chars]
                + f"\n# ... [{truncated_chars} characters truncated — fix only what is shown]"
            )
            self.logger.debug(
                "  PoC truncated from %d to %d chars for prompt.",
                len(original_code), max_poc_chars,
            )
        else:
            prompt_code = original_code

        for attempt in range(1, max_attempts + 1):
            self.logger.info("  Attempt %d/%d …", attempt, max_attempts)

            # Build the prompt
            if attempt == 1:
                user_prompt = _build_repair_prompt(prompt_code, language, current_errors)
                system_prompt = SYSTEM_PROMPT
            else:
                user_prompt = _build_retry_prompt(
                    prompt_code,
                    previous_attempt or "",
                    language,
                    current_errors,
                    attempt,
                )
                system_prompt = RETRY_SYSTEM_PROMPT

            # Stagger temperature: base on attempt 1, +0.1 per retry (cap 0.5)
            # This encourages slight exploration without hallucination.
            attempt_temperature = min(temperature + (attempt - 1) * 0.1, 0.5)

            # Call the LLM
            raw_response, api_meta = self._call_llm(
                api_endpoint=api_endpoint,
                model=model,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                timeout=api_timeout,
                temperature=attempt_temperature,
                num_ctx=num_ctx,
                provider=provider,
                openai_model=openai_model,
                openai_api_key=openai_api_key,
            )

            if raw_response is None:
                self.logger.warning(
                    "  LLM returned no response on attempt %d.", attempt
                )
                attempt_history.append({
                    "attempt": attempt,
                    "api_success": False,
                    "api_error": api_meta.get("error"),
                })
                continue

            # Clean the LLM output
            cleaned_code = strip_markdown_fences(raw_response)
            cleaned_code = _strip_llm_preamble(cleaned_code, language)
            if not cleaned_code.strip():
                self.logger.warning("  LLM returned empty code on attempt %d.", attempt)
                attempt_history.append({
                    "attempt": attempt,
                    "api_success": True,
                    "validation_passed": False,
                    "errors": ["empty_response"],
                })
                continue

            # ── Re-validate using Module 5 logic ──
            vr: SyntaxValidationResult = syntax_validator._validate(
                cleaned_code, language, sv_cfg
            )

            attempt_history.append({
                "attempt": attempt,
                "api_success": True,
                "validation_passed": vr.is_valid,
                "errors": vr.errors,
                "warnings": vr.warnings,
            })

            if vr.is_valid:
                self.logger.info("  ✓ Repair succeeded on attempt %d.", attempt)
                return {
                    "repaired": True,
                    "fixed_code": cleaned_code,
                    "attempts": attempt,
                    "last_errors": [],
                    "attempt_history": attempt_history,
                }

            # Prepare for next iteration
            self.logger.info(
                "  ✗ Still invalid (%d error(s)), retrying …", len(vr.errors)
            )
            current_errors = vr.errors
            previous_attempt = cleaned_code

        # Exhausted all attempts
        self.logger.warning("  All %d repair attempts exhausted.", max_attempts)
        return {
            "repaired": False,
            "fixed_code": None,
            "attempts": max_attempts,
            "last_errors": current_errors,
            "attempt_history": attempt_history,
        }

    # ------------------------------------------------------------------
    # LLM API call (matches Phase 2 Ollama pattern)
    # ------------------------------------------------------------------

    def _call_llm(
        self,
        *,
        api_endpoint: str,
        model: str,
        system_prompt: str,
        user_prompt: str,
        timeout: int,
        temperature: float,
        num_ctx: int = 0,
        max_retries: int = 2,
        retry_delay: int = 5,
        provider: str = "ollama",
        openai_model: str = "",
        openai_api_key: str = "",
    ) -> Tuple[Optional[str], Dict[str, Any]]:
        """Call the configured LLM backend (Ollama or OpenAI) with retry logic.

        Dispatches to the Ollama-compatible implementation or to the OpenAI
        client based on *provider*.  Mirrors ``call_llm_api`` in
        ``patch_generator.py`` (Phase 2 of the master pipeline).
        """
        if provider == "openai":
            return self._call_openai_api(
                model=openai_model,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                timeout=timeout,
                temperature=temperature,
                max_retries=max_retries,
                retry_delay=retry_delay,
                openai_api_key=openai_api_key,
            )
        return self._call_ollama_api(
            api_endpoint=api_endpoint,
            model=model,
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            timeout=timeout,
            temperature=temperature,
            num_ctx=num_ctx,
            max_retries=max_retries,
            retry_delay=retry_delay,
        )

    def _call_ollama_api(
        self,
        *,
        api_endpoint: str,
        model: str,
        system_prompt: str,
        user_prompt: str,
        timeout: int,
        temperature: float,
        num_ctx: int = 0,
        max_retries: int = 2,
        retry_delay: int = 5,
    ) -> Tuple[Optional[str], Dict[str, Any]]:
        """Call the Ollama-compatible local server API with retry logic."""
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        options: Dict[str, Any] = {"temperature": temperature}
        if num_ctx:
            options["num_ctx"] = num_ctx

        payload = {
            "model": model,
            "messages": messages,
            "stream": False,
            "options": options,
        }

        # Rough token estimate (~4 chars/token for code).
        total_chars = len(system_prompt) + len(user_prompt)
        est_prompt_tokens = total_chars // 4
        effective_ctx = num_ctx or 4096
        if est_prompt_tokens > effective_ctx * 0.8:
            self.logger.warning(
                "  Prompt may exceed context window (~%d tokens vs num_ctx=%d). "
                "Increase poc_repair.num_ctx or reduce prompt size.",
                est_prompt_tokens, effective_ctx,
            )
        else:
            self.logger.debug(
                "  Prompt size: ~%d tokens (num_ctx=%d)",
                est_prompt_tokens, effective_ctx,
            )

        metadata: Dict[str, Any] = {
            "model": model,
            "provider": "ollama",
            "timestamp_start": datetime.now().isoformat(),
            "payload_size": len(json.dumps(payload)),
            "est_prompt_tokens": est_prompt_tokens,
            "retries": 0,
            "success": False,
            "error": None,
        }

        for attempt in range(max_retries):
            try:
                self.logger.debug(
                    "  API call attempt %d/%d (model=%s)",
                    attempt + 1, max_retries, model,
                )
                response = requests.post(
                    api_endpoint, json=payload, timeout=timeout
                )
                response.raise_for_status()

                result = response.json()
                content = result.get("message", {}).get("content", "")

                metadata["timestamp_end"] = datetime.now().isoformat()
                metadata["success"] = True
                metadata["retries"] = attempt
                metadata["prompt_tokens"] = result.get("prompt_eval_count")
                metadata["response_tokens"] = result.get("eval_count")
                metadata["total_duration"] = result.get("total_duration")

                self._check_gpu_status(api_endpoint, model)

                return content, metadata

            except requests.exceptions.Timeout:
                self.logger.warning(
                    "  Timeout on API attempt %d/%d", attempt + 1, max_retries
                )
                metadata["error"] = f"Timeout after {timeout}s"
                metadata["retries"] = attempt + 1

            except requests.exceptions.RequestException as exc:
                self.logger.warning(
                    "  Request error on API attempt %d/%d: %s",
                    attempt + 1, max_retries, exc,
                )
                metadata["error"] = str(exc)
                metadata["retries"] = attempt + 1

            except json.JSONDecodeError as exc:
                self.logger.error("  Invalid JSON from LLM API: %s", exc)
                metadata["error"] = f"Invalid JSON: {exc}"
                metadata["retries"] = attempt + 1

            if attempt < max_retries - 1:
                self.logger.info("  Retrying in %d s …", retry_delay)
                time.sleep(retry_delay)

        metadata["timestamp_end"] = datetime.now().isoformat()
        self.logger.error(
            "All %d API attempts failed for model %s", max_retries, model
        )
        return None, metadata

    def _call_openai_api(
        self,
        *,
        model: str,
        system_prompt: str,
        user_prompt: str,
        timeout: int,
        temperature: float,
        max_retries: int = 2,
        retry_delay: int = 5,
        openai_api_key: str = "",
    ) -> Tuple[Optional[str], Dict[str, Any]]:
        """Call the OpenAI API with retry logic."""
        try:
            from openai import OpenAI, APIError, APIConnectionError, APITimeoutError, RateLimitError
        except ImportError:
            raise RuntimeError(
                "The 'openai' package is required for provider='openai'. "
                "Install it with: pip install openai>=1.0.0"
            )

        if not openai_api_key:
            raise RuntimeError(
                "OpenAI API key not configured. Set the OPENAI_API_KEY environment "
                "variable or poc_repair.openai_api_key in the config file."
            )

        client = OpenAI(api_key=openai_api_key, timeout=timeout)
        metadata: Dict[str, Any] = {
            "model": model,
            "provider": "openai",
            "timestamp_start": datetime.now().isoformat(),
            "retries": 0,
            "success": False,
            "error": None,
        }

        for attempt in range(max_retries):
            try:
                self.logger.debug(
                    "  OpenAI API call attempt %d/%d (model=%s)",
                    attempt + 1, max_retries, model,
                )
                completion = client.chat.completions.create(
                    model=model,
                    messages=[
                        {"role": "system", "content": system_prompt},
                        {"role": "user", "content": user_prompt},
                    ],
                    temperature=temperature,
                )
                content = completion.choices[0].message.content or ""
                usage = completion.usage
                metadata["timestamp_end"] = datetime.now().isoformat()
                metadata["success"] = True
                metadata["retries"] = attempt
                metadata["prompt_tokens"] = usage.prompt_tokens if usage else None
                metadata["response_tokens"] = usage.completion_tokens if usage else None
                metadata["total_tokens"] = usage.total_tokens if usage else None
                self.logger.debug("  OpenAI API call successful for model %s", model)
                return content, metadata

            except (APITimeoutError, APIConnectionError) as exc:
                self.logger.warning(
                    "  OpenAI connection/timeout on attempt %d/%d: %s",
                    attempt + 1, max_retries, exc,
                )
                metadata["error"] = str(exc)
                metadata["retries"] = attempt + 1

            except RateLimitError as exc:
                self.logger.warning(
                    "  OpenAI rate limit on attempt %d/%d: %s",
                    attempt + 1, max_retries, exc,
                )
                metadata["error"] = str(exc)
                metadata["retries"] = attempt + 1

            except APIError as exc:
                self.logger.error(
                    "  OpenAI API error on attempt %d/%d: %s",
                    attempt + 1, max_retries, exc,
                )
                metadata["error"] = str(exc)
                metadata["retries"] = attempt + 1

            if attempt < max_retries - 1:
                self.logger.info("  Retrying in %d s …", retry_delay)
                time.sleep(retry_delay)

        metadata["timestamp_end"] = datetime.now().isoformat()
        self.logger.error(
            "All %d OpenAI API attempts failed for model %s", max_retries, model
        )
        return None, metadata

    # ------------------------------------------------------------------
    # API health check + GPU/CPU detection
    # ------------------------------------------------------------------

    def _check_api_health(
        self,
        api_endpoint: str,
        model: str,
        *,
        provider: str = "ollama",
        openai_api_key: str = "",
        openai_model: str = "",
    ) -> bool:
        """Quick health check before processing.

        For the "openai" provider, validates that an API key is set.
        For the "ollama" provider, uses GET /api/tags (fast, no inference).
        """
        if provider == "openai":
            if not openai_api_key:
                self.logger.error(
                    "✗ OpenAI API key not configured. Set the OPENAI_API_KEY "
                    "environment variable or poc_repair.openai_api_key in config."
                )
                return False
            self.logger.info(
                "✓ OpenAI provider configured (model: %s)", openai_model
            )
            return True

        # --- Ollama health check ---
        from urllib.parse import urlparse, urlunparse

        parsed = urlparse(api_endpoint)
        base_url = urlunparse((parsed.scheme, parsed.netloc, "/api/tags", "", "", ""))
        try:
            resp = requests.get(base_url, timeout=10)
            resp.raise_for_status()
            self.logger.info(
                "✓ LLM API health check passed (%s reachable, %d models listed)",
                api_endpoint,
                len(resp.json().get("models", [])),
            )
            # Best-effort GPU check — model may not be loaded yet (Ollama
            # lazy-loads on first inference), so we also check after the first
            # successful call in _call_llm.
            self._check_gpu_status(api_endpoint, model)
            return True
        except requests.exceptions.Timeout:
            self.logger.error("✗ LLM API health check timed out (GET %s).", base_url)
            return False
        except requests.exceptions.ConnectionError:
            self.logger.error(
                "✗ Cannot connect to LLM API at %s", api_endpoint
            )
            return False
        except Exception as exc:
            self.logger.error("✗ LLM API health check failed: %s", exc)
            return False

    def _check_gpu_status(self, api_endpoint: str, model: str) -> None:
        """Check whether the model is GPU- or CPU-accelerated via /api/ps.

        Ollama's /api/ps lists currently loaded runners.  Each entry includes:
          • ``size``      – total model size in bytes
          • ``size_vram`` – bytes currently held in GPU VRAM (0 ↔ CPU-only)

        If the model is not yet loaded (lazy Ollama behaviour), the list will
        be empty and we defer to the post-inference check in ``_call_llm``.
        This method is idempotent: it sets ``self._gpu_status_logged = True``
        after the first conclusive check so subsequent calls are no-ops.
        """
        if getattr(self, "_gpu_status_logged", False):
            return

        from urllib.parse import urlparse, urlunparse

        parsed = urlparse(api_endpoint)
        ps_url = urlunparse((parsed.scheme, parsed.netloc, "/api/ps", "", "", ""))
        try:
            resp = requests.get(ps_url, timeout=5)
            resp.raise_for_status()
            running = resp.json().get("models", [])

            # Match by model name prefix (ignore tag suffix for flexibility)
            model_base = model.split(":")[0].lower()
            for entry in running:
                if model_base in entry.get("name", "").lower():
                    size_vram = entry.get("size_vram", 0)
                    size_total = entry.get("size", 0)
                    self._gpu_status_logged = True

                    if size_vram == 0:
                        self.logger.warning(
                            "⚠ WARNING: Model '%s' is running on CPU only "
                            "(size_vram=0). Inference will be significantly "
                            "slower than GPU. Check that the Ollama server has "
                            "CUDA/ROCm drivers installed and the container has "
                            "GPU access (e.g. --gpus all).",
                            model,
                        )
                    elif size_total > 0 and size_vram < size_total:
                        pct = size_vram / size_total * 100
                        self.logger.warning(
                            "⚠ WARNING: Model '%s' is only partially "
                            "GPU-accelerated (%.0f%% in VRAM, %.1f/%.1f GiB). "
                            "Some layers are running on CPU — consider a "
                            "smaller model or a GPU with more VRAM.",
                            model, pct,
                            size_vram / 1024 ** 3,
                            size_total / 1024 ** 3,
                        )
                    else:
                        self.logger.info(
                            "✓ Model '%s' is fully GPU-accelerated "
                            "(%.1f GiB in VRAM).",
                            model, size_vram / 1024 ** 3,
                        )
                    return  # conclusive result found

            # Model not loaded yet — will re-check after first inference
            self.logger.debug(
                "GPU status check: model '%s' not yet loaded in /api/ps — "
                "will re-check after first inference.",
                model,
            )

        except Exception as exc:
            self.logger.debug("GPU status check skipped (%s).", exc)

    def _wait_for_gpu(self, api_endpoint: str, timeout: int = 120,
                      poll_interval: int = 15) -> bool:
        """Poll /api/ps until GPU VRAM is free or *timeout* expires.

        Returns True if GPU is available, False if the wait timed out.
        """
        from urllib.parse import urlparse, urlunparse

        parsed = urlparse(api_endpoint)
        ps_url = urlunparse((parsed.scheme, parsed.netloc, "/api/ps", "", "", ""))
        start = time.time()

        while True:
            try:
                resp = requests.get(ps_url, timeout=10)
                resp.raise_for_status()
                running = resp.json().get("models", [])
                total_vram = sum(e.get("size_vram", 0) for e in running)
                if not running or total_vram == 0:
                    return True
            except Exception:
                return True  # can't reach /api/ps — assume available

            elapsed = time.time() - start
            if elapsed >= timeout:
                return False

            names = [e.get("name", "?") for e in running]
            vram_gib = total_vram / (1024 ** 3)
            self.logger.info(
                "GPU busy (%.1f GiB VRAM used by %s) — waiting (%d/%d s) …",
                vram_gib, ", ".join(names), int(elapsed), timeout,
            )
            time.sleep(poll_interval)

    def _preload_model(self, api_endpoint: str, model: str,
                       timeout: int = 300, poll_interval: int = 10) -> bool:
        """Trigger Ollama lazy-loading and wait until *model* is in GPU VRAM.

        Ollama loads model weights on the first inference request.  For large
        models this cold-start can take several minutes, causing the first
        real API call to time out.  This method sends a zero-effort
        ``/api/generate`` request (no prompt) to trigger loading, then polls
        ``/api/ps`` until the model's ``size_vram`` is non-zero.

        Returns True when the model is confirmed in VRAM, False on timeout.
        """
        from urllib.parse import urlparse, urlunparse
        import threading

        parsed = urlparse(api_endpoint)
        ps_url = urlunparse((parsed.scheme, parsed.netloc, "/api/ps", "", "", ""))
        gen_url = urlunparse((parsed.scheme, parsed.netloc, "/api/generate", "", "", ""))

        self.logger.info("Pre-loading model '%s' into GPU VRAM …", model)

        # Fire the preload POST in a background thread so we can poll
        # /api/ps independently without blocking on the response.
        def _trigger() -> None:
            try:
                requests.post(
                    gen_url,
                    json={"model": model, "keep_alive": "10m"},
                    timeout=timeout,
                )
            except Exception:
                pass  # expected — loading large model may take a while

        threading.Thread(target=_trigger, daemon=True).start()

        model_base = model.split(":")[0].lower()
        start = time.time()
        while True:
            try:
                resp = requests.get(ps_url, timeout=5)
                resp.raise_for_status()
                for entry in resp.json().get("models", []):
                    if model_base in entry.get("name", "").lower():
                        size_vram = entry.get("size_vram", 0)
                        if size_vram > 0:
                            self.logger.info(
                                "✓ Model '%s' ready in GPU VRAM (%.1f GiB).",
                                model, size_vram / 1024 ** 3,
                            )
                            return True
            except Exception:
                pass

            elapsed = time.time() - start
            if elapsed >= timeout:
                self.logger.warning(
                    "Model '%s' not in GPU VRAM after %d s.", model, int(elapsed)
                )
                return False

            self.logger.debug(
                "Waiting for '%s' to load … (%d/%d s)", model, int(elapsed), timeout
            )
            time.sleep(poll_interval)

    # ------------------------------------------------------------------
    # Report / manual-queue persistence
    # ------------------------------------------------------------------

    @staticmethod
    def _save_report(report: Dict[str, Any], path: Path) -> None:
        summary = {
            "generated_at": datetime.now().isoformat(),
            "total_processed": len(report),
            "repaired": sum(1 for r in report.values() if r.get("repaired")),
            "failed": sum(1 for r in report.values() if not r.get("repaired")),
            "details": report,
        }
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(summary, indent=2), encoding="utf-8")
            logger.info("PoC repair report saved → %s", path)
        except IOError as exc:
            logger.error("Failed to save repair report: %s", exc)

    @staticmethod
    def _save_manual_queue(queue: List[Dict[str, Any]], path: Path) -> None:
        if not queue:
            return
        # Append to existing queue if present
        existing: List[Dict[str, Any]] = []
        if path.exists():
            try:
                existing = json.loads(path.read_text(encoding="utf-8"))
                if not isinstance(existing, list):
                    existing = []
            except (json.JSONDecodeError, IOError):
                existing = []

        merged = existing + queue
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(merged, indent=2), encoding="utf-8")
            logger.info(
                "Manual review queue updated (%d new item(s)) → %s",
                len(queue), path,
            )
        except IOError as exc:
            logger.error("Failed to save manual review queue: %s", exc)
