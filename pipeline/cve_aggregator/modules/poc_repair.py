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

# --- Language-specific guidance injected into prompts ---
_LANG_GUIDANCE: Dict[str, str] = {
    "c": (
        "C-SPECIFIC CORRUPTION PATTERNS TO FIX:\n"
        "  • Preprocessor directives missing the leading '#' (e.g. 'include <stdio.h>' → '#include <stdio.h>')\n"
        "  • Bare numeric tokens on their own line (OCR/scraping noise) — comment them out with '//'\n"
        "  • Plain-English prose lines embedded in code — comment them out with '//'\n"
        "  • Unbalanced braces or parentheses from truncated scraping\n"
        "  • Missing 'int main()' or function return types stripped during extraction\n"
        "  DO NOT add #include statements that were not in the original to fix missing-header errors."
    ),
    "python": (
        "PYTHON-SPECIFIC CORRUPTION PATTERNS TO FIX:\n"
        "  • Python 2 syntax that is not valid Python 3 (print statement, except E, e: syntax)\n"
        "  • Indentation errors caused by HTML-to-text conversion (tabs vs spaces mixed)\n"
        "  • Prose/description lines inserted between code sections — comment them out with '#'\n"
        "  • Truncated string literals or unclosed parentheses from line-wrap during scraping\n"
        "  • Missing colons at the end of def/class/if/for/while lines (stripped by scrapers)"
    ),
    "shell": (
        "SHELL-SPECIFIC CORRUPTION PATTERNS TO FIX:\n"
        "  • Missing shebang line (add '#!/bin/bash' or '#!/bin/sh' if absent)\n"
        "  • Prose/description lines not commented out — prefix them with '#'\n"
        "  • Broken heredoc syntax from scraping (EOF markers not on their own line)\n"
        "  • Unmatched quotes or unclosed subshell expressions '$(...)'\n"
        "  • Variable assignments with spaces around '=' (bash requires no spaces)"
    ),
    "ruby": (
        "RUBY-SPECIFIC CORRUPTION PATTERNS TO FIX:\n"
        "  • Prose lines without comment markers — prefix with '#'\n"
        "  • Missing 'end' keywords from truncated scraping\n"
        "  • Require statements with incorrect string quoting from HTML entities\n"
        "  • Unbalanced do/end or begin/rescue/end blocks"
    ),
    "perl": (
        "PERL-SPECIFIC CORRUPTION PATTERNS TO FIX:\n"
        "  • Missing 'use strict;' / 'use warnings;' is OK — do not add them\n"
        "  • Prose lines not commented — prefix with '#'\n"
        "  • Broken heredoc markers\n"
        "  • Missing semicolons at end of statements stripped during scraping"
    ),
    "php": (
        "PHP-SPECIFIC CORRUPTION PATTERNS TO FIX:\n"
        "  • Missing '<?php' opening tag — add if absent\n"
        "  • Prose lines inside code blocks — comment out with '//'\n"
        "  • HTML entity artefacts (&lt; &gt; &amp;) that should be < > &\n"
        "  • Missing semicolons at end of PHP statements"
    ),
}

_DEFAULT_LANG_GUIDANCE = (
    "COMMON SCRAPING CORRUPTION PATTERNS TO FIX:\n"
    "  • Prose/description lines embedded in code — comment them out\n"
    "  • Truncated lines or missing closing delimiters from line-wrap\n"
    "  • HTML entity artefacts (&lt; &gt; &amp;) that should be < > &\n"
    "  • Unbalanced brackets or block delimiters"
)

SYSTEM_PROMPT = """\
You are a senior security researcher and expert programmer.\
 Your task is to repair the SYNTAX errors in a Proof-of-Concept (PoC) exploit\
 script that was automatically scraped from ExploitDB.

CONTEXT — WHY THESE FILES HAVE SYNTAX ERRORS:
These PoC scripts were scraped from web pages and PDF files.\
 During extraction, the following corruption routinely occurs:
  • Prose/description text is mixed into the source code without comment markers.
  • Preprocessor directives lose their leading character (e.g. '#' in C).
  • Lines get truncated, merged, or duplicated by HTML-to-text converters.
  • HTML entities (&lt; &gt; &amp;) replace real characters.
  • Indentation is garbled (tabs replaced by spaces inconsistently).
  • Numeric labels or line numbers from listings are left as bare tokens.

YOUR JOB:
  1. Identify and fix the SYNTAX errors reported by the validator.
  2. Treat the EXPLOIT LOGIC as sacred — never change what the script does.
  3. Do NOT rewrite, optimise, or modernise the code beyond what is needed for syntax.
  4. Do NOT add imports, headers, or dependencies not originally in the script.
  5. Comment out (do NOT delete) any prose lines that cannot be valid code.
  6. Return ONLY the complete, corrected source code — no markdown fences,\
 no explanations, no preamble.

OUTPUT FORMAT:
Start directly with the first line of the source file (e.g. '#!/usr/bin/env python3',\
 '#include <stdio.h>', '<?php', etc.).\
 Do NOT wrap the code in triple backticks or any other delimiters.\
"""

RETRY_SYSTEM_PROMPT = """\
You are a senior security researcher and expert programmer.\
 Your previous attempt to repair a scraped PoC exploit script FAILED syntax validation.\
 You must analyse your mistake and produce a corrected version.

CONTEXT — WHY THESE FILES HAVE SYNTAX ERRORS:
These PoC scripts were scraped from ExploitDB web pages and PDFs.\
 Common corruption: prose lines mixed into code without comment markers,\
 missing preprocessor '#' characters, truncated lines, HTML entities,\
 garbled indentation, and bare numeric line-number artefacts.

YOUR JOB:
  1. Study BOTH the original errors AND the new errors from your previous attempt.
  2. Your previous repair introduced NEW errors or failed to fix the original ones — fix these.
  3. Treat the EXPLOIT LOGIC as sacred — never change what the script does.
  4. Do NOT add imports, headers, or dependencies not originally in the script.
  5. Comment out (do NOT delete) any prose lines that cannot be valid code.
  6. Return ONLY the complete, corrected source code — no markdown fences,\
 no explanations, no preamble.

OUTPUT FORMAT:
Start directly with the first line of the source file.\
 Do NOT wrap the code in triple backticks or any other delimiters.\
"""


def _build_repair_prompt(
    poc_code: str,
    language: str,
    errors: List[str],
) -> str:
    """Build the initial user prompt for PoC repair.

    Includes language-specific guidance about ExploitDB scraping artefacts
    and the exact validator error messages to target.
    """
    lang_guidance = _LANG_GUIDANCE.get(language, _DEFAULT_LANG_GUIDANCE)
    error_block = "\n".join(f"  [{i+1}] {e}" for i, e in enumerate(errors))

    return (
        f"LANGUAGE: {language.upper()}\n\n"
        f"{lang_guidance}\n\n"
        f"══════════════════════════════════════════════════════════\n"
        f"SYNTAX ERRORS REPORTED BY VALIDATOR:\n"
        f"══════════════════════════════════════════════════════════\n"
        f"{error_block}\n\n"
        f"══════════════════════════════════════════════════════════\n"
        f"POC SOURCE CODE (scraped — may contain corruption):\n"
        f"══════════════════════════════════════════════════════════\n"
        f"{poc_code}\n"
        f"══════════════════════════════════════════════════════════\n\n"
        f"TASK: Fix the {len(errors)} syntax error(s) listed above while\n"
        f"preserving all exploit logic.\n"
        f"Return the complete corrected script — nothing else."
    )


def _build_retry_prompt(
    original_code: str,
    previous_attempt: str,
    language: str,
    new_errors: List[str],
    attempt_number: int,
) -> str:
    """Build a retry prompt that surfaces the failed attempt and new errors.

    Forces the LLM to reason about what went wrong before producing a new
    version, rather than blindly regenerating.
    """
    lang_guidance = _LANG_GUIDANCE.get(language, _DEFAULT_LANG_GUIDANCE)
    error_block = "\n".join(f"  [{i+1}] {e}" for i, e in enumerate(new_errors))

    return (
        f"RETRY ATTEMPT #{attempt_number} — LANGUAGE: {language.upper()}\n\n"
        f"{lang_guidance}\n\n"
        f"══════════════════════════════════════════════════════════\n"
        f"YOUR PREVIOUS REPAIR ATTEMPT (STILL INVALID):\n"
        f"══════════════════════════════════════════════════════════\n"
        f"{previous_attempt}\n\n"
        f"══════════════════════════════════════════════════════════\n"
        f"NEW SYNTAX ERRORS FROM YOUR PREVIOUS ATTEMPT:\n"
        f"══════════════════════════════════════════════════════════\n"
        f"{error_block}\n\n"
        f"══════════════════════════════════════════════════════════\n"
        f"ORIGINAL SCRAPED POC (for reference):\n"
        f"══════════════════════════════════════════════════════════\n"
        f"{original_code}\n"
        f"══════════════════════════════════════════════════════════\n\n"
        f"TASK: Before writing code, identify WHAT was wrong with your\n"
        f"previous repair (in a single-line comment at the top, e.g.\n"
        f"'# FIX: previous attempt left prose line on line 12 uncommented').\n"
        f"Then return the complete corrected script — nothing else."
    )


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
        api_endpoint: str = cfg.get("api_endpoint", "http://10.3.2.171:80/api/chat")
        model: str = cfg.get("model", "qwen2.5-coder:7b")
        max_attempts: int = cfg.get("max_repair_attempts", 3)
        api_timeout: int = cfg.get("api_timeout", 300)
        temperature: float = cfg.get("temperature", 0.2)
        report_path = Path(cfg.get("report_path", "poc_repair_report.json"))
        manual_queue_path = Path(cfg.get("manual_review_queue_path", "manual_review_queue.json"))
        poc_dir = Path(self.config.get("output", {}).get("poc_dir", "exploits"))

        poc_dir.mkdir(parents=True, exist_ok=True)

        # Read inputs from earlier pipeline stages
        syntax_results: Dict[str, Dict] = context.get("syntax_results", {})
        dataset: Dataset = context.get("dataset", Dataset())

        if not syntax_results:
            self.logger.info("No syntax results found – skipping PoC repair.")
            return context

        # Identify invalid PoCs that need repair — respect the same
        # commit-gating filter that Module 5 uses to flag for review.
        sv_allow = self.config.get("syntax_validator", {}).get(
            "allow_manual_without_commit", True
        )
        invalid_pocs = self._collect_invalid_pocs(
            syntax_results, dataset, allow_without_commit=sv_allow
        )
        if not invalid_pocs:
            self.logger.info("All PoCs passed validation – nothing to repair.")
            return context

        self.logger.info(
            "Found %d invalid PoC(s) to attempt LLM repair.", len(invalid_pocs)
        )

        # Pre-flight: check API health
        if not self._check_api_health(api_endpoint, model):
            self.logger.error(
                "LLM API at %s is not reachable – skipping PoC repair.", api_endpoint
            )
            return context

        # Instantiate a SyntaxValidator to reuse Module 5 validation logic
        syntax_validator = SyntaxValidator(self.config)
        sv_cfg = self.config.get("syntax_validator", {})

        # Track results
        repair_report: Dict[str, Any] = {}
        manual_queue: List[Dict[str, Any]] = []
        repaired_count = 0
        failed_count = 0

        for item in invalid_pocs:
            cve_id = item["cve_id"]
            exploit_idx = item["exploit_idx"]
            original_code = item["content"]
            language = item["language"]
            errors = item["errors"]
            key = f"{cve_id}:{exploit_idx}"

            self.logger.info(
                "Repairing PoC %s (lang=%s, errors=%d) …",
                key, language, len(errors),
            )

            result = self._repair_loop(
                original_code=original_code,
                language=language,
                errors=errors,
                max_attempts=max_attempts,
                api_endpoint=api_endpoint,
                model=model,
                api_timeout=api_timeout,
                temperature=temperature,
                syntax_validator=syntax_validator,
                sv_cfg=sv_cfg,
            )

            repair_report[key] = result

            if result["repaired"]:
                repaired_count += 1
                fixed_code = result["fixed_code"]

                # ── Update the dataset in-place so OutputGenerator sees the fix
                entry = dataset.cves.get(cve_id)
                if entry and exploit_idx < len(entry.exploits):
                    entry.exploits[exploit_idx].source_code_content = fixed_code

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
            else:
                failed_count += 1
                # ── Flag for manual supervision
                manual_queue.append({
                    "cve_id": cve_id,
                    "exploit_idx": exploit_idx,
                    "language": language,
                    "original_errors": errors,
                    "last_errors": result["last_errors"],
                    "attempts": result["attempts"],
                    "flagged_at": datetime.now().isoformat(),
                })

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
        temperature: float,
        syntax_validator: SyntaxValidator,
        sv_cfg: Dict,
    ) -> Dict[str, Any]:
        """Try up to *max_attempts* LLM repairs, re-validating each time.

        Returns a dict with keys: repaired, fixed_code, attempts, last_errors,
        and attempt_history.
        """
        current_errors = list(errors)
        previous_attempt: Optional[str] = None
        attempt_history: List[Dict[str, Any]] = []

        for attempt in range(1, max_attempts + 1):
            self.logger.info("  Attempt %d/%d …", attempt, max_attempts)

            # Build the prompt
            if attempt == 1:
                user_prompt = _build_repair_prompt(original_code, language, current_errors)
                system_prompt = SYSTEM_PROMPT
            else:
                user_prompt = _build_retry_prompt(
                    original_code,
                    previous_attempt or "",
                    language,
                    current_errors,
                    attempt,
                )
                system_prompt = RETRY_SYSTEM_PROMPT

            # Stagger temperature: base on attempt 1, +0.2 per retry (cap 0.9)
            # This forces the LLM to explore different outputs rather than
            # reproducing the same failed repair on every retry.
            attempt_temperature = min(temperature + (attempt - 1) * 0.2, 0.9)

            # Call the LLM
            raw_response, api_meta = self._call_llm(
                api_endpoint=api_endpoint,
                model=model,
                system_prompt=system_prompt,
                user_prompt=user_prompt,
                timeout=api_timeout,
                temperature=attempt_temperature,
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
        max_retries: int = 2,     # was 3; with lower api_timeout each retry is cheap
        retry_delay: int = 5,     # was 10; shorter wait between inner retries
    ) -> Tuple[Optional[str], Dict[str, Any]]:
        """Call the Ollama-compatible LLM API with retry logic.

        Mirrors the ``call_llm_api`` function in ``patch_generator.py``
        (Phase 2 of the master pipeline).
        """
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ]

        payload = {
            "model": model,
            "messages": messages,
            "stream": False,
            "options": {
                "temperature": temperature,
            },
        }

        metadata: Dict[str, Any] = {
            "model": model,
            "timestamp_start": datetime.now().isoformat(),
            "payload_size": len(json.dumps(payload)),
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

    # ------------------------------------------------------------------
    # API health check
    # ------------------------------------------------------------------

    def _check_api_health(self, api_endpoint: str, model: str) -> bool:
        """Quick health check before processing (mirrors Phase 2)."""
        try:
            test_payload = {
                "model": model,
                "messages": [{"role": "user", "content": "test"}],
                "stream": False,
                "options": {"num_predict": 1},
            }
            resp = requests.post(api_endpoint, json=test_payload, timeout=30)
            resp.raise_for_status()
            self.logger.info("✓ LLM API health check passed (%s)", api_endpoint)
            return True
        except requests.exceptions.Timeout:
            self.logger.error("✗ LLM API health check timed out.")
            return False
        except requests.exceptions.ConnectionError:
            self.logger.error(
                "✗ Cannot connect to LLM API at %s", api_endpoint
            )
            return False
        except Exception as exc:
            self.logger.error("✗ LLM API health check failed: %s", exc)
            return False

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
