#!/usr/bin/env python3
"""
AI-SSD Phase 2: Automated Patch Generation Pipeline

This script automates the generation of security patches for known CVEs using
multiple Large Language Models (LLMs). It processes vulnerable C code snippets,
generates candidate patches, validates syntax, and organizes outputs.

Author: AI-SSD Project
Date: 2026-01-03
"""

import os
import re
import sys
import json
import time
import difflib
import logging
import tempfile
import threading
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Optional, Tuple, Dict, Any, List

import requests
import pandas as pd
import yaml

# =============================================================================
# Configuration – loaded from config.yaml via master_pipeline.config
# =============================================================================

BASE_DIR = Path(__file__).parent.resolve()

# Import the shared config loader
sys.path.insert(0, str(BASE_DIR))
from master_pipeline.config import (  # noqa: E402
    load_pipeline_config, cfg_section, project_section, _load_yaml,
)
# Candidate fan-out framework (over-generate-and-validate). Pure/stdlib-only, no
# circular import: candidates.py imports nothing from patch_generator.
from master_pipeline.candidates import Recipe, Candidate  # noqa: E402

# Structural-analysis view: blanks comment interiors and non-first
# preprocessor branches while preserving offsets, so brace matching is not
# corrupted by braces/apostrophes in comments (e.g. GNU-style `foo' quoting)
# or by #if/#else groups that open the same brace in every branch.
from cve_aggregator.utils.code_parser import _build_analysis_view  # noqa: E402
from cve_aggregator.utils.gpu_lock import gpu_lock  # noqa: E402
from cve_aggregator.utils.llm_compat import (  # noqa: E402
    is_openai_reasoning_model as _shared_is_openai_reasoning_model,
)
try:  # best-effort live-progress heartbeat for the dashboard (never fatal)
    from cve_aggregator.utils import live_progress  # noqa: E402
except Exception:  # pragma: no cover
    live_progress = None

_cfg = load_pipeline_config(BASE_DIR)
_llm = _cfg.get("llm", {}) if isinstance(_cfg.get("llm"), dict) else {}
_paths = _cfg.get("paths", {}) if isinstance(_cfg.get("paths"), dict) else {}
_gen = _cfg.get("generation", {}) if isinstance(_cfg.get("generation"), dict) else {}

# Prompt-component ablation toggles (generation.prompt_components). All default
# ON ⇒ today's prompt verbatim; the ablation harness flips these (via SSD_PROMPT_*
# env, overlaid by the config loader) to measure each component's contribution.
_pc = _gen.get("prompt_components", {}) if isinstance(_gen.get("prompt_components"), dict) else {}
PROMPT_INCLUDE_POC = bool(_pc.get("include_poc", True))
PROMPT_INCLUDE_CWE = bool(_pc.get("include_cwe", True))
PROMPT_INCLUDE_DESCRIPTION = bool(_pc.get("include_description", True))
PROMPT_PROJECT_PRIMING = bool(_pc.get("project_priming", True))

# ---------------------------------------------------------------------------
# Provider selection: "ollama" (local GPU server) or "openai" (OpenAI API)
# ---------------------------------------------------------------------------
LLM_PROVIDER = str(_llm.get("provider", "ollama")).lower()

# Ollama-specific settings
API_ENDPOINT = str(_llm.get("endpoint", "http://10.3.2.171:80/api/chat"))
NUM_CTX = int(_llm.get("num_ctx", 32768))
MODELS = [str(m) for m in _llm.get("models", [
    "qwen2.5-coder:1.5b", "qwen2.5-coder:7b", "qwen2.5:1.5b", "qwen2.5:7b"
])]

# OpenAI-specific settings
OPENAI_MODEL = str(_llm.get("openai_model", "gpt-4.1-mini"))
# Optional custom OpenAI-compatible base URL (vLLM / proxy / LM Studio). Empty
# string ⇒ the SDK's default OpenAI endpoint. Set via profile (LLM_OPENAI_BASE_URL).
OPENAI_BASE_URL = str(_llm.get("openai_base_url", "") or "")
# API key: env var takes precedence over config file value
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY") or str(_llm.get("openai_api_key", ""))
if not OPENAI_API_KEY:
    _key_file = BASE_DIR / "API-openai-key"
    if _key_file.exists():
        OPENAI_API_KEY = _key_file.read_text().strip()

# Optional HTTP Basic Auth for a proxied Ollama backend (profile sets
# OLLAMA_USERNAME/OLLAMA_PASSWORD, overlaid onto llm.* by the config loader).
# None ⇒ unauthenticated (the legacy direct-server behaviour).
_OLLAMA_USERNAME = str(_llm.get("ollama_username", "") or "")
_OLLAMA_PASSWORD = str(_llm.get("ollama_password", "") or "")
OLLAMA_AUTH = (_OLLAMA_USERNAME, _OLLAMA_PASSWORD) if (_OLLAMA_USERNAME and _OLLAMA_PASSWORD) else None

# Optional per-attempt model escalation for the feedback loop. Keys are attempt
# numbers (1 = the initial Phase 2 generation, 2 = first retry, ...), values are
# model ids. Honored only for the OpenAI provider; an attempt not listed falls
# back to OPENAI_MODEL. The feedback loop reads the same config and passes the
# resolved model per retry via ``generation_model`` (see generate_patch_with_feedback).
_fb_cfg = _cfg.get("feedback_loop", {}) if isinstance(_cfg.get("feedback_loop"), dict) else {}
FEEDBACK_MODELS_BY_ATTEMPT = {
    str(k): str(v) for k, v in (_fb_cfg.get("models_by_attempt") or {}).items() if v
}
# Attempt-1 override: the initial Phase 2 generation (which the feedback loop
# reuses as attempt 1) should use the attempt-1 model when one is configured,
# so the per-attempt schedule is honored end-to-end.
if LLM_PROVIDER == "openai" and FEEDBACK_MODELS_BY_ATTEMPT.get("1"):
    OPENAI_MODEL = FEEDBACK_MODELS_BY_ATTEMPT["1"]

# Host-global GPU mutex: serialize GPU-bound inference across concurrent cells so
# the single shared Ollama GPU isn't thrashed by two model families at once. No-op
# for the OpenAI provider and uncontended (≈free) when only one cell runs. Disable
# with llm.gpu_lock: false or SSD_GPU_LOCK=0.
GPU_LOCK_ENABLED = bool(_llm.get("gpu_lock", True))

# Shared request settings
API_TIMEOUT = int(_llm.get("timeout", 600))
MAX_RETRIES = int(_llm.get("retry_attempts", 3))
RETRY_DELAY = int(_llm.get("retry_delay", 5))
# How often (seconds) the background pulser refreshes the live-progress heartbeat
# while a single CVE is being processed, so the executor's idle watchdog does not
# false-kill a phase that is healthy but blocked inside one long LLM call. Must be
# well under the Phase-2 idle timeout (config phase_idle_timeouts[2]). 0 disables.
LLM_HEARTBEAT_INTERVAL = int(_llm.get("heartbeat_interval", 60))

# LLM Parameters
LLM_TEMPERATURE = float(_llm.get("temperature", 0.2))
# Ollama model warm-up: keep the model resident in (the remote proxy's) VRAM
# between requests so a slow/spaced Phase-2 burst doesn't pay a cold multi-GiB
# reload. keep_alive is sent on every Ollama request; preload warms the model
# once before each model's CVE loop (mirrors Phase-0's PoCRepairLLM._preload_model).
# Both are NO-OPS for the OpenAI provider. Set keep_alive: "" to send nothing
# (exact legacy behaviour).
LLM_KEEP_ALIVE = str(_llm.get("keep_alive", "15m"))
LLM_PRELOAD = bool(_llm.get("preload", True))
LLM_PRELOAD_TIMEOUT = int(_llm.get("preload_timeout", 300))
LLM_MAX_TOKENS = int(_llm.get("max_tokens", 8192))

# Paths
CSV_PATH = BASE_DIR / str(_paths.get("csv_file", "documentation/file-function.csv"))
OUTPUT_DIR = BASE_DIR / str(_paths.get("patches", "patches"))
LOG_DIR = BASE_DIR / str(_paths.get("logs", "logs"))
EXPLOITS_DIR = BASE_DIR / str(_paths.get("exploits_dir", "exploits"))

# =============================================================================
# Logging Setup
# =============================================================================

def setup_logging() -> logging.Logger:
    """Configure logging for the pipeline."""
    LOG_DIR.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = LOG_DIR / f"patch_generator_{timestamp}.log"
    syntax_error_log = LOG_DIR / "syntax_errors.log"
    
    # Create formatter
    formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    # Setup main logger
    logger = logging.getLogger('patch_generator')
    logger.setLevel(logging.DEBUG)
    
    # Clear existing handlers to prevent duplicates when module is re-imported
    logger.handlers.clear()
    
    # File handler for all logs
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    
    # Console handler for INFO and above
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # Setup syntax error logger (separate file)
    syntax_logger = logging.getLogger('syntax_errors')
    syntax_logger.setLevel(logging.ERROR)
    # Clear existing handlers to prevent duplicates
    syntax_logger.handlers.clear()
    syntax_handler = logging.FileHandler(syntax_error_log, mode='a')
    syntax_handler.setFormatter(formatter)
    syntax_logger.addHandler(syntax_handler)
    
    return logger

logger = setup_logging()
syntax_logger = logging.getLogger('syntax_errors')

# =============================================================================
# Prompt Engineering
# =============================================================================

# Shared description of the SEARCH/REPLACE edit format both prompts require.
# Patches are expressed as minimal edits applied by literal string match, NOT
# as whole-function rewrites — so the model never re-transcribes (and corrupts)
# the hundreds of unchanged lines / macros / K&R prototypes around the fix.
_SEARCH_REPLACE_FORMAT = """You fix the vulnerability by emitting one or more SEARCH/REPLACE edit blocks, each in EXACTLY this format (markers on their own lines):

<<<<<<< SEARCH
<lines copied VERBATIM from the vulnerable code shown to you>
=======
<the replacement lines>
>>>>>>> REPLACE

EDIT RULES:
1. The SEARCH text MUST be copied character-for-character from the VULNERABLE FUNCTION CODE shown to you — same tokens, same indentation. It is located by literal matching, so any deviation makes the edit fail.
2. SEARCH must match a UNIQUE location. If a single line is ambiguous, include a few unchanged surrounding lines so the block matches exactly one place.
3. Make the SMALLEST edit that fixes the vulnerability. Change only the lines that must change. Do NOT reprint the whole function. Do NOT touch the function signature, return type, declaring macros (e.g. MPN_VAR), or unrelated lines.
4. Emit MULTIPLE SEARCH/REPLACE blocks when the fix spans several places. Each block is applied independently.
5. Preserve behavior for all legitimate inputs; add the bounds/overflow/validation checks needed to stop the exploit.
6. Output ONLY the SEARCH/REPLACE block(s) — no prose, no explanations, no markdown code fences."""


# ---------------------------------------------------------------------------
# Phase 2 prompts + language are PROJECT-SUPPLIED (project YAML phase2: section);
# the code carries only GENERIC defaults so nothing here is glibc/C-specific.
# The role preamble comes from config; the SEARCH/REPLACE format (the parser
# contract) and the feedback tail stay in code so every project emits the edit
# format Phase 2's extractor expects. glibc keeps its exact wording via its YAML.
# ---------------------------------------------------------------------------
_DEFAULT_SYSTEM_PREAMBLE = (
    "You are an expert security engineer specializing in fixing software "
    "vulnerabilities. Your task is to fix a security vulnerability by making the "
    "SMALLEST POSSIBLE EDIT to the vulnerable function — never by rewriting it."
)
_DEFAULT_FEEDBACK_PREAMBLE = (
    "You are an expert security engineer specializing in fixing software "
    "vulnerabilities. Your previous patch attempt FAILED validation. Analyze the "
    "failure and produce an improved fix as MINIMAL edits — never rewrite the "
    "whole function."
)
_FEEDBACK_TAIL = (
    "\n\nCarefully read the FAILURE ANALYSIS: if the PoC still works your fix was "
    "insufficient; if the build failed your edit introduced a compile error (often "
    "by quoting SEARCH text that did not match, or by editing lines you should have "
    "left alone)."
)

# Populated by _apply_phase2() at import (and re-applied in main() once the
# active --phase0-config is known). Module globals so functions read the current
# value at call time.
SYSTEM_PROMPT = ""
FEEDBACK_SYSTEM_PROMPT = ""
PATCH_LANGUAGE = "c"
# Project-internal headers that don't exist host-side (only the C/gcc validation
# path consults this; the generic missing-header regex is the primary arbiter).
INTERNAL_HEADERS: set = set()


def _apply_phase2(cfg2: Dict[str, Any]) -> None:
    """Assemble the prompts/language/headers from a project ``phase2:`` dict."""
    global SYSTEM_PROMPT, FEEDBACK_SYSTEM_PROMPT, PATCH_LANGUAGE, INTERNAL_HEADERS
    cfg2 = cfg2 or {}
    PATCH_LANGUAGE = str(cfg2.get("language", "c")).lower()
    # project_priming=False (ablation) drops the project's tailored system prompt
    # in favour of the generic preamble, isolating the effect of domain priming.
    sys_pre = (cfg2.get("system_prompt") if PROMPT_PROJECT_PRIMING else None) or _DEFAULT_SYSTEM_PREAMBLE
    fb_pre = (cfg2.get("feedback_system_prompt") if PROMPT_PROJECT_PRIMING else None) or _DEFAULT_FEEDBACK_PREAMBLE
    SYSTEM_PROMPT = sys_pre + "\n\n" + _SEARCH_REPLACE_FORMAT
    FEEDBACK_SYSTEM_PROMPT = fb_pre + "\n\n" + _SEARCH_REPLACE_FORMAT + _FEEDBACK_TAIL
    INTERNAL_HEADERS = set(cfg2.get("internal_headers") or [])


# Import-time default: read phase2 from config.yaml's active phase0_config pointer.
# main() re-applies this once an explicit --phase0-config is parsed.
_apply_phase2(project_section("phase2", BASE_DIR))


def _find_poc_source(cve_id: str, max_len: int = 3000) -> str:
    """Read the primary PoC source for *cve_id* from the exploits directory.

    Looks for ``exploits/<CVE>.<ext>`` (the primary PoC, not _pocN variants).
    Returns the truncated source, or "" when no PoC file exists.
    """
    exploits_dir = EXPLOITS_DIR  # rebased to the active --base-dir in main()/feedback
    try:
        candidates = sorted(
            p for p in exploits_dir.glob(f"{cve_id}.*")
            if p.is_file()
        )
    except OSError:
        return ""
    if not candidates:
        return ""
    try:
        src = candidates[0].read_text(errors="replace")
    except OSError:
        return ""
    if len(src) > max_len:
        src = src[:max_len] + "\n/* ... PoC truncated for brevity ... */"
    return src


def _build_vulnerability_context(
    cve_id: str,
    description: Optional[str] = None,
    cwe: Optional[str] = None,
    cwe_description: Optional[str] = None,
) -> str:
    """Build the vulnerability-knowledge section shared by both prompts:
    the CVE/CWE description (when available from the Phase 0 CSV) and the
    actual PoC exploit source — so the model knows the exact attack vector
    its patch must block."""
    sections = []

    desc = (description or "").strip()
    if PROMPT_INCLUDE_DESCRIPTION and desc and desc.lower() not in ("nan", "none"):
        if len(desc) > 900:
            desc = desc[:900] + " ..."
        sections.append(f"VULNERABILITY DESCRIPTION:\n{desc}")

    cwe_line = " ".join(
        s.strip() for s in (cwe, cwe_description)
        if s and str(s).strip().lower() not in ("nan", "none")
    )
    if PROMPT_INCLUDE_CWE and cwe_line:
        sections.append(f"WEAKNESS CLASS: {cwe_line}")

    if PROMPT_INCLUDE_POC:
        poc_src = _find_poc_source(cve_id)
        if poc_src:
            sections.append(
                "PROOF-OF-CONCEPT EXPLOIT (this is the exact attack your patch "
                "must stop — after patching, this program must no longer trigger "
                "the vulnerability):\n" + poc_src
            )

    return "\n\n".join(sections)


def create_patch_prompt(cve_id: str, function_name: str, vulnerable_code: str,
                        file_context: str, vuln_context: str = "",
                        extra_instructions: str = "") -> str:
    """
    Create a detailed prompt for patch generation.

    Args:
        cve_id: The CVE identifier
        function_name: Name of the vulnerable function
        vulnerable_code: The vulnerable function code
        file_context: Full file content for context (truncated if too long)
        vuln_context: CVE description / CWE / PoC source section (optional)
        extra_instructions: Trailing instructions contributed by a candidate
            recipe (granularity / chain-of-thought). Appended verbatim AFTER the
            base instructions so a recipe can override them (e.g. CoT relaxes the
            "output only" rule). Empty string ⇒ today's prompt, unchanged.

    Returns:
        Formatted user prompt string
    """
    # Truncate file context if too long (keep first 4000 chars for context)
    max_context_len = 4000
    if len(file_context) > max_context_len:
        file_context = file_context[:max_context_len] + "\n/* ... file truncated for brevity ... */"

    vuln_section = f"\n{vuln_context}\n" if vuln_context else ""

    prompt = f"""VULNERABILITY: {cve_id}
FUNCTION NAME: {function_name}
{vuln_section}
VULNERABLE FUNCTION CODE (copy your SEARCH text verbatim from here):
{vulnerable_code}

FILE CONTEXT (for understanding types and dependencies):
{file_context}

TASK: Fix the {cve_id} vulnerability in the function '{function_name}' using SEARCH/REPLACE edit block(s).

REMEMBER:
- Copy each SEARCH section character-for-character from the VULNERABLE FUNCTION CODE above
- Make the smallest edit that fixes the vulnerability; do not rewrite the whole function or touch its signature
- Output ONLY SEARCH/REPLACE block(s) — no markdown, no explanations"""

    if extra_instructions:
        prompt += extra_instructions

    return prompt


def _unified_diff(original: str, patched: str,
                  fromname: str = "original", toname: str = "patched",
                  max_lines: int = 60) -> str:
    """Compact unified diff between two function texts (for feedback memory).

    Returns "" when either side is empty or there is no difference. Truncated to
    *max_lines* so a large rewrite cannot blow up the prompt.
    """
    if not original or not patched:
        return ""
    lines = list(difflib.unified_diff(
        original.splitlines(), patched.splitlines(),
        fromfile=fromname, tofile=toname, lineterm=""))
    if not lines:
        return ""
    if len(lines) > max_lines:
        omitted = len(lines) - max_lines
        lines = lines[:max_lines] + [f"... (diff truncated, {omitted} more line(s))"]
    return "\n".join(lines)


def create_feedback_prompt(
    cve_id: str,
    function_name: str,
    vulnerable_code: str,
    file_context: str,
    previous_patch: str,
    failure_context: Dict[str, Any],
    attempt_number: int,
    vuln_context: str = "",
    prior_attempts: Optional[List[Dict[str, Any]]] = None,
    include_diff: bool = False,
    include_history: bool = False,
    reflexion: bool = False
) -> str:
    """
    Create a prompt for retry patch generation with failure feedback context.

    Args:
        cve_id: The CVE identifier
        function_name: Name of the vulnerable function
        vulnerable_code: The vulnerable function code
        file_context: Full file content for context
        previous_patch: The previous failed patch attempt
        failure_context: Dictionary containing failure details from Phase 3
        attempt_number: Current retry attempt number
        vuln_context: CVE description / CWE / PoC source section (optional)

    Returns:
        Formatted user prompt string with failure context
    """
    # Truncate file context if too long
    max_context_len = 3000  # Slightly smaller to accommodate failure context
    if len(file_context) > max_context_len:
        file_context = file_context[:max_context_len] + "\n/* ... file truncated for brevity ... */"

    # Truncate previous patch if too long
    max_patch_len = 2000
    if len(previous_patch) > max_patch_len:
        previous_patch = previous_patch[:max_patch_len] + "\n/* ... patch truncated ... */"

    # Build failure analysis section
    failure_analysis = _build_failure_analysis(failure_context)

    vuln_section = ""
    if vuln_context:
        vuln_section = f"""
═══════════════════════════════════════════════════════════════════
VULNERABILITY KNOWLEDGE (description / exploit your patch must stop):
═══════════════════════════════════════════════════════════════════
{vuln_context}
"""

    prompt = f"""RETRY ATTEMPT #{attempt_number} for VULNERABILITY: {cve_id}
FUNCTION NAME: {function_name}
{vuln_section}
═══════════════════════════════════════════════════════════════════
PREVIOUS PATCH ATTEMPT (FAILED):
═══════════════════════════════════════════════════════════════════
{previous_patch}

═══════════════════════════════════════════════════════════════════
FAILURE ANALYSIS:
═══════════════════════════════════════════════════════════════════
{failure_analysis}

═══════════════════════════════════════════════════════════════════
ORIGINAL VULNERABLE CODE (copy your SEARCH text verbatim from here):
═══════════════════════════════════════════════════════════════════
{vulnerable_code}

═══════════════════════════════════════════════════════════════════
FILE CONTEXT (for understanding types and dependencies):
═══════════════════════════════════════════════════════════════════
{file_context}

═══════════════════════════════════════════════════════════════════
TASK: Generate an IMPROVED fix, as SEARCH/REPLACE edit block(s), that:
1. Fixes the original {cve_id} vulnerability
2. Addresses the specific failures identified above
3. Changes as few lines as possible and never touches the signature/macros

CRITICAL: Learn from the failure. If PoC still works, your previous fix was insufficient.
If the build failed, your SEARCH text likely did not match the real code, or you edited
lines you should not have — re-copy SEARCH verbatim from the ORIGINAL VULNERABLE CODE.

REMEMBER:
- Copy each SEARCH section character-for-character from the ORIGINAL VULNERABLE CODE above
- Make the smallest edit that fixes the vulnerability
- Output ONLY SEARCH/REPLACE block(s) — no markdown, no explanations"""

    # ── Richer feedback memory (gated; all default off → prompt unchanged) ──────
    diff_section = ""
    if include_diff:
        d = _unified_diff(vulnerable_code, previous_patch,
                          fromname="original", toname="your_failed_patch")
        if d:
            diff_section = (
                "\n\n═══════════════════════════════════════════════════════════════════\n"
                "WHAT YOU CHANGED LAST TIME (unified diff: original → your FAILED patch):\n"
                "═══════════════════════════════════════════════════════════════════\n" + d
            )

    history_section = ""
    if include_history and prior_attempts and len(prior_attempts) > 1:
        # Attempts BEFORE the immediately-previous one (already shown in full),
        # most-recent first, capped — so the model stops re-proposing failed edits.
        earlier = prior_attempts[:-1][-3:]
        blocks = []
        for rec in reversed(earlier):
            n = rec.get("attempt_number", "?")
            outcome = rec.get("outcome", "failed")
            d = _unified_diff(vulnerable_code, rec.get("patched_function", ""),
                              fromname="original", toname=f"attempt{n}", max_lines=24)
            blocks.append(f"--- Attempt {n} → {outcome} ---\n{d or '(no diff captured)'}")
        if blocks:
            history_section = (
                "\n\n═══════════════════════════════════════════════════════════════════\n"
                "EARLIER FAILED ATTEMPTS — do NOT repeat these edits; each was rejected:\n"
                "═══════════════════════════════════════════════════════════════════\n"
                + "\n\n".join(blocks)
            )

    reflexion_tail = ""
    if reflexion:
        reflexion_tail = (
            "\n\nFIRST, on lines beginning 'DIAGNOSIS:', state in 2-3 sentences WHY the "
            "previous attempt(s) failed and what you will do DIFFERENTLY (this overrides "
            "the 'output only' rule above). THEN output the SEARCH/REPLACE block(s)."
        )

    return prompt + diff_section + history_section + reflexion_tail


def _build_failure_analysis(failure_context: Dict[str, Any]) -> str:
    """
    Build a human-readable failure analysis from the failure context.
    
    Args:
        failure_context: Dictionary containing failure details
    
    Returns:
        Formatted failure analysis string
    """
    lines = []
    
    # Validation status
    status = failure_context.get("status", "Unknown")
    lines.append(f"Validation Status: {status}")
    
    # PoC (Dynamic Check) Results
    if failure_context.get("poc_blocked") is False:
        lines.append("\n[DYNAMIC CHECK FAILED - PoC Still Works]")
        lines.append("The exploit STILL TRIGGERS the vulnerability. Your patch is INSUFFICIENT.")
        
        poc_exit_code = failure_context.get("poc_exit_code")
        if poc_exit_code is not None:
            lines.append(f"  Exit Code: {poc_exit_code}")
            if poc_exit_code == 139:
                lines.append("  (SIGSEGV - Segmentation fault detected)")
            elif poc_exit_code == 134:
                lines.append("  (SIGABRT - Abort signal detected)")
        
        poc_output = failure_context.get("poc_output", "")
        if poc_output:
            # Truncate and clean PoC output
            poc_output = poc_output[:1500].strip()
            lines.append(f"\n  PoC Output (truncated):\n  {'-'*40}")
            for line in poc_output.split('\n')[:30]:
                lines.append(f"  {line}")
            lines.append(f"  {'-'*40}")
    elif failure_context.get("poc_blocked") is True:
        lines.append("\n[DYNAMIC CHECK PASSED - PoC Blocked]")
    
    # SAST (Static Check) Results — only patch-INTRODUCED ("new") findings are
    # fed back. Pre-existing issues from the original code are out of scope for
    # this patch and must NOT be sent to the LLM (they are unrelated to it).
    sast_passed = failure_context.get("sast_passed", True)
    sast_new = failure_context.get("sast_new", [])

    if not sast_passed and sast_new:
        lines.append("\n[STATIC CHECK FAILED - Patch Introduced NEW Vulnerabilities]")
        lines.append("Your patch added the following NEW issues that were NOT in the original code.")
        lines.append("Fix ONLY these; do not modify code for any pre-existing issue:")
        for finding in sast_new[:10]:  # cap prompt size
            tool = finding.get("tool", "?")
            severity = finding.get("severity", "?")
            message = finding.get("message", "")
            line_num = finding.get("line")
            cwe = finding.get("cwe_id")
            loc = f"line {line_num} " if line_num else ""
            cwe_s = f" ({cwe})" if cwe else ""
            lines.append(f"  [{tool}/{severity}]{cwe_s} {loc}: {message[:140]}")
    elif sast_passed:
        lines.append("\n[STATIC CHECK PASSED - No New Vulnerabilities Introduced]")
    
    # Build error (if applicable)
    if not failure_context.get("build_success", True):
        lines.append("\n[BUILD FAILED]")
        error_msg = failure_context.get("error_message", "Unknown build error")
        lines.append(f"  Error: {error_msg[:500]}")
    
    # General error message
    error_message = failure_context.get("error_message")
    if error_message and failure_context.get("build_success", True):
        lines.append(f"\nAdditional Error Info: {error_message[:300]}")
    
    return '\n'.join(lines)


# =============================================================================
# API Integration
# =============================================================================

def check_api_health() -> bool:
    """
    Quick health check to verify LLM API is responsive before processing.

    For the "ollama" provider, uses GET /api/tags (fast, no inference).
    For the "openai" provider, validates that an API key is configured.

    Returns:
        True if API is healthy/configured, False otherwise
    """
    # Per-run provenance banner: record exactly which backend Phase 2 (and the
    # feedback loop) will use, so benchmark runs are auditable from the log.
    if LLM_PROVIDER == "openai":
        _banner_model = OPENAI_MODEL
        _banner_endpoint = OPENAI_BASE_URL or "<OpenAI default>"
    else:
        _banner_model = ", ".join(MODELS)
        _banner_endpoint = API_ENDPOINT
    logger.info(
        "LLM backend → provider=%s | model=%s | endpoint=%s | auth=%s",
        LLM_PROVIDER, _banner_model, _banner_endpoint,
        "basic" if (LLM_PROVIDER != "openai" and OLLAMA_AUTH) else "none",
    )
    if FEEDBACK_MODELS_BY_ATTEMPT:
        logger.info("LLM per-attempt ramp → %s", FEEDBACK_MODELS_BY_ATTEMPT)

    if LLM_PROVIDER == "openai":
        if not OPENAI_API_KEY:
            logger.error(
                "✗ OpenAI health check failed: no API key found. "
                "Set the OPENAI_API_KEY environment variable or llm.openai_api_key in config.yaml."
            )
            return False
        logger.info("✓ OpenAI provider configured (model: %s)", OPENAI_MODEL)
        return True

    # --- Ollama health check ---
    from urllib.parse import urlparse, urlunparse
    parsed = urlparse(API_ENDPOINT)
    tags_url = urlunparse((parsed.scheme, parsed.netloc, "/api/tags", "", "", ""))
    try:
        response = requests.get(tags_url, timeout=10, auth=OLLAMA_AUTH)
        response.raise_for_status()
        n_models = len(response.json().get("models", []))
        logger.info("✓ API health check passed (%d models available)", n_models)
        # Best-effort GPU check at startup (model may not be loaded yet)
        for model in MODELS:
            _check_gpu_status(model)
        return True
    except requests.exceptions.Timeout:
        logger.error("✗ API health check failed: Server not responding (GET %s timed out)", tags_url)
        return False
    except requests.exceptions.ConnectionError:
        logger.error(f"✗ API health check failed: Cannot connect to {API_ENDPOINT}")
        return False
    except Exception as e:
        logger.error(f"✗ API health check failed: {e}")
        return False


# Module-level set tracking which models have already had their GPU status logged
_gpu_status_logged: set = set()


def _check_gpu_status(model: str) -> None:
    """Check whether *model* is GPU- or CPU-accelerated via Ollama's /api/ps.

    Ollama's /api/ps lists currently loaded runners with:
      • ``size``      – total model size in bytes
      • ``size_vram`` – bytes in GPU VRAM (0 means CPU-only)

    If the model is not yet loaded (Ollama lazy-loads on first inference)
    the list will be empty and the check is silently deferred.
    Each model is only reported once per process (tracked by _gpu_status_logged).
    """
    global _gpu_status_logged
    if model in _gpu_status_logged:
        return

    from urllib.parse import urlparse, urlunparse
    parsed = urlparse(API_ENDPOINT)
    ps_url = urlunparse((parsed.scheme, parsed.netloc, "/api/ps", "", "", ""))
    try:
        resp = requests.get(ps_url, timeout=5, auth=OLLAMA_AUTH)
        resp.raise_for_status()
        running = resp.json().get("models", [])

        model_base = model.split(":")[0].lower()
        for entry in running:
            if model_base in entry.get("name", "").lower():
                size_vram = entry.get("size_vram", 0)
                size_total = entry.get("size", 0)
                _gpu_status_logged.add(model)

                if size_vram == 0:
                    logger.warning(
                        "⚠ WARNING: Model '%s' is running on CPU only "
                        "(size_vram=0). Inference will be significantly slower "
                        "than GPU. Ensure the Ollama server has CUDA/ROCm "
                        "drivers and the container has GPU access (--gpus all).",
                        model,
                    )
                elif size_total > 0 and size_vram < size_total:
                    pct = size_vram / size_total * 100
                    logger.warning(
                        "⚠ WARNING: Model '%s' is only partially "
                        "GPU-accelerated (%.0f%% in VRAM, %.1f/%.1f GiB). "
                        "Some layers are on CPU — consider a GPU with more VRAM.",
                        model, pct,
                        size_vram / 1024 ** 3,
                        size_total / 1024 ** 3,
                    )
                else:
                    logger.info(
                        "✓ Model '%s' is fully GPU-accelerated (%.1f GiB VRAM).",
                        model, size_vram / 1024 ** 3,
                    )
                return
        # Model not in /api/ps yet — deferred to post-inference check
        logger.debug("GPU status check: '%s' not yet loaded in /api/ps.", model)
    except Exception as exc:
        logger.debug("GPU status check skipped for '%s' (%s).", model, exc)


# GPU wait timeout – loaded from config.yaml llm.gpu_wait_timeout
GPU_WAIT_TIMEOUT = int(_llm.get("gpu_wait_timeout", 120))


def wait_for_gpu(model: Optional[str] = None, timeout: Optional[int] = None,
                 poll_interval: int = 15) -> bool:
    """Poll /api/ps until the backend can serve our request, or *timeout* expires.

    Returns True when ready to serve: the GPU is idle, OR our target *model* is
    already resident. On a SHARED / persistent Ollama proxy the GPU is rarely
    idle and keeps models loaded across requests, so a resident target model is
    the BEST case (it serves immediately), not a busy one — waiting for the GPU
    to fully empty would block forever. Only blocks while the GPU is occupied by
    OTHER models and ours is not loaded. For the "openai" provider this is a
    no-op (always True). Set llm.gpu_wait_timeout to 0 to skip the wait entirely.
    """
    if LLM_PROVIDER == "openai":
        return True  # No GPU to wait for when using OpenAI

    from urllib.parse import urlparse, urlunparse

    if timeout is None:
        timeout = GPU_WAIT_TIMEOUT
    if timeout <= 0:
        return True  # wait disabled via config (shared backend manages its own VRAM)

    parsed = urlparse(API_ENDPOINT)
    ps_url = urlunparse((parsed.scheme, parsed.netloc, "/api/ps", "", "", ""))
    start = time.time()

    while True:
        try:
            resp = requests.get(ps_url, timeout=10, auth=OLLAMA_AUTH)
            resp.raise_for_status()
            running = resp.json().get("models", [])
            total_vram = sum(e.get("size_vram", 0) for e in running)
            if not running or total_vram == 0:
                return True
            # Our target model is already loaded → it will serve immediately; a
            # busy GPU only matters when it is occupied by OTHER models and ours
            # is not resident (then we wait for ollama to load/evict).
            if model and any(e.get("name") == model or e.get("model") == model
                             for e in running):
                return True
        except Exception:
            return True  # can't reach /api/ps — assume available

        elapsed = time.time() - start
        if timeout and elapsed >= timeout:
            return False

        names = [e.get("name", "?") for e in running]
        vram_gib = total_vram / (1024 ** 3)
        logger.info(
            "GPU busy (%.1f GiB VRAM used by %s) — waiting (%d/%d s) …",
            vram_gib, ", ".join(names), int(elapsed), timeout,
        )
        time.sleep(poll_interval)


def _preload_ollama_model(model: str, timeout: Optional[int] = None,
                          poll_interval: int = 10) -> bool:
    """Warm *model* into the (remote) Ollama proxy's VRAM before the per-CVE burst.

    Mirrors ``PoCRepairLLM._preload_model``: fire a zero-token ``/api/generate``
    with ``keep_alive`` in a daemon thread, then poll ``/api/ps`` until the
    model's ``size_vram`` is non-zero (or *timeout*). Best-effort — returns
    False on timeout/unreachable and the caller proceeds (the first real request
    then pays the load, exactly as today). No-op for the OpenAI provider.
    """
    if LLM_PROVIDER == "openai":
        return True
    if timeout is None:
        timeout = LLM_PRELOAD_TIMEOUT
    from urllib.parse import urlparse, urlunparse
    parsed = urlparse(API_ENDPOINT)
    ps_url = urlunparse((parsed.scheme, parsed.netloc, "/api/ps", "", "", ""))
    gen_url = urlunparse((parsed.scheme, parsed.netloc, "/api/generate", "", "", ""))
    logger.info("Pre-loading Ollama model '%s' into VRAM …", model)

    def _trigger():
        try:
            requests.post(gen_url,
                          json={"model": model, "keep_alive": LLM_KEEP_ALIVE or "15m"},
                          timeout=timeout, auth=OLLAMA_AUTH)
        except Exception:
            pass  # large-model load can exceed the request timeout; we poll /api/ps

    threading.Thread(target=_trigger, daemon=True, name="ollama-preload").start()

    model_base = model.split(":")[0].lower()
    start = time.time()
    while True:
        try:
            resp = requests.get(ps_url, timeout=5, auth=OLLAMA_AUTH)
            resp.raise_for_status()
            for entry in resp.json().get("models", []):
                # Warm once the model is loaded — size_vram>0 (GPU-resident) OR
                # size>0 (loaded in RAM on a CPU-only / non-VRAM-reporting backend).
                # Requiring size_vram>0 alone would wait the full timeout PER model
                # on such backends even though the model is ready.
                if model_base in entry.get("name", "").lower() and (
                        entry.get("size_vram", 0) > 0 or entry.get("size", 0) > 0):
                    vram = entry.get("size_vram", 0)
                    where = f"{vram / 1024 ** 3:.1f} GiB VRAM" if vram > 0 else "RAM (CPU)"
                    logger.info("✓ Ollama model '%s' warm (%s).", model, where)
                    return True
        except Exception:
            pass
        if time.time() - start >= timeout:
            logger.warning("Ollama model '%s' not confirmed warm after %ds — proceeding.",
                           model, timeout)
            return False
        time.sleep(poll_interval)


# Minimum output room (tokens) a model must have AFTER the prompt to be usable.
# If the prompt leaves less than this within the model's window, the prompt is
# treated as too large for that model and the ramp advances to the next one.
_MIN_OUTPUT_HEADROOM = 1024
_MODEL_MAX_CTX_CACHE: Dict[str, int] = {}


def _model_max_ctx(model: str) -> int:
    """Best-effort max context window (tokens) the model was trained for, read
    from the Ollama server's ``/api/show`` ``model_info`` (cached per model).

    Falls back to ``NUM_CTX`` when the server can't report it, so the guard still
    catches prompts that exceed the configured window even if /api/show is
    unavailable, and behavior is otherwise unchanged.
    """
    if model in _MODEL_MAX_CTX_CACHE:
        return _MODEL_MAX_CTX_CACHE[model]
    ctx = NUM_CTX
    try:
        from urllib.parse import urlparse, urlunparse
        parsed = urlparse(API_ENDPOINT)
        show_url = urlunparse((parsed.scheme, parsed.netloc, "/api/show", "", "", ""))
        resp = requests.post(show_url, json={"model": model}, timeout=10, auth=OLLAMA_AUTH)
        resp.raise_for_status()
        info = resp.json().get("model_info", {}) or {}
        # model_info keys are arch-prefixed, e.g. "qwen2.context_length".
        for k, v in info.items():
            if k.endswith(".context_length") and isinstance(v, (int, float)) and v > 0:
                ctx = int(v)
                break
    except Exception as exc:
        logger.debug("Could not read max context for '%s' via /api/show (%s); using %d.",
                     model, exc, ctx)
    _MODEL_MAX_CTX_CACHE[model] = ctx
    return ctx


def _request_with_deadline(method: str, url: str, deadline: float, **kwargs):
    """Run a blocking ``requests`` call under a HARD wall-clock *deadline* (s).

    ``requests``' own ``timeout=`` is an *inactivity* (between-bytes) timeout, so a
    wedged backend that dribbles a byte every few seconds can block far past it —
    this is exactly the failure that stalled a Phase-2 run for ~30 min on a single
    CVE. Running the call in a daemon thread and joining for ``deadline`` seconds
    turns it into a true total-time cap: if it has not returned by then we raise
    ``Timeout`` and abandon the worker (it dies on its own once its socket times
    out). The worker does NOT hold the GPU lock — the dispatcher does — so
    abandoning it is safe. This is what makes one hung LLM call recoverable
    (caught per-attempt, then per-CVE) instead of phase-fatal.
    """
    box: Dict[str, Any] = {}

    def _worker():
        try:
            box["resp"] = requests.request(method, url, **kwargs)
        except BaseException as exc:  # noqa: BLE001 — re-raised in the caller below
            box["exc"] = exc

    t = threading.Thread(target=_worker, daemon=True, name="llm-http")
    t.start()
    t.join(deadline)
    if t.is_alive():
        raise requests.exceptions.Timeout(
            f"hard deadline {deadline:.0f}s exceeded (backend unresponsive)")
    if "exc" in box:
        raise box["exc"]
    return box["resp"]


class _HeartbeatPulser:
    """Background daemon that periodically refreshes the live-progress heartbeat.

    The executor's idle watchdog keys "is this phase alive?" off the mtime of
    ``results/.live_progress_p{N}.json``, which the main loop only rewrites *after*
    each CVE completes. A single long (or wedged) LLM call therefore produces no
    heartbeat for its whole duration and can trip the idle kill, taking the rest
    of the phase (and Phases 3–4) down with it. This pulser re-emits the heartbeat
    every ``interval`` seconds for as long as a CVE is being processed, so a
    healthy-but-slow CVE keeps the watchdog satisfied while the hard per-call
    deadline above still bounds a genuinely stuck one. Strictly best-effort: the
    pulse callback swallows its own errors and the thread only ever writes a tiny
    file, so it cannot disturb or slow the run, and it never touches the GPU lock.
    """

    def __init__(self, pulse, interval: int):
        self._pulse = pulse
        self._interval = max(5, int(interval)) if interval else 0
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None

    def __enter__(self):
        if self._pulse and self._interval:
            self._thread = threading.Thread(
                target=self._run, daemon=True, name="phase2-heartbeat")
            self._thread.start()
        return self

    def _run(self):
        while not self._stop.wait(self._interval):
            try:
                self._pulse()
            except Exception:  # noqa: BLE001 — heartbeat must never break a run
                pass

    def __exit__(self, *exc):
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        return False


def _call_ollama_api(model: str, user_prompt: str, system_prompt: str,
                     temperature: Optional[float] = None) -> Tuple[Optional[str], Dict[str, Any]]:
    """Call the Ollama-compatible local server API with retry logic.

    Before sending, verify the prompt fits the model's context window. If it does
    not, the model is SKIPPED with a clearly logged reason (also recorded in
    ``metadata['error']``) so the feedback-loop ramp advances to the next model
    instead of the Ollama server silently truncating the prompt.

    *temperature* (when set) overrides ``LLM_TEMPERATURE`` for this call (used by
    the candidate fan-out); ``None`` keeps the configured default.
    """
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt}
    ]

    # --- Context-fit guard ---------------------------------------------------
    model_max = _model_max_ctx(model)
    eff_ctx = min(NUM_CTX, model_max)        # never request more than the model supports
    est_prompt_tokens = (len(system_prompt) + len(user_prompt)) // 4   # ~4 chars/token
    metadata: Dict[str, Any] = {
        "model": model,
        "provider": "ollama",
        "timestamp_start": datetime.now().isoformat(),
        "retries": 0,
        "success": False,
        "error": None,
        "est_prompt_tokens": est_prompt_tokens,
        "model_max_ctx": model_max,
        "num_ctx": eff_ctx,
    }
    if est_prompt_tokens > eff_ctx - _MIN_OUTPUT_HEADROOM:
        # Check against eff_ctx (what we actually allocate = min(NUM_CTX, model_max)),
        # not model_max — otherwise a prompt could pass on the model's theoretical
        # max yet still overflow the smaller window we send and be silently truncated.
        reason = (f"context_exceeds_model_window: prompt ~{est_prompt_tokens} tokens "
                  f"exceeds the usable context window ({eff_ctx} tokens; model "
                  f"'{model}' max {model_max})")
        logger.error(
            "Model '%s' SKIPPED — prompt (~%d tokens) exceeds its usable context "
            "window (%d tokens); advancing to the next model in the ramp.",
            model, est_prompt_tokens, eff_ctx)
        metadata["error"] = reason
        metadata["context_skip"] = True
        metadata["timestamp_end"] = datetime.now().isoformat()
        return None, metadata

    # Cap the output budget so prompt + output fit within the effective window.
    num_predict = min(LLM_MAX_TOKENS, max(256, eff_ctx - est_prompt_tokens))
    payload = {
        "model": model,
        "messages": messages,
        "stream": False,
        "options": {
            "temperature": LLM_TEMPERATURE if temperature is None else float(temperature),
            # num_ctx capped at the model's window; output budget pinned so a long
            # patch is not truncated by the server's default num_predict.
            "num_ctx": eff_ctx,
            "num_predict": num_predict,
        }
    }
    # Keep the model warm in the (remote proxy) VRAM so the next request in this
    # burst doesn't trigger a cold reload. Empty ⇒ omit (Ollama's 5m default).
    if LLM_KEEP_ALIVE:
        payload["keep_alive"] = LLM_KEEP_ALIVE
    metadata["payload_size"] = len(json.dumps(payload))
    for attempt in range(MAX_RETRIES):
        try:
            logger.debug(f"Ollama API call attempt {attempt + 1}/{MAX_RETRIES} for model {model}")
            # HARD wall-clock cap (not just requests' inactivity timeout) so a
            # wedged/dribbling backend can't block this attempt past API_TIMEOUT.
            response = _request_with_deadline(
                "POST", API_ENDPOINT, deadline=API_TIMEOUT,
                json=payload, timeout=API_TIMEOUT, auth=OLLAMA_AUTH)
            response.raise_for_status()
            result = response.json()
            content = result.get('message', {}).get('content', '')
            metadata["timestamp_end"] = datetime.now().isoformat()
            metadata["success"] = True
            metadata["retries"] = attempt
            metadata["prompt_tokens"] = result.get('prompt_eval_count', None)
            metadata["response_tokens"] = result.get('eval_count', None)
            metadata["total_duration"] = result.get('total_duration', None)
            logger.debug(f"Ollama API call successful for model {model}")
            _check_gpu_status(model)
            return content, metadata
        except requests.exceptions.Timeout:
            logger.warning(f"Timeout on attempt {attempt + 1} for model {model}")
            metadata["error"] = f"Timeout after {API_TIMEOUT}s"
            metadata["retries"] = attempt + 1
        except requests.exceptions.RequestException as e:
            logger.warning(f"Request error on attempt {attempt + 1} for model {model}: {e}")
            metadata["error"] = str(e)
            metadata["retries"] = attempt + 1
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode error for model {model}: {e}")
            metadata["error"] = f"Invalid JSON response: {e}"
            metadata["retries"] = attempt + 1
        if attempt < MAX_RETRIES - 1:
            logger.info(f"Retrying in {RETRY_DELAY} seconds...")
            time.sleep(RETRY_DELAY)
    metadata["timestamp_end"] = datetime.now().isoformat()
    logger.error(f"All {MAX_RETRIES} attempts failed for model {model}")
    return None, metadata


def _is_openai_reasoning_model(model: str) -> bool:
    """True for models that use the newer Chat Completions parameter contract.

    The gpt-5 family and the o-series reasoning models (o1/o3/o4...) reject
    ``max_tokens`` (they require ``max_completion_tokens``) and only accept the
    default ``temperature`` (1). Older chat models (gpt-4.1, gpt-4o, gpt-4-*,
    gpt-3.5-*) take ``max_tokens`` + a custom temperature.

    Delegates to the shared rule in ``cve_aggregator.utils.llm_compat`` so the
    model-family list lives in exactly one place across all LLM phases.
    """
    return _shared_is_openai_reasoning_model(model)


def _openai_sampling_kwargs(model: str, temperature: Optional[float] = None) -> Dict[str, Any]:
    """Return model-appropriate token/temperature kwargs for the chat call.

    *temperature* overrides the configured ``LLM_TEMPERATURE`` for this single
    call (used by the candidate fan-out to sample diverse candidates at different
    temperatures); ``None`` keeps the configured default — so existing callers
    are unchanged.
    """
    if _is_openai_reasoning_model(model):
        # Reasoning models bill reasoning tokens against the completion budget,
        # so give them headroom (8k can be fully consumed by reasoning, leaving
        # empty content). Temperature is omitted (only the default is allowed),
        # so a per-candidate override does not apply to these models.
        return {"max_completion_tokens": max(LLM_MAX_TOKENS, 16384)}
    temp = LLM_TEMPERATURE if temperature is None else float(temperature)
    return {"max_tokens": LLM_MAX_TOKENS, "temperature": temp}


def _call_openai_api(model: str, user_prompt: str, system_prompt: str,
                     temperature: Optional[float] = None) -> Tuple[Optional[str], Dict[str, Any]]:
    """Call the OpenAI API with retry logic.

    *temperature* (when set) overrides ``LLM_TEMPERATURE`` for this call; ``None``
    keeps the configured default.
    """
    try:
        from openai import OpenAI, APIError, APIConnectionError, APITimeoutError, RateLimitError
    except ImportError:
        raise RuntimeError(
            "The 'openai' package is required for provider='openai'. "
            "Install it with: pip install openai>=1.0.0"
        )

    if not OPENAI_API_KEY:
        raise RuntimeError(
            "OpenAI API key not configured. Set the OPENAI_API_KEY environment "
            "variable or llm.openai_api_key in config.yaml."
        )

    _client_kwargs: Dict[str, Any] = {"api_key": OPENAI_API_KEY, "timeout": API_TIMEOUT}
    if OPENAI_BASE_URL:
        _client_kwargs["base_url"] = OPENAI_BASE_URL
    client = OpenAI(**_client_kwargs)
    metadata: Dict[str, Any] = {
        "model": model,
        "provider": "openai",
        "timestamp_start": datetime.now().isoformat(),
        "retries": 0,
        "success": False,
        "error": None
    }

    # Token/temperature contract differs between classic and reasoning models.
    # Start from the name-based guess; the loop below adapts if the API rejects it.
    sampling = _openai_sampling_kwargs(model, temperature)

    for attempt in range(MAX_RETRIES):
        try:
            logger.debug(f"OpenAI API call attempt {attempt + 1}/{MAX_RETRIES} for model {model}")
            completion = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                **sampling,
            )
            content = completion.choices[0].message.content or ""
            usage = completion.usage
            metadata["timestamp_end"] = datetime.now().isoformat()
            metadata["success"] = True
            metadata["retries"] = attempt
            metadata["prompt_tokens"] = usage.prompt_tokens if usage else None
            metadata["response_tokens"] = usage.completion_tokens if usage else None
            metadata["total_tokens"] = usage.total_tokens if usage else None
            logger.debug(f"OpenAI API call successful for model {model}")
            return content, metadata
        except (APITimeoutError, APIConnectionError) as e:
            logger.warning(f"OpenAI connection/timeout on attempt {attempt + 1}: {e}")
            metadata["error"] = str(e)
            metadata["retries"] = attempt + 1
        except RateLimitError as e:
            logger.warning(f"OpenAI rate limit on attempt {attempt + 1}: {e}")
            metadata["error"] = str(e)
            metadata["retries"] = attempt + 1
        except APIError as e:
            logger.error(f"OpenAI API error on attempt {attempt + 1}: {e}")
            metadata["error"] = str(e)
            metadata["retries"] = attempt + 1
            # Adaptive parameter fallback: if the model rejects the token/
            # temperature parameter we chose (e.g. a reasoning model the name
            # heuristic missed), swap to the other contract and retry without
            # consuming the delay. Covers both directions.
            msg = str(e).lower()
            if "max_completion_tokens" in msg and "max_tokens" in sampling:
                logger.info(
                    f"Model {model} requires max_completion_tokens — switching "
                    f"parameter contract and retrying."
                )
                sampling = {"max_completion_tokens": max(LLM_MAX_TOKENS, 16384)}
                continue
            if (("'temperature'" in msg or "unsupported value: 'temperature'" in msg
                 or "temperature" in msg and "unsupported" in msg)
                    and "temperature" in sampling):
                logger.info(
                    f"Model {model} rejects a custom temperature — dropping it and retrying."
                )
                sampling.pop("temperature", None)
                continue
            if "max_tokens" in msg and "max_completion_tokens" in sampling:
                logger.info(
                    f"Model {model} requires max_tokens — switching parameter contract."
                )
                sampling = {"max_tokens": LLM_MAX_TOKENS,
                            "temperature": LLM_TEMPERATURE if temperature is None else float(temperature)}
                continue
        if attempt < MAX_RETRIES - 1:
            logger.info(f"Retrying in {RETRY_DELAY} seconds...")
            time.sleep(RETRY_DELAY)

    metadata["timestamp_end"] = datetime.now().isoformat()
    logger.error(f"All {MAX_RETRIES} OpenAI attempts failed for model {model}")
    return None, metadata


def call_llm_api(model: str, user_prompt: str, system_prompt: Optional[str] = None,
                 model_override: Optional[str] = None,
                 temperature: Optional[float] = None) -> Tuple[Optional[str], Dict[str, Any]]:
    """
    Call the configured LLM backend (Ollama or OpenAI) with retry logic.

    Dispatches to ``_call_ollama_api`` or ``_call_openai_api`` based on
    ``llm.provider`` in config.yaml.  For the OpenAI provider, *model* is
    normally replaced by ``OPENAI_MODEL`` (the caller-supplied value is ignored
    so the per-CVE model-iteration loop in Phase 2 still works without changes).

    ``model_override`` takes precedence over both: the feedback loop uses it to
    select a different model per retry attempt (see ``models_by_attempt`` in
    config.yaml). When set, it is the model actually used and recorded in the
    returned metadata for BOTH providers.

    Args:
        model: Ollama model name (ignored when provider="openai" and no override)
        user_prompt: The user's prompt
        system_prompt: System prompt for context
        model_override: Explicit model id to use, overriding the provider default
        temperature: Optional per-call sampling-temperature override (candidate
            fan-out); None keeps the configured llm.temperature

    Returns:
        Tuple of (response_content, metadata_dict)
    """
    # Resolve the default at CALL time so a project-specific prompt applied after
    # import (main() re-applies phase2 once --phase0-config is known) is honored.
    if system_prompt is None:
        system_prompt = SYSTEM_PROMPT
    # Hold the host-global GPU mutex for the duration of this inference so a
    # concurrent cell's GPU work can't thrash the shared model. No-op for OpenAI
    # and uncontended when a single cell runs. Per-call here is safe: Phase 2 and
    # the feedback loop both reach this dispatcher sequentially (no intra-process
    # threads), and releasing between calls lets other GPU tasks interleave.
    _used_model = (model_override or OPENAI_MODEL) if LLM_PROVIDER == "openai" else (model_override or model)
    with gpu_lock(LLM_PROVIDER, enabled=GPU_LOCK_ENABLED, endpoint=API_ENDPOINT,
                  logger=logger, label=f"phase2:{_used_model}"):
        if LLM_PROVIDER == "openai":
            return _call_openai_api(model_override or OPENAI_MODEL, user_prompt,
                                    system_prompt, temperature=temperature)
        return _call_ollama_api(model_override or model, user_prompt,
                                system_prompt, temperature=temperature)

# =============================================================================
# Code Extraction & Cleaning
# =============================================================================

def strip_markdown_fences(code: str) -> str:
    """
    Aggressively remove all markdown code fences from the code.
    
    Args:
        code: Code string potentially containing markdown fences
    
    Returns:
        Code with all markdown fences removed
    """
    if not code:
        return ""
    
    # First pass: remove code blocks with language specifiers
    # Handles: ```c, ```C, ```cpp, ```h, ```c\n, ```c\r\n, etc.
    code = re.sub(r'^\s*```[a-zA-Z0-9+#]*\s*[\r\n]+', '', code)
    code = re.sub(r'[\r\n]+\s*```[a-zA-Z0-9+#]*\s*[\r\n]+', '\n', code)
    
    # Remove closing code fences at end of string or line
    code = re.sub(r'[\r\n]*\s*```\s*$', '', code)
    code = re.sub(r'[\r\n]+\s*```\s*[\r\n]+', '\n', code)
    
    # Remove any remaining standalone ``` lines (with or without language)
    code = re.sub(r'^\s*```[a-zA-Z0-9+#]*\s*$', '', code, flags=re.MULTILINE)
    
    # Remove any backtick sequences that might remain (3 or more)
    code = re.sub(r'^`{3,}[^`\n]*[\r\n]?', '', code, flags=re.MULTILINE)
    code = re.sub(r'[\r\n]?`{3,}\s*$', '', code)
    
    # Handle inline backticks around code blocks sometimes added by LLMs
    code = re.sub(r'^`+\s*[\r\n]', '', code)
    code = re.sub(r'[\r\n]\s*`+$', '', code)
    
    return code.strip()


def _walk_to_matching_brace(view: str, open_idx: int) -> int:
    """Return the index just past the brace matching ``view[open_idx]``.

    *view* must be an analysis view (comments and inactive #if branches
    blanked), so only string/char literals need handling here. Returns -1
    if no matching brace is found.
    """
    depth = 0
    in_string = False
    in_char = False
    escape_next = False
    i = open_idx
    n = len(view)
    while i < n:
        ch = view[i]
        if escape_next:
            escape_next = False
        elif ch == '\\':
            escape_next = True
        elif ch == '"' and not in_char:
            in_string = not in_string
        elif ch == "'" and not in_string:
            in_char = not in_char
        elif not in_string and not in_char:
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    return i + 1
        i += 1
    return -1


def extract_code_from_response(response: str, function_name: str) -> str:
    """
    Extract clean C code from LLM response.
    
    Args:
        response: Raw LLM response
        function_name: Expected function name for validation
    
    Returns:
        Cleaned C code string
    """
    if not response:
        return ""
    
    code = response.strip()
    
    # First pass: aggressively strip markdown fences
    code = strip_markdown_fences(code)
    
    # Try to extract code from within markdown code blocks first (if present)
    # This handles cases where the LLM wraps code in ``` despite being told not to
    code_block_match = re.search(r'```[a-zA-Z]*\s*\n(.*?)```', code, re.DOTALL)
    if code_block_match:
        code = code_block_match.group(1).strip()
    
    # Remove any leading/trailing explanatory text before/after the function
    # Look for the function definition start - handle various C function signatures
    # Support common patterns: return_type func_name(...) {
    func_patterns = [
        # Standard pattern with function name
        rf'((?:static\s+)?(?:inline\s+)?(?:__attribute__\s*\([^)]*\)\s*)?' \
        rf'(?:const\s+)?(?:unsigned\s+)?(?:signed\s+)?(?:long\s+)?(?:short\s+)?' \
        rf'(?:struct\s+\w+\s*\*?|enum\s+\w+|union\s+\w+|\w+)\s*\**\s*' \
        rf'{re.escape(function_name)}\s*\([^{{]*\)\s*\{{)',
        # Try with less strict matching (in case params span multiple lines)
        rf'(\b{re.escape(function_name)}\s*\([^;]*?\)\s*\{{)',
    ]
    
    # Search and brace-match on the analysis view (comments and inactive
    # #if branches blanked) but slice from the original text — apostrophes
    # in comments and #if/#else brace imbalance must not corrupt the walk.
    view = _build_analysis_view(code)
    match = None
    for pattern in func_patterns:
        match = re.search(pattern, view, re.MULTILINE | re.DOTALL)
        if match:
            break
    if match:
        start_idx = match.start()
        open_idx = view.find('{', start_idx)
        end_idx = _walk_to_matching_brace(view, open_idx) if open_idx != -1 else -1
        if end_idx == -1:
            # No matching brace found — keep the rest of the response
            # rather than returning an empty extraction.
            end_idx = len(code)
        code = code[start_idx:end_idx]
    
    # Final cleanup - strip markdown fences again after extraction
    code = strip_markdown_fences(code)
    code = code.strip()
    
    # Remove any remaining markdown artifacts (belt and suspenders)
    code = re.sub(r'^\s*```.*$', '', code, flags=re.MULTILINE)
    code = re.sub(r'`{3,}', '', code)  # Remove any remaining triple backticks
    
    return code.strip()

def clean_code(code: str) -> str:
    """
    Additional cleaning for the extracted code.
    
    Args:
        code: Extracted C code
    
    Returns:
        Cleaned C code
    """
    if not code:
        return ""
    
    # First, strip any remaining markdown fences
    code = strip_markdown_fences(code)
    
    # Remove potential leading/trailing artifacts
    lines = code.split('\n')
    cleaned_lines = []
    skip_until_code = True  # Skip non-code lines at the start
    
    for line in lines:
        stripped = line.strip()
        
        # Skip markdown fence lines
        if stripped.startswith('```'):
            continue
        
        # Skip lines that look like LLM explanatory text at the start
        if skip_until_code:
            # Check if this looks like the start of actual C code
            is_code_start = (
                stripped.startswith(('static ', 'int ', 'void ', 'char ', 'unsigned ', 
                                   'signed ', 'long ', 'short ', 'struct ', 'enum ',
                                   'const ', 'extern ', 'inline ', '__', '#', '/*',
                                   'typedef ', 'union ', 'float ', 'double ', 'size_t ',
                                   'ssize_t ', 'bool ', '_Bool ')) or
                re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*\s*\(', stripped) or  # Function name
                re.match(r'^[a-zA-Z_][a-zA-Z0-9_]*\s+[a-zA-Z_]', stripped)  # Type name
            )
            if is_code_start:
                skip_until_code = False
            elif stripped and not stripped.startswith('//'):
                # Non-empty, non-comment line that doesn't look like code - skip it
                continue
        
        # Skip explanatory comments from LLM (but keep legitimate code comments)
        if stripped.startswith('//') and any(x in line.lower() for x in 
            ['here is', 'here\'s', 'this is', 'the following', 'note:', 'patched version', 
             'fixed version', 'solution:', 'below is', 'i have', 'i\'ve']):
            continue
        
        cleaned_lines.append(line)
    
    # Remove trailing non-code lines
    while cleaned_lines and not cleaned_lines[-1].strip():
        cleaned_lines.pop()
    
    result = '\n'.join(cleaned_lines).strip()
    
    # Final pass to remove any remaining markdown artifacts
    result = re.sub(r'`{3,}[a-zA-Z0-9]*', '', result)
    
    return result


# Lines consisting only of type/qualifier tokens (e.g. "char *",
# "static unsigned long int", "internal_function") — used to pull the
# GNU-style return type, written on its own line, into the function span.
_DECL_PREFIX_RE = re.compile(r'^[ \t]*[A-Za-z_][A-Za-z0-9_ \t]*\**[ \t]*$')


# Whitespace + optional K&R-style parameter declarations between `)` and `{`.
# `;` is a hard delimiter and `()` are excluded, so it can't bridge across a
# call site or run away (no catastrophic backtracking). Matches the empty string
# for ANSI `) {`, so normal functions are unaffected.
_KR_PARAMS_RE = re.compile(r'\s*(?:[^;{}()]*;)*\s*')


def find_function_boundaries(file_content: str, function_name: str) -> Tuple[int, int]:
    """
    Find the start and end positions of a function in C source code.

    Scans an analysis view (comments and inactive #if branches blanked) with
    an O(n) walk — no regex backtracking — and slices using offsets valid in
    the original content. The returned span includes return-type/qualifier
    lines written above the function name (GNU style: ``char *\\n__getcwd``),
    so replacing the span never leaves a stray return-type line behind.

    Returns:
        Tuple of (start_index, end_index) or (-1, -1) if not found
    """
    view = _build_analysis_view(file_content)
    name_pat = re.compile(rf'\b{re.escape(function_name)}\s*\(')

    for m in name_pat.finditer(view):
        name_start = m.start()

        # Walk past the parameter list (balanced parens)
        i = m.end() - 1  # position of the '(' matched by \(
        paren_depth = 0
        scan_limit = min(name_start + 8192, len(view))
        while i < scan_limit:
            c = view[i]
            if c == '(':
                paren_depth += 1
            elif c == ')':
                paren_depth -= 1
                if paren_depth == 0:
                    i += 1
                    break
            i += 1
        else:
            continue  # no matching )

        # Skip whitespace / newlines AND optional K&R-style parameter
        # declarations between ) and { — old C puts the decls there:
        #   ____STRTOF_INTERNAL (nptr, endptr, group, loc)
        #        const STRING_TYPE *nptr;
        #        ... { ... }
        # Mirrors the Phase 0 code_parser fix. The `;`-delimited, ()-free skip
        # cannot bridge a CALL site (`f(a,b);` then code) into a brace: a call
        # hits `}` (end of caller) or `(` before any `{`, so it's still rejected.
        kr = _KR_PARAMS_RE.match(view, i, scan_limit)
        if kr:
            i = kr.end()

        if i >= scan_limit or view[i] != '{':
            # No opening brace → this is a call or forward declaration
            continue

        brace_pos = i

        # Start of the line containing the function name
        line_start = view.rfind('\n', 0, name_start)
        func_start = line_start + 1 if line_start != -1 else 0

        # Extend upward over return-type/qualifier lines (GNU style puts
        # the return type on its own line above the name).
        for _ in range(4):
            if func_start == 0:
                break
            prev_nl = view.rfind('\n', 0, func_start - 1)
            prev_start = prev_nl + 1 if prev_nl != -1 else 0
            prev_line = view[prev_start:func_start - 1]
            if prev_line.strip() and _DECL_PREFIX_RE.match(prev_line):
                func_start = prev_start
            else:
                break

        end_idx = _walk_to_matching_brace(view, brace_pos)
        if end_idx != -1:
            return func_start, end_idx

    logger.warning(f"Could not find function '{function_name}' in file content")
    return -1, -1


def replace_function_in_file(file_content: str, function_name: str, patched_function: str) -> Tuple[str, bool]:
    """
    Replace a function in the full file content with a patched version.
    
    Args:
        file_content: Full C source file content
        function_name: Name of the function to replace
        patched_function: The patched function code
    
    Returns:
        Tuple of (patched_file_content, success)
    """
    start_idx, end_idx = find_function_boundaries(file_content, function_name)
    
    if start_idx == -1 or end_idx == -1:
        logger.error(f"Could not locate function '{function_name}' for replacement")
        return file_content, False
    
    # Build the new file content
    before = file_content[:start_idx]
    after = file_content[end_idx:]
    
    # Ensure proper spacing
    patched_function = patched_function.strip()
    
    # Add newline before if needed
    if before and not before.endswith('\n'):
        before += '\n'
    
    # Add newline after if needed  
    if after and not after.startswith('\n'):
        patched_function += '\n'
    
    patched_file = before + patched_function + after

    logger.debug(f"Replaced function '{function_name}' (chars {start_idx}-{end_idx})")
    return patched_file, True


# =============================================================================
# SEARCH/REPLACE edit application
# =============================================================================
#
# Phase 2 asks the model for minimal SEARCH/REPLACE edits rather than a whole
# rewritten function. Each block is applied to the PRISTINE original file by
# literal string match, so the function signature, declaring macros (MPN_VAR),
# K&R prototypes and the hundreds of unchanged lines are never re-transcribed
# (and therefore never corrupted). Whole-function regeneration is kept only as
# a fallback for when the model ignores the edit-block format entirely.

# Tolerant block matcher: any run of >=3 of the marker char, `SEARCH`/`REPLACE`
# may carry trailing text, and the `=======` / `>>>>>>> REPLACE` lines are
# anchored to line starts (^) so a stray `=`/`>` inside code can't terminate a
# block early.
_SR_BLOCK_RE = re.compile(
    r"<{3,}\s*SEARCH[^\n]*\n(.*?)^={3,}[^\n]*\n(.*?)^>{3,}\s*REPLACE",
    re.DOTALL | re.MULTILINE,
)


def parse_search_replace_blocks(response: str) -> List[Tuple[str, str]]:
    """Parse all SEARCH/REPLACE blocks from an LLM response.

    Returns a list of ``(search_text, replace_text)`` tuples (leading/trailing
    blank lines trimmed). Empty-SEARCH blocks are dropped — we only support
    anchored edits, not blind insertions. Returns ``[]`` when the response
    contains no well-formed blocks (the caller then falls back to whole-function
    handling).
    """
    if not response:
        return []
    blocks: List[Tuple[str, str]] = []
    for m in _SR_BLOCK_RE.finditer(response):
        search = m.group(1).strip("\n")
        replace = m.group(2).strip("\n")
        if search.strip() == "":
            continue
        blocks.append((search, replace))
    return blocks


def _line_start_offsets(content: str) -> List[int]:
    """Char offset of the start of each line in *content* (split on '\\n')."""
    offsets = []
    idx = 0
    for line in content.split("\n"):
        offsets.append(idx)
        idx += len(line) + 1  # + newline
    return offsets


def _find_block_region(content: str, search: str) -> Optional[Tuple[int, int]]:
    """Locate *search* within *content*.

    Tries an exact substring match first, then a whitespace-tolerant match that
    compares lines after stripping leading/trailing whitespace (handles tab/space
    and trailing-whitespace drift between the model's quote and the real file —
    harmless for C, which is whitespace-insensitive). Returns ``(start, end)``
    char offsets of the matched region, or ``None`` if not found.
    """
    # 1. Exact match
    pos = content.find(search)
    if pos != -1:
        return pos, pos + len(search)

    # 2. Whitespace-tolerant, line-based match
    c_lines = content.split("\n")
    s_lines = [ln.strip() for ln in search.split("\n")]
    while s_lines and s_lines[0] == "":
        s_lines.pop(0)
    while s_lines and s_lines[-1] == "":
        s_lines.pop()
    if not s_lines:
        return None

    n = len(s_lines)
    offsets = _line_start_offsets(content)
    c_stripped = [ln.strip() for ln in c_lines]
    for i in range(len(c_lines) - n + 1):
        if c_stripped[i:i + n] == s_lines:
            start = offsets[i]
            end = offsets[i + n - 1] + len(c_lines[i + n - 1])  # end of last line, before its '\n'
            return start, end
    return None


def apply_search_replace_blocks(
    file_content: str, blocks: List[Tuple[str, str]]
) -> Tuple[str, int, List[str]]:
    """Apply SEARCH/REPLACE *blocks* to *file_content* in order.

    Each block's SEARCH region is located in the CURRENT (progressively edited)
    content and replaced. Returns ``(new_content, applied_count, errors)`` where
    *errors* lists the 1-based indices/reasons of blocks whose SEARCH text could
    not be located.
    """
    new_content = file_content
    applied = 0
    errors: List[str] = []
    for i, (search, replace) in enumerate(blocks, 1):
        region = _find_block_region(new_content, search)
        if region is None:
            first_line = search.strip().splitlines()[0] if search.strip() else ""
            errors.append(f"block {i}: SEARCH text not found (starts with: {first_line[:80]!r})")
            continue
        start, end = region
        new_content = new_content[:start] + replace + new_content[end:]
        applied += 1
    return new_content, applied, errors


def build_patched_file_from_response(
    raw_response: str, function_name: str, file_context: str
) -> Dict[str, Any]:
    """Turn an LLM response into a patched file + the contract the rest of
    Phase 2 expects.

    Preference order:
      1. SEARCH/REPLACE edit blocks applied to the pristine ``file_context``.
      2. Fallback (model ignored the format): whole-function extraction + splice.

    Returns a dict with:
      - ``full_patched_file``: the patched file content
      - ``patched_function``: the patched function text (re-extracted from the
        file for SR mode, or the extracted function for whole-function mode) —
        used for the ``_function_only`` artifact and structural validation
      - ``function_replaced``: bool
      - ``mode``: ``"search_replace"`` | ``"whole_function"``
      - ``apply_error``: set when SR blocks parsed but did NOT apply cleanly
        (forces an invalid verdict so the file is never silently left unpatched)
      - ``sr_blocks`` / ``sr_applied``: edit-block counts (for metadata)
    """
    blocks = parse_search_replace_blocks(raw_response)

    if blocks:
        new_file, applied, errors = apply_search_replace_blocks(file_context, blocks)
        if applied == len(blocks) and not errors:
            patched_function = _extract_function_text(new_file, function_name)
            return {
                "full_patched_file": new_file,
                "patched_function": patched_function or new_file,
                "function_replaced": True,
                "mode": "search_replace",
                "apply_error": None,
                "sr_blocks": len(blocks),
                "sr_applied": applied,
            }
        # Blocks were produced but did not all apply — do NOT fall back to a
        # whole-function parse (the response isn't a function). Surface the
        # mismatch so the feedback loop can re-quote SEARCH text. The file is
        # left unchanged and explicitly marked invalid.
        msg = (
            f"{applied}/{len(blocks)} SEARCH/REPLACE blocks applied; "
            + "; ".join(errors)
        )
        logger.warning(f"SEARCH/REPLACE apply incomplete for '{function_name}': {msg}")
        partial_file, _ = (new_file, applied) if applied else (file_context, 0)
        return {
            "full_patched_file": partial_file,
            "patched_function": f"/* SEARCH/REPLACE apply failed: {msg} */",
            "function_replaced": applied > 0,
            "mode": "search_replace",
            "apply_error": msg,
            "sr_blocks": len(blocks),
            "sr_applied": applied,
        }

    # Fallback: no edit blocks at all → treat the response as a whole function.
    patched_function = clean_code(extract_code_from_response(raw_response, function_name))
    if not patched_function:
        patched_function = raw_response
    full_file, replaced = replace_function_in_file(file_context, function_name, patched_function)
    if not replaced:
        full_file = patched_function
    return {
        "full_patched_file": full_file,
        "patched_function": patched_function,
        "function_replaced": replaced,
        "mode": "whole_function",
        "apply_error": None,
        "sr_blocks": 0,
        "sr_applied": 0,
    }


def _extract_function_text(file_content: str, function_name: str) -> str:
    """Slice the full text of *function_name* out of *file_content* (return-type
    line included), or ``""`` if it can't be located."""
    start_idx, end_idx = find_function_boundaries(file_content, function_name)
    if start_idx == -1 or end_idx == -1:
        return ""
    return file_content[start_idx:end_idx].strip()


# =============================================================================
# Syntax Validation
# =============================================================================

def is_missing_header_error(error_msg: str) -> bool:
    """
    Check if the error is due to a missing project-internal header.

    The project-internal header list is project-supplied (project YAML
    ``phase2.internal_headers`` -> the ``INTERNAL_HEADERS`` global); the generic
    "fatal error: <name>.h" regex below is the primary, project-agnostic arbiter,
    so even an empty list catches missing-header errors.

    Args:
        error_msg: The GCC error message

    Returns:
        True if the error is about a missing internal header
    """
    if 'No such file or directory' not in error_msg and 'file not found' not in error_msg.lower():
        return False

    # Any missing header during HOST-side syntax checking is an environment
    # limitation, not a patch defect: project-internal headers only exist
    # inside the container build tree (Phase 3's in-container rebuild is the
    # real arbiter). Fall back to structural validation in that case.
    if re.search(r'fatal error:\s*[^\n:]+\.h', error_msg):
        return True

    # Check if any known project-internal header is mentioned
    for header in INTERNAL_HEADERS:
        if header in error_msg:
            return True

    return False


def validate_function_structure(code: str, function_name: str) -> Tuple[bool, str]:
    """
    Perform structural validation on a C function without requiring compilation.
    
    This checks for common issues like mismatched braces, parentheses, and
    other structural problems that don't require header files.
    
    Args:
        code: The function code to validate
        function_name: Name of the function for error messages
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not code or not code.strip():
        return False, "Empty code provided"
    
    # Check for markdown artifacts
    if '```' in code:
        return False, "Code contains markdown artifacts (```)"
    
    # Check for mismatched braces on the analysis view: comments and
    # non-first #if/#else branches are blanked, so glibc-style code that
    # opens the same brace in every preprocessor branch (e.g. STRCOLL) is
    # not falsely flagged, and apostrophes in comments don't corrupt the
    # char-literal tracking.
    view = _build_analysis_view(code)
    brace_count = 0
    in_string = False
    in_char = False
    escape_next = False
    for char in view:
        if escape_next:
            escape_next = False
        elif char == '\\':
            escape_next = True
        elif char == '"' and not in_char:
            in_string = not in_string
        elif char == "'" and not in_string:
            in_char = not in_char
        elif not in_string and not in_char:
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1

    if brace_count != 0:
        return False, f"Mismatched braces: {brace_count} {'unclosed' if brace_count > 0 else 'extra closing'}"

    # Check parentheses balance on the same view (comments and inactive
    # branches excluded for the same reason)
    paren_count = view.count('(') - view.count(')')
    if abs(paren_count) > 0:
        return False, f"Mismatched parentheses: {paren_count} {'unclosed' if paren_count > 0 else 'extra closing'}"
    
    # Check for common C syntax issues
    # Double semicolons (usually a mistake)
    if ';;' in re.sub(r'for\s*\([^)]*\)', '', code):  # Exclude for loop headers
        pass  # This is actually sometimes valid in C
    
    # Check that function starts with a reasonable declaration
    if not re.search(rf'\b{re.escape(function_name)}\s*\(', code):
        return False, f"Function '{function_name}' declaration not found in code"
    
    return True, ""


def validate_syntax(full_file_code: str, function_name: str, patched_function: str = None) -> Tuple[bool, str]:
    """
    Validate C code syntax using multiple strategies.
    
    First performs structural validation, then attempts GCC compilation.
    For glibc code with internal headers, falls back to structural validation only.
    
    Args:
        full_file_code: Complete C source file with patched function integrated
        function_name: Name of the function (for logging)
        patched_function: The patched function code only (for structural checks)
    
    Returns:
        Tuple of (is_valid, error_message)
    """
    if not full_file_code or not full_file_code.strip():
        return False, "Empty code provided"
    
    # First, validate the patched function structure
    if patched_function:
        struct_valid, struct_error = validate_function_structure(patched_function, function_name)
        if not struct_valid:
            return False, struct_error
    
    # Check for markdown artifacts in full file
    if '```' in full_file_code:
        return False, "Code contains markdown artifacts (```)"

    # GCC syntax checking only applies to C (project YAML phase2.language). For
    # other languages the brace/paren structural check above is the host-side
    # arbiter; Phase 3's in-container rebuild is the real compile gate. Keeps the
    # validator project-agnostic — no language toolchain assumption in code.
    if PATCH_LANGUAGE != "c":
        if patched_function:
            return validate_function_structure(patched_function, function_name)
        return True, ""

    # Try GCC validation
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.c', delete=False) as f:
            f.write(full_file_code)
            temp_path = f.name
        
        # Run GCC syntax check with relaxed warnings
        result = subprocess.run(
            ['gcc', '-fsyntax-only', '-c', '-w', '-Wno-implicit-function-declaration', temp_path],
            capture_output=True,
            text=True,
            timeout=30
        )
        
        os.unlink(temp_path)
        
        if result.returncode == 0:
            return True, ""
        else:
            error_msg = result.stderr.strip() if result.stderr else result.stdout.strip()
            error_msg = re.sub(r'/tmp/tmp\w+\.c:', 'line ', error_msg)
            
            # If the error is just about missing glibc-internal headers,
            # consider the structural validation sufficient
            if is_missing_header_error(error_msg):
                logger.debug(f"GCC failed due to missing glibc headers, using structural validation")
                # Re-validate structure to be sure
                if patched_function:
                    struct_valid, struct_error = validate_function_structure(patched_function, function_name)
                    if struct_valid:
                        return True, ""  # Structural validation passed
                    return False, struct_error
                return True, ""  # No patched function to check, assume OK
            
            return False, error_msg
            
    except subprocess.TimeoutExpired:
        if os.path.exists(temp_path):
            os.unlink(temp_path)
        return False, "GCC timeout during syntax check"
        
    except FileNotFoundError:
        logger.error("GCC not found. Please ensure GCC is installed and in PATH.")
        # Fall back to structural validation
        if patched_function:
            return validate_function_structure(patched_function, function_name)
        return False, "GCC not found and no function code to structurally validate"
        
    except Exception as e:
        if 'temp_path' in locals() and os.path.exists(temp_path):
            os.unlink(temp_path)
        return False, f"Validation error: {str(e)}"

# =============================================================================
# Output Management
# =============================================================================

def sanitize_model_name(model: str) -> str:
    """Convert model name to filesystem-safe format."""
    return model.replace(':', '_').replace('/', '_')

def save_patch_artifacts(
    cve_id: str,
    model: str,
    original_filepath: str,
    patched_function: str,
    full_patched_file: str,
    raw_response: str,
    metadata: Dict[str, Any],
    is_valid: bool,
    validation_error: str,
    function_replaced: bool
) -> Path:
    """
    Save all patch artifacts to the output directory.
    
    Args:
        cve_id: CVE identifier
        model: Model name used
        original_filepath: Original file path from CSV
        patched_function: Extracted/cleaned patched function code
        full_patched_file: Complete file with patched function integrated
        raw_response: Raw LLM response
        metadata: API call metadata
        is_valid: Whether syntax validation passed
        validation_error: Error message if validation failed
        function_replaced: Whether the function was successfully replaced in file
    
    Returns:
        Path to the output directory
    """
    # Create output directory structure
    model_safe = sanitize_model_name(model)
    output_path = OUTPUT_DIR / cve_id / model_safe
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Determine output filename. Derive the extension from the actual vulnerable
    # file (e.g. .c, .java) so the artifacts are not hardcoded to C.
    original_filename = Path(original_filepath).name
    base_name = Path(original_filename).stem
    ext = Path(original_filename).suffix or ".c"

    if is_valid:
        patch_filename = original_filename
    else:
        patch_filename = f"{base_name}_invalid{ext}"

    # Save the full patched file (complete file with function replaced)
    patch_file = output_path / patch_filename
    with open(patch_file, 'w') as f:
        f.write(full_patched_file)
    logger.info(f"Saved full patched file: {patch_file}")

    # Also save just the patched function for reference
    function_file = output_path / f"{base_name}_function_only{ext}"
    with open(function_file, 'w') as f:
        f.write(patched_function)
    logger.debug(f"Saved patched function: {function_file}")
    
    # Save raw response
    raw_file = output_path / "raw_response.txt"
    with open(raw_file, 'w') as f:
        f.write(raw_response if raw_response else "")
    
    # Update metadata with validation info
    metadata["syntax_valid"] = is_valid
    metadata["validation_error"] = validation_error if not is_valid else None
    metadata["output_file"] = str(patch_file)
    metadata["function_file"] = str(function_file)
    metadata["original_filepath"] = original_filepath
    metadata["cve_id"] = cve_id
    metadata["function_replaced"] = function_replaced
    
    # Save metadata
    metadata_file = output_path / "response.json"
    with open(metadata_file, 'w') as f:
        json.dump(metadata, f, indent=2)
    
    # Log syntax errors to dedicated log
    if not is_valid and validation_error:
        syntax_logger.error(
            f"CVE: {cve_id} | Model: {model} | File: {patch_filename}\n"
            f"Error: {validation_error}\n"
            f"{'-' * 60}"
        )
    
    return output_path

# =============================================================================
# Data Loading
# =============================================================================

def _detect_csv_delimiter(csv_path: Path) -> str:
    """Detect the CSV delimiter from the header line.

    The Phase 0 aggregator writes standard comma-separated CSV (quoted),
    while the legacy ``documentation/file-function.csv`` is
    semicolon-separated.  Counting candidate delimiters on the header line
    (column names never contain either character) disambiguates reliably.
    """
    with open(csv_path, 'r', encoding='utf-8', errors='replace') as f:
        header = f.readline()
    return ';' if header.count(';') > header.count(',') else ','


def load_vulnerability_data(csv_path: Path) -> pd.DataFrame:
    """
    Load and validate the vulnerability dataset.

    Args:
        csv_path: Path to the CSV file

    Returns:
        Pandas DataFrame with vulnerability data (one row per CVE, only
        rows that carry usable function-level data)
    """
    logger.info(f"Loading vulnerability data from {csv_path}")

    if not csv_path.exists():
        raise FileNotFoundError(f"CSV file not found: {csv_path}")

    sep = _detect_csv_delimiter(csv_path)
    logger.info(f"Detected CSV delimiter: {sep!r}")
    df = pd.read_csv(csv_path, sep=sep)

    # Validate required columns
    required_columns = ['CVE', 'FilePath', 'F_NAME', 'V_FILE', 'V_FUNCTION']
    missing_columns = [col for col in required_columns if col not in df.columns]
    if missing_columns:
        raise ValueError(f"Missing required columns: {missing_columns}")

    total_cves = df['CVE'].nunique()

    # Keep only rows with usable function-level data: patch generation
    # needs the vulnerable function body, its name, and the file path the
    # patch will later be applied to.
    usable = df
    for col in ('V_FUNCTION', 'F_NAME', 'FilePath'):
        usable = usable[usable[col].notna() & (usable[col].astype(str).str.strip() != '')]

    skipped = sorted(set(df['CVE'].unique()) - set(usable['CVE'].unique()))
    if skipped:
        logger.warning(
            f"Skipping {len(skipped)} CVE(s) with no extracted vulnerable-function "
            f"data (V_FUNCTION/F_NAME/FilePath empty): {skipped}"
        )

    # One row per CVE: Phase 0 orders rows best-first (production source
    # files before test files, units with vulnerable bodies first).
    usable = usable.drop_duplicates(subset=['CVE'], keep='first')

    logger.info(f"Loaded {len(usable)} usable CVE entries (of {total_cves} total)")
    logger.info(f"CVEs: {usable['CVE'].unique().tolist()}")

    return usable

# =============================================================================
# Main Pipeline
# =============================================================================

def _family_ramp_from(start_model: str) -> List[str]:
    """Ordered family ramp (by attempt number) beginning at *start_model*.

    Phase 2 uses the first model of the family; this returns that model followed
    by the rest of the ramp so generation can fall through to the next model when
    one cannot fit the prompt in its context window. Falls back to just
    ``[start_model]`` when no per-attempt ramp is configured.
    """
    if not FEEDBACK_MODELS_BY_ATTEMPT:
        return [start_model]
    ordered, seen = [], set()
    for k in sorted(FEEDBACK_MODELS_BY_ATTEMPT, key=lambda x: int(x)):
        m = FEEDBACK_MODELS_BY_ATTEMPT[k]
        if m and m not in seen:
            seen.add(m)
            ordered.append(m)
    if start_model in ordered:
        return ordered[ordered.index(start_model):]
    return [start_model] + [m for m in ordered if m != start_model]


def _generate_with_family_fallback(
    prompt: str, start_model: str
) -> Tuple[Optional[str], Dict[str, Any], str]:
    """Phase-2 generation with family-ramp fallback on context overflow.

    Starts with *start_model* (the first model of the family). If a model cannot
    fit the prompt in its context window (``metadata['context_skip']``), advance
    to the next model in the ramp and retry — so Phase 2 still produces an
    attempt-1 patch instead of leaving nothing for the feedback loop to build on.
    ONLY a context overflow advances the ramp; any other outcome (success, or a
    different failure handled elsewhere) stops here. Returns
    ``(raw_response, metadata, model_used)``.
    """
    ramp = _family_ramp_from(start_model)
    raw_response: Optional[str] = None
    metadata: Dict[str, Any] = {"error": "no model attempted"}
    used_model = start_model
    for candidate in ramp:
        used_model = candidate
        raw_response, metadata = call_llm_api(candidate, prompt)
        if raw_response is None and metadata.get("context_skip") and candidate != ramp[-1]:
            logger.warning(
                "Phase 2: model '%s' cannot fit the prompt in its context window — "
                "falling back to the next model in the family ramp.", candidate)
            continue
        break
    return raw_response, metadata, used_model


def process_single_vulnerability(
    row: pd.Series,
    model: str
) -> Dict[str, Any]:
    """
    Process a single vulnerability with a specific model.
    
    Args:
        row: DataFrame row containing vulnerability data
        model: Model name to use
    
    Returns:
        Dictionary with processing results
    """
    cve_id = row['CVE']
    function_name = row['F_NAME']
    vulnerable_code = row['V_FUNCTION']
    file_context = row['V_FILE']
    original_filepath = row['FilePath']
    
    logger.info(f"\n{'─' * 60}")
    logger.info(f"  {cve_id}  [{function_name}]  model={model}")
    logger.info(f"{'─' * 60}")
    
    result = {
        "cve_id": cve_id,
        "function_name": function_name,
        "model": model,
        "success": False
    }

    # Generate prompt (with CVE description + PoC source when available)
    vuln_context = _build_vulnerability_context(
        cve_id,
        description=str(row.get("CVE_Description", "") or ""),
        cwe=str(row.get("CWE", "") or ""),
        cwe_description=str(row.get("CWE_Description", "") or ""),
    )
    prompt = create_patch_prompt(cve_id, function_name, vulnerable_code,
                                 file_context, vuln_context)

    # Call the LLM, starting with the first model of the family and falling
    # through to the next model on a context-window overflow (ollama only; a
    # no-op for OpenAI, which ignores the per-call model). The model that
    # actually handled it is what we record for this CVE.
    raw_response, metadata, model = _generate_with_family_fallback(prompt, model)
    result["model"] = model

    if raw_response is None:
        logger.error(f"Failed to get response for {cve_id} with {model}")
        result["error"] = metadata.get("error", "Unknown error")
        
        # Save empty artifacts for tracking
        save_patch_artifacts(
            cve_id=cve_id,
            model=model,
            original_filepath=original_filepath,
            patched_function="/* No response from LLM */",
            full_patched_file=file_context,  # Keep original file
            raw_response="",
            metadata=metadata,
            is_valid=False,
            validation_error="No LLM response",
            function_replaced=False
        )
        return result
    
    # Build the patched file from the response: minimal SEARCH/REPLACE edits
    # applied to the pristine file, with whole-function regeneration as a
    # fallback when the model ignores the edit-block format.
    patch = build_patched_file_from_response(raw_response, function_name, file_context)
    patched_function = patch["patched_function"]
    full_patched_file = patch["full_patched_file"]
    function_replaced = patch["function_replaced"]
    metadata["patch_mode"] = patch["mode"]
    metadata["sr_blocks"] = patch["sr_blocks"]
    metadata["sr_applied"] = patch["sr_applied"]

    if patch["mode"] == "search_replace":
        logger.info(
            f"✓ Applied {patch['sr_applied']}/{patch['sr_blocks']} SEARCH/REPLACE "
            f"edit(s) for {cve_id} with {model}"
        )
    elif function_replaced:
        logger.info(f"✓ Function replaced (whole-function fallback) for {cve_id} with {model}")
    else:
        logger.warning(f"Could not apply patch for {cve_id} with {model}")

    # Validate: an unapplied edit block is an immediate failure (file unchanged);
    # otherwise syntax-check the FULL patched file (has all includes and type defs).
    if patch["apply_error"]:
        is_valid, validation_error = False, patch["apply_error"]
    else:
        is_valid, validation_error = validate_syntax(
            full_patched_file, function_name, patched_function
        )

    if is_valid:
        logger.info(f"✓ Syntax valid for {cve_id} with {model}")
    else:
        logger.warning(f"✗ Syntax invalid for {cve_id} with {model}: {validation_error[:100]}...")
    
    # Save artifacts
    output_path = save_patch_artifacts(
        cve_id=cve_id,
        model=model,
        original_filepath=original_filepath,
        patched_function=patched_function,
        full_patched_file=full_patched_file,
        raw_response=raw_response,
        metadata=metadata,
        is_valid=is_valid,
        validation_error=validation_error,
        function_replaced=function_replaced
    )
    
    result["success"] = True
    result["syntax_valid"] = is_valid
    result["output_path"] = str(output_path)
    
    # Include token usage and runtime metadata
    result["prompt_tokens"] = metadata.get("prompt_tokens")
    result["response_tokens"] = metadata.get("response_tokens")
    result["total_duration_ns"] = metadata.get("total_duration")
    result["timestamp_start"] = metadata.get("timestamp_start")
    result["timestamp_end"] = metadata.get("timestamp_end")

    return result


def generate_one_candidate(row: Any, model: str, recipe: Recipe) -> Candidate:
    """Generate ONE patch candidate for *row* under the diversity knobs in *recipe*.

    This is the binding between the project-agnostic candidate fan-out framework
    (``master_pipeline.candidates``) and the existing Phase 2 generation
    primitives. It builds the same vulnerability-context + prompt as
    :func:`process_single_vulnerability`, then applies the recipe's diversity
    dimensions (sampling temperature, granularity / chain-of-thought prompt
    suffix, per-recipe model), parses the response into a patched file, and
    syntax-checks it — WITHOUT writing artifacts to disk (the caller persists
    only the selected winner). The returned :class:`Candidate` is what the
    framework dedupes, pre-filters and hands to the oracle.

    With the greedy recipe (index 0, minimal granularity, CoT off, base
    temperature) this reproduces today's single-shot generation exactly.

    Args:
        row: vulnerability row (pandas Series or dict) with the Phase 0 fields
            ``CVE``, ``F_NAME``, ``V_FUNCTION``, ``V_FILE`` and optionally
            ``CVE_Description`` / ``CWE`` / ``CWE_Description``.
        model: the cell's base model id (recipe.model overrides it when set).
        recipe: the diversity point to generate.

    Returns:
        A :class:`Candidate` (``error`` set when the LLM returned nothing).
    """
    def _get(key: str, default: str = "") -> str:
        try:
            val = row.get(key, default)
        except AttributeError:
            val = row[key] if key in row else default
        return "" if val is None else str(val)

    cve_id = _get("CVE")
    function_name = _get("F_NAME")
    vulnerable_code = _get("V_FUNCTION")
    file_context = _get("V_FILE")

    vuln_context = _build_vulnerability_context(
        cve_id,
        description=_get("CVE_Description"),
        cwe=_get("CWE"),
        cwe_description=_get("CWE_Description"),
    )
    prompt = create_patch_prompt(
        cve_id, function_name, vulnerable_code, file_context, vuln_context,
        extra_instructions=recipe.prompt_suffix(),
    )

    raw_response, metadata = call_llm_api(
        model, prompt,
        model_override=recipe.model,
        temperature=recipe.temperature,
    )
    metadata["recipe"] = recipe.label()

    if raw_response is None:
        return Candidate(
            recipe=recipe,
            full_patched_file=file_context,   # unchanged original
            patched_function="",
            syntax_valid=False,
            raw_response="",
            metadata=metadata,
            error=metadata.get("error", "no LLM response"),
        )

    patch = build_patched_file_from_response(raw_response, function_name, file_context)
    metadata["patch_mode"] = patch["mode"]
    metadata["sr_blocks"] = patch["sr_blocks"]
    metadata["sr_applied"] = patch["sr_applied"]

    if patch["apply_error"]:
        is_valid, validation_error = False, patch["apply_error"]
    else:
        is_valid, validation_error = validate_syntax(
            patch["full_patched_file"], function_name, patch["patched_function"]
        )
    metadata["validation_error"] = validation_error if not is_valid else None

    return Candidate(
        recipe=recipe,
        full_patched_file=patch["full_patched_file"],
        patched_function=patch["patched_function"],
        syntax_valid=is_valid,
        raw_response=raw_response,
        changes=int(patch.get("sr_applied") or 0),
        metadata=metadata,
        error=None,
    )


def generate_patch_with_feedback(
    cve_id: str,
    function_name: str,
    vulnerable_code: str,
    file_context: str,
    original_filepath: str,
    model: str,
    previous_patch: str,
    failure_context: Dict[str, Any],
    attempt_number: int,
    output_dir: Optional[Path] = None,
    generation_model: Optional[str] = None,
    prior_attempts: Optional[List[Dict[str, Any]]] = None,
    include_diff: bool = False,
    include_history: bool = False,
    reflexion: bool = False
) -> Dict[str, Any]:
    """
    Generate a new patch using failure feedback from Phase 3 validation.
    
    This function is called by the iterative feedback loop when a patch fails
    validation. It provides the LLM with context about why the previous
    patch failed to guide generation of an improved patch.
    
    Args:
        cve_id: The CVE identifier
        function_name: Name of the vulnerable function
        vulnerable_code: The vulnerable function code
        file_context: Full file content for context
        original_filepath: Original file path from CSV
        model: Model name to use
        previous_patch: The previous failed patch attempt
        failure_context: Dictionary containing failure details from Phase 3
        attempt_number: Current retry attempt number (1-based)
        output_dir: Optional custom output directory
        generation_model: Explicit model id for this attempt (per-attempt
            escalation from feedback_loop.models_by_attempt). None = provider default.

    Returns:
        Dictionary with processing results including:
        - success: Whether patch generation succeeded
        - syntax_valid: Whether the patch has valid syntax
        - output_path: Path to saved artifacts
        - patched_function: The generated patch code
        - full_patched_file: Complete file with patch integrated
        - attempt_number: The attempt number
    """
    # In-process feedback retries call this function directly (not via main()),
    # so rebase the module-global EXPLOITS_DIR to the active run's base dir here.
    # output_dir is <base_dir>/patches, so its parent is the run base_dir; without
    # this the PoC lookup would fall back to the pipeline-root exploits/ and the
    # exploit would be silently dropped from the retry prompt.
    global EXPLOITS_DIR
    if output_dir is not None:
        EXPLOITS_DIR = Path(output_dir).parent / str(_paths.get("exploits_dir", "exploits"))

    # Resolve the model actually used for this attempt. ``generation_model`` (from
    # feedback_loop.models_by_attempt) escalates per retry; when absent we fall
    # back to the provider default (OPENAI_MODEL for OpenAI, else the loop model).
    effective_model = generation_model or (OPENAI_MODEL if LLM_PROVIDER == "openai" else model)
    logger.info(
        f"    generating with {effective_model}"
        + (f" (escalated from {model})" if generation_model and generation_model != model else "")
    )

    result = {
        "cve_id": cve_id,
        "function_name": function_name,
        "model": model,
        "generation_model": effective_model,
        "attempt_number": attempt_number,
        "success": False,
        "is_retry": True
    }
    
    # Create feedback-enhanced prompt (PoC source so the model sees the
    # exact attack it failed to stop; description comes from the CSV when
    # invoked through Phase 2, or is omitted in feedback-only invocations)
    vuln_context = _build_vulnerability_context(cve_id)
    prompt = create_feedback_prompt(
        cve_id=cve_id,
        function_name=function_name,
        vulnerable_code=vulnerable_code,
        file_context=file_context,
        previous_patch=previous_patch,
        failure_context=failure_context,
        attempt_number=attempt_number,
        vuln_context=vuln_context,
        prior_attempts=prior_attempts,
        include_diff=include_diff,
        include_history=include_history,
        reflexion=reflexion
    )
    
    # Call LLM API with feedback system prompt (escalated model when configured)
    raw_response, metadata = call_llm_api(
        model, prompt, system_prompt=FEEDBACK_SYSTEM_PROMPT,
        model_override=generation_model,
    )

    # Add retry metadata
    metadata["is_retry"] = True
    metadata["attempt_number"] = attempt_number
    metadata["generation_model"] = effective_model
    metadata["failure_context_summary"] = {
        "status": failure_context.get("status"),
        "poc_blocked": failure_context.get("poc_blocked"),
        "sast_passed": failure_context.get("sast_passed"),
        "build_success": failure_context.get("build_success")
    }
    
    if raw_response is None:
        logger.error(f"Failed to get retry response for {cve_id} with {effective_model}")
        result["error"] = metadata.get("error", "Unknown error")
        return result
    
    # Build the patched file via SEARCH/REPLACE edits (whole-function fallback)
    patch = build_patched_file_from_response(raw_response, function_name, file_context)
    patched_function = patch["patched_function"]
    full_patched_file = patch["full_patched_file"]
    function_replaced = patch["function_replaced"]
    metadata["patch_mode"] = patch["mode"]
    metadata["sr_blocks"] = patch["sr_blocks"]
    metadata["sr_applied"] = patch["sr_applied"]

    if patch["mode"] == "search_replace":
        logger.info(
            f"✓ Applied {patch['sr_applied']}/{patch['sr_blocks']} SEARCH/REPLACE "
            f"edit(s) for retry {cve_id} with {effective_model}"
        )
    elif function_replaced:
        logger.info(f"✓ Function replaced (whole-function fallback) for retry {cve_id} with {effective_model}")
    else:
        logger.warning(f"Could not apply retry patch for {cve_id} with {effective_model}")

    # Validate: an unapplied edit block fails immediately; else syntax-check the file.
    if patch["apply_error"]:
        is_valid, validation_error = False, patch["apply_error"]
    else:
        is_valid, validation_error = validate_syntax(
            full_patched_file, function_name, patched_function
        )

    if is_valid:
        logger.info(f"✓ Syntax valid for retry #{attempt_number} of {cve_id} with {effective_model}")
    else:
        logger.warning(f"✗ Syntax invalid for retry #{attempt_number}: {validation_error[:100]}...")
    
    # Determine output directory (with retry suffix)
    if output_dir is None:
        output_dir = OUTPUT_DIR
    
    # Name the retry directory by the model that ACTUALLY generated it (the
    # escalated per-attempt model), not the loop's base identity — so the
    # artifacts path matches the "Generating … with <model>" logs.
    model_safe = sanitize_model_name(effective_model)
    retry_output_path = output_dir / cve_id / f"{model_safe}_retry{attempt_number}"
    retry_output_path.mkdir(parents=True, exist_ok=True)
    
    # Save artifacts with retry-specific naming (extension from the vuln file)
    original_filename = Path(original_filepath).name
    base_name = Path(original_filename).stem
    ext = Path(original_filename).suffix or ".c"

    patch_filename = original_filename if is_valid else f"{base_name}_invalid{ext}"

    # Save the full patched file
    patch_file = retry_output_path / patch_filename
    with open(patch_file, 'w') as f:
        f.write(full_patched_file)

    # Save function only
    function_file = retry_output_path / f"{base_name}_function_only{ext}"
    with open(function_file, 'w') as f:
        f.write(patched_function)
    
    # Save raw response
    raw_file = retry_output_path / "raw_response.txt"
    with open(raw_file, 'w') as f:
        f.write(raw_response if raw_response else "")
    
    # Update and save metadata
    metadata["syntax_valid"] = is_valid
    metadata["validation_error"] = validation_error if not is_valid else None
    metadata["output_file"] = str(patch_file)
    metadata["function_file"] = str(function_file)
    metadata["original_filepath"] = original_filepath
    metadata["cve_id"] = cve_id
    metadata["function_replaced"] = function_replaced
    
    metadata_file = retry_output_path / "response.json"
    with open(metadata_file, 'w') as f:
        json.dump(metadata, f, indent=2)
    
    logger.info(f"Saved retry patch #{attempt_number} artifacts to: {retry_output_path}")
    
    result["success"] = True
    result["syntax_valid"] = is_valid
    result["output_path"] = str(retry_output_path)
    result["patched_function"] = patched_function
    result["full_patched_file"] = full_patched_file
    result["patch_file"] = str(patch_file)
    result["validation_error"] = validation_error if not is_valid else None
    
    # Include token usage and runtime metadata
    result["prompt_tokens"] = metadata.get("prompt_tokens")
    result["response_tokens"] = metadata.get("response_tokens")
    result["total_duration_ns"] = metadata.get("total_duration")
    result["timestamp_start"] = metadata.get("timestamp_start")
    result["timestamp_end"] = metadata.get("timestamp_end")
    
    return result

def run_pipeline(
    csv_path: Path = CSV_PATH,
    models: List[str] = MODELS,
    cve_filter: Optional[List[str]] = None,
    manifest_path: Optional[Path] = None,
) -> Dict[str, Any]:
    """
    Run the complete patch generation pipeline.
    
    Args:
        csv_path: Path to the vulnerability CSV
        models: List of models to use
        cve_filter: Optional list of CVE IDs to process (None = all)
    
    Returns:
        Pipeline execution summary
    """
    phase_start_time = datetime.now()
    logger.info("=" * 60)
    logger.info("Starting Phase 2: Patch Generation Pipeline")
    logger.info(f"Phase Start Time: {phase_start_time.isoformat()}")
    logger.info("=" * 60)
    logger.info(f"Models: {models}")
    
    # Load data
    try:
        df = load_vulnerability_data(csv_path)
    except Exception as e:
        logger.error(f"Failed to load data: {e}")
        return {"success": False, "error": str(e)}

    # Apply CVE filter if specified
    if cve_filter:
        df = df[df['CVE'].isin(cve_filter)]
        logger.info(f"Filtered to {len(df)} entries for CVEs: {cve_filter}")

    # Restrict to CVEs whose vulnerability Phase 1 actually reproduced
    # (a deterministic baseline exit code exists in the image manifest).
    # Generating patches for unreproduced CVEs would waste LLM calls AND
    # produce patches Phase 3 could never validate dynamically.
    # Use the PROJECT's manifest path (phase1.image_manifest_path, resolved in
    # main()), NOT a hardcoded name — otherwise a non-glibc run reads glibc's
    # stale results/image_manifest.json and ignores its OWN reproduced CVEs.
    if manifest_path is None:
        manifest_path = OUTPUT_DIR.parent / str(_paths.get("results", "results")) / "image_manifest.json"
    reproduced = None   # set when the manifest is read; drives funnel bookkeeping
    if manifest_path.exists():
        try:
            with open(manifest_path) as f:
                manifest = json.load(f)
            reproduced = {
                e["cve"] for e in manifest.get("cve_images", [])
                if e.get("baseline_exit_code") is not None
                and not e.get("needs_manual_revision")
            }
            not_reproduced = sorted(set(df['CVE'].unique()) - reproduced)
            if not_reproduced:
                logger.warning(
                    f"Skipping {len(not_reproduced)} CVE(s) without a Phase 1 "
                    f"baseline (not reproduced / manual revision): {not_reproduced}"
                )
            df = df[df['CVE'].isin(reproduced)]
            logger.info(f"{len(df)} CVE(s) have a Phase 1 baseline and proceed to generation")
        except Exception as e:
            logger.warning(f"Could not apply Phase 1 manifest filter ({e}); proceeding with all CVEs")
    else:
        logger.warning(f"No Phase 1 manifest at {manifest_path} — proceeding with all CVEs")

    # Funnel bookkeeping (persisted so the dashboard reconciles Phase 1 → Phase 2
    # from the artifact instead of inferring it): CVEs Phase 1 reproduced but
    # skipped here for having no extractable vulnerable function (empty
    # V_FUNCTION/F_NAME/FilePath — e.g. test-only fix commits). The only filters
    # between "reproduced" and "patch task" are the reproduced gate itself and the
    # no-function drop in load_vulnerability_data(), so this difference is exactly
    # the no-function set.
    _df_cves = {str(c).upper() for c in df['CVE'].unique()}
    if reproduced is not None:
        _repro_up = {str(c).upper() for c in reproduced}
        # A --cve filter restricts this run to a subset; without intersecting,
        # reproduced CVEs outside the filter would be mislabeled "no function".
        if cve_filter:
            _repro_up &= {str(c).upper() for c in cve_filter}
        skipped_no_function = sorted(_repro_up - _df_cves)
        phase1_reproduced = len(_repro_up)
    else:
        skipped_no_function = []
        phase1_reproduced = None
    funnel = {
        "phase1_reproduced": phase1_reproduced,
        "patch_cves": len(_df_cves),
        "skipped_no_function": skipped_no_function,
        "skipped_no_function_count": len(skipped_no_function),
    }

    if len(df) == 0:
        # Legitimate empty result, NOT a failure: this run simply reproduced no
        # CVEs in Phase 1 (e.g. a project whose only PoCs don't exercise the build),
        # or no CVE had an extracted vulnerable function. There is nothing to patch,
        # so exit cleanly and let Phases 3/4 run on an empty set — a red ❌ here
        # would wrongly fail the whole pipeline over "nothing to do".
        logger.warning("No CVEs eligible for patch generation (none reproduced in "
                       "Phase 1 / no extracted function) — nothing to patch; exiting cleanly")
        # Write a fresh ZEROED summary so the execution-summary table reads 0/0
        # for THIS run — otherwise a stale pipeline_summary.json (e.g. a previous
        # project's run in a shared base-dir) would be read and show a bogus count.
        empty_summary = {"summary": {"total_tasks": 0, "successful": 0,
                                     "syntax_valid": 0, "failed": 0},
                         "funnel": funnel, "results": []}
        try:
            OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
            with open(OUTPUT_DIR / "pipeline_summary.json", "w") as f:
                json.dump(empty_summary, f, indent=2)
        except Exception as exc:
            logger.warning(f"Could not write empty pipeline_summary.json: {exc}")
        return {"success": True, "no_eligible_cves": True, "summary": {}}
    
    logger.info(f"Total tasks to process: {len(df) * len(models)}")
    
    # Process each vulnerability with each model
    results = []
    total_tasks = len(df) * len(models)
    current_task = 0
    _live_dir = OUTPUT_DIR.parent / str(_paths.get("results", "results"))

    def _emit_live(done, running=True):
        if not live_progress:
            return
        sv = sum(1 for r in results if r.get("syntax_valid"))
        si = sum(1 for r in results if r.get("success") and not r.get("syntax_valid"))
        live_progress.emit(_live_dir, 2, total_tasks, done,
                           {"syntax_valid": sv, "syntax_invalid": si}, running=running)

    _emit_live(0)

    for model in models:
        logger.info(f"\n{'='*40}")
        logger.info(f"Processing with model: {model}")
        logger.info(f"{'='*40}")

        # Warm this model into VRAM before its CVE burst (Ollama only); the
        # keep_alive on each request then holds it resident. Best-effort.
        if LLM_PRELOAD and LLM_PROVIDER != "openai":
            try:
                _preload_ollama_model(model)
            except Exception as exc:  # preload must never break the phase
                logger.warning("Ollama preload skipped for %s: %s", model, exc)

        for idx, row in df.iterrows():
            current_task += 1
            task_start = datetime.now()
            logger.info(f"\nTask {current_task}/{total_tasks} - {row['CVE']} with {model}")
            
            try:
                # Keep the idle watchdog informed for the whole CVE (LLM call +
                # post-processing), not just at completion, so a healthy-but-slow
                # CVE is not mistaken for a stalled phase. The hard per-call
                # deadline still bounds a genuinely stuck call; a failure there is
                # caught here, recorded, and the loop moves on (stall isolation).
                with _HeartbeatPulser(lambda: _emit_live(len(results)),
                                      LLM_HEARTBEAT_INTERVAL):
                    result = process_single_vulnerability(row, model)
                results.append(result)
                task_duration = (datetime.now() - task_start).total_seconds()
                logger.info(f"Completed task {current_task}/{total_tasks} in {task_duration:.1f}s")
            except Exception as e:
                logger.error(f"Unexpected error processing {row['CVE']} with {model}: {e}")
                results.append({
                    "cve_id": row['CVE'],
                    "model": model,
                    "success": False,
                    "error": str(e),
                    "timestamp_start": task_start.isoformat(),
                    "timestamp_end": datetime.now().isoformat()
                })
            
            _emit_live(current_task)

            # Small delay between API calls to avoid overwhelming the server
            time.sleep(1)

    _emit_live(total_tasks, running=False)

    # Generate summary
    phase_end_time = datetime.now()
    phase_duration = (phase_end_time - phase_start_time).total_seconds()
    
    # Calculate aggregate statistics per model
    model_stats = {}
    for r in results:
        model = r.get("model")
        if model not in model_stats:
            model_stats[model] = {
                "total_tasks": 0,
                "successful": 0,
                "syntax_valid": 0,
                "total_prompt_tokens": 0,
                "total_response_tokens": 0,
                "total_duration_ns": 0,
                "total_runtime_seconds": 0.0
            }
        model_stats[model]["total_tasks"] += 1
        if r.get("success"):
            model_stats[model]["successful"] += 1
        if r.get("syntax_valid"):
            model_stats[model]["syntax_valid"] += 1
        if r.get("prompt_tokens"):
            model_stats[model]["total_prompt_tokens"] += r.get("prompt_tokens", 0)
        if r.get("response_tokens"):
            model_stats[model]["total_response_tokens"] += r.get("response_tokens", 0)
        if r.get("total_duration_ns"):
            model_stats[model]["total_duration_ns"] += r.get("total_duration_ns", 0)
            model_stats[model]["total_runtime_seconds"] += r.get("total_duration_ns", 0) / 1e9
    
    # Calculate aggregate statistics per CVE
    cve_stats = {}
    for r in results:
        cve_id = r.get("cve_id")
        if cve_id not in cve_stats:
            cve_stats[cve_id] = {
                "total_tasks": 0,
                "successful": 0,
                "syntax_valid": 0,
                "total_prompt_tokens": 0,
                "total_response_tokens": 0,
                "total_duration_ns": 0,
                "total_runtime_seconds": 0.0
            }
        cve_stats[cve_id]["total_tasks"] += 1
        if r.get("success"):
            cve_stats[cve_id]["successful"] += 1
        if r.get("syntax_valid"):
            cve_stats[cve_id]["syntax_valid"] += 1
        if r.get("prompt_tokens"):
            cve_stats[cve_id]["total_prompt_tokens"] += r.get("prompt_tokens", 0)
        if r.get("response_tokens"):
            cve_stats[cve_id]["total_response_tokens"] += r.get("response_tokens", 0)
        if r.get("total_duration_ns"):
            cve_stats[cve_id]["total_duration_ns"] += r.get("total_duration_ns", 0)
            cve_stats[cve_id]["total_runtime_seconds"] += r.get("total_duration_ns", 0) / 1e9
    
    # Calculate totals
    total_prompt_tokens = sum(r.get("prompt_tokens", 0) or 0 for r in results)
    total_response_tokens = sum(r.get("response_tokens", 0) or 0 for r in results)
    total_llm_duration_ns = sum(r.get("total_duration_ns", 0) or 0 for r in results)
    total_llm_runtime_seconds = total_llm_duration_ns / 1e9 if total_llm_duration_ns else 0.0
    
    # Count different outcomes for better analysis
    api_success = sum(1 for r in results if r.get("success"))
    syntax_valid = sum(1 for r in results if r.get("syntax_valid"))
    api_failures = sum(1 for r in results if not r.get("success"))
    syntax_invalid = sum(1 for r in results if r.get("success") and not r.get("syntax_valid"))
    
    summary = {
        "metadata": {
            "generated_at": datetime.now().isoformat(),
            "phase": "Phase 2 - Patch Generation",
        },
        "phase_timing": {
            "start_time": phase_start_time.isoformat(),
            "end_time": phase_end_time.isoformat(),
            "total_duration_seconds": phase_duration,
        },
        "summary": {
            "total_tasks": total_tasks,
            "successful": api_success,
            "syntax_valid": syntax_valid,
            "failed": api_failures,
            "total_prompt_tokens": total_prompt_tokens,
            "total_response_tokens": total_response_tokens,
            "total_llm_runtime_seconds": total_llm_runtime_seconds,
        },
        "outcome_breakdown": {
            "api_success_count": api_success,
            "api_failure_count": api_failures,
            "syntax_valid_count": syntax_valid,
            "syntax_invalid_count": syntax_invalid,
            "success_rate": f"{(api_success/total_tasks*100):.1f}%" if total_tasks > 0 else "N/A",
            "syntax_valid_rate": f"{(syntax_valid/total_tasks*100):.1f}%" if total_tasks > 0 else "N/A",
        },
        "funnel": funnel,
        "model_statistics": model_stats,
        "cve_statistics": cve_stats,
        "results": results
    }
    
    # Save summary
    summary_file = OUTPUT_DIR / "pipeline_summary.json"
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    with open(summary_file, 'w') as f:
        json.dump(summary, f, indent=2)
    
    # Print final summary
    logger.info("\n" + "=" * 60)
    logger.info("Phase 2 Complete")
    logger.info("=" * 60)
    logger.info(f"Phase End Time: {phase_end_time.isoformat()}")
    logger.info(f"Phase Duration: {phase_duration:.1f}s ({phase_duration/60:.1f}m)")
    logger.info(f"Total tasks: {total_tasks}")
    logger.info(f"Successful API calls: {summary['summary']['successful']}")
    logger.info(f"Syntax valid patches: {summary['summary']['syntax_valid']}")
    logger.info(f"Failed: {summary['summary']['failed']}")
    logger.info(f"Total prompt tokens: {total_prompt_tokens}")
    logger.info(f"Total response tokens: {total_response_tokens}")
    logger.info(f"Total LLM runtime: {total_llm_runtime_seconds:.1f}s")
    logger.info(f"Output directory: {OUTPUT_DIR}")
    logger.info(f"Summary saved to: {summary_file}")
    logger.info("=" * 60)
    
    return summary

# =============================================================================
# CLI Interface
# =============================================================================

def main():
    """Main entry point with CLI argument handling."""
    import argparse
    
    parser = argparse.ArgumentParser(
        description="AI-SSD Automated Patch Generation Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python patch_generator.py                    # Process all CVEs with all models
  python patch_generator.py --cve CVE-2015-7547  # Process specific CVE
  python patch_generator.py --model qwen2.5:7b   # Use specific model only
  python patch_generator.py --dry-run            # Show what would be processed
        """
    )
    
    parser.add_argument(
        '--base-dir',
        type=str,
        default=str(BASE_DIR),
        help='Base directory for the project (default: script directory)'
    )
    
    parser.add_argument(
        '--cve',
        type=str,
        nargs='+',
        help='Specific CVE ID(s) to process'
    )
    
    parser.add_argument(
        '--model',
        type=str,
        nargs='+',
        help='Specific model(s) to use'
    )
    
    parser.add_argument(
        '--csv',
        type=str,
        default=None,
        help='Path to the vulnerability CSV file'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be processed without making API calls'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose/debug logging output'
    )

    parser.add_argument(
        '--phase0-config',
        type=str,
        default=None,
        help='Path to the active project Phase 0 YAML; its phase2: section '
             '(prompts, language, internal_headers) overrides the defaults.'
    )

    args = parser.parse_args()

    # Re-apply the project phase2 config now that the active project YAML is
    # known (the import-time default followed config.yaml's pointer, which may
    # not be the project this run targets, e.g. tomcat vs the glibc default).
    # Also resolve THIS project's Phase 1 manifest path (phase1.image_manifest_path)
    # so the reproduced-CVE filter reads the right manifest, not glibc's default.
    base_dir = Path(args.base_dir)
    manifest_path = base_dir / "results" / "image_manifest.json"
    if args.phase0_config:
        p0 = Path(args.phase0_config)
        _p0doc = _load_yaml(p0) if p0.exists() else {}
        _apply_phase2((_p0doc.get("phase2") or {}))
        _mrel = (_p0doc.get("phase1") or {}).get("image_manifest_path")
        if _mrel:
            _mpath = Path(_mrel)
            manifest_path = _mpath if _mpath.is_absolute() else base_dir / _mpath

    # Set up paths based on base-dir
    csv_path = Path(args.csv) if args.csv else CSV_PATH
    
    # Update global OUTPUT_DIR / EXPLOITS_DIR based on base_dir
    global OUTPUT_DIR, EXPLOITS_DIR
    OUTPUT_DIR = base_dir / str(_paths.get("patches", "patches"))
    EXPLOITS_DIR = base_dir / str(_paths.get("exploits_dir", "exploits"))

    # Re-point logging at the ACTIVE project's logs dir. The module-level
    # setup_logging() ran at import against the pipeline-root LOG_DIR (BASE_DIR/
    # logs), so without this Phase 2's log lands in the global logs/ instead of
    # projects/<project>/logs/ (alongside Phase 0/1/3) — i.e. "not stored" from a
    # per-project view. Re-init now that --base-dir is known; setup_logging()
    # clears+re-adds handlers, so this moves the file cleanly.
    global LOG_DIR, logger
    LOG_DIR = base_dir / str(_paths.get("logs", "logs"))
    logger = setup_logging()

    # Adjust logging level if verbose
    if args.verbose:
        logging.getLogger('patch_generator').setLevel(logging.DEBUG)
        for handler in logging.getLogger('patch_generator').handlers:
            if isinstance(handler, logging.StreamHandler):
                handler.setLevel(logging.DEBUG)
    
    # Handle dry run
    if args.dry_run:
        df = load_vulnerability_data(csv_path)
        if args.model:
            models = args.model
        elif LLM_PROVIDER == "openai":
            models = [OPENAI_MODEL]
        else:
            models = MODELS
        cves = args.cve if args.cve else df['CVE'].unique().tolist()
        
        print("\nDry Run Summary:")
        print(f"  CVEs to process: {cves}")
        print(f"  Models to use: {models}")
        print(f"  Total API calls: {len(cves) * len(models)}")
        print(f"\nVulnerability Details:")
        
        for _, row in df[df['CVE'].isin(cves)].iterrows():
            print(f"  - {row['CVE']}: {row['F_NAME']} in {row['FilePath']}")
        
        return
    
    # Perform API health check before starting
    logger.info("Checking LLM API connectivity...")
    if not check_api_health():
        logger.error("Cannot proceed without a responsive LLM API. Please check:")
        if LLM_PROVIDER == "openai":
            logger.error("  1. Is OPENAI_API_KEY set correctly?")
            logger.error("  2. Is llm.openai_model a valid model name?")
        else:
            logger.error(f"  1. Is the server at {API_ENDPOINT} running?")
            logger.error("  2. Are the configured models available in Ollama?")
            logger.error(f"  3. Is there network connectivity?")
        sys.exit(1)
    
    # Pre-flight GPU readiness — ADVISORY ONLY. On a shared/persistent Ollama
    # proxy the GPU is rarely idle and ollama loads/evicts models itself, so a
    # "still busy" result must NOT abort the phase (the old sys.exit(2) killed
    # every CVE in the cell when the GPU merely had a model resident — which on a
    # proxy is the normal, ready state). Proceed and let each inference call's own
    # timeout + retries handle a genuinely unavailable backend.
    logger.info("Checking GPU availability...")
    _first_model = (args.model[0] if args.model
                    else (MODELS[0] if (LLM_PROVIDER != "openai" and MODELS) else None))
    if not wait_for_gpu(_first_model):
        logger.warning(
            "GPU still busy with other models after %d s — proceeding anyway "
            "(shared backend; ollama will load/evict as needed; each request is "
            "still bounded by the per-call timeout).",
            GPU_WAIT_TIMEOUT,
        )
    
    # Resolve models for the active provider: with OpenAI every configured
    # Ollama model name would route to the SAME OpenAI model, producing N
    # identical generations stored under misleading directory names.
    if args.model:
        models = args.model
    elif LLM_PROVIDER == "openai":
        models = [OPENAI_MODEL]
    else:
        models = MODELS

    # Run pipeline
    summary = run_pipeline(
        csv_path=csv_path,
        models=models,
        cve_filter=args.cve,
        manifest_path=manifest_path,
    )

    # Exit with appropriate code.
    #  * "nothing to patch" (no CVE reproduced / no extracted function) is a
    #    CLEAN no-op for multi-project runs — exit 0 so the pipeline continues.
    #  * A real hard failure (data load error) propagates as non-zero.
    #  * Producing 0 valid patches FROM eligible CVEs is still a failure.
    if summary.get("no_eligible_cves"):
        logger.info("Phase 2: no CVEs to patch (none reproduced) — clean no-op, exiting 0")
        sys.exit(0)
    if summary.get("success") is False or summary.get("error"):
        logger.error(f"Phase 2 failed: {summary.get('error', 'unknown error')}")
        sys.exit(1)
    stats = summary.get("summary", {})
    if stats.get("syntax_valid", 0) < 1:
        logger.error("Phase 2 produced no syntactically valid patch — failing phase")
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
