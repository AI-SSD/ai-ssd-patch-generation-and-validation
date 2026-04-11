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
import logging
import tempfile
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
from master_pipeline.config import load_pipeline_config, cfg_section  # noqa: E402

_cfg = load_pipeline_config(BASE_DIR)
_llm = _cfg.get("llm", {}) if isinstance(_cfg.get("llm"), dict) else {}
_paths = _cfg.get("paths", {}) if isinstance(_cfg.get("paths"), dict) else {}

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
# API key: env var takes precedence over config file value
OPENAI_API_KEY = os.environ.get("OPENAI_API_KEY") or str(_llm.get("openai_api_key", ""))

# Shared request settings
API_TIMEOUT = int(_llm.get("timeout", 600))
MAX_RETRIES = int(_llm.get("retry_attempts", 3))
RETRY_DELAY = int(_llm.get("retry_delay", 5))

# LLM Parameters
LLM_TEMPERATURE = float(_llm.get("temperature", 0.2))
LLM_MAX_TOKENS = int(_llm.get("max_tokens", 8192))

# Paths
CSV_PATH = BASE_DIR / str(_paths.get("csv_file", "documentation/file-function.csv"))
OUTPUT_DIR = BASE_DIR / str(_paths.get("patches", "patches"))
LOG_DIR = BASE_DIR / str(_paths.get("logs", "logs"))

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

SYSTEM_PROMPT = """You are an expert C security engineer specializing in vulnerability patching for the GNU C Library (glibc). Your task is to fix security vulnerabilities in C functions while maintaining complete backward compatibility.

CRITICAL REQUIREMENTS:
1. PRESERVE THE EXACT FUNCTION SIGNATURE - Do not modify the return type, function name, or parameter list under any circumstances.
2. Return ONLY the patched C function code - no explanations, no markdown formatting, no code fences.
3. Ensure the patch addresses the specific vulnerability while maintaining the original functionality.
4. Use defensive programming practices: bounds checking, input validation, and safe memory operations.
5. Maintain code style consistency with the original function.
6. Do not add new includes or external dependencies unless absolutely necessary for the fix.

OUTPUT FORMAT:
Return only valid C code. Start directly with the function definition. Do not wrap in markdown code blocks (```). Do not include any text before or after the function code."""


# System prompt for retry/feedback loop with failure context
FEEDBACK_SYSTEM_PROMPT = """You are an expert C security engineer specializing in vulnerability patching for the GNU C Library (glibc). Your previous patch attempt FAILED validation. You must analyze the failure and generate an improved patch.

CRITICAL REQUIREMENTS:
1. PRESERVE THE EXACT FUNCTION SIGNATURE - Do not modify the return type, function name, or parameter list under any circumstances.
2. Return ONLY the patched C function code - no explanations, no markdown formatting, no code fences.
3. Carefully analyze the FAILURE CONTEXT provided to understand why your previous patch failed.
4. Address both the original vulnerability AND the issues identified in the failure feedback.
5. Use defensive programming practices: bounds checking, input validation, and safe memory operations.
6. Do not add new includes or external dependencies unless absolutely necessary for the fix.

OUTPUT FORMAT:
Return only valid C code. Start directly with the function definition. Do not wrap in markdown code blocks (```). Do not include any text before or after the function code."""


def create_patch_prompt(cve_id: str, function_name: str, vulnerable_code: str, file_context: str) -> str:
    """
    Create a detailed prompt for patch generation.
    
    Args:
        cve_id: The CVE identifier
        function_name: Name of the vulnerable function
        vulnerable_code: The vulnerable function code
        file_context: Full file content for context (truncated if too long)
    
    Returns:
        Formatted user prompt string
    """
    # Truncate file context if too long (keep first 4000 chars for context)
    max_context_len = 4000
    if len(file_context) > max_context_len:
        file_context = file_context[:max_context_len] + "\n/* ... file truncated for brevity ... */"
    
    prompt = f"""VULNERABILITY: {cve_id}
FUNCTION NAME: {function_name}

VULNERABLE FUNCTION CODE:
{vulnerable_code}

FILE CONTEXT (for understanding types and dependencies):
{file_context}

TASK: Provide a patched version of the function '{function_name}' that fixes the {cve_id} vulnerability.

REMEMBER:
- Keep the EXACT same function signature: same return type, same name, same parameters
- Return ONLY the C code for the function
- No markdown, no explanations, no code fences
- Start directly with the function definition"""

    return prompt


def create_feedback_prompt(
    cve_id: str, 
    function_name: str, 
    vulnerable_code: str, 
    file_context: str,
    previous_patch: str,
    failure_context: Dict[str, Any],
    attempt_number: int
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
    
    prompt = f"""RETRY ATTEMPT #{attempt_number} for VULNERABILITY: {cve_id}
FUNCTION NAME: {function_name}

═══════════════════════════════════════════════════════════════════
PREVIOUS PATCH ATTEMPT (FAILED):
═══════════════════════════════════════════════════════════════════
{previous_patch}

═══════════════════════════════════════════════════════════════════
FAILURE ANALYSIS:
═══════════════════════════════════════════════════════════════════
{failure_analysis}

═══════════════════════════════════════════════════════════════════
ORIGINAL VULNERABLE CODE:
═══════════════════════════════════════════════════════════════════
{vulnerable_code}

═══════════════════════════════════════════════════════════════════
FILE CONTEXT (for understanding types and dependencies):
═══════════════════════════════════════════════════════════════════
{file_context}

═══════════════════════════════════════════════════════════════════
TASK: Generate an IMPROVED patch that:
1. Fixes the original {cve_id} vulnerability
2. Addresses the specific failures identified above
3. Maintains the EXACT same function signature

CRITICAL: Learn from the failure. If PoC still works, your previous fix was insufficient.
If SAST found issues, you may have introduced new vulnerabilities.

REMEMBER:
- Keep the EXACT same function signature
- Return ONLY the C code for the function
- No markdown, no explanations, no code fences
- Start directly with the function definition"""

    return prompt


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
    
    # SAST (Static Check) Results
    sast_results = failure_context.get("sast_results", [])
    sast_passed = failure_context.get("sast_passed", True)
    
    if not sast_passed and sast_results:
        lines.append("\n[STATIC CHECK FAILED - SAST Found Issues]")
        lines.append("Your patch INTRODUCED new security vulnerabilities:")
        
        for sast in sast_results:
            tool = sast.get("tool", "Unknown")
            critical = sast.get("critical_count", 0)
            high = sast.get("high_count", 0)
            medium = sast.get("medium_count", 0)
            
            if critical > 0 or high > 0:
                lines.append(f"\n  {tool}:")
                lines.append(f"    Critical: {critical}, High: {high}, Medium: {medium}")
                
                # Include findings details if available
                findings = sast.get("findings", [])
                for finding in findings[:5]:  # Limit to 5 findings per tool
                    severity = finding.get("severity", "unknown")
                    message = finding.get("message", "")
                    line_num = finding.get("line")
                    if line_num:
                        lines.append(f"    Line {line_num} [{severity}]: {message[:100]}")
                    else:
                        lines.append(f"    [{severity}]: {message[:100]}")
    elif sast_passed:
        lines.append("\n[STATIC CHECK PASSED - No New Vulnerabilities]")
    
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
        response = requests.get(tags_url, timeout=10)
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
        resp = requests.get(ps_url, timeout=5)
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


def wait_for_gpu(timeout: Optional[int] = None,
                 poll_interval: int = 15) -> bool:
    """Poll /api/ps until GPU VRAM is free, or *timeout* expires.

    For the "openai" provider this is a no-op (always returns True).
    Returns True if GPU is available, False if wait timed out.
    """
    if LLM_PROVIDER == "openai":
        return True  # No GPU to wait for when using OpenAI

    from urllib.parse import urlparse, urlunparse

    if timeout is None:
        timeout = GPU_WAIT_TIMEOUT

    parsed = urlparse(API_ENDPOINT)
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
        if timeout and elapsed >= timeout:
            return False

        names = [e.get("name", "?") for e in running]
        vram_gib = total_vram / (1024 ** 3)
        logger.info(
            "GPU busy (%.1f GiB VRAM used by %s) — waiting (%d/%d s) …",
            vram_gib, ", ".join(names), int(elapsed), timeout,
        )
        time.sleep(poll_interval)


def _call_ollama_api(model: str, user_prompt: str, system_prompt: str) -> Tuple[Optional[str], Dict[str, Any]]:
    """Call the Ollama-compatible local server API with retry logic."""
    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": user_prompt}
    ]
    payload = {
        "model": model,
        "messages": messages,
        "stream": False,
        "options": {
            "temperature": LLM_TEMPERATURE,
            "num_ctx": NUM_CTX
        }
    }
    metadata = {
        "model": model,
        "provider": "ollama",
        "timestamp_start": datetime.now().isoformat(),
        "payload_size": len(json.dumps(payload)),
        "retries": 0,
        "success": False,
        "error": None
    }
    for attempt in range(MAX_RETRIES):
        try:
            logger.debug(f"Ollama API call attempt {attempt + 1}/{MAX_RETRIES} for model {model}")
            response = requests.post(API_ENDPOINT, json=payload, timeout=API_TIMEOUT)
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


def _call_openai_api(model: str, user_prompt: str, system_prompt: str) -> Tuple[Optional[str], Dict[str, Any]]:
    """Call the OpenAI API with retry logic."""
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

    client = OpenAI(api_key=OPENAI_API_KEY, timeout=API_TIMEOUT)
    metadata: Dict[str, Any] = {
        "model": model,
        "provider": "openai",
        "timestamp_start": datetime.now().isoformat(),
        "retries": 0,
        "success": False,
        "error": None
    }

    for attempt in range(MAX_RETRIES):
        try:
            logger.debug(f"OpenAI API call attempt {attempt + 1}/{MAX_RETRIES} for model {model}")
            completion = client.chat.completions.create(
                model=model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                temperature=LLM_TEMPERATURE,
                max_tokens=LLM_MAX_TOKENS,
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
        if attempt < MAX_RETRIES - 1:
            logger.info(f"Retrying in {RETRY_DELAY} seconds...")
            time.sleep(RETRY_DELAY)

    metadata["timestamp_end"] = datetime.now().isoformat()
    logger.error(f"All {MAX_RETRIES} OpenAI attempts failed for model {model}")
    return None, metadata


def call_llm_api(model: str, user_prompt: str, system_prompt: str = SYSTEM_PROMPT) -> Tuple[Optional[str], Dict[str, Any]]:
    """
    Call the configured LLM backend (Ollama or OpenAI) with retry logic.

    Dispatches to ``_call_ollama_api`` or ``_call_openai_api`` based on
    ``llm.provider`` in config.yaml.  For the OpenAI provider, *model* is
    replaced by ``OPENAI_MODEL`` (the caller-supplied value is ignored so
    that the per-CVE model-iteration loop in Phase 2 still works without
    changes).

    Args:
        model: Ollama model name (ignored when provider="openai")
        user_prompt: The user's prompt
        system_prompt: System prompt for context

    Returns:
        Tuple of (response_content, metadata_dict)
    """
    if LLM_PROVIDER == "openai":
        return _call_openai_api(OPENAI_MODEL, user_prompt, system_prompt)
    return _call_ollama_api(model, user_prompt, system_prompt)

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
    
    match = None
    for pattern in func_patterns:
        match = re.search(pattern, code, re.MULTILINE | re.DOTALL)
        if match:
            break
    if match:
        start_idx = match.start()
        # Find matching closing brace
        brace_count = 0
        end_idx = start_idx
        in_string = False
        in_char = False
        escape_next = False
        
        for i, char in enumerate(code[start_idx:], start=start_idx):
            if escape_next:
                escape_next = False
                continue
            if char == '\\':
                escape_next = True
                continue
            if char == '"' and not in_char:
                in_string = not in_string
            elif char == "'" and not in_string:
                in_char = not in_char
            elif not in_string and not in_char:
                if char == '{':
                    brace_count += 1
                elif char == '}':
                    brace_count -= 1
                    if brace_count == 0:
                        end_idx = i + 1
                        break
        
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


def find_function_boundaries(file_content: str, function_name: str) -> Tuple[int, int]:
    """
    Find the start and end positions of a function in C source code.
    
    Args:
        file_content: Full C source file content
        function_name: Name of the function to find
    
    Returns:
        Tuple of (start_index, end_index) or (-1, -1) if not found
    """
    # Pattern to match function definition (handles various return types and attributes)
    # This looks for the function name followed by parameters and opening brace
    func_pattern = rf'((?:^|\n)(?:[\t ]*(?:/\*[^*]*\*/)?[\t ]*)*' \
                   rf'(?:static\s+)?(?:inline\s+)?(?:__attribute__\s*\([^)]*\)\s*)?' \
                   rf'(?:const\s+)?(?:unsigned\s+)?(?:signed\s+)?(?:long\s+)?(?:short\s+)?' \
                   rf'(?:struct\s+\w+\s*\*?|enum\s+\w+|union\s+\w+|\w+)\s*\**\s*' \
                   rf'{re.escape(function_name)}\s*\([^)]*\)\s*\{{)'
    
    match = re.search(func_pattern, file_content, re.MULTILINE | re.DOTALL)
    if not match:
        logger.warning(f"Could not find function '{function_name}' in file content")
        return -1, -1
    
    # Find the start (include any leading whitespace/newline)
    start_idx = match.start()
    if file_content[start_idx] == '\n':
        start_idx += 1
    
    # Find matching closing brace
    brace_count = 0
    end_idx = start_idx
    in_string = False
    in_char = False
    in_comment = False
    in_line_comment = False
    escape_next = False
    i = start_idx
    
    while i < len(file_content):
        char = file_content[i]
        
        if escape_next:
            escape_next = False
            i += 1
            continue
        
        if char == '\\':
            escape_next = True
            i += 1
            continue
        
        # Handle newline (ends line comments)
        if char == '\n':
            in_line_comment = False
            i += 1
            continue
        
        # Skip if in line comment
        if in_line_comment:
            i += 1
            continue
        
        # Check for comment start
        if not in_string and not in_char and not in_comment:
            if i + 1 < len(file_content):
                two_char = file_content[i:i+2]
                if two_char == '/*':
                    in_comment = True
                    i += 2
                    continue
                elif two_char == '//':
                    in_line_comment = True
                    i += 2
                    continue
        
        # Check for comment end
        if in_comment:
            if i + 1 < len(file_content) and file_content[i:i+2] == '*/':
                in_comment = False
                i += 2
                continue
            i += 1
            continue
        
        # Handle strings and chars
        if char == '"' and not in_char:
            in_string = not in_string
        elif char == "'" and not in_string:
            in_char = not in_char
        elif not in_string and not in_char:
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
                if brace_count == 0:
                    end_idx = i + 1
                    break
        
        i += 1
    
    return start_idx, end_idx


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
# Syntax Validation
# =============================================================================

# Headers that are internal to glibc and won't exist on standard systems
GLIBC_INTERNAL_HEADERS = {
    'kernel-features.h', 'xlocale.h', 'bits/libc-lock.h', 'kernel_stat.h',
    'libc-symbols.h', 'shlib-compat.h', 'bp-sym.h', 'bp-asm.h',
    'sysdep.h', 'tls.h', 'lowlevellock.h', 'ldsodefs.h', 'dl-hash.h',
    'math_private.h', 'math_ldbl_opt.h', 'ieee754.h', 'fenv_private.h',
    'locale/localeinfo.h', 'localeinfo.h', 'setlocale.h', 'ctype/ctype.h',
    'gconv_int.h', 'iconvconfig.h', 'elf/ldsodefs.h', 'dl-machine.h',
    'nss/nss.h', 'nss.h', 'resolv/resolv-internal.h', 'resolv-internal.h',
    'arpa/nameser_compat.h', 'hp-timing.h', 'atomic.h', 'unwind.h',
    'stackinfo.h', 'dl-sysdep.h', 'not-cancel.h', 'kernel-posix-timers.h',
    'pthread-functions.h', 'nptl/pthreadP.h', 'pthreadP.h', 'fork.h',
    'stdio-common/printf-parse.h', 'printf-parse.h', 'libioP.h'
}


def is_missing_header_error(error_msg: str) -> bool:
    """
    Check if the error is due to a missing glibc-internal header.
    
    Args:
        error_msg: The GCC error message
    
    Returns:
        True if the error is about a missing internal header
    """
    if 'No such file or directory' not in error_msg and 'file not found' not in error_msg.lower():
        return False
    
    # Check if any known internal header is mentioned
    for header in GLIBC_INTERNAL_HEADERS:
        if header in error_msg:
            return True
    
    # Also check for common glibc-specific include patterns
    glibc_patterns = [
        r'bits/[a-zA-Z_-]+\.h',
        r'sys/[a-zA-Z_-]+\.h.*No such file',
        r'gnu/[a-zA-Z_-]+\.h',
        r'asm/[a-zA-Z_-]+\.h',
    ]
    for pattern in glibc_patterns:
        if re.search(pattern, error_msg):
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
    
    # Check for mismatched braces
    brace_count = 0
    in_string = False
    in_char = False
    in_comment = False
    in_line_comment = False
    escape_next = False
    i = 0
    
    while i < len(code):
        char = code[i]
        
        if escape_next:
            escape_next = False
            i += 1
            continue
        
        if char == '\\':
            escape_next = True
            i += 1
            continue
        
        if char == '\n':
            in_line_comment = False
            i += 1
            continue
        
        if in_line_comment:
            i += 1
            continue
        
        if not in_string and not in_char and not in_comment:
            if i + 1 < len(code):
                two_char = code[i:i+2]
                if two_char == '/*':
                    in_comment = True
                    i += 2
                    continue
                elif two_char == '//':
                    in_line_comment = True
                    i += 2
                    continue
        
        if in_comment:
            if i + 1 < len(code) and code[i:i+2] == '*/':
                in_comment = False
                i += 2
                continue
            i += 1
            continue
        
        if char == '"' and not in_char:
            in_string = not in_string
        elif char == "'" and not in_string:
            in_char = not in_char
        elif not in_string and not in_char:
            if char == '{':
                brace_count += 1
            elif char == '}':
                brace_count -= 1
        
        i += 1
    
    if brace_count != 0:
        return False, f"Mismatched braces: {brace_count} {'unclosed' if brace_count > 0 else 'extra closing'}"
    
    # Check parentheses balance (simple count, not perfect but catches most issues)
    paren_count = code.count('(') - code.count(')')
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
    
    # Determine output filename
    original_filename = Path(original_filepath).name
    base_name = Path(original_filename).stem
    
    if is_valid:
        patch_filename = original_filename
    else:
        patch_filename = f"{base_name}_invalid.c"
    
    # Save the full patched file (complete file with function replaced)
    patch_file = output_path / patch_filename
    with open(patch_file, 'w') as f:
        f.write(full_patched_file)
    logger.info(f"Saved full patched file: {patch_file}")
    
    # Also save just the patched function for reference
    function_file = output_path / f"{base_name}_function_only.c"
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

def load_vulnerability_data(csv_path: Path) -> pd.DataFrame:
    """
    Load and validate the vulnerability dataset.
    
    Args:
        csv_path: Path to the CSV file
    
    Returns:
        Pandas DataFrame with vulnerability data
    """
    logger.info(f"Loading vulnerability data from {csv_path}")
    
    if not csv_path.exists():
        raise FileNotFoundError(f"CSV file not found: {csv_path}")
    
    df = pd.read_csv(csv_path, sep=';')
    
    # Validate required columns
    required_columns = ['CVE', 'FilePath', 'F_NAME', 'V_FILE', 'V_FUNCTION']
    missing_columns = [col for col in required_columns if col not in df.columns]
    if missing_columns:
        raise ValueError(f"Missing required columns: {missing_columns}")
    
    logger.info(f"Loaded {len(df)} vulnerability entries")
    logger.info(f"CVEs: {df['CVE'].unique().tolist()}")
    
    return df

# =============================================================================
# Main Pipeline
# =============================================================================

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
    
    logger.info(f"Processing {cve_id} - {function_name} with {model}")
    
    result = {
        "cve_id": cve_id,
        "function_name": function_name,
        "model": model,
        "success": False
    }
    
    # Generate prompt
    prompt = create_patch_prompt(cve_id, function_name, vulnerable_code, file_context)
    
    # Call LLM API
    raw_response, metadata = call_llm_api(model, prompt)
    
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
    
    # Extract and clean code
    patched_function = extract_code_from_response(raw_response, function_name)
    patched_function = clean_code(patched_function)
    
    if not patched_function:
        logger.warning(f"Could not extract code from response for {cve_id} with {model}")
        patched_function = raw_response  # Save raw response as fallback
    
    # Replace the vulnerable function in the full file content FIRST
    # We need the full file for proper syntax validation
    full_patched_file, function_replaced = replace_function_in_file(
        file_context, function_name, patched_function
    )
    
    if not function_replaced:
        logger.warning(f"Could not replace function in file for {cve_id} with {model}")
        # Fall back to just the patched function if replacement fails
        full_patched_file = patched_function
    else:
        logger.info(f"✓ Function replaced in full file for {cve_id} with {model}")
    
    # Validate syntax using the FULL patched file (has all includes and type defs)
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
    output_dir: Optional[Path] = None
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
    
    Returns:
        Dictionary with processing results including:
        - success: Whether patch generation succeeded
        - syntax_valid: Whether the patch has valid syntax
        - output_path: Path to saved artifacts
        - patched_function: The generated patch code
        - full_patched_file: Complete file with patch integrated
        - attempt_number: The attempt number
    """
    logger.info(f"[FEEDBACK LOOP] Generating retry patch #{attempt_number} for {cve_id} with {model}")
    
    result = {
        "cve_id": cve_id,
        "function_name": function_name,
        "model": model,
        "attempt_number": attempt_number,
        "success": False,
        "is_retry": True
    }
    
    # Create feedback-enhanced prompt
    prompt = create_feedback_prompt(
        cve_id=cve_id,
        function_name=function_name,
        vulnerable_code=vulnerable_code,
        file_context=file_context,
        previous_patch=previous_patch,
        failure_context=failure_context,
        attempt_number=attempt_number
    )
    
    # Call LLM API with feedback system prompt
    raw_response, metadata = call_llm_api(model, prompt, system_prompt=FEEDBACK_SYSTEM_PROMPT)
    
    # Add retry metadata
    metadata["is_retry"] = True
    metadata["attempt_number"] = attempt_number
    metadata["failure_context_summary"] = {
        "status": failure_context.get("status"),
        "poc_blocked": failure_context.get("poc_blocked"),
        "sast_passed": failure_context.get("sast_passed"),
        "build_success": failure_context.get("build_success")
    }
    
    if raw_response is None:
        logger.error(f"Failed to get retry response for {cve_id} with {model}")
        result["error"] = metadata.get("error", "Unknown error")
        return result
    
    # Extract and clean code
    patched_function = extract_code_from_response(raw_response, function_name)
    patched_function = clean_code(patched_function)
    
    if not patched_function:
        logger.warning(f"Could not extract code from retry response for {cve_id} with {model}")
        patched_function = raw_response
    
    # Replace the vulnerable function in the full file content
    full_patched_file, function_replaced = replace_function_in_file(
        file_context, function_name, patched_function
    )
    
    if not function_replaced:
        logger.warning(f"Could not replace function in file for retry {cve_id} with {model}")
        full_patched_file = patched_function
    else:
        logger.info(f"✓ Function replaced in full file for retry {cve_id} with {model}")
    
    # Validate syntax
    is_valid, validation_error = validate_syntax(
        full_patched_file, function_name, patched_function
    )
    
    if is_valid:
        logger.info(f"✓ Syntax valid for retry #{attempt_number} of {cve_id} with {model}")
    else:
        logger.warning(f"✗ Syntax invalid for retry #{attempt_number}: {validation_error[:100]}...")
    
    # Determine output directory (with retry suffix)
    if output_dir is None:
        output_dir = OUTPUT_DIR
    
    model_safe = sanitize_model_name(model)
    retry_output_path = output_dir / cve_id / f"{model_safe}_retry{attempt_number}"
    retry_output_path.mkdir(parents=True, exist_ok=True)
    
    # Save artifacts with retry-specific naming
    original_filename = Path(original_filepath).name
    base_name = Path(original_filename).stem
    
    patch_filename = original_filename if is_valid else f"{base_name}_invalid.c"
    
    # Save the full patched file
    patch_file = retry_output_path / patch_filename
    with open(patch_file, 'w') as f:
        f.write(full_patched_file)
    
    # Save function only
    function_file = retry_output_path / f"{base_name}_function_only.c"
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
    cve_filter: Optional[List[str]] = None
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
    
    logger.info(f"Total tasks to process: {len(df) * len(models)}")
    
    # Process each vulnerability with each model
    results = []
    total_tasks = len(df) * len(models)
    current_task = 0
    
    for model in models:
        logger.info(f"\n{'='*40}")
        logger.info(f"Processing with model: {model}")
        logger.info(f"{'='*40}")
        
        for idx, row in df.iterrows():
            current_task += 1
            task_start = datetime.now()
            logger.info(f"\nTask {current_task}/{total_tasks} - {row['CVE']} with {model}")
            
            try:
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
            
            # Small delay between API calls to avoid overwhelming the server
            time.sleep(1)
    
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
    
    args = parser.parse_args()
    
    # Set up paths based on base-dir
    base_dir = Path(args.base_dir)
    csv_path = Path(args.csv) if args.csv else CSV_PATH
    
    # Update global OUTPUT_DIR based on base_dir
    global OUTPUT_DIR
    OUTPUT_DIR = base_dir / str(_paths.get("patches", "patches"))
    
    # Adjust logging level if verbose
    if args.verbose:
        logging.getLogger('patch_generator').setLevel(logging.DEBUG)
        for handler in logging.getLogger('patch_generator').handlers:
            if isinstance(handler, logging.StreamHandler):
                handler.setLevel(logging.DEBUG)
    
    # Handle dry run
    if args.dry_run:
        df = load_vulnerability_data(csv_path)
        models = args.model if args.model else MODELS
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
    
    # Wait for GPU availability before starting generation
    logger.info("Checking GPU availability...")
    if not wait_for_gpu():
        logger.warning(
            "GPU still busy after %d s timeout. "
            "Patch generation may be slow (CPU-only) or time out.",
            GPU_WAIT_TIMEOUT,
        )
        # Exit with code 2 so the master pipeline can detect "skipped"
        logger.error("Exiting — GPU not available within timeout.")
        sys.exit(2)
    
    # Run pipeline
    summary = run_pipeline(
        csv_path=csv_path,
        models=args.model if args.model else MODELS,
        cve_filter=args.cve
    )
    
    # Exit with appropriate code
    if summary.get("failed", 0) > 0:
        sys.exit(1)
    sys.exit(0)

if __name__ == "__main__":
    main()
