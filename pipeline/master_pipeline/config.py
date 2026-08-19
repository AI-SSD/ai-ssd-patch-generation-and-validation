"""
Unified pipeline configuration.

All runtime values are loaded from ``config.yaml`` in the pipeline root.
CLI arguments override the YAML values when provided.
"""

import csv
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field

import yaml

logger = logging.getLogger("pipeline.config")

BASE_DIR = Path(__file__).parent.parent.resolve()

LOG_DIR = BASE_DIR / "logs"

# Increase CSV field size limit to handle large fields (e.g. PoC code)
csv.field_size_limit(sys.maxsize)


# ---------------------------------------------------------------------------
# YAML loader
# ---------------------------------------------------------------------------

def _load_yaml(path: Path) -> Dict[str, Any]:
    """Load a YAML file, returning an empty dict on failure."""
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    except Exception as exc:
        logger.warning("Could not parse %s: %s", path, exc)
        return {}


# ---------------------------------------------------------------------------
# Provider-profile env overlay
# ---------------------------------------------------------------------------
# A "profile" (profiles/<name>.env, sourced by run_project.sh) switches the LLM
# backend for a whole run via environment variables, WITHOUT editing any YAML.
# These overlay config.yaml's ``llm`` section (and the feedback-loop model
# schedule) so the same projects can be benchmarked across AI families by
# changing one flag. Precedence everywhere: env var > config.yaml > default.
# No LLM_* vars set ⇒ this is a no-op and the YAML behaves exactly as before.
# ---------------------------------------------------------------------------

def _env(name: str) -> Optional[str]:
    """Return a non-empty environment variable, or None."""
    val = os.environ.get(name)
    return val if val not in (None, "") else None


def parse_models_by_attempt(raw: Optional[str]) -> Dict[int, str]:
    """Parse ``"m1,m2,m3,m4"`` into ``{1: m1, 2: m2, ...}`` (1-indexed attempts)."""
    if not raw:
        return {}
    return {i + 1: m.strip() for i, m in enumerate(raw.split(",")) if m.strip()}


def _apply_llm_env_overrides(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Overlay profile-driven LLM settings from the environment onto *cfg*."""
    if not isinstance(cfg, dict):
        return cfg
    llm = cfg.get("llm")
    if not isinstance(llm, dict):
        llm = {}
        cfg["llm"] = llm

    if _env("LLM_PROVIDER"):
        llm["provider"] = _env("LLM_PROVIDER").lower()
    if _env("LLM_ENDPOINT"):
        llm["endpoint"] = _env("LLM_ENDPOINT")
    if _env("LLM_OPENAI_MODEL"):
        llm["openai_model"] = _env("LLM_OPENAI_MODEL")
    if _env("LLM_OPENAI_BASE_URL"):
        llm["openai_base_url"] = _env("LLM_OPENAI_BASE_URL")
    if _env("OLLAMA_USERNAME"):
        llm["ollama_username"] = _env("OLLAMA_USERNAME")
    if _env("OLLAMA_PASSWORD"):
        llm["ollama_password"] = _env("OLLAMA_PASSWORD")
    for env_name, key, caster in (
        ("LLM_NUM_CTX", "num_ctx", int),
        ("LLM_TEMPERATURE", "temperature", float),
        ("LLM_MAX_TOKENS", "max_tokens", int),
        ("LLM_TIMEOUT", "timeout", int),
    ):
        raw = _env(env_name)
        if raw is not None:
            try:
                llm[key] = caster(raw)
            except (TypeError, ValueError):
                logger.warning("Ignoring invalid %s=%r", env_name, raw)

    # Per-attempt model schedule (the 4-model ramp). When provided it drives the
    # feedback loop for BOTH providers, and its attempt-1 model becomes the
    # initial Phase 2 generation model (OpenAI: openai_model; Ollama: the single
    # entry of llm.models, so the per-CVE loop runs once then retries escalate).
    schedule = parse_models_by_attempt(_env("LLM_MODELS_BY_ATTEMPT"))
    if schedule:
        fb = cfg.get("feedback_loop")
        if not isinstance(fb, dict):
            fb = {}
            cfg["feedback_loop"] = fb
        fb["models_by_attempt"] = dict(schedule)
        m1 = schedule[1]
        llm["openai_model"] = m1
        llm["models"] = [m1]
    elif _env("LLM_MODELS"):
        llm["models"] = [m.strip() for m in _env("LLM_MODELS").split(",") if m.strip()]
    return cfg


def _env_bool_opt(name: str) -> Optional[bool]:
    """Tri-state env bool: True/False when set, None when unset (no override)."""
    v = _env(name)
    if v is None:
        return None
    return v.strip().lower() in ("1", "true", "yes", "on")


def _apply_generation_env_overrides(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Overlay ablation/generation knobs from the environment onto *cfg*.

    Mirrors :func:`_apply_llm_env_overrides` so the ablation harness can sweep
    generation, prompt-component and richer-feedback settings per variant via
    ``SSD_*`` env vars — the same profile/env-transport pattern — WITHOUT editing
    config.yaml. No ``SSD_*`` vars set ⇒ a complete no-op (YAML behaves as before).
    """
    if not isinstance(cfg, dict):
        return cfg
    gen = cfg.get("generation")
    if not isinstance(gen, dict):
        gen = {}
        cfg["generation"] = gen
    pc = gen.get("prompt_components")
    if not isinstance(pc, dict):
        pc = {}
        gen["prompt_components"] = pc

    raw = _env("SSD_NUM_CANDIDATES")
    if raw is not None:
        try:
            gen["num_candidates"] = int(raw)
        except ValueError:
            logger.warning("Ignoring invalid SSD_NUM_CANDIDATES=%r", raw)
    raw = _env("SSD_CANDIDATE_TEMPERATURES")
    if raw is not None:
        temps: List[float] = []
        for t in raw.split(","):
            t = t.strip()
            if not t:
                continue
            try:
                temps.append(float(t))
            except ValueError:
                logger.warning("Ignoring invalid temperature %r in SSD_CANDIDATE_TEMPERATURES", t)
        gen["candidate_temperatures"] = temps
    raw = _env("SSD_GRANULARITIES")
    if raw is not None:
        gen["granularities"] = [g.strip() for g in raw.split(",") if g.strip()]
    b = _env_bool_opt("SSD_CHAIN_OF_THOUGHT")
    if b is not None:
        gen["chain_of_thought"] = b

    # Prompt-component ablation toggles.
    for env_name, key in (
        ("SSD_PROMPT_INCLUDE_POC", "include_poc"),
        ("SSD_PROMPT_INCLUDE_CWE", "include_cwe"),
        ("SSD_PROMPT_INCLUDE_DESCRIPTION", "include_description"),
        ("SSD_PROMPT_PROJECT_PRIMING", "project_priming"),
    ):
        b = _env_bool_opt(env_name)
        if b is not None:
            pc[key] = b

    # Richer feedback memory toggles.
    fb = cfg.get("feedback_loop")
    if not isinstance(fb, dict):
        fb = {}
        cfg["feedback_loop"] = fb
    rc = fb.get("richer_context")
    if not isinstance(rc, dict):
        rc = {}
        fb["richer_context"] = rc
    for env_name, key in (
        ("SSD_FEEDBACK_APPLIED_DIFF", "applied_diff"),
        ("SSD_FEEDBACK_ATTEMPT_HISTORY", "attempt_history"),
        ("SSD_FEEDBACK_REFLEXION", "reflexion"),
    ):
        b = _env_bool_opt(env_name)
        if b is not None:
            rc[key] = b

    # Phase-3 patch-validation concurrency (validation.max_workers) and the
    # per-build make-j cap (docker.make_jobs) — settable per run/campaign so the
    # intra-phase concurrency can be tuned against the host's cores without
    # oversubscribing (builds are make -j$(nproc)). Unset ⇒ unchanged.
    val = cfg.get("validation")
    if not isinstance(val, dict):
        val = {}
        cfg["validation"] = val
    raw = _env("SSD_VALIDATION_WORKERS")
    if raw is not None:
        try:
            val["max_workers"] = max(1, int(raw))
        except ValueError:
            logger.warning("Ignoring invalid SSD_VALIDATION_WORKERS=%r", raw)
    dock = cfg.get("docker")
    if not isinstance(dock, dict):
        dock = {}
        cfg["docker"] = dock
    raw = _env("SSD_MAKE_JOBS")
    if raw is not None:
        try:
            dock["make_jobs"] = max(1, int(raw))
        except ValueError:
            logger.warning("Ignoring invalid SSD_MAKE_JOBS=%r", raw)
    return cfg


def _apply_contamination_env_overrides(cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Overlay contamination-filter knobs from the environment onto *cfg*.

    Same profile/env-transport pattern as the LLM overlay:
      SSD_CONTAMINATION_FILTER=1|0   -> contamination_filter.enabled
      LLM_TRAINING_CUTOFF=YYYY-MM-DD -> contamination_filter.cutoff_override
    Neither var set => a complete no-op (YAML behaves as before).
    """
    if not isinstance(cfg, dict):
        return cfg
    enabled = _env_bool_opt("SSD_CONTAMINATION_FILTER")
    cutoff = _env("LLM_TRAINING_CUTOFF")
    if enabled is None and cutoff is None:
        return cfg
    section = cfg.get("contamination_filter")
    if not isinstance(section, dict):
        section = {}
        cfg["contamination_filter"] = section
    if enabled is not None:
        section["enabled"] = enabled
    if cutoff is not None:
        section["cutoff_override"] = cutoff
    return cfg


def load_pipeline_config(base_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Load ``config.yaml`` from the pipeline root, with profile env overrides."""
    base = base_dir or BASE_DIR
    return _apply_contamination_env_overrides(_apply_generation_env_overrides(
        _apply_llm_env_overrides(_load_yaml(base / "config.yaml"))))


# ---------------------------------------------------------------------------
# Convenience accessors – give any module quick access to a config section
# without each file re-parsing the YAML.
# ---------------------------------------------------------------------------

_CACHED_CFG: Optional[Dict[str, Any]] = None


def get_config(base_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Return the cached pipeline config dict; load it on first call."""
    global _CACHED_CFG
    if _CACHED_CFG is None:
        _CACHED_CFG = load_pipeline_config(base_dir)
    return _CACHED_CFG


def reload_config(base_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Force-reload the pipeline config from disk."""
    global _CACHED_CFG
    _CACHED_CFG = load_pipeline_config(base_dir)
    return _CACHED_CFG


def cfg_section(section: str, base_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Return a top-level section from config.yaml (e.g. ``llm``, ``paths``)."""
    cfg = get_config(base_dir)
    val = cfg.get(section, {})
    return val if isinstance(val, dict) else {}


def resolve_phase0_config_path(base_dir: Optional[Path] = None) -> Optional[Path]:
    """Follow ``config.yaml``'s ``phase0_config`` pointer to the active project YAML.

    The pointer is relative to the pipeline root (where the ``cve_aggregator/*_config.yaml``
    files live), not ``base_dir`` (which may be a per-project working dir).
    """
    cfg = get_config(base_dir)
    rel = str(cfg.get("phase0_config", "cve_aggregator/glibc_config.yaml"))
    p = Path(rel)
    if not p.is_absolute():
        p = BASE_DIR / rel
    return p if p.exists() else None


def project_section(section: str, base_dir: Optional[Path] = None,
                    phase0_config_path: Optional[Path] = None) -> Dict[str, Any]:
    """Return a section (e.g. ``phase2``, ``phase1``) from the active PROJECT YAML.

    Unlike :func:`cfg_section` (which reads ``config.yaml``), this reads the
    per-project Phase 0 YAML — the home of project-specific sections. An explicit
    ``phase0_config_path`` wins (e.g. a phase passed ``--phase0-config``);
    otherwise the ``config.yaml`` pointer is followed.
    """
    path = phase0_config_path or resolve_phase0_config_path(base_dir)
    if not path or not Path(path).exists():
        return {}
    val = _load_yaml(Path(path)).get(section, {})
    return val if isinstance(val, dict) else {}


# ---------------------------------------------------------------------------
# Derived constants – kept as module-level variables for backwards
# compatibility.  Values are populated from config.yaml at import time
# and can be refreshed with ``reload_config()``.
# ---------------------------------------------------------------------------

_cfg = load_pipeline_config()

# LLM
_llm = _cfg.get("llm", {}) if isinstance(_cfg.get("llm"), dict) else {}
DEFAULT_MODELS: List[str] = [str(m) for m in _llm.get("models", [
    "qwen2.5-coder:1.5b", "qwen2.5-coder:7b", "qwen2.5:1.5b", "qwen2.5:7b"
])]

# Feedback loop
_fb = _cfg.get("feedback_loop", {}) if isinstance(_cfg.get("feedback_loop"), dict) else {}
MAX_RETRIES: int = int(_fb.get("max_retries", 3))
FEEDBACK_LOOP_ENABLED: bool = bool(_fb.get("enabled", True))

# Manual verification.  Env vars override config.yaml so the dashboard /
# run_all.sh can set per-run, per-phase manual-review behavior WITHOUT editing
# config.yaml (the same env-transport pattern the LLM profiles use). Precedence:
# env var > config.yaml > default. Defaults preserve the historical behavior
# (Phase 0 auto-skip honors config; Phase 1 hold gate OFF).
def _env_bool(name: str, default: bool) -> bool:
    v = _env(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "on")


def _env_int(name: str, default: int) -> int:
    v = _env(name)
    try:
        return int(v) if v is not None else int(default)
    except (TypeError, ValueError):
        return int(default)


_mv = _cfg.get("manual_verification", {}) if isinstance(_cfg.get("manual_verification"), dict) else {}
MANUAL_VERIFY_TIMEOUT: int = _env_int("MANUAL_VERIFY_TIMEOUT", int(_mv.get("timeout", 1800)))
MANUAL_VERIFY_POLL_INTERVAL: int = _env_int("MANUAL_VERIFY_POLL", int(_mv.get("poll_interval", 30)))
# Phase 0: when True the manual-verification gate never holds — every CVE still
# pending manual review is auto-excluded from Phase 1+ (the [S] outcome). When
# False AND non-interactive (dashboard run), the gate HOLDS and polls
# manual_supervision/ for dashboard approve/retry/discard/proceed decisions.
MANUAL_VERIFY_AUTO_SKIP: bool = _env_bool("MANUAL_VERIFY_AUTO_SKIP", bool(_mv.get("auto_skip", False)))
# Phase 1 manual-revision HOLD gate. Default OFF = historical behavior (flagged
# items silently dropped from Phase 2). When ON, after Phase 1 the run holds and
# polls manual_supervision/ for dashboard retry/discard/proceed decisions.
MANUAL_VERIFY_PHASE1_GATE: bool = _env_bool("PHASE1_MANUAL_GATE", bool(_mv.get("phase1_gate", False)))

# Phase scripts – structural, not user-facing config
PHASE_SCRIPTS = {
    0: "cve_aggregator",
    1: "orchestrator.py",
    2: "patch_generator.py",
    3: "patch_validator.py",
    4: "reporter.py",
}


# ---------------------------------------------------------------------------
# PipelineConfig dataclass
# ---------------------------------------------------------------------------

@dataclass
class PipelineConfig:
    """Configuration for a pipeline run.

    Field defaults are read from ``config.yaml`` at import time.
    CLI arguments override them when supplied.
    """
    base_dir: Path
    cves: Optional[List[str]] = None
    models: Optional[List[str]] = None
    phases: List[int] = field(default_factory=lambda: [0, 1, 2, 3, 4])
    verbose: bool = False
    cleanup: bool = False
    # When True, Phase 1 re-measures the baseline even if an identical-image /
    # identical-policy baseline is already recorded (disables memoization).
    force_baseline: bool = False
    skip_sast: bool = False
    dry_run: bool = False
    build_timeout: int = int(_cfg.get("build_timeout", 3600))
    run_timeout: int = int(_cfg.get("run_timeout", 300))
    # Feedback Loop
    enable_feedback_loop: bool = FEEDBACK_LOOP_ENABLED
    max_retries: int = MAX_RETRIES
    feedback_loop_timeout: int = int(_fb.get("timeout", 7200))
    # Phase 0 config
    phase0_config: str = str(_cfg.get("phase0_config", "cve_aggregator/glibc_config.yaml"))
    # Manual verification
    manual_verify_timeout: int = MANUAL_VERIFY_TIMEOUT
    manual_verify_poll_interval: int = MANUAL_VERIFY_POLL_INTERVAL
    manual_verify_auto_skip: bool = MANUAL_VERIFY_AUTO_SKIP
    manual_verify_phase1_gate: bool = MANUAL_VERIFY_PHASE1_GATE

    def resolve_phase0_outputs(self) -> Dict[str, Path]:
        """Read Phase 0 config YAML and return its output file paths resolved to base_dir."""
        defaults: Dict[str, str] = {
            "csv_path": "cve_poc_complete.csv",
            "filtered_json_path": "cve_poc_map_filtered.json",
            "global_json_path": "cve_poc_map.json",
        }

        config_path = Path(self.phase0_config)
        if not config_path.is_absolute():
            # Resolve relative to the pipeline root (where the YAML files
            # live), not base_dir which may be a per-project workdir.
            config_path = BASE_DIR / self.phase0_config

        if config_path.exists():
            try:
                cfg = _load_yaml(config_path)
                for key, val in cfg.get("output", {}).items():
                    if key in defaults and val:
                        defaults[key] = str(val)
            except Exception:
                pass

        return {k: self.base_dir / v for k, v in defaults.items()}

