"""
Unified pipeline configuration.

All runtime values are loaded from ``config.yaml`` in the pipeline root.
CLI arguments override the YAML values when provided.
"""

import csv
import logging
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


def load_pipeline_config(base_dir: Optional[Path] = None) -> Dict[str, Any]:
    """Load ``config.yaml`` from the pipeline root and return the raw dict."""
    base = base_dir or BASE_DIR
    return _load_yaml(base / "config.yaml")


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

# Manual verification
_mv = _cfg.get("manual_verification", {}) if isinstance(_cfg.get("manual_verification"), dict) else {}
MANUAL_VERIFY_TIMEOUT: int = int(_mv.get("timeout", 1800))
MANUAL_VERIFY_POLL_INTERVAL: int = int(_mv.get("poll_interval", 30))

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

    def resolve_phase0_outputs(self) -> Dict[str, Path]:
        """Read Phase 0 config YAML and return its output file paths resolved to base_dir."""
        defaults: Dict[str, str] = {
            "csv_path": "cve_poc_complete.csv",
            "filtered_json_path": "cve_poc_map_filtered.json",
            "global_json_path": "cve_poc_map.json",
        }

        config_path = Path(self.phase0_config)
        if not config_path.is_absolute():
            config_path = self.base_dir / self.phase0_config

        if config_path.exists():
            try:
                cfg = _load_yaml(config_path)
                for key, val in cfg.get("output", {}).items():
                    if key in defaults and val:
                        defaults[key] = str(val)
            except Exception:
                pass

        return {k: self.base_dir / v for k, v in defaults.items()}

