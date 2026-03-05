"""
Pipeline Orchestrator – ties all modules together.

Loads configuration, instantiates the pipeline modules in order,
and drives the shared ``context`` dict through each stage.
"""

from __future__ import annotations

import logging
import sys
import time
import yaml
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Type

from .modules.base import PipelineModule
from .modules.cve_fetcher import CVEFetcher
from .modules.commit_discovery import CommitDiscovery
from .modules.poc_mapper import PoCMapper
from .modules.data_aggregator import DataAggregator
from .modules.syntax_validator import SyntaxValidator
from .modules.output_generator import OutputGenerator

logger = logging.getLogger("cve_aggregator")

# Default ordered list of module classes
DEFAULT_PIPELINE: List[Type[PipelineModule]] = [
    CVEFetcher,
    CommitDiscovery,
    PoCMapper,
    DataAggregator,
    SyntaxValidator,
    OutputGenerator,
]


# ---------------------------------------------------------------------------
# Configuration loading
# ---------------------------------------------------------------------------

def load_config(config_path: Optional[str] = None) -> Dict[str, Any]:
    """Load pipeline configuration from a YAML file.

    Falls back to ``aggregator_config.yaml`` next to this module.
    """
    if config_path:
        path = Path(config_path)
    else:
        path = Path(__file__).parent / "aggregator_config.yaml"

    if not path.exists():
        logger.warning("Config file not found: %s – using empty config", path)
        return {}

    with open(path, "r", encoding="utf-8") as fh:
        cfg = yaml.safe_load(fh) or {}

    logger.info("Loaded configuration from %s", path)
    return cfg


# ---------------------------------------------------------------------------
# Logging setup
# ---------------------------------------------------------------------------

def setup_logging(config: Dict[str, Any]) -> None:
    log_cfg = config.get("logging", {})
    level_str = log_cfg.get("level", "INFO").upper()
    level = getattr(logging, level_str, logging.INFO)
    fmt = log_cfg.get("format", "%(asctime)s [%(levelname)s] %(name)s: %(message)s")

    handlers: list[logging.Handler] = [logging.StreamHandler(sys.stdout)]

    log_file = log_cfg.get("file")
    if log_file:
        Path(log_file).parent.mkdir(parents=True, exist_ok=True)
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))

    logging.basicConfig(level=level, format=fmt, handlers=handlers, force=True)


# ---------------------------------------------------------------------------
# Main orchestrator
# ---------------------------------------------------------------------------

class PipelineOrchestrator:
    """Runs the full CVE Aggregator pipeline.

    Parameters
    ----------
    config : dict
        Merged YAML configuration.
    modules : list[Type[PipelineModule]] | None
        Ordered list of module classes.  Defaults to :data:`DEFAULT_PIPELINE`.
    skip_modules : list[str] | None
        Module class names to skip (e.g. ``["SyntaxValidator"]``).
    """

    def __init__(
        self,
        config: Dict[str, Any],
        modules: Optional[List[Type[PipelineModule]]] = None,
        skip_modules: Optional[List[str]] = None,
    ):
        self.config = config
        self.skip = set(skip_modules or [])
        self._module_classes = modules or DEFAULT_PIPELINE

    def run(self) -> Dict[str, Any]:
        """Execute every module in order, passing a shared context."""
        project = self.config.get("project", {})
        name = project.get("name", "custom")

        logger.info("=" * 70)
        logger.info("CVE Aggregator Pipeline v1.0  –  Project: %s", name)
        logger.info("Timestamp: %s", datetime.now().isoformat())
        logger.info("=" * 70)

        context: Dict[str, Any] = {"config": self.config}
        total_modules = len(self._module_classes)

        for idx, cls in enumerate(self._module_classes, 1):
            if cls.__name__ in self.skip:
                logger.info("[%d/%d] Skipping %s (excluded)", idx, total_modules, cls.__name__)
                continue

            module = cls(self.config)

            # Validate config
            if not module.validate_config():
                logger.error("[%d/%d] %s config validation failed – aborting",
                             idx, total_modules, cls.__name__)
                break

            logger.info("\n[%d/%d] Running %s …", idx, total_modules, cls.__name__)
            t0 = time.time()
            try:
                context = module.run(context)
            except Exception:
                logger.exception("[%d/%d] %s failed", idx, total_modules, cls.__name__)
                # Decide whether to continue or abort based on config
                if self.config.get("pipeline", {}).get("abort_on_error", True):
                    break
            finally:
                module.cleanup()

            elapsed = time.time() - t0
            logger.info("[%d/%d] %s completed in %.1f s", idx, total_modules, cls.__name__, elapsed)

        # Final summary
        self._print_summary(context)
        return context

    def _print_summary(self, context: Dict[str, Any]) -> None:
        logger.info("\n" + "=" * 70)
        logger.info("Pipeline Completed")
        logger.info("=" * 70)

        out = context.get("output_summary", {})
        if out:
            logger.info("Output Files:")
            for key in ("global_json", "filtered_json", "csv", "poc_dir"):
                if key in out:
                    logger.info("  %s: %s", key, out[key])
            logger.info("Statistics:")
            logger.info("  Total processed:  %s", out.get("total_processed", "—"))
            logger.info("  Complete entries:  %s", out.get("complete_entries", "—"))
            logger.info("  PoC files saved:   %s", out.get("poc_files_saved", "—"))

        logger.info("=" * 70)


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------

def run_pipeline(config_path: Optional[str] = None, **overrides: Any) -> Dict[str, Any]:
    """One-liner to load config and run the full pipeline."""
    cfg = load_config(config_path)
    cfg.update(overrides)
    setup_logging(cfg)
    orchestrator = PipelineOrchestrator(cfg)
    return orchestrator.run()
