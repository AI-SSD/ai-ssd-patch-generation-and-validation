import csv
import sys
from pathlib import Path
from typing import List, Optional
from dataclasses import dataclass, field

BASE_DIR = Path(__file__).parent.parent.resolve()

LOG_DIR = BASE_DIR / "logs"

# Increase CSV field size limit to handle large fields (e.g. PoC code)
csv.field_size_limit(sys.maxsize)

# Iterative Feedback Loop Configuration
MAX_RETRIES = 3  # Maximum retry attempts for failed patches
FEEDBACK_LOOP_ENABLED = True  # Enable/disable the feedback loop

# Phase 0 Manual Verification Configuration
MANUAL_VERIFY_TIMEOUT = 1800  # 30 minutes in seconds
MANUAL_VERIFY_POLL_INTERVAL = 30  # Poll every 30 seconds

# Default models available for patch generation
DEFAULT_MODELS = [
    "qwen2.5-coder:1.5b",
    "qwen2.5-coder:7b",
    "qwen2.5:1.5b",
    "qwen2.5:7b"
]

# Phase scripts
PHASE_SCRIPTS = {
    0: "cve_aggregator",
    1: "orchestrator.py",
    2: "patch_generator.py",
    3: "patch_validator.py",
    4: "reporter.py"
}

@dataclass
class PipelineConfig:
    """Configuration for the pipeline run."""
    base_dir: Path
    cves: Optional[List[str]] = None
    models: Optional[List[str]] = None
    phases: List[int] = field(default_factory=lambda: [0, 1, 2, 3, 4])
    verbose: bool = False
    cleanup: bool = False
    skip_sast: bool = False
    dry_run: bool = False
    build_timeout: int = 7200
    run_timeout: int = 300
    # Feedback Loop Configuration
    enable_feedback_loop: bool = True
    max_retries: int = MAX_RETRIES
    feedback_loop_timeout: int = 7200  # 2 hours for feedback loop process
    # Phase 0 Configuration
    phase0_config: str = "cve_aggregator/glibc_config.yaml"
    # Phase 0 Manual Verification Configuration
    manual_verify_timeout: int = MANUAL_VERIFY_TIMEOUT
    manual_verify_poll_interval: int = MANUAL_VERIFY_POLL_INTERVAL

