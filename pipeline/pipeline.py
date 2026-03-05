#!/usr/bin/env python3
"""
AI-SSD Master Pipeline Orchestrator

This script executes the complete AI-SSD pipeline sequentially:
  Phase 1: Vulnerability Reproduction (orchestrator.py)
  Phase 2: Patch Generation (patch_generator.py)
  Phase 3: Patch Validation (patch_validator.py)
  Phase 4: Automated Reporting (reporter.py)

It handles argument passing between phases and ensures outputs from each
phase are correctly detected by subsequent phases.

NEW: Implements Iterative Feedback Loop (Self-Healing) between Phase 2 and 3
- If Phase 3 validation fails, extracts failure context
- Passes failure context back to Phase 2 for improved patch generation
- Retries up to MAX_RETRIES times before marking as "Unpatchable"

Author: AI-SSD Project
Date: 2026-01-04
"""

import os
import sys
import json
import csv
import logging
import argparse
import subprocess
import time
import shutil
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, asdict, field
from enum import Enum

# =============================================================================
# Configuration
# =============================================================================

BASE_DIR = Path(__file__).parent.resolve()
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
    0: "glibc_cve_aggregator.py",
    1: "orchestrator.py",
    2: "patch_generator.py",
    3: "patch_validator.py",
    4: "reporter.py"
}

# =============================================================================
# Enums and Data Classes
# =============================================================================

class PhaseStatus(Enum):
    """Status of a pipeline phase."""
    PENDING = "pending"
    RUNNING = "running"
    SUCCESS = "success"
    FAILED = "failed"
    SKIPPED = "skipped"


class PatchStatus(Enum):
    """Status of a patch in the iterative feedback loop."""
    PENDING = "pending"
    VALIDATING = "validating"
    SUCCESS = "success"
    RETRYING = "retrying"
    UNPATCHABLE = "unpatchable"
    FAILED = "failed"


@dataclass
class FeedbackLoopResult:
    """Result of the iterative feedback loop for a single patch."""
    cve_id: str
    model_name: str
    final_status: PatchStatus
    total_attempts: int
    successful_attempt: Optional[int] = None  # Which attempt succeeded (1-based)
    final_patch_path: Optional[str] = None
    validation_history: List[Dict[str, Any]] = field(default_factory=list)
    failure_reason: Optional[str] = None
    total_duration_seconds: float = 0.0
    start_time: Optional[str] = None  # ISO format start time
    end_time: Optional[str] = None  # ISO format end time
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "cve_id": self.cve_id,
            "model_name": self.model_name,
            "final_status": self.final_status.value,
            "total_attempts": self.total_attempts,
            "successful_attempt": self.successful_attempt,
            "final_patch_path": self.final_patch_path,
            "validation_history": self.validation_history,
            "failure_reason": self.failure_reason,
            "total_duration_seconds": self.total_duration_seconds,
            "start_time": self.start_time,
            "end_time": self.end_time,
        }


@dataclass
class PhaseResult:
    """Result of a single phase execution."""
    phase: int
    name: str
    status: PhaseStatus
    start_time: Optional[str] = None
    end_time: Optional[str] = None
    duration_seconds: float = 0.0
    exit_code: int = 0
    output_files: List[str] = field(default_factory=list)
    error_message: Optional[str] = None
    stdout: str = ""
    stderr: str = ""

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
    # Phase 0 Manual Verification Configuration
    manual_verify_timeout: int = MANUAL_VERIFY_TIMEOUT
    manual_verify_poll_interval: int = MANUAL_VERIFY_POLL_INTERVAL

@dataclass
class PipelineSummary:
    """Summary of the entire pipeline run."""
    start_time: str
    end_time: str
    duration_seconds: float
    config: Dict[str, Any]
    phases_completed: int
    phases_failed: int
    results: List[Dict[str, Any]]
    overall_status: str
    # Feedback Loop Summary
    feedback_loop_results: List[Dict[str, Any]] = field(default_factory=list)
    total_patches_processed: int = 0
    patches_successful: int = 0
    patches_unpatchable: int = 0
    total_retry_attempts: int = 0

# =============================================================================
# Logging Setup
# =============================================================================

def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure logging for the pipeline."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    
    logger = logging.getLogger('pipeline')
    logger.setLevel(logging.DEBUG)
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Console handler with colors
    console = logging.StreamHandler()
    console.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    class ColorFormatter(logging.Formatter):
        COLORS = {
            'DEBUG': '\033[36m',     # Cyan
            'INFO': '\033[32m',      # Green
            'WARNING': '\033[33m',   # Yellow
            'ERROR': '\033[31m',     # Red
            'CRITICAL': '\033[35m',  # Magenta
        }
        RESET = '\033[0m'
        
        def format(self, record):
            color = self.COLORS.get(record.levelname, self.RESET)
            record.levelname = f"{color}{record.levelname}{self.RESET}"
            return super().format(record)
    
    console.setFormatter(ColorFormatter(
        '%(asctime)s [%(levelname)s] %(message)s',
        datefmt='%H:%M:%S'
    ))
    logger.addHandler(console)
    
    # File handler
    log_file = LOG_DIR / f'pipeline_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log'
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s [%(levelname)s] %(message)s'
    ))
    logger.addHandler(file_handler)
    
    return logger

logger = setup_logging()

# =============================================================================
# Utility Functions
# =============================================================================

def print_banner():
    """Print pipeline banner."""
    banner = """
╔═══════════════════════════════════════════════════════════════════╗
║                                                                   ║
║              █████╗ ██╗      ███████╗███████╗██████╗              ║
║             ██╔══██╗██║      ██╔════╝██╔════╝██╔══██╗             ║
║             ███████║██║█████╗███████╗███████╗██║  ██║             ║
║             ██╔══██║██║╚════╝╚════██║╚════██║██║  ██║             ║
║             ██║  ██║██║      ███████║███████║██████╔╝             ║
║             ╚═╝  ╚═╝╚═╝      ╚══════╝╚══════╝╚═════╝              ║
║                                                                   ║
║     Automated Security Patch Generation & Validation Pipeline     ║
║                                                                   ║
╚═══════════════════════════════════════════════════════════════════╝
"""
    print(banner)

def print_phase_header(phase: int, name: str):
    """Print phase header."""
    print(f"\n{'='*70}")
    print(f"  PHASE {phase}: {name.upper()}")
    print(f"{'='*70}\n")

def print_summary_table(results: List[PhaseResult]):
    """Print summary table of phase results."""
    print("\n" + "="*70)
    print("  PIPELINE EXECUTION SUMMARY")
    print("="*70)
    print(f"\n{'Phase':<8} {'Name':<25} {'Status':<12} {'Duration':<12} {'Exit':<6}")
    print("-"*70)
    
    for r in results:
        status_icon = {
            PhaseStatus.SUCCESS: "✅",
            PhaseStatus.FAILED: "❌",
            PhaseStatus.SKIPPED: "⏭️",
            PhaseStatus.PENDING: "⏳",
            PhaseStatus.RUNNING: "🔄"
        }.get(r.status, "❓")
        
        print(f"{r.phase:<8} {r.name:<25} {status_icon} {r.status.value:<10} "
              f"{r.duration_seconds:>8.1f}s   {r.exit_code:<6}")
    
    print("-"*70)

def format_duration(seconds: float) -> str:
    """Format duration in human-readable format."""
    if seconds < 60:
        return f"{seconds:.1f}s"
    elif seconds < 3600:
        mins = int(seconds // 60)
        secs = int(seconds % 60)
        return f"{mins}m {secs}s"
    else:
        hours = int(seconds // 3600)
        mins = int((seconds % 3600) // 60)
        return f"{hours}h {mins}m"

# =============================================================================
# Phase Executors
# =============================================================================

class PhaseExecutor:
    """Executes individual pipeline phases."""
    
    def __init__(self, config: PipelineConfig):
        self.config = config
        self.python_cmd = sys.executable
        self.skipped_cves: List[str] = []  # CVEs excluded during manual verification
    
    def execute_phase(self, phase: int) -> PhaseResult:
        """Execute a specific phase."""
        phase_names = {
            0: "Data Aggregation (Phase 0)",
            1: "Vulnerability Reproduction",
            2: "Patch Generation",
            3: "Patch Validation",
            4: "Automated Reporting"
        }
        
        name = phase_names.get(phase, f"Unknown Phase {phase}")
        script = PHASE_SCRIPTS.get(phase)
        
        if not script:
            return PhaseResult(
                phase=phase,
                name=name,
                status=PhaseStatus.FAILED,
                error_message=f"No script defined for phase {phase}"
            )
        
        script_path = self.config.base_dir / script
        if not script_path.exists():
            return PhaseResult(
                phase=phase,
                name=name,
                status=PhaseStatus.FAILED,
                error_message=f"Script not found: {script_path}"
            )
        
        # Build command based on phase
        cmd = self._build_command(phase, script_path)
        
        logger.info(f"Executing: {' '.join(cmd)}")
        
        # Execute phase
        start_time = datetime.now()
        result = PhaseResult(
            phase=phase,
            name=name,
            status=PhaseStatus.RUNNING,
            start_time=start_time.isoformat()
        )
        
        try:
            process = subprocess.run(
                cmd,
                cwd=str(self.config.base_dir),
                capture_output=True,
                text=True,
                timeout=self._get_timeout(phase)
            )
            
            end_time = datetime.now()
            result.end_time = end_time.isoformat()
            result.duration_seconds = (end_time - start_time).total_seconds()
            result.exit_code = process.returncode
            result.stdout = process.stdout
            result.stderr = process.stderr
            
            if process.returncode == 0:
                result.status = PhaseStatus.SUCCESS
                result.output_files = self._detect_output_files(phase)
                logger.info(f"Phase {phase} completed successfully in {format_duration(result.duration_seconds)}")
                
                # Check if output files are missing even on success
                if not result.output_files and phase in [0, 2]:  # Phase 0 and 2 are critical for files
                    logger.warning(f"Phase {phase} completed but no output files were detected!")
                    logger.warning(f"STDOUT:\n{process.stdout}")
                    logger.warning(f"STDERR:\n{process.stderr}")

                if self.config.verbose:
                    logger.info(f"Phase {phase} Output:\n{process.stdout}")
                    if process.stderr:
                        logger.warning(f"Phase {phase} Stderr:\n{process.stderr}")
            else:
                result.status = PhaseStatus.FAILED
                result.error_message = f"Exit code {process.returncode}"
                logger.error(f"Phase {phase} failed with exit code {process.returncode}")
                if process.stderr:
                    logger.error(f"STDERR: {process.stderr[:500]}")
        
        except subprocess.TimeoutExpired:
            end_time = datetime.now()
            result.end_time = end_time.isoformat()
            result.duration_seconds = (end_time - start_time).total_seconds()
            result.status = PhaseStatus.FAILED
            result.error_message = f"Timeout after {self._get_timeout(phase)}s"
            result.exit_code = -1
            logger.error(f"Phase {phase} timed out")
        
        except Exception as e:
            end_time = datetime.now()
            result.end_time = end_time.isoformat()
            result.duration_seconds = (end_time - start_time).total_seconds()
            result.status = PhaseStatus.FAILED
            result.error_message = str(e)
            result.exit_code = -1
            logger.error(f"Phase {phase} failed with exception: {e}")
        
        return result
    
    def _build_command(self, phase: int, script_path: Path) -> List[str]:
        """Build command for a specific phase."""
        cmd = [self.python_cmd, str(script_path)]
        
        # Phase-specific arguments
        if phase == 0:  # glibc_cve_aggregator
            # Phase 0 aggregator has its own CLI; it does not accept --base-dir / --verbose
            pass
        
        elif phase == 1:  # Orchestrator
            cmd.extend(['--base-dir', str(self.config.base_dir)])
            if self.config.verbose:
                cmd.append('--verbose')
            if self.config.cves:
                cmd.extend(['--cve', self.config.cves[0]])  # Single CVE for phase 1
            cmd.extend(['--build-timeout', str(self.config.build_timeout)])
            cmd.extend(['--run-timeout', str(self.config.run_timeout)])
            if self.config.cleanup:
                cmd.append('--cleanup')
            # Pass excluded CVEs from manual verification
            if self.skipped_cves:
                # Deduplicate to be safe
                unique_skipped = sorted(set(self.skipped_cves))
                cmd.extend(['--skip-cves', ','.join(unique_skipped)])
        
        elif phase == 2:  # Patch Generator
            cmd.extend(['--base-dir', str(self.config.base_dir)])
            if self.config.verbose:
                cmd.append('--verbose')
            if self.config.cves:
                cmd.extend(['--cve'] + self.config.cves)
            if self.config.models:
                cmd.extend(['--model'] + self.config.models)
            if self.config.dry_run:
                cmd.append('--dry-run')
        
        elif phase == 3:  # Patch Validator
            cmd.extend(['--base-dir', str(self.config.base_dir)])
            if self.config.verbose:
                cmd.append('--verbose')
            if self.config.cves:
                cmd.extend(['--cve', self.config.cves[0]])
            cmd.extend(['--build-timeout', str(self.config.build_timeout)])
            cmd.extend(['--run-timeout', str(self.config.run_timeout)])
            if self.config.skip_sast:
                cmd.append('--skip-sast')
            if self.config.cleanup:
                cmd.append('--cleanup')
        
        elif phase == 4:  # Reporter
            cmd.extend(['--base-dir', str(self.config.base_dir)])
            if self.config.verbose:
                cmd.append('--verbose')
        
        return cmd
    
    def _get_timeout(self, phase: int) -> int:
        """Get timeout for a specific phase."""
        # Phase 0 involves API calls and git operations
        if phase == 0:
            return 7200  # 2 hours for data aggregation
        # Phase 1 involves Docker builds for reproduction
        elif phase == 1:
            return self.config.build_timeout  # ~1 hours
        # Phase 2 involves LLM API calls (16 tasks × ~10min each worst case)
        elif phase == 2:
            return self.config.build_timeout * 3  # 3 hours for patch generation
        # Phase 3 involves validation - 1h30 as standard
        elif phase == 3:
            return self.config.build_timeout * 2  # 1 hour 30 minutes for validation
        # Phase 4 is reporting - should be quick
        else:
            return 600  # 10 minutes
    
    def _detect_output_files(self, phase: int) -> List[str]:
        """Detect output files generated by a phase."""
        output_files = []
        
        if phase == 0:
            csv_file = self.config.base_dir / "glibc_cve_poc_complete.csv"
            if csv_file.exists():
                output_files.append(str(csv_file))
            json_file = self.config.base_dir / "glibc_cve_poc_map_filtered.json"
            if json_file.exists():
                output_files.append(str(json_file))
        
        elif phase == 1:
            results_file = self.config.base_dir / "results" / "results.json"
            if results_file.exists():
                output_files.append(str(results_file))
            
            docker_builds = self.config.base_dir / "docker_builds"
            if docker_builds.exists():
                for cve_dir in docker_builds.iterdir():
                    if cve_dir.is_dir():
                        output_files.append(str(cve_dir))
        
        elif phase == 2:
            summary_file = self.config.base_dir / "patches" / "pipeline_summary.json"
            if summary_file.exists():
                output_files.append(str(summary_file))
            
            patches_dir = self.config.base_dir / "patches"
            if patches_dir.exists():
                for cve_dir in patches_dir.iterdir():
                    if cve_dir.is_dir() and cve_dir.name.startswith("CVE-"):
                        output_files.append(str(cve_dir))
        
        elif phase == 3:
            validation_dir = self.config.base_dir / "validation_results"
            if validation_dir.exists():
                for f in validation_dir.glob("validation_summary_*.json"):
                    output_files.append(str(f))
        
        elif phase == 4:
            reports_dir = self.config.base_dir / "reports"
            if reports_dir.exists():
                for f in reports_dir.glob("*.md"):
                    output_files.append(str(f))
                for f in reports_dir.glob("*.png"):
                    output_files.append(str(f))
        
        return output_files

# =============================================================================
# Iterative Feedback Loop (Self-Healing Mechanism)
# =============================================================================

class IterativeFeedbackLoop:
    """
    Implements the self-healing mechanism between Phase 2 (Patch Generation)
    and Phase 3 (Validation).
    
    When a patch fails validation:
    1. Extract detailed failure context (PoC results, SAST findings)
    2. Pass failure context back to LLM for improved patch generation
    3. Retry validation with the new patch
    4. Repeat up to MAX_RETRIES times
    5. Mark as "Unpatchable" if all retries fail
    """
    
    def __init__(self, config: PipelineConfig):
        self.config = config
        self.max_retries = config.max_retries
        self.timeout = config.feedback_loop_timeout  # Total timeout for feedback loop
        self.feedback_results: List[FeedbackLoopResult] = []
        
        # Import required modules
        self._import_modules()
        
        # Initialize logger
        self.logger = logging.getLogger('pipeline.feedback_loop')
    
    def _import_modules(self):
        """Import Phase 2 and Phase 3 modules dynamically."""
        import importlib.util
        
        # Import patch_generator module
        gen_spec = importlib.util.spec_from_file_location(
            "patch_generator",
            self.config.base_dir / "patch_generator.py"
        )
        self.patch_generator = importlib.util.module_from_spec(gen_spec)
        gen_spec.loader.exec_module(self.patch_generator)
        
        # Import patch_validator module
        val_spec = importlib.util.spec_from_file_location(
            "patch_validator",
            self.config.base_dir / "patch_validator.py"
        )
        self.patch_validator = importlib.util.module_from_spec(val_spec)
        val_spec.loader.exec_module(self.patch_validator)
    
    def run_with_feedback(
        self,
        cve_id: str,
        model_name: str,
        vuln_data: Dict[str, Any],
        initial_validation_result: Any
    ) -> FeedbackLoopResult:
        """
        Execute the iterative feedback loop for a single patch.
        
        Args:
            cve_id: CVE identifier
            model_name: Model that generated the initial patch
            vuln_data: Vulnerability data from CSV (contains V_FILE, V_FUNCTION, etc.)
            initial_validation_result: Initial validation result from Phase 3
        
        Returns:
            FeedbackLoopResult with complete history
        """
        start_time = datetime.now()
        
        result = FeedbackLoopResult(
            cve_id=cve_id,
            model_name=model_name,
            final_status=PatchStatus.PENDING,
            total_attempts=1,
            validation_history=[],
            start_time=start_time.isoformat()
        )
        
        # Store initial validation result with proper timestamps
        # The initial validation timestamp serves as the end time for attempt 1
        initial_end_time = initial_validation_result.timestamp
        initial_duration = initial_validation_result.execution_time_seconds if hasattr(initial_validation_result, 'execution_time_seconds') else 0.0
        result.validation_history.append({
            "attempt": 1,
            "is_retry": False,
            "status": initial_validation_result.status,
            "poc_blocked": initial_validation_result.poc_blocked,
            "sast_passed": initial_validation_result.sast_passed,
            "error_message": initial_validation_result.error_message,
            "start_time": start_time.isoformat(),
            "end_time": initial_end_time,
            "duration_seconds": initial_duration,
        })
        
        # Check if initial validation passed
        if initial_validation_result.status == self.patch_validator.ValidationStatus.SUCCESS.value:
            end_time = datetime.now()
            result.final_status = PatchStatus.SUCCESS
            result.successful_attempt = 1
            result.final_patch_path = initial_validation_result.patch_file
            result.total_duration_seconds = (end_time - start_time).total_seconds()
            result.end_time = end_time.isoformat()
            self.logger.info(f"✓ {cve_id}/{model_name} passed on first attempt")
            return result
        
        # Initial validation failed - enter feedback loop
        self.logger.info(
            f"[FEEDBACK LOOP] Starting retry cycle for {cve_id}/{model_name} "
            f"(max {self.max_retries} retries)"
        )
        
        current_validation = initial_validation_result
        previous_patch = self._get_patch_content(cve_id, model_name)
        
        for retry in range(1, self.max_retries + 1):
            # Track attempt start time
            attempt_start_time = datetime.now()
            
            # Check timeout before starting retry
            elapsed = (attempt_start_time - start_time).total_seconds()
            if elapsed > self.timeout:
                timeout_end = datetime.now()
                self.logger.warning(
                    f"[TIMEOUT] Feedback loop timeout ({self.timeout}s) exceeded for "
                    f"{cve_id}/{model_name} after {retry - 1} retries"
                )
                result.final_status = PatchStatus.UNPATCHABLE
                result.failure_reason = f"Timeout after {elapsed:.0f}s ({retry - 1} retries)"
                result.total_duration_seconds = elapsed
                result.end_time = timeout_end.isoformat()
                return result
            
            result.total_attempts = retry + 1
            
            self.logger.info(f"[RETRY {retry}/{self.max_retries}] {cve_id}/{model_name}")
            
            # Extract failure context from previous validation
            failure_context = current_validation.to_failure_context()
            
            # Generate new patch with feedback
            new_patch_result = self._generate_patch_with_feedback(
                cve_id=cve_id,
                model_name=model_name,
                vuln_data=vuln_data,
                previous_patch=previous_patch,
                failure_context=failure_context,
                attempt_number=retry + 1
            )
            
            if not new_patch_result.get("success"):
                attempt_end_time = datetime.now()
                attempt_duration = (attempt_end_time - attempt_start_time).total_seconds()
                self.logger.warning(
                    f"Failed to generate retry patch #{retry + 1} for {cve_id}/{model_name}"
                )
                result.validation_history.append({
                    "attempt": retry + 1,
                    "is_retry": True,
                    "status": "generation_failed",
                    "error_message": new_patch_result.get("error", "Unknown generation error"),
                    "start_time": attempt_start_time.isoformat(),
                    "end_time": attempt_end_time.isoformat(),
                    "duration_seconds": attempt_duration,
                })
                continue
            
            # Validate the new patch
            new_validation = self._validate_retry_patch(
                cve_id=cve_id,
                model_name=model_name,
                patch_file=Path(new_patch_result["patch_file"]),
                vuln_data=vuln_data,
                attempt_number=retry + 1
            )
            
            # Calculate attempt duration
            attempt_end_time = datetime.now()
            attempt_duration = (attempt_end_time - attempt_start_time).total_seconds()
            
            # Store validation result in history with complete timestamps
            result.validation_history.append({
                "attempt": retry + 1,
                "is_retry": True,
                "status": new_validation.status,
                "poc_blocked": new_validation.poc_blocked,
                "sast_passed": new_validation.sast_passed,
                "error_message": new_validation.error_message,
                "start_time": attempt_start_time.isoformat(),
                "end_time": attempt_end_time.isoformat(),
                "duration_seconds": attempt_duration,
                "patch_file": new_patch_result.get("patch_file"),
                "generation_duration_seconds": new_patch_result.get("total_duration_ns", 0) / 1e9 if new_patch_result.get("total_duration_ns") else None,
                "validation_duration_seconds": new_validation.execution_time_seconds,
            })
            
            # Check if validation passed
            if new_validation.status == self.patch_validator.ValidationStatus.SUCCESS.value:
                success_end_time = datetime.now()
                result.final_status = PatchStatus.SUCCESS
                result.successful_attempt = retry + 1
                result.final_patch_path = new_patch_result.get("patch_file")
                result.total_duration_seconds = (success_end_time - start_time).total_seconds()
                result.end_time = success_end_time.isoformat()
                
                self.logger.info(
                    f"✓✓ {cve_id}/{model_name} SUCCEEDED on attempt #{retry + 1}"
                )
                
                # Copy successful retry patch to main patches directory
                self._promote_successful_patch(
                    cve_id=cve_id,
                    model_name=model_name,
                    retry_patch_path=Path(new_patch_result["patch_file"]),
                    attempt_number=retry + 1
                )
                
                return result
            
            # Update for next iteration
            current_validation = new_validation
            previous_patch = new_patch_result.get("patched_function", previous_patch)
            
            self.logger.warning(
                f"Retry #{retry} failed for {cve_id}/{model_name}: {new_validation.status}"
            )
        
        # All retries exhausted
        final_end_time = datetime.now()
        result.final_status = PatchStatus.UNPATCHABLE
        result.failure_reason = (
            f"Failed after {self.max_retries} retry attempts. "
            f"Last failure: {current_validation.error_message}"
        )
        result.total_duration_seconds = (final_end_time - start_time).total_seconds()
        result.end_time = final_end_time.isoformat()
        
        self.logger.error(
            f"✗✗ {cve_id}/{model_name} marked as UNPATCHABLE after {result.total_attempts} attempts"
        )
        
        return result
    
    def _get_patch_content(self, cve_id: str, model_name: str) -> str:
        """Get the content of the initial patch."""
        model_safe = model_name.replace(":", "_").replace(".", "_")
        patches_dir = self.config.base_dir / "patches" / cve_id / model_safe
        
        # Find the function-only file
        for f in patches_dir.glob("*_function_only.c"):
            with open(f, 'r') as file:
                return file.read()
        
        # Fallback to main patch file
        for f in patches_dir.glob("*.c"):
            if "_invalid" not in f.name and "_function_only" not in f.name:
                with open(f, 'r') as file:
                    return file.read()
        
        return ""
    
    def _generate_patch_with_feedback(
        self,
        cve_id: str,
        model_name: str,
        vuln_data: Dict[str, Any],
        previous_patch: str,
        failure_context: Dict[str, Any],
        attempt_number: int
    ) -> Dict[str, Any]:
        """Generate a new patch using failure feedback."""
        
        return self.patch_generator.generate_patch_with_feedback(
            cve_id=cve_id,
            function_name=vuln_data['F_NAME'],
            vulnerable_code=vuln_data['V_FUNCTION'],
            file_context=vuln_data['V_FILE'],
            original_filepath=vuln_data['FilePath'],
            model=model_name,
            previous_patch=previous_patch,
            failure_context=failure_context,
            attempt_number=attempt_number,
            output_dir=self.config.base_dir / "patches"
        )
    
    def _validate_retry_patch(
        self,
        cve_id: str,
        model_name: str,
        patch_file: Path,
        vuln_data: Dict[str, Any],
        attempt_number: int
    ) -> Any:
        """Validate a retry patch."""
        
        # Create a minimal args namespace for the validator
        class ValidatorArgs:
            def __init__(self, config: PipelineConfig):
                self.base_dir = str(config.base_dir)
                self.csv_file = str(config.base_dir / "documentation" / "file-function.csv")
                self.patches_dir = str(config.base_dir / "patches")
                self.exploits_dir = str(config.base_dir / "exploits")
                self.build_timeout = config.build_timeout
                self.run_timeout = config.run_timeout
                self.cleanup = config.cleanup
                self.skip_sast = config.skip_sast
                self.verbose = config.verbose
                self.cve = cve_id
        
        args = ValidatorArgs(self.config)
        
        # Create validator pipeline instance
        validator = self.patch_validator.ValidationPipeline(args)
        
        # Get vulnerability info
        vuln_info = self.patch_validator.VulnerabilityInfo(
            cve=cve_id,
            commit_hash=vuln_data.get('V_COMMIT', ''),
            file_path=vuln_data.get('FilePath', ''),
            function_name=vuln_data.get('F_NAME', ''),
            unit_type=vuln_data.get('UNIT_TYPE', '')
        )
        
        # Validate the retry patch
        return validator.validate_single_patch_file(
            patch_file=patch_file,
            cve_id=cve_id,
            model_name=model_name,
            vuln_info=vuln_info,
            attempt_number=attempt_number,
            is_retry=True
        )
    
    def _promote_successful_patch(
        self,
        cve_id: str,
        model_name: str,
        retry_patch_path: Path,
        attempt_number: int
    ):
        """
        Copy successful retry patch to mark it as the final successful patch.
        Also create a metadata file indicating the successful attempt.
        """
        model_safe = model_name.replace(":", "_").replace(".", "_")
        main_patch_dir = self.config.base_dir / "patches" / cve_id / model_safe
        
        # Create success marker file
        success_marker = main_patch_dir / "feedback_loop_success.json"
        with open(success_marker, 'w') as f:
            json.dump({
                "successful_attempt": attempt_number,
                "successful_patch": str(retry_patch_path),
                "timestamp": datetime.now().isoformat()
            }, f, indent=2)
        
        self.logger.info(f"Created success marker at {success_marker}")
    
    def get_results_summary(self) -> Dict[str, Any]:
        """Get summary of all feedback loop results."""
        total = len(self.feedback_results)
        successful = sum(1 for r in self.feedback_results if r.final_status == PatchStatus.SUCCESS)
        unpatchable = sum(1 for r in self.feedback_results if r.final_status == PatchStatus.UNPATCHABLE)
        total_retries = sum(r.total_attempts - 1 for r in self.feedback_results)
        
        return {
            "total_patches": total,
            "successful": successful,
            "unpatchable": unpatchable,
            "success_rate": f"{(successful/total*100):.1f}%" if total > 0 else "N/A",
            "total_retry_attempts": total_retries,
            "results": [r.to_dict() for r in self.feedback_results]
        }


# =============================================================================
# Pipeline Orchestrator
# =============================================================================

class MasterPipeline:
    """Main pipeline orchestrator with iterative feedback loop support."""
    
    def __init__(self, config: PipelineConfig):
        self.config = config
        self.executor = PhaseExecutor(config)
        self.results: List[PhaseResult] = []
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
        # Feedback loop state
        self.feedback_loop: Optional[IterativeFeedbackLoop] = None
        self.feedback_results: List[FeedbackLoopResult] = []
        # Phase 0 state: CVEs skipped due to pending manual review
        self.skipped_cves: set = set()
    
    def run(self) -> bool:
        """Run the complete pipeline with iterative feedback loop support."""
        print_banner()
        
        self.start_time = datetime.now()
        logger.info(f"Pipeline started at {self.start_time.isoformat()}")
        
        # Log configuration
        self._log_configuration()
        
        # Log feedback loop configuration
        if self.config.enable_feedback_loop:
            logger.info(f"Feedback Loop: ENABLED (max_retries={self.config.max_retries})")
        else:
            logger.info("Feedback Loop: DISABLED")
        
        # Validate prerequisites
        if not self._validate_prerequisites():
            logger.error("Prerequisite validation failed")
            return False
        
        # Execute phases
        success = True
        for phase in sorted(self.config.phases):
            print_phase_header(phase, PHASE_SCRIPTS.get(phase, "Unknown"))
            
            # Check if we should skip due to previous failure
            if not success and phase > 0:
                logger.warning(f"Skipping phase {phase} due to previous failure")
                self.results.append(PhaseResult(
                    phase=phase,
                    name=self._get_phase_name(phase),
                    status=PhaseStatus.SKIPPED,
                    error_message="Skipped due to previous phase failure"
                ))
                continue
            
            # Check phase dependencies
            if not self._check_phase_dependencies(phase):
                logger.error(f"Phase {phase} dependencies not met")
                self.results.append(PhaseResult(
                    phase=phase,
                    name=self._get_phase_name(phase),
                    status=PhaseStatus.FAILED,
                    error_message="Dependencies not met"
                ))
                success = False
                continue
            
            # Execute phase
            result = self.executor.execute_phase(phase)
            self.results.append(result)
            
            if result.status != PhaseStatus.SUCCESS:
                success = False
                logger.error(f"Phase {phase} failed: {result.error_message}")
                
                # Print stdout/stderr for debugging
                if result.stdout:
                    logger.debug(f"STDOUT:\n{result.stdout[:1000]}")
                if result.stderr:
                    logger.debug(f"STDERR:\n{result.stderr[:1000]}")
            
            # After Phase 0: wait for manual verification if needed
            if phase == 0 and result.status == PhaseStatus.SUCCESS:
                self._wait_for_manual_verification()
                # Pass excluded CVEs to the executor for subsequent phases
                self.executor.skipped_cves = sorted(self.skipped_cves)
                logger.info(f"Excluded CVEs for Phase 1: {self.executor.skipped_cves}")
            
            # Run feedback loop after Phase 3 if enabled and Phase 3 completed
            if phase == 3 and self.config.enable_feedback_loop:
                self._run_feedback_loop()
        
        self.end_time = datetime.now()
        
        # Generate summary
        self._generate_summary()
        
        # Print results table
        print_summary_table(self.results)
        
        # Print feedback loop summary if applicable
        if self.feedback_results:
            self._print_feedback_loop_summary()
        
        # Final status
        total_duration = (self.end_time - self.start_time).total_seconds()
        status_msg = "COMPLETED SUCCESSFULLY" if success else "COMPLETED WITH FAILURES"
        
        print(f"\n{'='*70}")
        print(f"  PIPELINE {status_msg}")
        print(f"  Total Duration: {format_duration(total_duration)}")
        print(f"{'='*70}\n")
        
        return success
    
    def _wait_for_manual_verification(self):
        """
        After Phase 0, check glibc_cve_poc_complete.csv for rows needing
        manual verification. Present an interactive console menu to the user
        so they can approve all, exclude specific CVEs, or wait.
        
        Also checks for marker files in pipeline/manual_supervision/{CVE}.ok
        """
        csv_path = self.config.base_dir / "glibc_cve_poc_complete.csv"
        if not csv_path.exists():
            logger.warning("Phase 0 CSV output not found, skipping manual verification wait")
            return
        
        # Check for .ok marker files first
        self._check_marker_files(csv_path)
        
        # Initial check for rows needing manual review
        pending_cves = self._get_pending_manual_cves(csv_path)
        
        if not pending_cves:
            logger.info("No CVEs require manual verification - proceeding immediately")
            return
        
        # Show syntax reports flagged for manual supervision
        self._generate_missing_reports(csv_path, pending_cves)
        self._show_syntax_reports(pending_cves)
        
        # Interactive loop
        while True:
            print(f"\n{'='*70}")
            print(f"  MANUAL VERIFICATION REQUIRED")
            print(f"{'='*70}")
            print(f"\n{len(pending_cves)} CVE(s) require manual verification:\n")
            for i, cve in enumerate(pending_cves, 1):
                report_path = self.config.base_dir / "manual_supervision" / f"{cve}_syntax_report.txt"
                # Check if there is an exploit file in exploits/
                exploits_dir = self.config.base_dir / "exploits"
                has_exploit = any(
                    f.stem == cve for f in exploits_dir.iterdir() if f.is_file()
                ) if exploits_dir.exists() else False
                
                status_tags = []
                if report_path.exists():
                    status_tags.append("report available")
                if not has_exploit:
                    status_tags.append("no PoC file")
                tag = f" [{', '.join(status_tags)}]" if status_tags else ""
                print(f"  {i}. {cve}{tag}")
            
            print(f"\nOptions:")
            print(f"  [A] Approve all and continue")
            print(f"  [E] Exclude CVE(s) from the pipeline run and continue")
            print(f"  [V] View syntax report for a CVE")
            print(f"  [R] Refresh (re-check for .ok marker files)")
            print(f"  [Q] Quit pipeline")
            
            try:
                choice = input("\nSelect option: ").strip().upper()
            except (EOFError, KeyboardInterrupt):
                print()
                logger.warning("User interrupted manual verification")
                self.skipped_cves = set(pending_cves)
                return
            
            if choice == 'A':
                # Approve all pending CVEs
                self._approve_cves(csv_path, pending_cves)
                logger.info(f"All {len(pending_cves)} CVE(s) approved")
                return
            
            elif choice == 'E':
                # Let user pick which CVEs to exclude
                excluded = self._interactive_exclude(pending_cves)
                if excluded:
                    self.skipped_cves.update(excluded)
                    remaining = [c for c in pending_cves if c not in excluded]
                    logger.info(f"Excluded {len(excluded)} CVE(s): {', '.join(excluded)}")
                    if remaining:
                        # Ask again for the remaining ones
                        pending_cves = remaining
                        continue
                    else:
                        logger.info("All pending CVEs excluded - proceeding")
                        return
                else:
                    print("No CVEs excluded.")
                    continue
            
            elif choice == 'V':
                # View a syntax report
                self._interactive_view_report(pending_cves)
                continue
            
            elif choice == 'R':
                # Refresh: re-check marker files and CSV
                self._check_marker_files(csv_path)
                pending_cves = self._get_pending_manual_cves(csv_path)
                if not pending_cves:
                    logger.info("All manual verifications completed")
                    return
                print(f"Refreshed - {len(pending_cves)} CVE(s) still pending")
                continue
            
            elif choice == 'Q':
                logger.warning("User chose to quit pipeline during manual verification")
                self.skipped_cves = set(pending_cves)
                return
            
            else:
                print(f"Invalid option '{choice}'. Please try again.")
                continue
    
    def _show_syntax_reports(self, pending_cves: List[str]):
        """Show available syntax reports for CVEs needing manual review."""
        supervision_dir = self.config.base_dir / "manual_supervision"
        if not supervision_dir.exists():
            return
        
        reports = []
        for cve in pending_cves:
            report_path = supervision_dir / f"{cve}_syntax_report.txt"
            if report_path.exists():
                reports.append((cve, report_path))
        
        # Also show reports for CVEs not in the pending list (already in the dir)
        for report_file in sorted(supervision_dir.glob("*_syntax_report.txt")):
            cve_id = report_file.name.replace("_syntax_report.txt", "")
            if cve_id not in [r[0] for r in reports]:
                reports.append((cve_id, report_file))
        
        if reports:
            print(f"\n{'='*70}")
            print(f"  SYNTAX REPORTS FLAGGED FOR MANUAL REVIEW")
            print(f"{'='*70}")
            for cve_id, path in reports:
                # Read first few lines to show status
                try:
                    with open(path, 'r') as f:
                        lines = f.readlines()
                    status_line = next((l.strip() for l in lines if 'Validation Status:' in l), 'Unknown')
                    print(f"  - {cve_id}: {status_line}")
                    print(f"    Report: {path}")
                except Exception:
                    print(f"  - {cve_id}: {path}")
            print()
    
    def _interactive_exclude(self, pending_cves: List[str]) -> List[str]:
        """Let the user choose which CVEs to exclude."""
        print(f"\nSelect CVE(s) to exclude (comma-separated numbers, or 'all'):")
        for i, cve in enumerate(pending_cves, 1):
            print(f"  {i}. {cve}")
        
        try:
            selection = input("\nExclude: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return []
        
        if not selection:
            return []
        
        if selection.lower() == 'all':
            return list(pending_cves)
        
        excluded = []
        for part in selection.split(','):
            part = part.strip()
            try:
                idx = int(part) - 1
                if 0 <= idx < len(pending_cves):
                    excluded.append(pending_cves[idx])
                else:
                    print(f"  Invalid number: {part}")
            except ValueError:
                # Maybe they typed the CVE ID directly
                if part in pending_cves:
                    excluded.append(part)
                else:
                    print(f"  Invalid input: {part}")
        return excluded
    
    def _interactive_view_report(self, pending_cves: List[str]):
        """Let the user view a syntax report for a specific CVE."""
        supervision_dir = self.config.base_dir / "manual_supervision"
        
        print(f"\nSelect CVE to view syntax report:")
        for i, cve in enumerate(pending_cves, 1):
            report_path = supervision_dir / f"{cve}_syntax_report.txt"
            exists = " [available]" if report_path.exists() else " [no report]"
            print(f"  {i}. {cve}{exists}")
        
        try:
            selection = input("\nView report for: ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return
        
        try:
            idx = int(selection) - 1
            if 0 <= idx < len(pending_cves):
                cve = pending_cves[idx]
            else:
                print(f"Invalid number: {selection}")
                return
        except ValueError:
            cve = selection if selection in pending_cves else None
            if not cve:
                print(f"Invalid input: {selection}")
                return
        
        report_path = supervision_dir / f"{cve}_syntax_report.txt"
        if report_path.exists():
            print(f"\n{'─'*70}")
            print(f"Syntax Report: {cve}")
            print(f"{'─'*70}")
            try:
                print(report_path.read_text())
            except Exception as e:
                print(f"Error reading report: {e}")
            print(f"{'─'*70}")
        else:
            print(f"No syntax report found for {cve}")
    
    def _approve_cves(self, csv_path: Path, cves: List[str]):
        """Mark the given CVEs as manually verified in the CSV."""
        try:
            rows = []
            with open(csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                fieldnames = reader.fieldnames
                for row in reader:
                    if row.get('CVE', '').strip() in cves:
                        row['manual_verified'] = 'done'
                        row['manual_verified_at'] = datetime.now().isoformat()
                    rows.append(row)
            
            temp_path = csv_path.parent / f".{csv_path.name}.tmp"
            with open(temp_path, 'w', encoding='utf-8', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
                writer.writeheader()
                writer.writerows(rows)
            temp_path.replace(csv_path)
        except Exception as e:
            logger.error(f"Error approving CVEs in CSV: {e}")
    
    def _get_pending_manual_cves(self, csv_path: Path) -> List[str]:
        """Read CSV and return CVE IDs where manual_review_required=True and manual_verified!=done."""
        pending = []
        try:
            with open(csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    manual_required = str(row.get('manual_review_required', '')).strip().lower()
                    manual_verified = str(row.get('manual_verified', '')).strip().lower()
                    cve_id = row.get('CVE', '').strip()
                    
                    if manual_required in ('true', '1', 'yes') and manual_verified != 'done':
                        # If specific CVEs are requested, only track those
                        if self.config.cves and cve_id not in self.config.cves:
                            continue
                        pending.append(cve_id)
        except Exception as e:
            logger.error(f"Error reading CSV for manual verification check: {e}")
        return pending
    
    def _get_pending_cve_details(self, csv_path: Path) -> Dict[str, Dict[str, str]]:
        """Read CSV and return details for CVEs needing manual review."""
        details = {}
        try:
            with open(csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                for row in reader:
                    manual_required = str(row.get('manual_review_required', '')).strip().lower()
                    manual_verified = str(row.get('manual_verified', '')).strip().lower()
                    cve_id = row.get('CVE', '').strip()
                    
                    if manual_required in ('true', '1', 'yes') and manual_verified != 'done':
                        if self.config.cves and cve_id not in self.config.cves:
                            continue
                        details[cve_id] = {
                            'poc_path': row.get('poc_path', '').strip(),
                            'poc_language': row.get('poc_language', '').strip(),
                            'description': row.get('CVE_Description', '').strip(),
                            'cwe': row.get('CWE', '').strip(),
                            'v_file': row.get('V_FILE', '').strip(),
                            'v_function': row.get('V_FUNCTION', '').strip(),
                        }
        except Exception as e:
            logger.error(f"Error reading CSV for CVE details: {e}")
        return details
    
    def _generate_missing_reports(self, csv_path: Path, pending_cves: List[str]):
        """
        Generate syntax/manual-review reports for any pending CVE that
        does not yet have a report in manual_supervision/.
        
        Two cases:
          - CVE has an exploit file in exploits/ but no report -> run syntax check, generate report
          - CVE has NO exploit file -> generate a report indicating missing/invalid PoC content
        """
        supervision_dir = self.config.base_dir / "manual_supervision"
        supervision_dir.mkdir(parents=True, exist_ok=True)
        exploits_dir = self.config.base_dir / "exploits"
        
        # Get details for all pending CVEs
        cve_details = self._get_pending_cve_details(csv_path)
        
        generated = 0
        for cve_id in pending_cves:
            report_path = supervision_dir / f"{cve_id}_syntax_report.txt"
            if report_path.exists():
                continue  # Already has a report
            
            details = cve_details.get(cve_id, {})
            poc_path_str = details.get('poc_path', '')
            description = details.get('description', 'N/A')
            cwe = details.get('cwe', 'N/A')
            v_file = details.get('v_file', 'N/A')
            v_function = details.get('v_function', 'N/A')
            poc_language = details.get('poc_language', 'unknown')
            
            # Check if exploit file exists
            exploit_file = None
            if poc_path_str:
                candidate = Path(poc_path_str)
                if candidate.exists():
                    exploit_file = candidate
            
            # Also check exploits/ directory for any file matching this CVE
            if not exploit_file and exploits_dir.exists():
                for f in exploits_dir.iterdir():
                    if f.is_file() and f.stem == cve_id:
                        exploit_file = f
                        poc_language = f.suffix.lstrip('.') or 'unknown'
                        break
            
            if exploit_file:
                # Exploit file exists but no report — generate syntax report
                self._generate_syntax_report(
                    cve_id, exploit_file, poc_language, supervision_dir,
                    description=description, cwe=cwe, v_file=v_file, v_function=v_function
                )
            else:
                # No exploit file — generate missing-PoC report
                self._generate_missing_poc_report(
                    cve_id, supervision_dir,
                    description=description, cwe=cwe, v_file=v_file, v_function=v_function
                )
            
            generated += 1
        
        if generated:
            logger.info(f"Generated {generated} missing report(s) in {supervision_dir}")
    
    def _generate_syntax_report(self, cve_id: str, exploit_file: Path, language: str,
                                 supervision_dir: Path, **kwargs):
        """Generate a syntax validation report for an existing exploit file."""
        import shutil as _shutil
        
        # Copy exploit to supervision dir if not already there
        flagged_path = supervision_dir / exploit_file.name
        if not flagged_path.exists():
            _shutil.copy2(exploit_file, flagged_path)
        
        # Basic syntax checks
        errors = []
        warnings = []
        try:
            content = exploit_file.read_text(encoding='utf-8')
            lines = content.splitlines()
            
            if not content.strip():
                errors.append("File is empty")
            elif len(content.strip()) < 20:
                warnings.append(f"File is very short ({len(content.strip())} chars)")
            
            # Language-specific checks
            ext = exploit_file.suffix.lower()
            if ext == '.c':
                if '#include' not in content and 'int main' not in content:
                    warnings.append("No #include directives or main() function found")
            elif ext == '.py':
                try:
                    compile(content, exploit_file.name, 'exec')
                except SyntaxError as se:
                    errors.append(f"Python syntax error at line {se.lineno}: {se.msg}")
            elif ext == '.sh':
                if not lines[0].startswith('#!') if lines else True:
                    warnings.append("Missing shebang line")
            elif ext == '.txt':
                warnings.append("File has .txt extension — may not be directly executable")
                if any(kw in content.lower() for kw in ['proof of concept', 'advisory', 'description']):
                    warnings.append("Content appears to be an advisory/description rather than executable code")
        except Exception as e:
            errors.append(f"Error reading file: {e}")
        
        status = "FAILED - NEEDS MANUAL REVIEW" if errors else "WARNINGS - NEEDS MANUAL REVIEW"
        
        report = f"""SYNTAX VALIDATION REPORT
========================
CVE ID: {cve_id}
File: {exploit_file.name}
Language: {language}
Validation Status: {status}
Generated: {datetime.now().isoformat()}

VULNERABILITY CONTEXT:
---------------------
Description: {kwargs.get('description', 'N/A')}
CWE: {kwargs.get('cwe', 'N/A')}
Vulnerable File: {kwargs.get('v_file', 'N/A')}
Vulnerable Function: {kwargs.get('v_function', 'N/A')}
"""
        if errors:
            report += "\nERRORS:\n-------\n"
            for i, err in enumerate(errors, 1):
                report += f"{i}. {err}\n"
        
        if warnings:
            report += "\nWARNINGS:\n---------\n"
            for i, warn in enumerate(warnings, 1):
                report += f"{i}. {warn}\n"
        
        report += f"""
RECOMMENDED ACTIONS:
-------------------
1. Review the exploit file for correctness
2. Fix any syntax errors identified above
3. Verify the PoC targets the correct vulnerability
4. Once validated, approve via the pipeline menu or create a .ok marker file

EXPLOIT FILE: {exploit_file}
FLAGGED COPY: {flagged_path}
"""
        
        report_path = supervision_dir / f"{cve_id}_syntax_report.txt"
        report_path.write_text(report, encoding='utf-8')
    
    def _generate_missing_poc_report(self, cve_id: str, supervision_dir: Path, **kwargs):
        """Generate a report for a CVE that has no exploit/PoC file."""
        report = f"""MANUAL REVIEW REPORT
========================
CVE ID: {cve_id}
File: NONE — No valid PoC file was generated
Validation Status: MISSING POC - NEEDS MANUAL REVIEW
Generated: {datetime.now().isoformat()}

VULNERABILITY CONTEXT:
---------------------
Description: {kwargs.get('description', 'N/A')}
CWE: {kwargs.get('cwe', 'N/A')}
Vulnerable File: {kwargs.get('v_file', 'N/A')}
Vulnerable Function: {kwargs.get('v_function', 'N/A')}

ISSUE:
------
The Phase 0 aggregator could not produce a valid PoC/exploit file for this CVE.
Possible reasons:
  - The PoC content from ExploitDB or advisories was empty or too short
  - The content failed basic validity checks (e.g., only text, no code)
  - The source exploit data did not contain extractable code blocks
  - An I/O error occurred during file generation

RECOMMENDED ACTIONS:
-------------------
1. Search ExploitDB manually for a PoC: https://www.exploit-db.com/search?cve={cve_id}
2. Check NVD for references: https://nvd.nist.gov/vuln/detail/{cve_id}
3. Search GitHub for existing exploits or PoCs
4. If a PoC is found, save it to exploits/{cve_id}.<ext>
5. Once a valid PoC is in place, approve via the pipeline menu or create a .ok marker file
6. If no PoC exists, exclude this CVE from the pipeline run
"""
        
        report_path = supervision_dir / f"{cve_id}_syntax_report.txt"
        report_path.write_text(report, encoding='utf-8')
    
    def _check_marker_files(self, csv_path: Path):
        """Check for .ok marker files in manual_supervision/ and update CSV."""
        marker_dir = self.config.base_dir / "manual_supervision"
        if not marker_dir.exists():
            return
        
        updated_cves = []
        for marker in marker_dir.glob("*.ok"):
            cve_id = marker.stem  # e.g., CVE-2015-7547.ok -> CVE-2015-7547
            updated_cves.append(cve_id)
        
        if not updated_cves:
            return
        
        # Update CSV to mark these CVEs as verified
        try:
            rows = []
            with open(csv_path, 'r', encoding='utf-8') as f:
                reader = csv.DictReader(f)
                fieldnames = reader.fieldnames
                for row in reader:
                    if row.get('CVE', '').strip() in updated_cves:
                        row['manual_verified'] = 'done'
                        row['manual_verified_at'] = datetime.now().isoformat()
                        logger.info(f"Marker file found - marking {row['CVE']} as verified")
                    rows.append(row)
            
            # Atomic write back
            temp_path = csv_path.parent / f".{csv_path.name}.tmp"
            with open(temp_path, 'w', encoding='utf-8', newline='') as f:
                writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL)
                writer.writeheader()
                writer.writerows(rows)
            temp_path.replace(csv_path)
        except Exception as e:
            logger.error(f"Error updating CSV from marker files: {e}")
    
    def _run_feedback_loop(self):
        """
        Execute the iterative feedback loop for failed validations.
        
        This method:
        1. Loads validation results from Phase 3
        2. Identifies failed patches
        3. Runs the feedback loop for each failed patch
        4. Updates results with retry outcomes
        """
        feedback_loop_start = datetime.now()
        
        logger.info("\n" + "="*70)
        logger.info("  ITERATIVE FEEDBACK LOOP (Self-Healing)")
        logger.info(f"  Started at: {feedback_loop_start.isoformat()}")
        logger.info("="*70)
        
        # Load validation results
        validation_results = self._load_validation_results()
        if not validation_results:
            logger.warning("No validation results found for feedback loop")
            return
        
        # Load vulnerability data from CSV
        vuln_data_map = self._load_vulnerability_data()
        if not vuln_data_map:
            logger.error("Failed to load vulnerability data")
            return
        
        # Initialize feedback loop
        self.feedback_loop = IterativeFeedbackLoop(self.config)
        
        # Identify failed patches that need retry
        failed_patches = [
            r for r in validation_results 
            if r.get("status") != "Success"
        ]
        
        logger.info(f"Found {len(failed_patches)} failed patches for retry")
        
        for idx, failed in enumerate(failed_patches, 1):
            cve_id = failed.get("cve_id")
            model_name = failed.get("model_name")
            
            if not cve_id or not model_name:
                continue
            
            vuln_data = vuln_data_map.get(cve_id)
            if not vuln_data:
                logger.warning(f"No vulnerability data found for {cve_id}")
                continue
            
            # Create ValidationResult-like object from loaded data
            class LoadedValidationResult:
                def __init__(self, data):
                    self.status = data.get("status", "Unknown")
                    self.poc_blocked = data.get("poc_blocked", False)
                    self.sast_passed = data.get("sast_passed", False)
                    self.poc_exit_code = data.get("poc_exit_code")
                    self.poc_output = data.get("poc_output", "")
                    self.build_success = data.get("build_success", False)
                    self.build_logs = data.get("build_logs")
                    self.sast_results = data.get("sast_results", [])
                    self.sast_findings = data.get("sast_findings", [])
                    self.error_message = data.get("error_message")
                    self.timestamp = data.get("timestamp", "")
                    self.patch_file = data.get("patch_file", "")
                    self.attempt_number = data.get("attempt_number", 1)
                    self.execution_time_seconds = data.get("execution_time_seconds", 0.0)
                
                def to_failure_context(self):
                    return {
                        "status": self.status,
                        "poc_blocked": self.poc_blocked,
                        "poc_exit_code": self.poc_exit_code,
                        "poc_output": self.poc_output,
                        "build_success": self.build_success,
                        "build_logs": self.build_logs,
                        "sast_passed": self.sast_passed,
                        "sast_results": self.sast_results,
                        "sast_findings": self.sast_findings,
                        "error_message": self.error_message,
                        "attempt_number": self.attempt_number,
                    }
            
            initial_result = LoadedValidationResult(failed)
            
            logger.info(f"\n[FEEDBACK LOOP] Processing ({idx}/{len(failed_patches)}): {cve_id}/{model_name}")
            
            # Run feedback loop for this patch
            try:
                feedback_result = self.feedback_loop.run_with_feedback(
                    cve_id=cve_id,
                    model_name=model_name,
                    vuln_data=vuln_data,
                    initial_validation_result=initial_result
                )
                self.feedback_results.append(feedback_result)
                logger.info(f"[FEEDBACK LOOP] Completed {cve_id}/{model_name}: {feedback_result.final_status.value} "
                           f"(attempts: {feedback_result.total_attempts}, duration: {feedback_result.total_duration_seconds:.1f}s)")
            except Exception as e:
                logger.exception(f"Error in feedback loop for {cve_id}/{model_name}: {e}")
                # Create failed result with proper timestamps
                error_time = datetime.now()
                self.feedback_results.append(FeedbackLoopResult(
                    cve_id=cve_id,
                    model_name=model_name,
                    final_status=PatchStatus.FAILED,
                    total_attempts=1,
                    failure_reason=str(e),
                    start_time=feedback_loop_start.isoformat(),
                    end_time=error_time.isoformat(),
                    total_duration_seconds=(error_time - feedback_loop_start).total_seconds()
                ))
        
        feedback_loop_end = datetime.now()
        feedback_loop_duration = (feedback_loop_end - feedback_loop_start).total_seconds()
        
        logger.info(f"\n[FEEDBACK LOOP] Completed all patches in {feedback_loop_duration:.1f}s")
        
        # Save feedback loop results with phase timing
        self._save_feedback_loop_results(feedback_loop_start, feedback_loop_end)
    
    def _load_validation_results(self) -> List[Dict[str, Any]]:
        """Load validation results from Phase 3."""
        validation_dir = self.config.base_dir / "validation_results"
        results = []
        
        # Find the most recent summary file
        summary_files = sorted(validation_dir.glob("validation_summary_*.json"), reverse=True)
        if summary_files:
            with open(summary_files[0], 'r') as f:
                data = json.load(f)
                results = data.get("all_results", [])
        
        return results
    
    def _load_vulnerability_data(self) -> Dict[str, Dict[str, Any]]:
        """Load vulnerability data from CSV."""
        import pandas as pd
        
        csv_file = self.config.base_dir / "documentation" / "file-function.csv"
        if not csv_file.exists():
            return {}
        
        df = pd.read_csv(csv_file, sep=';')
        
        vuln_map = {}
        for _, row in df.iterrows():
            cve = row.get('CVE', '')
            if cve:
                vuln_map[cve] = row.to_dict()
        
        return vuln_map
    
    def _save_feedback_loop_results(self, phase_start: datetime = None, phase_end: datetime = None):
        """Save feedback loop results to file with comprehensive timing information."""
        if not self.feedback_results:
            return
        
        results_dir = self.config.base_dir / "results"
        results_dir.mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_file = results_dir / f"feedback_loop_results_{timestamp}.json"
        
        # Calculate total durations per CVE and per model
        duration_by_cve = {}
        duration_by_model = {}
        for r in self.feedback_results:
            # By CVE
            if r.cve_id not in duration_by_cve:
                duration_by_cve[r.cve_id] = {"total_duration_seconds": 0.0, "patch_count": 0, "successful": 0, "failed": 0}
            duration_by_cve[r.cve_id]["total_duration_seconds"] += r.total_duration_seconds
            duration_by_cve[r.cve_id]["patch_count"] += 1
            if r.final_status == PatchStatus.SUCCESS:
                duration_by_cve[r.cve_id]["successful"] += 1
            else:
                duration_by_cve[r.cve_id]["failed"] += 1
            
            # By Model
            if r.model_name not in duration_by_model:
                duration_by_model[r.model_name] = {"total_duration_seconds": 0.0, "patch_count": 0, "successful": 0, "failed": 0}
            duration_by_model[r.model_name]["total_duration_seconds"] += r.total_duration_seconds
            duration_by_model[r.model_name]["patch_count"] += 1
            if r.final_status == PatchStatus.SUCCESS:
                duration_by_model[r.model_name]["successful"] += 1
            else:
                duration_by_model[r.model_name]["failed"] += 1
        
        # Calculate phase total duration
        total_feedback_duration = sum(r.total_duration_seconds for r in self.feedback_results)
        
        # Calculate success statistics
        successful = sum(1 for r in self.feedback_results if r.final_status == PatchStatus.SUCCESS)
        unpatchable = sum(1 for r in self.feedback_results if r.final_status == PatchStatus.UNPATCHABLE)
        failed = sum(1 for r in self.feedback_results if r.final_status == PatchStatus.FAILED)
        total_patches = len(self.feedback_results)
        
        summary = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "phase": "Feedback Loop (Self-Healing)",
            },
            "phase_timing": {
                "start_time": phase_start.isoformat() if phase_start else None,
                "end_time": phase_end.isoformat() if phase_end else None,
                "total_duration_seconds": (phase_end - phase_start).total_seconds() if phase_start and phase_end else total_feedback_duration,
            },
            "configuration": {
                "max_retries": self.config.max_retries,
                "feedback_loop_timeout": self.config.feedback_loop_timeout,
            },
            "summary": {
                "total_patches_processed": total_patches,
                "successful": successful,
                "unpatchable": unpatchable,
                "failed": failed,
                "total_retry_attempts": sum(r.total_attempts - 1 for r in self.feedback_results),
                "total_processing_duration_seconds": total_feedback_duration,
                "success_rate": f"{(successful/total_patches*100):.1f}%" if total_patches > 0 else "N/A",
            },
            "outcome_breakdown": {
                "successful_first_try": sum(1 for r in self.feedback_results if r.final_status == PatchStatus.SUCCESS and r.successful_attempt == 1),
                "successful_after_retry": sum(1 for r in self.feedback_results if r.final_status == PatchStatus.SUCCESS and r.successful_attempt and r.successful_attempt > 1),
                "exhausted_retries": unpatchable,
                "error_during_retry": failed,
            },
            "duration_by_cve": duration_by_cve,
            "duration_by_model": duration_by_model,
            "results": [r.to_dict() for r in self.feedback_results]
        }
        
        with open(results_file, 'w') as f:
            json.dump(summary, f, indent=2)
        
        logger.info(f"Feedback loop results saved to: {results_file}")
    
    def _print_feedback_loop_summary(self):
        """Print feedback loop summary to console."""
        total = len(self.feedback_results)
        successful = sum(1 for r in self.feedback_results if r.final_status == PatchStatus.SUCCESS)
        unpatchable = sum(1 for r in self.feedback_results if r.final_status == PatchStatus.UNPATCHABLE)
        total_retries = sum(r.total_attempts - 1 for r in self.feedback_results)
        
        print("\n" + "="*70)
        print("  FEEDBACK LOOP SUMMARY")
        print("="*70)
        print(f"\n{'Patches Processed:':<30} {total}")
        print(f"{'Successful (after retry):':<30} {successful}")
        print(f"{'Unpatchable:':<30} {unpatchable}")
        print(f"{'Total Retry Attempts:':<30} {total_retries}")
        
        if total > 0:
            print(f"{'Success Rate:':<30} {(successful/total*100):.1f}%")
        
        print("\nDetails:")
        print("-"*70)
        for r in self.feedback_results:
            status_icon = "✓" if r.final_status == PatchStatus.SUCCESS else "✗"
            attempt_info = f"(attempt #{r.successful_attempt})" if r.successful_attempt else f"(after {r.total_attempts} attempts)"
            print(f"  {status_icon} {r.cve_id}/{r.model_name}: {r.final_status.value} {attempt_info}")
        
        print("-"*70)
    
    def _log_configuration(self):
        """Log pipeline configuration."""
        logger.info("Pipeline Configuration:")
        logger.info(f"  Base Directory: {self.config.base_dir}")
        logger.info(f"  CVEs: {self.config.cves or 'All'}")
        logger.info(f"  Models: {self.config.models or 'All'}")
        logger.info(f"  Phases: {self.config.phases}")
        logger.info(f"  Verbose: {self.config.verbose}")
        logger.info(f"  Cleanup: {self.config.cleanup}")
        logger.info(f"  Skip SAST: {self.config.skip_sast}")
        logger.info(f"  Feedback Loop: {'Enabled' if self.config.enable_feedback_loop else 'Disabled'}")
        if self.config.enable_feedback_loop:
            logger.info(f"  Max Retries: {self.config.max_retries}")
        logger.info(f"  Manual Verify Timeout: {self.config.manual_verify_timeout}s")
        logger.info(f"  Manual Verify Poll: {self.config.manual_verify_poll_interval}s")
    
    def _validate_prerequisites(self) -> bool:
        """Validate prerequisites before running pipeline."""
        logger.info("Validating prerequisites...")
        
        # Check if required scripts exist
        for phase, script in PHASE_SCRIPTS.items():
            if phase in self.config.phases:
                script_path = self.config.base_dir / script
                if not script_path.exists():
                    logger.error(f"Missing script: {script_path}")
                    return False
        
        # Check Docker availability for phases 1 and 3
        if 1 in self.config.phases or 3 in self.config.phases:
            try:
                result = subprocess.run(
                    ['docker', 'info'],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                if result.returncode != 0:
                    logger.error("Docker is not running or not accessible")
                    return False
            except Exception as e:
                logger.error(f"Docker check failed: {e}")
                return False
        
        # Check CSV file for phases 1-3
        if any(p in self.config.phases for p in [1, 2, 3]):
            csv_file = self.config.base_dir / "documentation" / "file-function.csv"
            if not csv_file.exists():
                logger.error(f"Missing CSV file: {csv_file}")
                return False
        
        # Pre-flight LLM API health check for Phase 2
        if 2 in self.config.phases:
            logger.info("Checking LLM API connectivity...")
            if not self._check_llm_api_health():
                logger.error("LLM API is not accessible - Phase 2 cannot run")
                logger.error("Please verify the API server is running and accessible")
                return False
            logger.info("✓ LLM API is accessible")
        
        logger.info("Prerequisites validated successfully")
        return True
    
    def _check_llm_api_health(self) -> bool:
        """Check if the LLM API is accessible before starting Phase 2."""
        import requests
        
        # Get API endpoint from config or use default
        api_endpoint = "http://10.3.2.171:80/api/chat"
        
        try:
            # Test with a minimal request
            test_payload = {
                "model": "qwen2.5-coder:1.5b",
                "messages": [{"role": "user", "content": "Hello"}],
                "stream": False,
                "options": {"num_predict": 5}  # Minimal response
            }
            
            logger.info(f"Testing connection to {api_endpoint}...")
            response = requests.post(
                api_endpoint,
                json=test_payload,
                timeout=60  # 60 second timeout for health check
            )
            
            if response.status_code == 200:
                # Verify we got a valid response
                data = response.json()
                if "message" in data or "response" in data:
                    return True
                else:
                    logger.warning(f"API returned unexpected format: {data.keys()}")
                    return True  # Still accessible, might work
            else:
                logger.error(f"API returned status {response.status_code}: {response.text[:200]}")
                return False
                
        except requests.exceptions.Timeout:
            logger.error(f"LLM API timeout - server at {api_endpoint} not responding")
            logger.error("Consider checking if the Ollama server is running")
            return False
        except requests.exceptions.ConnectionError as e:
            logger.error(f"Cannot connect to LLM API at {api_endpoint}")
            logger.error(f"Connection error: {e}")
            return False
        except Exception as e:
            logger.error(f"LLM API health check failed: {e}")
            return False
    
    def _check_phase_dependencies(self, phase: int) -> bool:
        """Check if dependencies for a phase are met."""
        
        if phase == 0:
            # Phase 0 has no dependencies (it produces data)
            return True
        
        elif phase == 1:
            # Phase 1 needs Phase 0 CSV output if Phase 0 was run
            if 0 in self.config.phases:
                csv_file = self.config.base_dir / "glibc_cve_poc_complete.csv"
                if not csv_file.exists():
                    logger.error(f"Phase 0 CSV output not found: {csv_file}")
                    logger.error("Phase 0 likely failed to find any PoC exploits.")
                    logger.error("Ensure the ExploitDB repository is cloned under: %s",
                                 self.config.base_dir / "exploit-database")
                    return False
                # Check if CSV has actual data rows (not just headers)
                try:
                    with open(csv_file, 'r') as f:
                        reader = csv.reader(f)
                        header = next(reader, None)
                        first_row = next(reader, None)
                        if header and not first_row:
                            logger.error(f"Phase 0 CSV is empty (headers only): {csv_file}")
                            logger.error("No CVEs with both git commits AND PoC exploits were found.")
                            logger.error("Check Phase 0 logs for ExploitDB loading issues.")
                            return False
                except Exception as e:
                    logger.error(f"Error reading Phase 0 CSV: {e}")
                    return False
            return True
        
        elif phase == 2:
            # Phase 2 needs Phase 1 outputs (or can run independently)
            # Check if docker_builds exist
            docker_builds = self.config.base_dir / "docker_builds"
            if not docker_builds.exists() or not any(docker_builds.iterdir()):
                logger.warning("Phase 1 outputs not found - Phase 2 may work with limited context")
            return True
        
        elif phase == 3:
            # Phase 3 needs Phase 2 outputs (patches)
            patches_dir = self.config.base_dir / "patches"
            if not patches_dir.exists():
                logger.error("No patches directory found - Phase 2 must run first")
                return False
            
            # Check for VALID patch files (excluding _invalid.c which means API failed)
            # Valid patches are .c files that are NOT _function_only.c and NOT _invalid.c
            all_c_files = list(patches_dir.glob("CVE-*/*/*.c"))
            invalid_files = [f for f in all_c_files if f.name.endswith("_invalid.c")]
            function_only_files = [f for f in all_c_files if f.name.endswith("_function_only.c")]
            valid_patch_files = [f for f in all_c_files 
                                if not f.name.endswith("_function_only.c") 
                                and not f.name.endswith("_invalid.c")]
            
            if not valid_patch_files:
                logger.error("="*60)
                logger.error("NO VALID PATCHES FOUND - Phase 3 cannot proceed")
                logger.error("="*60)
                
                # Provide detailed diagnostics
                if invalid_files:
                    logger.error(f"Found {len(invalid_files)} INVALID patch files (API failures):")
                    for f in invalid_files[:5]:  # Show first 5
                        logger.error(f"  - {f.relative_to(patches_dir)}")
                    if len(invalid_files) > 5:
                        logger.error(f"  ... and {len(invalid_files) - 5} more")
                
                # Check pipeline_summary.json for more details
                summary_file = patches_dir / "pipeline_summary.json"
                if summary_file.exists():
                    try:
                        import json
                        with open(summary_file) as f:
                            summary = json.load(f)
                        stats = summary.get("summary", {})
                        logger.error(f"\nPhase 2 Summary:")
                        logger.error(f"  Total tasks: {stats.get('total_tasks', 'N/A')}")
                        logger.error(f"  Successful: {stats.get('successful', 'N/A')}")
                        logger.error(f"  Failed: {stats.get('failed', 'N/A')}")
                        logger.error(f"  Syntax valid: {stats.get('syntax_valid', 'N/A')}")
                    except Exception:
                        pass
                
                logger.error("\nPossible causes:")
                logger.error("  1. LLM API was not responding (timeout)")
                logger.error("  2. All generated patches had syntax errors")
                logger.error("  3. Phase 2 did not complete successfully")
                logger.error("\nRecommendation: Check logs/patch_generator_*.log for details")
                return False
            
            logger.info(f"Found {len(valid_patch_files)} valid patch files for validation")
            if invalid_files:
                logger.warning(f"Also found {len(invalid_files)} invalid patches (will be skipped)")
            return True
        
        elif phase == 4:
            # Phase 4 can run with any available data
            # But warn if key files are missing
            results_file = self.config.base_dir / "results" / "results.json"
            patches_summary = self.config.base_dir / "patches" / "pipeline_summary.json"
            validation_dir = self.config.base_dir / "validation_results"
            
            warnings = []
            if not results_file.exists():
                warnings.append("Phase 1 results not found")
            if not patches_summary.exists():
                warnings.append("Phase 2 summary not found")
            if not validation_dir.exists() or not any(validation_dir.glob("*.json")):
                warnings.append("Phase 3 validation results not found")
            
            for w in warnings:
                logger.warning(f"Report generation: {w}")
            
            return True
        
        return True
    
    def _get_phase_name(self, phase: int) -> str:
        """Get human-readable phase name."""
        names = {
            0: "Data Aggregation",
            1: "Vulnerability Reproduction",
            2: "Patch Generation",
            3: "Patch Validation",
            4: "Automated Reporting"
        }
        return names.get(phase, f"Phase {phase}")
    
    def _generate_summary(self):
        """Generate and save pipeline summary including feedback loop results."""
        if not self.start_time or not self.end_time:
            return
        
        # Calculate feedback loop statistics
        feedback_loop_stats = []
        total_patches = 0
        patches_successful = 0
        patches_unpatchable = 0
        total_retries = 0
        
        if self.feedback_results:
            total_patches = len(self.feedback_results)
            patches_successful = sum(1 for r in self.feedback_results if r.final_status == PatchStatus.SUCCESS)
            patches_unpatchable = sum(1 for r in self.feedback_results if r.final_status == PatchStatus.UNPATCHABLE)
            total_retries = sum(r.total_attempts - 1 for r in self.feedback_results)
            feedback_loop_stats = [r.to_dict() for r in self.feedback_results]
        
        summary = PipelineSummary(
            start_time=self.start_time.isoformat(),
            end_time=self.end_time.isoformat(),
            duration_seconds=(self.end_time - self.start_time).total_seconds(),
            config={
                'base_dir': str(self.config.base_dir),
                'cves': self.config.cves,
                'models': self.config.models,
                'phases': self.config.phases,
                'verbose': self.config.verbose,
                'cleanup': self.config.cleanup,
                'skip_sast': self.config.skip_sast,
                'enable_feedback_loop': self.config.enable_feedback_loop,
                'max_retries': self.config.max_retries
            },
            phases_completed=sum(1 for r in self.results if r.status == PhaseStatus.SUCCESS),
            phases_failed=sum(1 for r in self.results if r.status == PhaseStatus.FAILED),
            results=[{
                'phase': r.phase,
                'name': r.name,
                'status': r.status.value,
                'start_time': r.start_time,
                'end_time': r.end_time,
                'duration_seconds': r.duration_seconds,
                'exit_code': r.exit_code,
                'output_files': r.output_files,
                'error_message': r.error_message
            } for r in self.results],
            overall_status='success' if all(
                r.status in [PhaseStatus.SUCCESS, PhaseStatus.SKIPPED] 
                for r in self.results
            ) else 'failed',
            # Feedback loop results
            feedback_loop_results=feedback_loop_stats,
            total_patches_processed=total_patches,
            patches_successful=patches_successful,
            patches_unpatchable=patches_unpatchable,
            total_retry_attempts=total_retries
        )
        
        # Save summary
        summary_file = self.config.base_dir / "results" / f"pipeline_run_{self.start_time.strftime('%Y%m%d_%H%M%S')}.json"
        summary_file.parent.mkdir(parents=True, exist_ok=True)
        
        with open(summary_file, 'w') as f:
            json.dump(asdict(summary), f, indent=2)
        
        logger.info(f"Pipeline summary saved to: {summary_file}")

# =============================================================================
# CLI Entry Point
# =============================================================================

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="AI-SSD Master Pipeline Orchestrator with Iterative Feedback Loop",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run complete pipeline with feedback loop
  python pipeline.py
  
  # Run for specific CVE
  python pipeline.py --cve CVE-2015-7547
  
  # Run with specific models
  python pipeline.py --models qwen2.5-coder:7b qwen2.5:7b
  
  # Run only phases 2-4 (skip reproduction)
  python pipeline.py --phases 2 3 4
  
  # Disable feedback loop (no retries)
  python pipeline.py --no-feedback-loop
  
  # Custom max retries for feedback loop
  python pipeline.py --max-retries 5
  
  # Run with cleanup and verbose output
  python pipeline.py --cleanup --verbose
  
  # Dry run to see what would be executed
  python pipeline.py --dry-run
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
        dest='cves',
        metavar='CVE',
        help='Specific CVE ID(s) to process (e.g., CVE-2015-7547)'
    )
    
    parser.add_argument(
        '--models',
        type=str,
        nargs='+',
        metavar='MODEL',
        help=f'Specific model(s) to use for patch generation. Available: {", ".join(DEFAULT_MODELS)}'
    )
    
    parser.add_argument(
        '--phases',
        type=int,
        nargs='+',
        default=[0, 1, 2, 3, 4],
        choices=[0, 1, 2, 3, 4],
        help='Phases to execute (0=Aggregation, 1=Reproduction, 2=Generation, 3=Validation, 4=Reporting)'
    )
    
    parser.add_argument(
        '--build-timeout',
        type=int,
        default=7200,
        help='Docker build timeout in seconds (default: 7200)'
    )
    
    parser.add_argument(
        '--run-timeout',
        type=int,
        default=300,
        help='Container run timeout in seconds (default: 300)'
    )
    
    parser.add_argument(
        '--skip-sast',
        action='store_true',
        help='Skip SAST analysis in validation phase'
    )
    
    parser.add_argument(
        '--cleanup',
        action='store_true',
        help='Clean up Docker images and containers after execution'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Show what would be executed without running'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    # Feedback Loop Arguments
    parser.add_argument(
        '--no-feedback-loop',
        action='store_true',
        help='Disable the iterative feedback loop (no retries for failed patches)'
    )
    
    parser.add_argument(
        '--max-retries',
        type=int,
        default=MAX_RETRIES,
        help=f'Maximum retry attempts for failed patches in feedback loop (default: {MAX_RETRIES})'
    )
    
    # Phase 0 Manual Verification Arguments
    parser.add_argument(
        '--manual-verify-timeout',
        type=int,
        default=MANUAL_VERIFY_TIMEOUT,
        help=f'Timeout in seconds for manual verification wait (default: {MANUAL_VERIFY_TIMEOUT})'
    )
    
    parser.add_argument(
        '--manual-verify-poll',
        type=int,
        default=MANUAL_VERIFY_POLL_INTERVAL,
        help=f'Poll interval in seconds for manual verification (default: {MANUAL_VERIFY_POLL_INTERVAL})'
    )
    
    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_arguments()
    
    # Setup logging
    global logger
    logger = setup_logging(args.verbose)
    
    # Build configuration with feedback loop settings
    config = PipelineConfig(
        base_dir=Path(args.base_dir),
        cves=args.cves,
        models=args.models,
        phases=sorted(args.phases),
        verbose=args.verbose,
        cleanup=args.cleanup,
        skip_sast=args.skip_sast,
        dry_run=args.dry_run,
        build_timeout=args.build_timeout,
        run_timeout=args.run_timeout,
        enable_feedback_loop=not args.no_feedback_loop,
        max_retries=args.max_retries,
        manual_verify_timeout=args.manual_verify_timeout,
        manual_verify_poll_interval=args.manual_verify_poll,
    )
    
    # Handle dry run
    if args.dry_run:
        print_banner()
        print("\n" + "="*70)
        print("  DRY RUN - No actions will be taken")
        print("="*70)
        print("\nConfiguration:")
        print(f"  Base Directory: {config.base_dir}")
        print(f"  CVEs: {config.cves or 'All'}")
        print(f"  Models: {config.models or 'All'}")
        print(f"  Phases to Execute: {config.phases}")
        print(f"  Build Timeout: {config.build_timeout}s")
        print(f"  Run Timeout: {config.run_timeout}s")
        print(f"  Skip SAST: {config.skip_sast}")
        print(f"  Cleanup: {config.cleanup}")
        print(f"  Verbose: {config.verbose}")
        print(f"  Feedback Loop: {'Enabled' if config.enable_feedback_loop else 'Disabled'}")
        if config.enable_feedback_loop:
            print(f"  Max Retries: {config.max_retries}")
        print(f"  Manual Verify Timeout: {config.manual_verify_timeout}s")
        print(f"  Manual Verify Poll: {config.manual_verify_poll_interval}s")
        
        print("\nPhases that would be executed:")
        for phase in config.phases:
            script = PHASE_SCRIPTS.get(phase, "Unknown")
            script_path = config.base_dir / script
            exists = "✅" if script_path.exists() else "❌"
            print(f"  Phase {phase}: {script} {exists}")
        
        if 0 in config.phases:
            print("\nPhase 0 Flow:")
            print("  glibc_cve_aggregator.py → glibc_cve_poc_complete.csv")
            print(f"  → Wait up to {config.manual_verify_timeout}s for manual verification")
            print("  → Proceed to Phase 1 (exclude pending CVEs)")
        
        if config.enable_feedback_loop:
            print("\nFeedback Loop Flow:")
            print("  Phase 3 (Validation) → Failed? → Extract Failure Context")
            print("  → Phase 2 (Regenerate with Context) → Phase 3 (Re-validate)")
            print(f"  → Repeat up to {config.max_retries}x → Success or 'Unpatchable'")
        
        return 0
    
    # Run pipeline
    try:
        pipeline = MasterPipeline(config)
        success = pipeline.run()
        return 0 if success else 1
        
    except KeyboardInterrupt:
        print("\n\nPipeline interrupted by user")
        logger.warning("Pipeline interrupted by user")
        return 130
    
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
