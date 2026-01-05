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

Author: AI-SSD Project
Date: 2026-01-04
"""

import os
import sys
import json
import logging
import argparse
import subprocess
import time
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

# Default models available for patch generation
DEFAULT_MODELS = [
    "qwen2.5-coder:1.5b",
    "qwen2.5-coder:7b",
    "qwen2.5:1.5b",
    "qwen2.5:7b"
]

# Phase scripts
PHASE_SCRIPTS = {
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
    phases: List[int] = field(default_factory=lambda: [1, 2, 3, 4])
    verbose: bool = False
    cleanup: bool = False
    skip_sast: bool = False
    dry_run: bool = False
    build_timeout: int = 3600
    run_timeout: int = 300

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
    
    def execute_phase(self, phase: int) -> PhaseResult:
        """Execute a specific phase."""
        phase_names = {
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
        
        # Common arguments
        cmd.extend(['--base-dir', str(self.config.base_dir)])
        
        if self.config.verbose:
            cmd.append('--verbose')
        
        # Phase-specific arguments
        if phase == 1:  # Orchestrator
            if self.config.cves:
                cmd.extend(['--cve', self.config.cves[0]])  # Single CVE for phase 1
            cmd.extend(['--build-timeout', str(self.config.build_timeout)])
            cmd.extend(['--run-timeout', str(self.config.run_timeout)])
            if self.config.cleanup:
                cmd.append('--cleanup')
        
        elif phase == 2:  # Patch Generator
            if self.config.cves:
                cmd.extend(['--cve'] + self.config.cves)
            if self.config.models:
                cmd.extend(['--model'] + self.config.models)
            if self.config.dry_run:
                cmd.append('--dry-run')
        
        elif phase == 3:  # Patch Validator
            if self.config.cves:
                cmd.extend(['--cve', self.config.cves[0]])
            cmd.extend(['--build-timeout', str(self.config.build_timeout)])
            cmd.extend(['--run-timeout', str(self.config.run_timeout)])
            if self.config.skip_sast:
                cmd.append('--skip-sast')
            if self.config.cleanup:
                cmd.append('--cleanup')
        
        elif phase == 4:  # Reporter
            # Reporter only needs base-dir and verbose, already added
            pass
        
        return cmd
    
    def _get_timeout(self, phase: int) -> int:
        """Get timeout for a specific phase."""
        # Phase 1 and 3 involve Docker builds - allow more time
        if phase in [1, 3]:
            return self.config.build_timeout * 5
        # Phase 2 involves LLM API calls
        elif phase == 2:
            return 3600  # 1 hour for patch generation
        # Phase 4 is reporting - should be quick
        else:
            return 600  # 10 minutes
    
    def _detect_output_files(self, phase: int) -> List[str]:
        """Detect output files generated by a phase."""
        output_files = []
        
        if phase == 1:
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
# Pipeline Orchestrator
# =============================================================================

class MasterPipeline:
    """Main pipeline orchestrator."""
    
    def __init__(self, config: PipelineConfig):
        self.config = config
        self.executor = PhaseExecutor(config)
        self.results: List[PhaseResult] = []
        self.start_time: Optional[datetime] = None
        self.end_time: Optional[datetime] = None
    
    def run(self) -> bool:
        """Run the complete pipeline."""
        print_banner()
        
        self.start_time = datetime.now()
        logger.info(f"Pipeline started at {self.start_time.isoformat()}")
        
        # Log configuration
        self._log_configuration()
        
        # Validate prerequisites
        if not self._validate_prerequisites():
            logger.error("Prerequisite validation failed")
            return False
        
        # Execute phases
        success = True
        for phase in sorted(self.config.phases):
            print_phase_header(phase, PHASE_SCRIPTS.get(phase, "Unknown"))
            
            # Check if we should skip due to previous failure
            if not success and phase > 1:
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
        
        self.end_time = datetime.now()
        
        # Generate summary
        self._generate_summary()
        
        # Print results table
        print_summary_table(self.results)
        
        # Final status
        total_duration = (self.end_time - self.start_time).total_seconds()
        status_msg = "COMPLETED SUCCESSFULLY" if success else "COMPLETED WITH FAILURES"
        
        print(f"\n{'='*70}")
        print(f"  PIPELINE {status_msg}")
        print(f"  Total Duration: {format_duration(total_duration)}")
        print(f"{'='*70}\n")
        
        return success
    
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
        
        logger.info("Prerequisites validated successfully")
        return True
    
    def _check_phase_dependencies(self, phase: int) -> bool:
        """Check if dependencies for a phase are met."""
        
        if phase == 1:
            # Phase 1 has no dependencies
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
            
            # Check for patch files
            patch_files = list(patches_dir.glob("CVE-*/*/strtod_l.c")) + \
                         list(patches_dir.glob("CVE-*/*/gconv_trans.c")) + \
                         list(patches_dir.glob("CVE-*/*/res_send.c"))
            
            if not patch_files:
                logger.error("No patch files found - Phase 2 must run first")
                return False
            
            logger.info(f"Found {len(patch_files)} patch files for validation")
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
            1: "Vulnerability Reproduction",
            2: "Patch Generation",
            3: "Patch Validation",
            4: "Automated Reporting"
        }
        return names.get(phase, f"Phase {phase}")
    
    def _generate_summary(self):
        """Generate and save pipeline summary."""
        if not self.start_time or not self.end_time:
            return
        
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
                'skip_sast': self.config.skip_sast
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
            ) else 'failed'
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
        description="AI-SSD Master Pipeline Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run complete pipeline
  python pipeline.py
  
  # Run for specific CVE
  python pipeline.py --cve CVE-2015-7547
  
  # Run with specific models
  python pipeline.py --models qwen2.5-coder:7b qwen2.5:7b
  
  # Run only phases 2-4 (skip reproduction)
  python pipeline.py --phases 2 3 4
  
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
        default=[1, 2, 3, 4],
        choices=[1, 2, 3, 4],
        help='Phases to execute (1=Reproduction, 2=Generation, 3=Validation, 4=Reporting)'
    )
    
    parser.add_argument(
        '--build-timeout',
        type=int,
        default=3600,
        help='Docker build timeout in seconds (default: 3600)'
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
    
    return parser.parse_args()


def main():
    """Main entry point."""
    args = parse_arguments()
    
    # Setup logging
    global logger
    logger = setup_logging(args.verbose)
    
    # Build configuration
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
        run_timeout=args.run_timeout
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
        
        print("\nPhases that would be executed:")
        for phase in config.phases:
            script = PHASE_SCRIPTS.get(phase, "Unknown")
            script_path = config.base_dir / script
            exists = "✅" if script_path.exists() else "❌"
            print(f"  Phase {phase}: {script} {exists}")
        
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
