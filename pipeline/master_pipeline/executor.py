import subprocess
import sys
import logging
from datetime import datetime
from pathlib import Path
from typing import List
from .config import PipelineConfig, PHASE_SCRIPTS, cfg_section
from .models import PhaseResult, PhaseStatus
from .utils import format_duration

logger = logging.getLogger('pipeline')

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
        if phase == 0:
            cmd = [self.python_cmd, "-m", "cve_aggregator"]
        else:
            cmd = [self.python_cmd, str(script_path)]
        
        # Phase-specific arguments
        if phase == 0:  # cve_aggregator
            config_path = self.config.base_dir / self.config.phase0_config
            cmd.extend(['--config', str(config_path)])
        
        elif phase == 1:  # Orchestrator
            cmd.extend(['--base-dir', str(self.config.base_dir)])
            # Pass the Phase 0 config so Phase 1 can resolve project-specific paths
            phase0_config_path = (
                Path(self.config.phase0_config)
                if Path(self.config.phase0_config).is_absolute()
                else self.config.base_dir / self.config.phase0_config
            )
            cmd.extend(['--phase0-config', str(phase0_config_path)])
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
        """Get timeout for a specific phase from config.yaml phase_timeouts."""
        phase_timeouts = cfg_section("phase_timeouts", self.config.base_dir)
        # Try config.yaml first, fall back to computed defaults
        if phase_timeouts and phase in phase_timeouts:
            return int(phase_timeouts[phase])
        # Also try string keys (YAML may parse int keys as int or str)
        if phase_timeouts and str(phase) in phase_timeouts:
            return int(phase_timeouts[str(phase)])
        # Legacy fallbacks
        if phase == 0:
            return 7200
        elif phase == 1:
            return self.config.build_timeout
        elif phase == 2:
            return self.config.build_timeout * 3
        elif phase == 3:
            return self.config.build_timeout * 2
        else:
            return 600
    
    def _detect_output_files(self, phase: int) -> List[str]:
        """Detect output files generated by a phase."""
        output_files = []
        paths_cfg = cfg_section("paths", self.config.base_dir)
        
        if phase == 0:
            phase0_paths = self.config.resolve_phase0_outputs()
            for path in phase0_paths.values():
                if path.exists():
                    output_files.append(str(path))
        
        elif phase == 1:
            results_dir = self.config.base_dir / str(paths_cfg.get("results", "results"))
            results_file = results_dir / "results.json"
            if results_file.exists():
                output_files.append(str(results_file))
            
            docker_builds = self.config.base_dir / str(paths_cfg.get("docker_builds", "docker_builds"))
            if docker_builds.exists():
                for cve_dir in docker_builds.iterdir():
                    if cve_dir.is_dir():
                        output_files.append(str(cve_dir))
        
        elif phase == 2:
            patches_dir = self.config.base_dir / str(paths_cfg.get("patches", "patches"))
            summary_file = patches_dir / "pipeline_summary.json"
            if summary_file.exists():
                output_files.append(str(summary_file))
            
            if patches_dir.exists():
                for cve_dir in patches_dir.iterdir():
                    if cve_dir.is_dir() and cve_dir.name.startswith("CVE-"):
                        output_files.append(str(cve_dir))
        
        elif phase == 3:
            validation_dir = self.config.base_dir / str(paths_cfg.get("validation_results", "validation_results"))
            if validation_dir.exists():
                for f in validation_dir.glob("validation_summary_*.json"):
                    output_files.append(str(f))
        
        elif phase == 4:
            reports_dir = self.config.base_dir / str(paths_cfg.get("reports", "reports"))
            if reports_dir.exists():
                for f in reports_dir.glob("*.md"):
                    output_files.append(str(f))
                for f in reports_dir.glob("*.png"):
                    output_files.append(str(f))
        
        return output_files

