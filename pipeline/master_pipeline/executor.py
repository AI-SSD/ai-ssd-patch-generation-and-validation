import os
import subprocess
import sys
import logging
from datetime import datetime
from pathlib import Path
from typing import List
from .config import BASE_DIR, PipelineConfig, PHASE_SCRIPTS, cfg_section
from .models import PhaseResult, PhaseStatus
from .utils import format_duration
from . import notify

logger = logging.getLogger('pipeline')

class PhaseExecutor:
    """Executes individual pipeline phases."""
    
    def __init__(self, config: PipelineConfig):
        self.config = config
        self.python_cmd = sys.executable
        self.skipped_cves: List[str] = []  # CVEs excluded during manual verification
        # Pipeline root: where scripts and packages live (always the repo root,
        # even when base_dir points to a per-project working directory).
        self._pipeline_root = BASE_DIR
    
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
        
        script_path = self._pipeline_root / script
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

        # Notify: phase starting (gated by notify_phase; low priority so it
        # delivers silently). The cell = the project__profile working-dir name.
        cell = self.config.base_dir.name
        ntitle = f"AI-SSD {cell}"
        notify.send("phase_start",
                    f"{cell} — Phase {phase} ({notify.phase_label(phase)}) started",
                    title=ntitle, base_dir=self.config.base_dir)

        # Execute phase
        start_time = datetime.now()
        result = PhaseResult(
            phase=phase,
            name=name,
            status=PhaseStatus.RUNNING,
            start_time=start_time.isoformat()
        )
        
        try:
            # Build an env that includes the pipeline root on PYTHONPATH so
            # that ``python -m cve_aggregator`` resolves even when base_dir
            # (the CWD) is a per-project working directory.
            env = os.environ.copy()
            pp = env.get("PYTHONPATH", "")
            root_str = str(self._pipeline_root)
            if root_str not in pp.split(os.pathsep):
                env["PYTHONPATH"] = root_str + (os.pathsep + pp if pp else "")
            # Phase 0 runs with cwd=base_dir (a per-project workdir), so shared
            # INPUT clones referenced by relative paths in the Phase 0 YAML
            # (poc_mapper.exploitdb_path, commit_discovery.repo_local_path — kept
            # beside the pipeline dir) must be resolved against the pipeline root,
            # not the CWD. cve_aggregator.modules.base.resolve_input_path reads this.
            env["SSD_PIPELINE_ROOT"] = root_str

            process = subprocess.run(
                cmd,
                cwd=str(self.config.base_dir),
                env=env,
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
                # Notify: phase done, with a best-effort headline metric.
                _hl = notify.phase_headline(phase, self.config.base_dir)
                _dur = format_duration(result.duration_seconds)
                notify.send("phase_done",
                            f"{cell} — Phase {phase} ({notify.phase_label(phase)}) done in {_dur}"
                            + (f" · {_hl}" if _hl else ""),
                            title=ntitle, base_dir=self.config.base_dir)
                # The phase runs as a subprocess with captured output, so the
                # banner above it in this (tee'd) log would otherwise be blank.
                # Each phase ALSO writes its own detailed log under base_dir/logs;
                # point there so the run is never an empty banner. Use --verbose to
                # inline the full child stdout/stderr here instead.
                logger.info(f"Phase {phase} detailed output → {self.config.base_dir / 'logs'}/  (use --verbose to inline)")

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
                notify.send("phase_failed",
                            f"❌ {cell} — Phase {phase} ({notify.phase_label(phase)}) "
                            f"FAILED (exit {process.returncode}) after "
                            f"{format_duration(result.duration_seconds)}",
                            title=ntitle, base_dir=self.config.base_dir)

        except subprocess.TimeoutExpired:
            end_time = datetime.now()
            result.end_time = end_time.isoformat()
            result.duration_seconds = (end_time - start_time).total_seconds()
            result.status = PhaseStatus.FAILED
            result.error_message = f"Timeout after {self._get_timeout(phase)}s"
            result.exit_code = -1
            logger.error(f"Phase {phase} timed out")
            notify.send("phase_failed",
                        f"⏱ {cell} — Phase {phase} ({notify.phase_label(phase)}) "
                        f"TIMED OUT after {self._get_timeout(phase)}s",
                        title=ntitle, base_dir=self.config.base_dir)

        except Exception as e:
            end_time = datetime.now()
            result.end_time = end_time.isoformat()
            result.duration_seconds = (end_time - start_time).total_seconds()
            result.status = PhaseStatus.FAILED
            result.error_message = str(e)
            result.exit_code = -1
            logger.error(f"Phase {phase} failed with exception: {e}")
            notify.send("phase_failed",
                        f"❌ {cell} — Phase {phase} ({notify.phase_label(phase)}) "
                        f"crashed: {str(e)[:160]}",
                        title=ntitle, base_dir=self.config.base_dir)

        return result
    
    def _build_command(self, phase: int, script_path: Path) -> List[str]:
        """Build command for a specific phase."""
        if phase == 0:
            cmd = [self.python_cmd, "-m", "cve_aggregator"]
        else:
            cmd = [self.python_cmd, str(script_path)]
        
        # Phase-specific arguments
        if phase == 0:  # cve_aggregator
            # Resolve Phase 0 config from the pipeline root (where the YAML
            # files live), not from base_dir which may be a project workdir.
            p0 = Path(self.config.phase0_config)
            config_path = p0 if p0.is_absolute() else self._pipeline_root / p0
            cmd.extend(['--config', str(config_path)])
        
        elif phase == 1:  # Orchestrator
            cmd.extend(['--base-dir', str(self.config.base_dir)])
            # Pass the Phase 0 config so Phase 1 can resolve project-specific paths
            phase0_config_path = (
                Path(self.config.phase0_config)
                if Path(self.config.phase0_config).is_absolute()
                else self._pipeline_root / self.config.phase0_config
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
            if getattr(self.config, 'force_baseline', False):
                cmd.append('--force-baseline')
            # Pass excluded CVEs from manual verification
            if self.skipped_cves:
                # Deduplicate to be safe
                unique_skipped = sorted(set(self.skipped_cves))
                cmd.extend(['--skip-cves', ','.join(unique_skipped)])
        
        elif phase == 2:  # Patch Generator
            cmd.extend(['--base-dir', str(self.config.base_dir)])
            # Pass the active project Phase 0 YAML so Phase 2 reads the right
            # phase2: section (prompts/language) instead of the config.yaml default.
            phase0_config_path = (
                Path(self.config.phase0_config)
                if Path(self.config.phase0_config).is_absolute()
                else self._pipeline_root / self.config.phase0_config
            )
            cmd.extend(['--phase0-config', str(phase0_config_path)])
            phase0_csv = self.config.resolve_phase0_outputs().get("csv_path")
            if phase0_csv:
                cmd.extend(['--csv', str(phase0_csv)])
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
            # Pass the active project Phase 0 YAML so Phase 3 resolves the right
            # image_manifest_path and SAST tooling (mirrors Phase 1/2). Without
            # it the validator falls back to config.yaml's glibc default manifest,
            # finds nothing, and reports every CVE as "No Phase 1 Baseline".
            phase0_config_path = (
                Path(self.config.phase0_config)
                if Path(self.config.phase0_config).is_absolute()
                else self._pipeline_root / self.config.phase0_config
            )
            cmd.extend(['--phase0-config', str(phase0_config_path)])
            phase0_csv = self.config.resolve_phase0_outputs().get("csv_path")
            if phase0_csv:
                cmd.extend(['--csv-file', str(phase0_csv)])
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
                # Newest first. glob() order is arbitrary and this dir accumulates
                # one validation_summary per run, so an unsorted list lets a
                # first-match consumer (the execution-summary metric) read a STALE
                # summary from a prior run. The timestamped filenames sort
                # chronologically, so reverse-sort puts THIS run's summary first.
                for f in sorted(validation_dir.glob("validation_summary_*.json"), reverse=True):
                    output_files.append(str(f))

        elif phase == 4:
            reports_dir = self.config.base_dir / str(paths_cfg.get("reports", "reports"))
            if reports_dir.exists():
                # Newest first (timestamped report names sort chronologically) so
                # the current run's report leads instead of a stale one.
                for f in sorted(reports_dir.glob("*.md"), reverse=True):
                    output_files.append(str(f))
                for f in sorted(reports_dir.glob("*.png")):
                    output_files.append(str(f))
        
        return output_files

