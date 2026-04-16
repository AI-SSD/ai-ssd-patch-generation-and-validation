import csv
import json
import logging
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any
from dataclasses import asdict
from .config import PipelineConfig, PHASE_SCRIPTS, DEFAULT_MODELS, MAX_RETRIES, BASE_DIR, cfg_section
from .models import PhaseResult, PhaseStatus, PatchStatus, FeedbackLoopResult, PipelineSummary
from .utils import (print_banner, print_phase_header, print_summary_table,
                     format_duration, check_gpu_availability, prompt_gpu_action,
                     wait_for_gpu)
from .executor import PhaseExecutor
from .feedback import IterativeFeedbackLoop

logger = logging.getLogger('pipeline')

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
        # Resolve Phase 0 output paths from its config (project-agnostic)
        self._phase0_outputs = config.resolve_phase0_outputs()
    
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

            # GPU availability check for LLM-dependent phases (0 and 2)
            if phase in (0, 2) and not self.config.dry_run:
                gpu_action = self._check_gpu_before_phase(phase)
                if gpu_action == "skip":
                    logger.info(f"Phase {phase} skipped by user (GPU unavailable).")
                    self.results.append(PhaseResult(
                        phase=phase,
                        name=self._get_phase_name(phase),
                        status=PhaseStatus.SKIPPED,
                        error_message="Skipped by user — GPU unavailable"
                    ))
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
        After Phase 0, check the Phase 0 CSV output for rows needing
        manual verification. Present an interactive console menu to the user
        so they can approve all, exclude specific CVEs, or wait.

        Also checks for marker files in pipeline/manual_supervision/{CVE}.ok
        """
        csv_path = self._phase0_outputs["csv_path"]
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
                supervision_dir = self.config.base_dir / "manual_supervision"
                report_path = supervision_dir / f"{cve}_syntax_report.txt"
                json_reports = list(supervision_dir.glob(f"{cve}_*.validation.json"))
                
                # Check if there is an exploit file in exploits/ or manual_supervision/
                exploits_dir = self.config.base_dir / "exploits"
                has_exploit = any(
                    f.stem == cve for f in exploits_dir.iterdir() if f.is_file()
                ) if exploits_dir.exists() else False
                
                has_manual_exploit = any(f.suffix != ".json" for f in supervision_dir.glob(f"{cve}_*.*"))
                
                status_tags = []
                if report_path.exists() or json_reports:
                    status_tags.append("report available")
                if not has_exploit and not has_manual_exploit:
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
            json_reports = list(supervision_dir.glob(f"{cve}_*.validation.json"))
            if json_reports:
                for jp in json_reports:
                    if (cve, jp) not in reports:
                        reports.append((cve, jp))
            else:
                report_path = supervision_dir / f"{cve}_syntax_report.txt"
                if report_path.exists() and (cve, report_path) not in reports:
                    reports.append((cve, report_path))
        
        # Also show reports for CVEs not in the pending list (already in the dir)
        for report_file in sorted(supervision_dir.glob("*.validation.json")):
            cve_id = report_file.name.split('_')[0]
            if cve_id not in [r[0] for r in reports]:
                reports.append((cve_id, report_file))
        
        for report_file in sorted(supervision_dir.glob("*_syntax_report.txt")):
            cve_id = report_file.name.replace("_syntax_report.txt", "")
            if cve_id not in [r[0] for r in reports]:
                reports.append((cve_id, report_file))
        
        if reports:
            print(f"\n{'='*70}")
            print(f"  SYNTAX REPORTS FLAGGED FOR MANUAL REVIEW")
            print(f"{'='*70}")
            for cve_id, path in reports:
                if path.suffix == '.json':
                    try:
                        data = json.loads(path.read_text())
                        status = "FAILED" if not data.get("is_valid") else "WARNINGS"
                        errs = " | ".join(data.get("errors", [])) or " | ".join(data.get("warnings", []))
                        print(f"  - {cve_id}: Validation Status: {status} ({errs})")
                        print(f"    Report: {path}")
                    except Exception:
                        print(f"  - {cve_id}: {path}")
                else:
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
            has_json = list(supervision_dir.glob(f"{cve}_*.validation.json"))
            report_path = supervision_dir / f"{cve}_syntax_report.txt"
            exists = " [available]" if report_path.exists() or has_json else " [no report]"
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
        
        json_paths = list(supervision_dir.glob(f"{cve}_*.validation.json"))
        report_path = supervision_dir / f"{cve}_syntax_report.txt"
        
        if json_paths:
            for jp in json_paths:
                print(f"\n{'─'*70}")
                print(f"Validation Report: {jp.name}")
                print(f"{'─'*70}")
                try:
                    data = json.loads(jp.read_text())
                    print(json.dumps(data, indent=2))
                except Exception as e:
                    print(f"Error reading JSON report: {e}")
                print(f"{'─'*70}")
        elif report_path.exists():
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
        """Mark the given CVEs as manually verified in the CSV,
        copy their PoC files from manual_supervision/ into exploits/,
        and clean up the manual_supervision/ directory."""
        import shutil as _shutil

        supervision_dir = self.config.base_dir / "manual_supervision"
        exploits_dir = self.config.base_dir / "exploits"
        exploits_dir.mkdir(parents=True, exist_ok=True)

        # 1. Update CSV
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
                writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL,
                                        extrasaction='ignore')
                writer.writeheader()
                writer.writerows(rows)
            temp_path.replace(csv_path)
        except Exception as e:
            logger.error(f"Error approving CVEs in CSV: {e}")

        # 2. Copy PoC files from manual_supervision/ → exploits/ and clean up
        if supervision_dir.exists():
            for cve_id in cves:
                # Find PoC source files (not .json, not .txt reports, not .ok markers)
                for src_file in sorted(supervision_dir.glob(f"{cve_id}_*")):
                    if src_file.suffix in ('.json', '.txt', '.ok'):
                        continue  # skip metadata / reports / markers
                    # Copy to exploits/ using the CVE name (strip the _N index)
                    dest = exploits_dir / src_file.name
                    if not dest.exists():
                        try:
                            _shutil.copy2(src_file, dest)
                            logger.info(f"Copied approved PoC to exploits: {dest.name}")
                        except OSError as exc:
                            logger.warning(f"Failed to copy {src_file.name} to exploits/: {exc}")

                # Remove ALL files for this CVE from manual_supervision/
                for stale in supervision_dir.glob(f"{cve_id}*"):
                    try:
                        stale.unlink()
                        logger.debug(f"Cleaned up manual_supervision/{stale.name}")
                    except OSError as exc:
                        logger.warning(f"Could not remove {stale.name}: {exc}")
    
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
        return list(dict.fromkeys(pending))
    
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
            # Check if cve_aggregator has already generated a JSON validation file
            json_reports = list(supervision_dir.glob(f"{cve_id}_*.validation.json"))
            if json_reports:
                continue
                
            report_path = supervision_dir / f"{cve_id}_syntax_report.txt"
            if report_path.exists():
                continue  # Already has a legacy report
            
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
        """Check for .ok marker files in manual_supervision/ and update CSV.
        Also copies PoC files to exploits/ and cleans up manual_supervision/."""
        import shutil as _shutil

        marker_dir = self.config.base_dir / "manual_supervision"
        if not marker_dir.exists():
            return
        
        updated_cves = []
        for marker in marker_dir.glob("*.ok"):
            cve_id = marker.stem  # e.g., CVE-2015-7547.ok -> CVE-2015-7547
            updated_cves.append(cve_id)
        
        if not updated_cves:
            return

        exploits_dir = self.config.base_dir / "exploits"
        exploits_dir.mkdir(parents=True, exist_ok=True)
        
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
                writer = csv.DictWriter(f, fieldnames=fieldnames, quoting=csv.QUOTE_ALL,
                                        extrasaction='ignore')
                writer.writeheader()
                writer.writerows(rows)
            temp_path.replace(csv_path)
        except Exception as e:
            logger.error(f"Error updating CSV from marker files: {e}")

        # Copy PoC files to exploits/ and clean up manual_supervision/
        for cve_id in updated_cves:
            for src_file in sorted(marker_dir.glob(f"{cve_id}_*")):
                if src_file.suffix in ('.json', '.txt', '.ok'):
                    continue
                dest = exploits_dir / src_file.name
                if not dest.exists():
                    try:
                        _shutil.copy2(src_file, dest)
                        logger.info(f"Copied marker-approved PoC to exploits: {dest.name}")
                    except OSError as exc:
                        logger.warning(f"Failed to copy {src_file.name} to exploits/: {exc}")

            # Remove ALL files for this CVE from manual_supervision/
            for stale in marker_dir.glob(f"{cve_id}*"):
                try:
                    stale.unlink()
                    logger.debug(f"Cleaned up manual_supervision/{stale.name}")
                except OSError as exc:
                    logger.warning(f"Could not remove {stale.name}: {exc}")
    
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
        
        # Check if required scripts exist (resolve from the pipeline root,
        # not base_dir which may be a per-project working directory)
        for phase, script in PHASE_SCRIPTS.items():
            if phase in self.config.phases:
                script_path = BASE_DIR / script
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

        llm_cfg = cfg_section("llm", self.config.base_dir)
        hc_cfg = llm_cfg.get("health_check", {}) if isinstance(llm_cfg.get("health_check"), dict) else {}

        api_endpoint = str(llm_cfg.get("endpoint", "http://localhost:11434/api/chat"))
        hc_timeout = int(hc_cfg.get("timeout", 60))
        hc_num_predict = int(hc_cfg.get("num_predict", 5))

        # Use the first configured model for the health check probe
        models = llm_cfg.get("models", [])
        test_model = str(models[0]) if models else "qwen2.5-coder:1.5b"
        
        try:
            test_payload = {
                "model": test_model,
                "messages": [{"role": "user", "content": "Hello"}],
                "stream": False,
                "options": {"num_predict": hc_num_predict}
            }
            
            logger.info(f"Testing connection to {api_endpoint}...")
            response = requests.post(
                api_endpoint,
                json=test_payload,
                timeout=hc_timeout
            )
            
            if response.status_code == 200:
                data = response.json()
                if "message" in data or "response" in data:
                    return True
                else:
                    logger.warning(f"API returned unexpected format: {data.keys()}")
                    return True
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
                csv_file = self._phase0_outputs["csv_path"]
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

    # ------------------------------------------------------------------
    # GPU availability gate for LLM-dependent phases
    # ------------------------------------------------------------------

    def _resolve_llm_endpoint(self) -> str:
        """Return the LLM API endpoint from config.yaml."""
        llm_cfg = cfg_section("llm", self.config.base_dir)
        return str(llm_cfg.get("endpoint", "http://localhost:11434/api/chat"))

    def _resolve_provider_for_phase(self, phase: int) -> str:
        """Return the LLM provider configured for *phase*.

        Phase 0 reads ``poc_repair.provider`` from the Phase 0 config YAML
        (e.g. ``glibc_config.yaml``).  All other phases read
        ``llm.provider`` from the global ``config.yaml``.
        """
        if phase == 0:
            from .config import _load_yaml, BASE_DIR
            config_path = Path(self.config.phase0_config)
            if not config_path.is_absolute():
                config_path = BASE_DIR / self.config.phase0_config
            p0_cfg = _load_yaml(config_path)
            return str(p0_cfg.get("poc_repair", {}).get("provider", "ollama")).lower()
        # Phases 2+ use the global config
        llm_cfg = cfg_section("llm", self.config.base_dir)
        return str(llm_cfg.get("provider", "ollama")).lower()

    def _check_gpu_before_phase(self, phase: int) -> str:
        """Check GPU availability before an LLM-dependent phase.

        Returns ``"proceed"`` (GPU is free or user chose to continue),
        or ``"skip"`` (user chose to skip the phase).
        """
        # GPU check is only relevant for local Ollama inference.
        provider = self._resolve_provider_for_phase(phase)
        if provider != "ollama":
            logger.info("Phase %d uses provider '%s' — skipping GPU check.", phase, provider)
            return "proceed"

        endpoint = self._resolve_llm_endpoint()
        free, detail = check_gpu_availability(endpoint)

        if free:
            return "proceed"

        phase_name = self._get_phase_name(phase)
        action = prompt_gpu_action(phase_name, detail)

        if action == "wait":
            logger.info("Waiting for GPU to become available …")
            gpu_ready = wait_for_gpu(endpoint, poll_interval=30, timeout=0)
            if gpu_ready:
                return "proceed"
            # Should not reach here (timeout=0 means infinite), but just in case
            return "skip"
        elif action == "skip":
            return "skip"
        else:  # "continue"
            logger.warning(
                "Proceeding with Phase %d on CPU — inference will be slow.", phase
            )
            return "proceed"

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

