import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
from .config import PipelineConfig
from .models import FeedbackLoopResult, PatchStatus

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


