import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, List
from .config import PipelineConfig, cfg_section, BASE_DIR
from .models import FeedbackLoopResult, PatchStatus
from .candidates import build_recipes, generate_and_select, Verdict

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

        # Per-attempt model escalation (feedback_loop.models_by_attempt in
        # config.yaml). Keys are attempt numbers (as strings), values are model
        # ids. Empty dict ⇒ every attempt uses the provider default model.
        fb_cfg = cfg_section("feedback_loop", config.base_dir)
        self.models_by_attempt: Dict[str, str] = {
            str(k): str(v)
            for k, v in (fb_cfg.get("models_by_attempt") or {}).items()
            if v
        }

        # Candidate fan-out (best-of-N) configuration. The ``generation:`` section
        # of config.yaml; empty/default (num_candidates: 1) makes the attempt-1
        # fan-out a no-op, so the loop behaves EXACTLY as before.
        self.generation_cfg = cfg_section("generation", config.base_dir)
        self._base_temperature = float(
            cfg_section("llm", config.base_dir).get("temperature", 0.2)
        )

        # Richer feedback memory (feedback_loop.richer_context). Each flag default
        # false ⇒ the retry prompt is byte-identical to today's.
        self.richer_ctx: Dict[str, Any] = fb_cfg.get("richer_context") or {}

        # Import required modules
        self._import_modules()

        # Initialize logger
        self.logger = logging.getLogger('pipeline.feedback_loop')

        # Dedicated feedback-loop log file (under the project logs dir). The
        # feedback loop previously had NO file of its own, and its many per-retry
        # re-validations each spawned a separate validator_<ts>.log (the Phase-3
        # formfactor). Consolidate everything the loop does — orchestration
        # messages, retry patch GENERATION (patch_generator logger), and retry
        # VALIDATION (routed via ValidatorArgs.log_file) — into ONE
        # feedback_loop_<ts>.log. Propagation stays on, so progress still shows in
        # the main run log too.
        self.feedback_log_file = None
        try:
            logs_dir = Path(self.config.base_dir) / "logs"
            logs_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            self.feedback_log_file = logs_dir / f"feedback_loop_{ts}.log"
            fh = logging.FileHandler(self.feedback_log_file)
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"))
            self.logger.addHandler(fh)
            self.logger.setLevel(logging.DEBUG)
            # Retry patch-generation messages go through patch_generator's logger;
            # tee them into the feedback log as well.
            logging.getLogger('patch_generator').addHandler(fh)
            self.logger.info(f"[FEEDBACK LOOP] Logging to {self.feedback_log_file}")
        except Exception as exc:  # logging must never break the loop
            self.feedback_log_file = None
            self.logger.warning(f"[FEEDBACK LOOP] Could not open dedicated log: {exc}")

        if self.models_by_attempt:
            self.logger.info(
                f"[FEEDBACK LOOP] Per-attempt model schedule: {self.models_by_attempt}"
            )

    def _model_for_attempt(self, attempt_number: int) -> Any:
        """Return the configured model id for *attempt_number*, or None.

        None means "use the provider default" (OPENAI_MODEL / the loop model),
        which is what patch_generator falls back to when generation_model is None.
        """
        return self.models_by_attempt.get(str(attempt_number))
    
    def _import_modules(self):
        """Import Phase 2 and Phase 3 modules dynamically."""
        import importlib.util
        
        # The Phase 2/3 scripts live at the PIPELINE ROOT (BASE_DIR), not in
        # config.base_dir — which is the per-project working dir (projects/<name>/)
        # when launched via run_project.sh --base-dir. Resolve against BASE_DIR so
        # the feedback loop finds them regardless of base_dir (mirrors executor.py,
        # which runs these scripts from _pipeline_root).
        # Import patch_generator module
        gen_spec = importlib.util.spec_from_file_location(
            "patch_generator",
            BASE_DIR / "patch_generator.py"
        )
        self.patch_generator = importlib.util.module_from_spec(gen_spec)
        gen_spec.loader.exec_module(self.patch_generator)

        # Import patch_validator module
        val_spec = importlib.util.spec_from_file_location(
            "patch_validator",
            BASE_DIR / "patch_validator.py"
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
            # Attempt 1 was produced by Phase 2 using the attempt-1 model (or the
            # base model when no schedule is configured).
            "generation_model": self._model_for_attempt(1),
        })
        
        # Check if initial validation passed
        if initial_validation_result.status == self.patch_validator.ValidationStatus.SUCCESS.value:
            end_time = datetime.now()
            result.final_status = PatchStatus.SUCCESS
            result.successful_attempt = 1
            result.final_patch_path = initial_validation_result.patch_file
            result.total_duration_seconds = (end_time - start_time).total_seconds()
            result.end_time = end_time.isoformat()
            self.logger.info(f"  ✓ passed on first attempt (no retry needed)")
            return result
        
        # Initial validation failed - enter feedback loop
        self.logger.info(
            f"  initial attempt failed ({initial_validation_result.status})"
            f" — entering retry cycle (max {self.max_retries})"
        )
        
        current_validation = initial_validation_result
        previous_patch = self._get_patch_content(cve_id, model_name)

        # ── Best-of-N attempt-1 fan-out (generation.num_candidates > 1) ──────────
        # The greedy Phase-2 patch (attempt 1) already failed validation; before
        # spending serial, feedback-driven retries, generate the REMAINING
        # diversity candidates (varied temperature / granularity / CoT) and let the
        # real Phase-3 oracle pick the first that blocks the PoC and passes SAST.
        # A no-op when num_candidates == 1 (returns immediately with empty history),
        # so the default run is unchanged.
        try:
            fan_file, fan_val, fan_history = self._run_attempt1_fanout(
                cve_id, model_name, vuln_data, previous_patch)
        except Exception as exc:  # fan-out must never break the serial fallback
            self.logger.warning(
                f"  best-of-N fan-out errored ({exc}); continuing with serial retries")
            fan_file, fan_val, fan_history = None, None, []
        result.validation_history.extend(fan_history)
        if fan_file is not None:
            end_time = datetime.now()
            result.final_status = PatchStatus.SUCCESS
            # total_attempts counts the greedy + the validated fan-out candidates;
            # the winner is the last one evaluated (we stop at first success).
            result.total_attempts = 1 + len(fan_history)
            result.successful_attempt = result.total_attempts
            result.final_patch_path = fan_file
            result.total_duration_seconds = (end_time - start_time).total_seconds()
            result.end_time = end_time.isoformat()
            self._promote_successful_patch(
                cve_id=cve_id, model_name=model_name,
                retry_patch_path=Path(fan_file), attempt_number=result.total_attempts)
            self.logger.info("  ✓ FIXED by best-of-N fan-out (attempt-1 family)")
            return result

        # Cumulative record of FAILED attempts (greedy + each failed retry), used
        # to build richer feedback memory (applied diff + earlier-attempt summaries
        # so the model stops re-proposing rejected edits). Inert when the
        # feedback_loop.richer_context flags are off.
        prior_attempts: List[Dict[str, Any]] = []
        if previous_patch:
            prior_attempts.append({
                "attempt_number": 1,
                "patched_function": previous_patch,
                "outcome": getattr(current_validation, "status", "failed"),
            })

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

            # Resolve the model for THIS attempt (attempt number = retry + 1).
            attempt_model = self._model_for_attempt(retry + 1)
            self.logger.info(
                f"\n  ┌─ Retry {retry}/{self.max_retries}"
                + (f"  →  {attempt_model}" if attempt_model else "")
            )

            # Extract failure context from previous validation
            failure_context = current_validation.to_failure_context()

            # Generate new patch with feedback (per-attempt model when configured)
            new_patch_result = self._generate_patch_with_feedback(
                cve_id=cve_id,
                model_name=model_name,
                vuln_data=vuln_data,
                previous_patch=previous_patch,
                failure_context=failure_context,
                attempt_number=retry + 1,
                generation_model=attempt_model,
                prior_attempts=prior_attempts
            )
            
            if not new_patch_result.get("success"):
                attempt_end_time = datetime.now()
                attempt_duration = (attempt_end_time - attempt_start_time).total_seconds()
                self.logger.warning(f"  └─ ✗ generation failed (retry {retry + 1})")
                result.validation_history.append({
                    "attempt": retry + 1,
                    "is_retry": True,
                    "status": "generation_failed",
                    "error_message": new_patch_result.get("error", "Unknown generation error"),
                    "start_time": attempt_start_time.isoformat(),
                    "end_time": attempt_end_time.isoformat(),
                    "duration_seconds": attempt_duration,
                    "generation_model": new_patch_result.get("generation_model", attempt_model),
                })
                continue
            
            # Validate the new patch
            new_validation = self._validate_retry_patch(
                cve_id=cve_id,
                model_name=model_name,
                patch_file=Path(new_patch_result["patch_file"]),
                vuln_data=vuln_data,
                attempt_number=retry + 1,
                generation_model=new_patch_result.get("generation_model") or attempt_model
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
                "generation_model": new_patch_result.get("generation_model"),
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
                
                self.logger.info(f"  └─ ✓ FIXED on attempt #{retry + 1}")
                
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
            prior_attempts.append({
                "attempt_number": retry + 1,
                "patched_function": new_patch_result.get("patched_function", ""),
                "outcome": new_validation.status,
            })

            self.logger.warning(f"  └─ ✗ retry {retry}/{self.max_retries} failed: {new_validation.status}")

            # Environment conditions cannot be fixed by regenerating the
            # patch — abort the retry cycle instead of burning LLM calls.
            if new_validation.status in ("No Phase 1 Baseline", "Execution Error",
                                         "Patch Not Found"):
                self.logger.warning(
                    f"  └─ aborting: '{new_validation.status}' cannot be fixed by regeneration"
                )
                break
        
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
            f"  ✗ UNPATCHABLE after {result.total_attempts} attempt(s)"
        )
        
        return result
    
    def _get_patch_content(self, cve_id: str, model_name: str) -> str:
        """Get the content of the initial patch."""
        # Use the SAME sanitization patch_generator used to WRITE the dir.
        # sanitize_model_name replaces ':' and '/', NOT '.', so the dir is e.g.
        # "gpt-4.1-mini". The old inline ".replace('.', '_')" looked in
        # "gpt-4_1-mini" (which never exists) and silently returned "" — masking
        # the previous-patch context (and crashing once the fallback used
        # iterdir() on the missing dir). Mirrors _generate_patch_with_feedback.
        model_safe = self.patch_generator.sanitize_model_name(model_name)
        patches_dir = self.config.base_dir / "patches" / cve_id / model_safe
        if not patches_dir.is_dir():
            return ""

        # Find the function-only file (any language extension, not just .c)
        for f in sorted(patches_dir.glob("*_function_only.*")):
            with open(f, 'r') as file:
                return file.read()

        # Fallback to the main patch file: any source file that isn't an
        # _invalid/_function_only artifact or a metadata/raw-response sidecar.
        for f in sorted(patches_dir.iterdir()):
            if not f.is_file() or f.suffix in (".txt", ".json"):
                continue
            if "_invalid" in f.name or "_function_only" in f.name:
                continue
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
        attempt_number: int,
        generation_model: Any = None,
        prior_attempts: Any = None
    ) -> Dict[str, Any]:
        """Generate a new patch using failure feedback.

        ``generation_model`` (when set) selects a per-attempt model for the
        OpenAI provider; None falls back to the provider default. ``prior_attempts``
        (the cumulative failed-attempt records) feeds the richer feedback memory
        gated by ``feedback_loop.richer_context``; the flags below default off, so
        an unconfigured run sends the same prompt as before.
        """
        rc = self.richer_ctx or {}
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
            output_dir=self.config.base_dir / "patches",
            generation_model=generation_model,
            prior_attempts=prior_attempts,
            include_diff=bool(rc.get("applied_diff", False)),
            include_history=bool(rc.get("attempt_history", False)),
            reflexion=bool(rc.get("reflexion", False)),
            # Spear-prompt context from the Phase 0 CSV row: retries name the
            # same CVE description + CWE class as the initial Phase 2 attempt.
            description=str(vuln_data.get('CVE_Description', '') or ''),
            cwe=str(vuln_data.get('CWE', '') or ''),
            cwe_description=str(vuln_data.get('CWE_Description', '') or ''),
        )
    
    def _validate_retry_patch(
        self,
        cve_id: str,
        model_name: str,
        patch_file: Path,
        vuln_data: Dict[str, Any],
        attempt_number: int,
        generation_model: Any = None
    ) -> Any:
        """Validate a retry patch."""
        
        # Create a minimal args namespace for the validator
        class ValidatorArgs:
            def __init__(self, config: PipelineConfig):
                self.base_dir = str(config.base_dir)
                phase0_csv = config.resolve_phase0_outputs().get("csv_path")
                if phase0_csv and phase0_csv.exists():
                    self.csv_file = str(phase0_csv)
                else:
                    self.csv_file = str(config.base_dir / "documentation" / "file-function.csv")
                self.patches_dir = str(config.base_dir / "patches")
                self.exploits_dir = str(config.base_dir / "exploits")
                self.build_timeout = config.build_timeout
                self.run_timeout = config.run_timeout
                self.cleanup = config.cleanup
                self.skip_sast = config.skip_sast
                self.verbose = config.verbose
                self.cve = cve_id
                # Active project's Phase 0 YAML — REQUIRED so the validator
                # resolves the right image_manifest_path (and SAST tooling).
                # Without it ValidationPipeline falls back to config.yaml's glibc
                # default manifest, finds nothing, and every retry is falsely
                # marked "No Phase 1 Baseline" / UNPATCHABLE without re-testing.
                p0 = Path(config.phase0_config)
                if not p0.is_absolute():
                    p0 = BASE_DIR / config.phase0_config
                self.phase0_config = str(p0)

        args = ValidatorArgs(self.config)
        # Route this retry's re-validation into the dedicated feedback log instead
        # of spawning a fresh validator_<ts>.log per attempt.
        args.log_file = str(self.feedback_log_file) if self.feedback_log_file else None

        # Create validator pipeline instance
        validator = self.patch_validator.ValidationPipeline(args)
        
        # Get vulnerability info. poc_language MUST be carried through: for
        # intree-test reproductions it drives is_intree_test, which selects the
        # regression-test re-validation path. Omitting it makes the retry fall
        # through to the ExploitDB run_poc path (no PoC file → spurious failure).
        vuln_info = self.patch_validator.VulnerabilityInfo(
            cve=cve_id,
            commit_hash=vuln_data.get('V_COMMIT', ''),
            file_path=vuln_data.get('FilePath', ''),
            function_name=vuln_data.get('F_NAME', ''),
            unit_type=vuln_data.get('UNIT_TYPE', ''),
            poc_language=vuln_data.get('poc_language', '')
        )
        
        # Validate the retry patch
        return validator.validate_single_patch_file(
            patch_file=patch_file,
            cve_id=cve_id,
            model_name=model_name,
            vuln_info=vuln_info,
            attempt_number=attempt_number,
            is_retry=True,
            generation_model=str(generation_model) if generation_model else ""
        )

    def _write_fanout_candidate(self, cve_id: str, model_name: str,
                                full_patched_file: str, k: int,
                                original_filepath: str) -> Path:
        """Persist a fan-out candidate's patched file to a unique dir on disk.

        The Phase-3 validator takes an explicit patch file path, so each candidate
        gets its own ``patches/<cve>/<model>_fanout{k}/<file>`` so candidates never
        clobber one another (or the Phase-2 / retry artifacts).
        """
        model_safe = self.patch_generator.sanitize_model_name(model_name)
        out_dir = self.config.base_dir / "patches" / cve_id / f"{model_safe}_fanout{k}"
        out_dir.mkdir(parents=True, exist_ok=True)
        fname = Path(original_filepath).name or "patch.c"
        patch_file = out_dir / fname
        patch_file.write_text(full_patched_file)
        return patch_file

    def _run_attempt1_fanout(
        self,
        cve_id: str,
        model_name: str,
        vuln_data: Dict[str, Any],
        greedy_patch_content: str,
    ):
        """Best-of-N diversity fan-out for the attempt-1 family.

        The greedy candidate IS the Phase-2 patch that already failed initial
        validation (that is why the loop is running), so this generates only the
        REMAINING diversity recipes (``build_recipes(...)[1:]``), validates each
        through the real Phase-3 oracle, and returns the first that validates.
        ``generation.num_candidates == 1`` ⇒ no diversity recipes ⇒ immediate
        no-op, leaving the loop's behaviour unchanged.

        Generation, syntactic pre-filter, dedup (incl. a short-circuit for any
        candidate identical to the already-failed greedy patch) and first-success
        selection are delegated to the project-agnostic framework in
        ``master_pipeline.candidates``.

        Returns ``(winner_patch_file | None, winner_validation | None, history)``.
        """
        gen_cfg = self.generation_cfg or {}
        recipes = build_recipes(gen_cfg, base_temperature=self._base_temperature)
        diversity = recipes[1:]  # exclude greedy (already tried as the Phase-2 patch)
        if not diversity:
            return None, None, []  # num_candidates == 1 → unchanged behaviour

        self.logger.info(
            f"  ┌─ best-of-N fan-out: {len(diversity)} diversity candidate(s) "
            f"[{', '.join(r.label() for r in diversity)}]"
        )

        # PoC source for the prompt is read from the run's exploits dir; rebase the
        # generator's module global so generate_one_candidate finds it (mirrors
        # generate_patch_with_feedback, which rebases via output_dir).
        try:
            self.patch_generator.EXPLOITS_DIR = self.config.base_dir / "exploits"
        except Exception:
            pass

        # Generation row = the CSV row (carries CVE/description/CWE/code), with CVE
        # ensured so the PoC lookup and vulnerability context match Phase 2.
        row = dict(vuln_data)
        row.setdefault("CVE", cve_id)
        original_filepath = str(vuln_data.get("FilePath", "patch.c") or "patch.c")

        history: List[Dict[str, Any]] = []
        counter = {"n": 0}
        success_value = self.patch_validator.ValidationStatus.SUCCESS.value

        def _generate(recipe):
            return self.patch_generator.generate_one_candidate(row, model_name, recipe)

        loop = self

        class _Phase3Oracle:
            """Adapt the Phase-3 validator to the candidate framework's Oracle."""

            def evaluate(self, candidate) -> Verdict:
                # Dedup vs the already-failed greedy: identical file → known
                # failure, no (expensive) Docker re-validation.
                if candidate.full_patched_file == greedy_patch_content:
                    return Verdict(success=False, status="duplicate_of_greedy")
                counter["n"] += 1
                k = counter["n"]
                patch_file = loop._write_fanout_candidate(
                    cve_id, model_name, candidate.full_patched_file, k, original_filepath)
                val = loop._validate_retry_patch(
                    cve_id=cve_id, model_name=model_name, patch_file=patch_file,
                    vuln_data=vuln_data, attempt_number=1,
                    generation_model=candidate.recipe.model)
                ok = (val.status == success_value)
                candidate.patch_file = str(patch_file)
                candidate.metadata["validation"] = val
                history.append({
                    "attempt": f"1.{k}",
                    "is_retry": True,
                    "is_fanout": True,
                    "recipe": candidate.recipe.label(),
                    "status": val.status,
                    "poc_blocked": val.poc_blocked,
                    "sast_passed": val.sast_passed,
                    "error_message": val.error_message,
                    "patch_file": str(patch_file),
                    "generation_model": candidate.recipe.model,
                })
                self_status = "✓ FIXED" if ok else f"✗ {val.status}"
                loop.logger.info(f"  │  candidate {candidate.recipe.label()} → {self_status}")
                return Verdict(success=ok, poc_blocked=val.poc_blocked,
                               sast_passed=val.sast_passed, status=val.status,
                               detail={"validation": val, "patch_file": str(patch_file)})

        selection = generate_and_select(
            diversity, _generate, _Phase3Oracle(),
            lazy=bool(gen_cfg.get("lazy", True)),
            dedupe=bool(gen_cfg.get("dedupe", True)),
            prefilter=bool(gen_cfg.get("syntactic_prefilter", True)),
        )

        if selection.succeeded:
            w = selection.winner
            detail = w.verdict.detail if w.verdict else {}
            self.logger.info(f"  └─ ✓ fan-out winner: [{w.recipe.label()}]")
            return detail.get("patch_file"), detail.get("validation"), history

        self.logger.info(
            "  └─ ✗ no fan-out candidate validated — proceeding to feedback retries")
        return None, None, history

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
        # Must match the directory Phase 2 actually created. patch_generator's
        # sanitize_model_name only replaces ':' and '/', NOT '.', so a model like
        # "gpt-4.1-mini" lives in patches/<cve>/gpt-4.1-mini. Sanitizing dots here
        # pointed at a non-existent "gpt-4_1-mini" dir and crashed promotion on a
        # genuine success. Reuse the canonical function and create defensively.
        model_safe = self.patch_generator.sanitize_model_name(model_name)
        main_patch_dir = self.config.base_dir / "patches" / cve_id / model_safe
        main_patch_dir.mkdir(parents=True, exist_ok=True)

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


