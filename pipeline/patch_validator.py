#!/usr/bin/env python3
# =============================================================================
# AI-SSD Project - Phase 3: Multi-Layered Patch Validation Pipeline
# =============================================================================
# Methodology v2 — validates LLM-generated security patches by:
# 1. Deriving a patched image FROM the Phase 1 CVE image (which already holds
#    the vulnerable checkout, configured build tree, installed build and the
#    compiled PoC + run wrapper), applying the patch and rebuilding
#    incrementally
# 2. Re-running the SAME PoC wrapper and comparing its exit code against the
#    deterministic baseline captured by Phase 1 (image_manifest.json):
#    a different exit code ⇒ the vulnerability no longer reproduces
# 3. Running SAST tools host-side on the patched source file
# 4. Generating comprehensive validation reports
# =============================================================================

import os
import sys
import csv
import json
import shutil
import logging
import argparse
import subprocess
import tempfile

# Increase CSV field size limit to handle large PoC content fields
csv.field_size_limit(sys.maxsize)
import re
import yaml
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum
from concurrent.futures import ThreadPoolExecutor, as_completed

# Try to import docker, provide helpful error if not installed
try:
    import docker
    from docker.errors import BuildError, ContainerError, ImageNotFound, APIError
except ImportError:
    print("Error: docker package not installed. Run: pip install docker")
    sys.exit(1)

# =============================================================================
# Configuration – loaded from config.yaml
# =============================================================================

_BASE_DIR = Path(__file__).parent.resolve()
sys.path.insert(0, str(_BASE_DIR))
from master_pipeline.config import load_pipeline_config, cfg_section  # noqa: E402
from master_pipeline.sast_config import (  # noqa: E402
    load_sast_config, SastConfig,
)
from master_pipeline import sast_runner  # noqa: E402  (shared Phase 1/3 SAST run + classify)
from poc_analyzer import PoCAnalyzer  # noqa: E402  (same negative filter Phase 1 uses)
try:  # best-effort live-progress heartbeat for the dashboard (never fatal)
    from cve_aggregator.utils import live_progress  # noqa: E402
except Exception:  # pragma: no cover
    live_progress = None

_cfg = load_pipeline_config(_BASE_DIR)
_paths = _cfg.get("paths", {}) if isinstance(_cfg.get("paths"), dict) else {}

# Per-container memory ceiling — must match Phase 1 (orchestrator.py) so the
# patched run is compared against the baseline under identical limits.
_docker_cfg = _cfg.get("docker", {}) if isinstance(_cfg.get("docker"), dict) else {}
_CONTAINER_MEM_LIMIT = str(_docker_cfg.get("memory_limit") or "6g")

# ---------------------------------------------------------------------------
# Phase 1 image layout (methodology v2)
#
# Phase 3 derives each patched validation image FROM the Phase 1 CVE image,
# which already contains the project checked out at the vulnerable commit
# (/build/<source_dir>), a configured build tree (/build/<build_dir>), the
# installed vulnerable build (<install_prefix>) and the compiled PoC + run
# wrapper. The directory names come from the same Phase 0 YAML the Phase 1
# orchestrator uses, with identical defaults — no per-CVE configuration.
# ---------------------------------------------------------------------------

_DEFAULT_SOURCE_DIR_NAME = "project-src"
_DEFAULT_BUILD_DIR_NAME = "project-build"
_DEFAULT_INSTALL_PREFIX = "/opt/project-build"
_DEFAULT_IMAGE_MANIFEST_PATH = "results/image_manifest.json"

# Must match orchestrator.py's _CONTAINER_SECURITY_OPT: the inherited PoC
# wrapper runs the exploit as a non-root user, and some PoCs need
# unprivileged user namespaces / restricted syscalls (e.g. CVE-2018-1000001).
# Phase 3 must run with the same relaxed profile as Phase 1 or the baseline
# comparison would not be apples-to-apples.
_CONTAINER_SECURITY_OPT = ["seccomp=unconfined", "apparmor=unconfined"]


def _resolve_phase1_layout(base_dir: Path,
                           phase0_config: Optional[Path] = None) -> Dict[str, Any]:
    """Resolve the Phase 1 image layout from the ACTIVE project's Phase 0 config.

    The project YAML is taken from ``phase0_config`` when supplied (the active
    project in a multi-project run, passed by the orchestrator via
    ``--phase0-config``); otherwise it falls back to the ``phase0_config``
    pointer in config.yaml. This matters: reading the wrong project's YAML
    resolves the wrong ``image_manifest_path`` (e.g. glibc's
    ``results/image_manifest.json`` instead of ``results/openssl_image_manifest.json``),
    so every CVE lookup misses and the whole run reports "No Phase 1 Baseline".
    Mirrors orchestrator.py defaults."""
    p1 = {}
    if phase0_config is not None:
        phase0_path: Optional[Path] = Path(phase0_config)
    else:
        phase0_rel = _cfg.get("phase0_config", "")
        phase0_path = Path(phase0_rel) if phase0_rel else None
    if phase0_path is not None:
        if not phase0_path.is_absolute():
            phase0_path = _BASE_DIR / phase0_path
        if phase0_path.exists():
            try:
                import yaml
                with open(phase0_path, "r", encoding="utf-8") as fh:
                    p1 = (yaml.safe_load(fh) or {}).get("phase1", {}) or {}
            except Exception:
                p1 = {}
    manifest_rel = p1.get("image_manifest_path", _DEFAULT_IMAGE_MANIFEST_PATH)
    manifest_path = Path(manifest_rel)
    if not manifest_path.is_absolute():
        manifest_path = base_dir / manifest_path
    return {
        "source_dir_name": p1.get("source_dir_name", _DEFAULT_SOURCE_DIR_NAME),
        "build_dir_name": p1.get("build_dir_name", _DEFAULT_BUILD_DIR_NAME),
        "install_prefix": p1.get("install_prefix", _DEFAULT_INSTALL_PREFIX),
        "image_manifest_path": manifest_path,
        # Project-supplied incremental rebuild recipe for the patched image (the
        # ONLY place build-system commands live in Phase 3). Run as patch_rebuild.sh
        # with the SOURCE_DIR/BUILD_DIR/INSTALL_PREFIX env inherited from the Phase 1
        # image + VULN_FILE; must write the /tmp/ssd_* markers the validator reads.
        "patch_rebuild_script": p1.get("patch_rebuild_script") or None,
    }


# SAST tooling — run HOST-SIDE on the patched source file.
#
# Static analysis of a single source file needs no container; running on the
# host avoids installing analysis tools into EOL-distro images and keeps tool
# versions consistent across all CVEs.
#
# The tool list is NOT hardcoded here — it is project-/language-specific and is
# declared in the active project's Phase 0 YAML (``sast:`` section), resolved by
# master_pipeline.sast_config. Execution, parsing, baseline classification and
# the fail_on gate all live in master_pipeline.sast_runner (shared with Phase 1).
_SAST_CONFIG: SastConfig = load_sast_config(pipeline_config_path=_BASE_DIR / "config.yaml")


class ValidationStatus(Enum):
    """Status codes for validation results"""
    SUCCESS = "Success"                          # Patch validated successfully
    POC_STILL_WORKS = "PoC Still Works"          # Vulnerability not fixed
    POC_HANG = "Patch Caused Hang"               # Patch turned a deterministic baseline into a timeout/hang
    BUILD_ERROR = "Build Error"                  # Failed to build patched glibc
    EXECUTION_ERROR = "Execution Error"          # PoC execution environment failed
    SAST_FAILED = "SAST Failed"                  # SAST found new vulnerabilities
    POC_NOT_FOUND = "PoC Not Found"              # No exploit found for CVE
    PATCH_NOT_FOUND = "Patch Not Found"          # No patch file found
    INVALID_PATCH = "Invalid Patch"              # Patch file is invalid/empty
    TIMEOUT = "Timeout"                          # Execution timed out
    NO_BASELINE = "No Phase 1 Baseline"          # CVE has no reproduction baseline
    UNKNOWN_ERROR = "Unknown Error"              # Unexpected error occurred


class SASTSeverity(Enum):
    """SAST finding severity levels"""
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


@dataclass
class VulnerabilityInfo:
    """Data class to hold vulnerability information from CSV"""
    cve: str
    commit_hash: str
    file_path: str
    function_name: str
    unit_type: str
    poc_language: str = ""

    @property
    def short_commit(self) -> str:
        return self.commit_hash[:12]

    @property
    def is_intree_test(self) -> bool:
        """True when reproduction used the project's own regression test (Option A):
        validation re-runs that test against the patched build (PASS = fixed),
        not exit-code-diff."""
        return (self.poc_language or "").lower() == "intree-test"


def _docker_safe_name(s: str) -> str:
    """Sanitize a string into a Docker-name-safe token (lowercase ``a-z0-9._-``)."""
    s = re.sub(r"[^a-z0-9_.-]+", "-", str(s).lower()).strip("-._")
    return s or "run"


@dataclass
class PatchInfo:
    """Data class to hold patch information"""
    cve_id: str
    model_name: str
    patch_dir: Path
    patched_file: Optional[Path] = None
    function_only_file: Optional[Path] = None
    response_json: Optional[Path] = None
    is_valid: bool = False
    original_filepath: str = ""
    # Model that ACTUALLY generated this patch (per-attempt escalation). The
    # feedback-loop identity stays in model_name (used for image tag/grouping);
    # this is for honest logging of which model produced the attempt.
    generation_model: str = ""
    # Per-cell / per-repeat discriminator (the sanitized run base_dir basename,
    # e.g. "glibc__openai-fast__rep2"). It makes the patched image + container
    # names UNIQUE across concurrently-running cells AND repeats that share the
    # same (cve, model) — the prerequisite for parallel sweeps / overlapping
    # families / parallel repeats. Empty ⇒ the LEGACY name (cve+model only),
    # byte-for-byte the prior behaviour, so any caller that doesn't set it is
    # unchanged.
    cell: str = ""

    @property
    def log_label(self) -> str:
        """`cve/model` for logs, annotated with the real generating model when
        it differs from the loop identity (e.g. an escalated retry)."""
        if self.generation_model and self.generation_model != self.model_name:
            return f"{self.cve_id}/{self.model_name} (patch by {self.generation_model})"
        return f"{self.cve_id}/{self.model_name}"

    @property
    def image_name(self) -> str:
        """Generate Docker image name for this patch (unique per cell when set)."""
        safe_model = self.model_name.replace(":", "_").replace(".", "_")
        suffix = f"-{self.cell}" if self.cell else ""
        return f"ai-ssd-patch/{self.cve_id.lower()}-{safe_model}{suffix}:latest"

    @property
    def container_name(self) -> str:
        """Generate container name for this patch (unique per cell when set)."""
        safe_model = self.model_name.replace(":", "_").replace(".", "_")
        suffix = f"-{self.cell}" if self.cell else ""
        return f"patch-test-{self.cve_id.lower()}-{safe_model}{suffix}"


# SAST findings are plain dicts produced by master_pipeline.sast_runner
# ({tool, severity, message, line, column, cwe_id, rule_id, file_path}); no
# local dataclass is needed — Phase 1 and Phase 3 exchange them via the manifest.


@dataclass
class ValidationResult:
    """Data class to hold validation results"""
    cve_id: str
    model_name: str
    status: str
    poc_blocked: bool                              # True if PoC no longer works (vulnerability fixed)
    build_success: bool
    sast_passed: bool
    sast_results: List[Dict[str, Any]] = field(default_factory=list)
    poc_exit_code: Optional[int] = None
    baseline_exit_code: Optional[int] = None       # Phase 1 deterministic baseline
    poc_output: Optional[str] = None
    error_message: Optional[str] = None
    execution_time_seconds: float = 0
    timestamp: str = ""
    patch_file: str = ""
    # New fields for feedback loop support
    sast_findings: List[Dict[str, Any]] = field(default_factory=list)  # All findings on the patched file
    # SAST baseline comparison (methodology: score the patch's delta, not the
    # codebase's pre-existing debt). Classified against the Phase 1 baseline:
    sast_baseline_findings: List[Dict[str, Any]] = field(default_factory=list)  # Phase 1 (unpatched) findings
    sast_preexisting: List[Dict[str, Any]] = field(default_factory=list)        # in both → unchanged debt
    sast_resolved: List[Dict[str, Any]] = field(default_factory=list)           # in baseline, gone after patch
    sast_new: List[Dict[str, Any]] = field(default_factory=list)                # introduced by patch → gates + feeds back
    build_logs: Optional[str] = None  # Build error logs for feedback
    attempt_number: int = 1  # Track which attempt this is
    is_retry: bool = False  # Whether this was a retry validation
    # Negative-filter evidence on the PATCHED run (mirrors Phase 1's proof model):
    # the verdict is no longer a bare exit-code delta — it records whether the
    # exploit output explicitly shows it failed, and how confident "blocked" is.
    nf_failed: Optional[bool] = None              # True if the patched PoC output shows the exploit failed
    nf_reason: Optional[str] = None               # short justification from the filter
    nf_source: Optional[str] = None               # "llm" | "regex" | "regex-fallback" | "binary-abstain"
    poc_proof_confidence: Optional[str] = None    # "confirmed" | "exit-change" | "completion-only" | None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            "cve_id": self.cve_id,
            "model_name": self.model_name,
            "status": self.status,
            "poc_blocked": self.poc_blocked,
            "build_success": self.build_success,
            "sast_passed": self.sast_passed,
            "sast_results": self.sast_results,
            "sast_findings": self.sast_findings,
            # Baseline-classified SAST (only `sast_new` affects pass/fail):
            "sast_preexisting": self.sast_preexisting,
            "sast_resolved": self.sast_resolved,
            "sast_new": self.sast_new,
            "sast_counts": {
                "baseline": len(self.sast_baseline_findings),
                "preexisting": len(self.sast_preexisting),
                "resolved": len(self.sast_resolved),
                "new": len(self.sast_new),
            },
            "poc_exit_code": self.poc_exit_code,
            "baseline_exit_code": self.baseline_exit_code,
            "poc_output": self.poc_output[:2000] if self.poc_output else None,  # Truncate long outputs
            "error_message": self.error_message,
            "execution_time_seconds": self.execution_time_seconds,
            "timestamp": self.timestamp,
            "patch_file": self.patch_file,
            "build_logs": self.build_logs[:2000] if self.build_logs else None,
            "attempt_number": self.attempt_number,
            "is_retry": self.is_retry,
            "nf_failed": self.nf_failed,
            "nf_reason": self.nf_reason,
            "nf_source": self.nf_source,
            "poc_proof_confidence": self.poc_proof_confidence,
        }
    
    def to_failure_context(self) -> Dict[str, Any]:
        """
        Convert validation result to failure context for feedback loop.
        
        This provides the necessary context for Phase 2 to generate an improved patch.
        """
        return {
            "status": self.status,
            "poc_blocked": self.poc_blocked,
            "poc_exit_code": self.poc_exit_code,
            "baseline_exit_code": self.baseline_exit_code,
            "poc_output": self.poc_output,
            "build_success": self.build_success,
            "build_logs": self.build_logs,
            "sast_passed": self.sast_passed,
            "sast_results": self.sast_results,
            "sast_findings": self.sast_findings,
            # Feedback must target ONLY patch-introduced findings — pre-existing
            # issues are out of scope for the patch and are never sent to the LLM.
            "sast_new": self.sast_new,
            "error_message": self.error_message,
            "attempt_number": self.attempt_number,
            "nf_failed": self.nf_failed,
            "nf_reason": self.nf_reason,
            "poc_proof_confidence": self.poc_proof_confidence,
        }


# =============================================================================
# Logging Configuration
# =============================================================================

def setup_logging(log_dir: Path, verbose: bool = False,
                  log_file: Optional[Path] = None) -> logging.Logger:
    """Configure logging for the validator.

    ``log_file`` overrides the default ``validator_<ts>.log`` name. The feedback
    loop passes its own ``feedback_loop_<ts>.log`` so its many per-retry
    re-validations append to ONE dedicated feedback log instead of spawning a
    fresh validator_*.log (the Phase-3 formfactor) for every attempt."""
    log_dir.mkdir(parents=True, exist_ok=True)

    if log_file is None:
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        log_file = log_dir / f"validator_{timestamp}.log"

    log_level = logging.DEBUG if verbose else logging.INFO
    
    # Create formatters
    file_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    console_formatter = logging.Formatter(
        '%(levelname)s: %(message)s'
    )
    
    # File handler
    file_handler = logging.FileHandler(log_file)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(file_formatter)
    
    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(console_formatter)
    
    # Configure logger
    logger = logging.getLogger('validator')
    logger.setLevel(logging.DEBUG)
    # Clear existing handlers to prevent duplicates when module is re-imported
    logger.handlers.clear()
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger


# =============================================================================
# CSV Parser
# =============================================================================

class CSVParser:
    """Parses the file-function.csv to extract vulnerability information"""
    
    def __init__(self, csv_path: Path, logger: logging.Logger):
        self.csv_path = csv_path
        self.logger = logger
    
    def parse(self) -> Dict[str, VulnerabilityInfo]:
        """Parse CSV and return dict mapping CVE to VulnerabilityInfo"""
        vulnerabilities = {}
        
        self.logger.info(f"Parsing CSV file: {self.csv_path}")
        
        if not self.csv_path.exists():
            raise FileNotFoundError(f"CSV file not found: {self.csv_path}")
        
        with open(self.csv_path, 'r', encoding='utf-8') as f:
            # Detect delimiter from the HEADER line only. Sampling the body is
            # unreliable: data cells embed semicolon-heavy C source (V_FUNCTION,
            # PoC code), which would falsely outvote the real comma delimiter.
            # Column headers never contain embedded code, so the first line is
            # the trustworthy signal.
            header_line = f.readline()
            f.seek(0)
            delimiter = ';' if header_line.count(';') > header_line.count(',') else ','

            reader = csv.DictReader(f, delimiter=delimiter)
            
            for row in reader:
                cve = row.get('CVE', '').strip()
                if not cve or cve in vulnerabilities:
                    continue
                
                vuln = VulnerabilityInfo(
                    cve=cve,
                    commit_hash=row.get('V_COMMIT', '').strip(),
                    file_path=row.get('FilePath', '').strip(),
                    function_name=row.get('F_NAME', '').strip(),
                    unit_type=row.get('UNIT_TYPE', '').strip(),
                    poc_language=row.get('poc_language', '').strip()
                )
                vulnerabilities[cve] = vuln
                self.logger.debug(f"Found vulnerability: {cve}")
        
        self.logger.info(f"Parsed {len(vulnerabilities)} vulnerabilities from CSV")
        return vulnerabilities


# =============================================================================
# Patch Discovery
# =============================================================================

class PatchDiscovery:
    """Discovers and loads patch files from the patches directory"""
    
    def __init__(self, patches_dir: Path, logger: logging.Logger, cell_disc: str = ""):
        self.patches_dir = patches_dir
        self.logger = logger
        # Per-cell/per-repeat Docker-name discriminator threaded onto each
        # discovered PatchInfo (see ValidationPipeline.cell_disc). Empty ⇒ legacy
        # cve+model image/container names.
        self.cell_disc = cell_disc
        # Patches that exist on disk but are deliberately NOT validated (test-file
        # targets, no usable patch produced). Recorded here so the Phase 3 summary
        # can report the Phase 2 → Phase 3 hand-off drop instead of silently
        # shrinking total_validations. Populated by _load_patch_info().
        self.skipped_patches: List[Dict[str, str]] = []

    def discover_patches(self, cve_filter: Optional[str] = None) -> List[PatchInfo]:
        """Discover all patches in the patches directory"""
        patches = []
        self.skipped_patches = []   # fresh per discovery run
        
        self.logger.info(f"Discovering patches in: {self.patches_dir}")
        
        if not self.patches_dir.exists():
            self.logger.error(f"Patches directory not found: {self.patches_dir}")
            return patches
        
        # Iterate through CVE directories
        for cve_dir in self.patches_dir.iterdir():
            if not cve_dir.is_dir():
                continue
            
            cve_id = cve_dir.name.upper()
            
            # Skip if filtering by specific CVE
            if cve_filter and cve_id != cve_filter.upper():
                continue
            
            # Iterate through model directories
            for model_dir in cve_dir.iterdir():
                if not model_dir.is_dir():
                    continue

                # Skip feedback-loop retry artifacts (e.g. "gpt-4.1-mini_retry2").
                # These are produced and validated IN-PROCESS by the feedback
                # loop, not Phase 2 outputs. Discovering them makes a standalone
                # Phase 3 re-run validate N× the real patch count (one per retry).
                if re.search(r'_retry\d+$', model_dir.name):
                    self.logger.debug(f"Skipping feedback retry dir: {model_dir.name}")
                    continue

                patch_info = self._load_patch_info(cve_id, model_dir)
                if patch_info:
                    patches.append(patch_info)
        
        self.logger.info(f"Discovered {len(patches)} patches")
        return patches
    
    def _load_patch_info(self, cve_id: str, model_dir: Path) -> Optional[PatchInfo]:
        """Load patch information from a model directory"""
        model_name = model_dir.name.replace("_", ":")  # Convert qwen2.5_7b back to qwen2.5:7b
        
        # Find patch files
        patched_file = None
        function_only_file = None
        response_json = None
        invalid_file = None

        for file in model_dir.iterdir():
            if file.name == "response.json":
                response_json = file
            elif file.name.endswith("_function_only.c"):
                function_only_file = file
            elif file.name.endswith("_invalid.c"):
                # Host-side `gcc -fsyntax-only` flagged this patch. That gate
                # FALSE-NEGATIVES on project-internal code (missing internal
                # headers/types it can't see standalone), so the patch may be
                # perfectly good. Keep it as a fallback and let the REAL
                # in-container rebuild be the arbiter (a true compile failure
                # then feeds the feedback loop) instead of hard-dropping it.
                invalid_file = file
            elif file.name.endswith(".c"):
                # This is the full patched file (e.g., strtod_l.c)
                if "_function_only" not in file.name:
                    patched_file = file

        # B1: defer the syntax verdict to the in-container build. When no clean
        # patched file exists, fall back to the host-syntax-flagged one (if it
        # carries real content) rather than dropping the CVE before Phase 3.
        if not patched_file and invalid_file and invalid_file.exists() and invalid_file.stat().st_size > 0:
            patched_file = invalid_file
            self.logger.info(
                f"{cve_id}/{model_name}: host gcc flagged {invalid_file.name}; "
                f"validating anyway — the in-container rebuild is the real arbiter"
            )
        
        # Load metadata from response.json if available
        original_filepath = ""
        is_valid = False
        
        if response_json and response_json.exists():
            try:
                with open(response_json, 'r') as f:
                    metadata = json.load(f)
                    original_filepath = metadata.get("original_filepath", "")
                    is_valid = metadata.get("syntax_valid", False)
            except Exception as e:
                self.logger.warning(f"Failed to parse {response_json}: {e}")
        
        # A patch whose TARGET is a regression TEST (not the vulnerable source)
        # can only "pass" validation by altering/deleting the test itself — a
        # false positive (cf. openssl CVE-2016-7055 editing test/bntest.c and
        # dropping the discriminating assertion). Reject it here so it can never
        # become a spurious Success. Project-agnostic: keys off the same test-path
        # conventions Phase 0 uses (tst-/test-/bug- basename or a test directory).
        if original_filepath:
            _p = original_filepath.replace("\\", "/").lower()
            _base = _p.rsplit("/", 1)[-1]
            _dirs = _p.split("/")[:-1]
            if _base.startswith(("tst-", "test-", "test_", "bug-")) or any(
                d in ("test", "tests", "testsuite", "regress", "regression") for d in _dirs
            ):
                self.logger.warning(
                    f"{cve_id}/{model_name}: patch target {original_filepath!r} is a TEST file, "
                    f"not vulnerable source — skipping (a test-file patch cannot be a real fix)"
                )
                self.skipped_patches.append({
                    "cve": cve_id, "model": model_name,
                    "reason": "test_file_target", "target": original_filepath,
                })
                return None

        # Only return if we have a valid patched file
        if patched_file and patched_file.exists():
            patch_info = PatchInfo(
                cve_id=cve_id,
                model_name=model_name,
                patch_dir=model_dir,
                patched_file=patched_file,
                function_only_file=function_only_file,
                response_json=response_json,
                is_valid=is_valid,
                original_filepath=original_filepath,
                cell=self.cell_disc,
            )
            self.logger.debug(f"Loaded patch: {cve_id}/{model_name} (valid={is_valid})")
            return patch_info

        self.logger.warning(f"No valid patch file found in {model_dir}")
        self.skipped_patches.append({
            "cve": cve_id, "model": model_name, "reason": "no_patch_file",
        })
        return None


# =============================================================================
# Dockerfile Generator for Patched Code
# =============================================================================

class ImageManifest:
    """Reads the Phase 1 image manifest (results/image_manifest.json).

    Per CVE it provides the built CVE image tag and the deterministic
    baseline exit code captured on the known-vulnerable build — the two
    pieces Phase 3 needs to derive a patched image and judge the re-run.
    """

    def __init__(self, manifest_path: Path, logger: logging.Logger):
        self.manifest_path = manifest_path
        self.logger = logger
        self.entries: Dict[str, Dict[str, Any]] = {}
        self._load()

    def _load(self):
        if not self.manifest_path.exists():
            self.logger.error(f"Phase 1 image manifest not found: {self.manifest_path}")
            return
        try:
            with open(self.manifest_path) as f:
                manifest = json.load(f)
            for entry in manifest.get("cve_images", []):
                cve = entry.get("cve", "").upper()
                if cve:
                    self.entries[cve] = entry
            self.logger.info(
                f"Loaded Phase 1 manifest: {len(self.entries)} CVE image(s), "
                f"{sum(1 for e in self.entries.values() if e.get('baseline_exit_code') is not None)} "
                f"with a baseline"
            )
        except Exception as e:
            self.logger.error(f"Failed to parse image manifest {self.manifest_path}: {e}")

    def get(self, cve_id: str) -> Optional[Dict[str, Any]]:
        return self.entries.get(cve_id.upper())


class PatchedDockerfileGenerator:
    """Generates Dockerfiles for patched validation images.

    Methodology v2: the patched image derives FROM the Phase 1 CVE image,
    which already contains the vulnerable checkout, the configured build
    tree, the installed vulnerable build, the compiled PoC and the run
    wrapper (CMD is inherited). Only the patched file is copied in and the
    project rebuilt incrementally — the same environment Phase 1 measured
    the baseline in, with exactly one variable changed: the patch.
    """

    DOCKERFILE_TEMPLATE = '''# =============================================================================
# AI-SSD Patched Validation Image - {cve}
# Model: {model_name}
# Derived from Phase 1 CVE image: {cve_image_tag}
# =============================================================================
FROM {cve_image_tag}

LABEL maintainer="AI-SSD Project"
LABEL ai-ssd.type="validation"
LABEL cve="{cve}"
LABEL model="{model_name}"

# Per-build compile-jobs cap (SSD_MAKE_JOBS): the rebuild script runs make -j
# with this value when set, else nproc. Passed as a build-arg by the validator
# so concurrent Phase-3 rebuilds don't oversubscribe the host cores. Declared
# here so it is in scope for the rebuild RUN below.
ARG SSD_MAKE_JOBS

# Apply the patch over the vulnerable source file. `touch` guarantees the
# file is newer than every existing build artifact (COPY may preserve an
# older mtime, which would make the incremental rebuild skip it). The COPY
# dest carries the file's real extension (e.g. .c / .java); the context name
# is a fixed staging name.
COPY patched_source.c /build/{source_dir}/{vuln_file_path}
RUN touch /build/{source_dir}/{vuln_file_path}

# The patched file (relative to the source tree) for the rebuild script's checks.
ENV VULN_FILE={vuln_file_path}

# Project-supplied incremental rebuild (phase1.patch_rebuild_script) — the ONLY
# place build-system/compiler commands live in Phase 3. Reuses the
# SOURCE_DIR/BUILD_DIR/INSTALL_PREFIX env baked into the Phase 1 image. It MUST
# write the markers the validator + feedback loop read:
#   /tmp/ssd_rebuild.log     full build trace
#   /tmp/ssd_build_errors    compiler diagnostics (feedback context)
#   /tmp/ssd_obj_rebuilt     did the patched object rebuild? (empty = didn't compile)
#   /tmp/ssd_poc_uses_build  honesty re-check (does the PoC resolve the project build?)
# Tolerant by design: a non-compiling PATCH must NOT fail the image build (it is
# surfaced via the markers), so the script exits 0. No build commands in code.
COPY patch_rebuild.sh /patch_rebuild.sh
RUN bash /patch_rebuild.sh

# Restore the parent image's working directory: the inherited run wrapper
# executes the PoC via relative path (./exploit) from /poc.
WORKDIR /poc

# CMD (the Phase 1 run wrapper) is inherited from the parent image: it
# re-runs the PoC identically and exits with the PoC's own exit code.
'''

    def __init__(self, logger: logging.Logger, layout: Dict[str, Any]):
        self.logger = logger
        self.layout = layout

    def generate(
        self,
        patch_info: PatchInfo,
        vuln_info: VulnerabilityInfo,
        cve_image_tag: str,
        output_dir: Path
    ) -> Optional[Path]:
        """Generate Dockerfile deriving from the Phase 1 CVE image."""
        # The in-repo path of the vulnerable file, recorded by Phase 0/2.
        vuln_file_path = (patch_info.original_filepath or vuln_info.file_path).strip().lstrip("/")
        if not vuln_file_path:
            self.logger.error(
                f"{patch_info.cve_id}: no vulnerable file path recorded "
                f"(Phase 2 response.json / Phase 0 CSV) — cannot apply patch"
            )
            return None

        self.logger.info(
            f"Generating Dockerfile for {patch_info.log_label} "
            f"derived from {cve_image_tag} (patching {vuln_file_path})"
        )

        dockerfile_content = self.DOCKERFILE_TEMPLATE.format(
            cve=patch_info.cve_id,
            model_name=patch_info.model_name,
            cve_image_tag=cve_image_tag,
            source_dir=self.layout["source_dir_name"],
            vuln_file_path=vuln_file_path,
        )

        # Create output directory
        safe_model = patch_info.model_name.replace(":", "_").replace(".", "_")
        build_dir = output_dir / patch_info.cve_id.lower() / safe_model
        build_dir.mkdir(parents=True, exist_ok=True)

        dockerfile_path = build_dir / "Dockerfile"
        with open(dockerfile_path, 'w') as f:
            f.write(dockerfile_content)

        # Project-supplied rebuild recipe (phase1.patch_rebuild_script). No recipe
        # configured → a stub that fails loudly rather than silently producing an
        # unrebuilt image (which would validate the patch against the OLD binary).
        rebuild_script = self.layout.get("patch_rebuild_script")
        if rebuild_script and rebuild_script.strip():
            patch_rebuild = rebuild_script
        else:
            self.logger.error(
                f"{patch_info.cve_id}: phase1.patch_rebuild_script is not configured "
                "for this project — cannot rebuild the patched image"
            )
            patch_rebuild = (
                "#!/bin/bash\n"
                "echo 'ERROR: no phase1.patch_rebuild_script configured' >&2\n"
                "echo '' > /tmp/ssd_obj_rebuilt\n"
                "exit 1\n"
            )
        (build_dir / "patch_rebuild.sh").write_text(patch_rebuild)

        self.logger.debug(f"Dockerfile written to: {dockerfile_path}")
        return build_dir

    # ----- Option A: in-tree regression-test validation (PROJECT-AGNOSTIC) -----
    # Derive FROM the Phase 1 in-tree image (vulnerable tree + overlaid test +
    # the project's baked build/run scripts), apply the patch over the vulnerable
    # file, rebuild by re-running the project's OWN build script, and inherit the
    # CMD (/run_intree_test.sh). No build-system/compiler commands live here —
    # the verdict is the test's PASS/FAIL (a non-compiling patch leaves the build
    # broken → the test won't PASS → reported as not-fixed). Works for any
    # project (glibc make, tomcat maven, kernel kbuild, …) unchanged.
    INTREE_DOCKERFILE_TEMPLATE = '''# =============================================================================
# AI-SSD Patched In-Tree-Test Validation Image - {cve}
# Model: {model_name}   Derived from Phase 1 in-tree image: {cve_image_tag}
# =============================================================================
FROM {cve_image_tag}

LABEL maintainer="AI-SSD Project"
LABEL ai-ssd.type="validation-intree"
LABEL cve="{cve}"
LABEL model="{model_name}"

# Per-build compile-jobs cap (SSD_MAKE_JOBS): the in-tree build script runs
# make -j with this value when set, else nproc. Declared here so the build-arg
# passed by build_image is in scope for the rebuild RUN below (and so no
# "unconsumed build-arg" warning is emitted when the cap is configured).
ARG SSD_MAKE_JOBS

# Apply the patch over the vulnerable source file (touch so the rebuild can't
# skip it on a preserved mtime).
COPY patched_source.c /build/{source_dir}/{vuln_file_path}
RUN touch /build/{source_dir}/{vuln_file_path}

# Rebuild with the patch using the project's OWN baked build script — the SAME
# one Phase 1 used. Project-agnostic: no build-system commands in the pipeline.
RUN bash /build_intree.sh > /tmp/ssd_rebuild.log 2>&1; \\
    echo "rebuild rc=$?"; tail -40 /tmp/ssd_rebuild.log; true

# CMD (/run_intree_test.sh) is inherited from the Phase 1 image: it re-runs the
# same test and prints SSD_TEST_RESULT=PASS|FAIL|NORESULT. PASS = patch fixed it.
'''

    def generate_intree(
        self,
        patch_info: PatchInfo,
        vuln_info: VulnerabilityInfo,
        cve_image_tag: str,
        output_dir: Path,
    ) -> Optional[Path]:
        """Generate the patched Dockerfile for an in-tree-test CVE."""
        vuln_file_path = (patch_info.original_filepath or vuln_info.file_path).strip().lstrip("/")
        if not vuln_file_path:
            self.logger.error(
                f"{patch_info.cve_id}: no vulnerable file path recorded — cannot apply patch"
            )
            return None
        self.logger.info(
            f"Generating in-tree validation Dockerfile for {patch_info.log_label} "
            f"from {cve_image_tag} (patching {vuln_file_path})"
        )
        dockerfile_content = self.INTREE_DOCKERFILE_TEMPLATE.format(
            cve=patch_info.cve_id, model_name=patch_info.model_name,
            cve_image_tag=cve_image_tag, source_dir=self.layout["source_dir_name"],
            vuln_file_path=vuln_file_path,
        )
        safe_model = patch_info.model_name.replace(":", "_").replace(".", "_")
        build_dir = output_dir / patch_info.cve_id.lower() / safe_model
        build_dir.mkdir(parents=True, exist_ok=True)
        (build_dir / "Dockerfile").write_text(dockerfile_content)
        return build_dir


# =============================================================================
# Docker Manager for Validation
# =============================================================================

class ValidationDockerManager:
    """Manages Docker operations for patch validation"""
    
    def __init__(self, logger: logging.Logger, timeout: int = 3600,
                 sast_config: Optional[SastConfig] = None):
        self.logger = logger
        self.timeout = timeout
        # Project-/language-specific SAST tool list (from the project YAML).
        self.sast_config = sast_config if sast_config is not None else _SAST_CONFIG
        # Same negative filter Phase 1 uses to prove the exploit WORKED — here it
        # proves the exploit no longer works (output shows explicit failure).
        self.poc_analyzer = PoCAnalyzer(logger)
        try:
            self.client = docker.from_env()
            self.client.ping()
            self.logger.info("Successfully connected to Docker daemon")
        except docker.errors.DockerException as e:
            self.logger.error(f"Failed to connect to Docker: {e}")
            raise
    
    def build_image(
        self,
        patch_info: PatchInfo,
        build_context: Path
    ) -> Tuple[bool, Optional[str]]:
        """Build Docker image for patch validation"""
        self.logger.info(f"Building image for {patch_info.log_label}...")

        # Per-build compile-jobs cap (docker.make_jobs / SSD_MAKE_JOBS): when set,
        # the rebuild script's `make -j"${SSD_MAKE_JOBS:-$(nproc)}"` uses it instead
        # of all cores, so N concurrent Phase-3 rebuilds (validation.max_workers > 1)
        # don't oversubscribe the host. Unset ⇒ no build-arg ⇒ $(nproc), unchanged.
        _jobs = (_cfg.get("docker") or {}).get("make_jobs")
        _buildargs = {"SSD_MAKE_JOBS": str(_jobs)} if _jobs else None
        try:
            image, build_logs = self.client.images.build(
                path=str(build_context),
                tag=patch_info.image_name,
                rm=True,
                forcerm=True,
                timeout=self.timeout,
                buildargs=_buildargs,
            )
            
            # Collect build logs
            log_output = []
            for chunk in build_logs:
                if 'stream' in chunk:
                    log_output.append(chunk['stream'])
                elif 'error' in chunk:
                    log_output.append(f"ERROR: {chunk['error']}")
            
            self.logger.info(f"Successfully built image: {patch_info.image_name}")
            return True, '\n'.join(log_output)
            
        except BuildError as e:
            self.logger.error(f"Build failed for {patch_info.cve_id}/{patch_info.model_name}: {e}")
            return False, str(e)
        except APIError as e:
            self.logger.error(f"Docker API error: {e}")
            return False, str(e)
    
    def read_build_verification(self, patch_info: PatchInfo) -> Dict[str, str]:
        """Read the verification artifacts baked into the patched image:
        whether the patched object was rebuilt, whether the PoC links
        against the project build, and the rebuild log tail."""
        out = {"obj_rebuilt": "", "poc_uses_build": "", "rebuild_log_tail": ""}
        try:
            raw = self.client.containers.run(
                patch_info.image_name,
                command=("/bin/bash -c '"
                         "echo \"OBJ:$(cat /tmp/ssd_obj_rebuilt 2>/dev/null)\"; "
                         "echo \"USES:$(cat /tmp/ssd_poc_uses_build 2>/dev/null)\"; "
                         "echo ===ERRORS===; cat /tmp/ssd_build_errors 2>/dev/null; "
                         "echo ===LOG===; tail -60 /tmp/ssd_rebuild.log 2>/dev/null'"),
                remove=True,
                network_disabled=True,
            ).decode("utf-8", errors="replace")
            head, _, rest = raw.partition("===ERRORS===")
            errors, _, log_tail = rest.partition("===LOG===")
            # Prefer the extracted compiler errors; fall back to the raw tail
            # only when no error lines were found.
            out["rebuild_log_tail"] = errors.strip() or log_tail.strip()
            for line in head.splitlines():
                if line.startswith("OBJ:"):
                    out["obj_rebuilt"] = line[len("OBJ:"):].strip()
                elif line.startswith("USES:"):
                    out["poc_uses_build"] = line[len("USES:"):].strip()
        except Exception as e:
            self.logger.warning(f"Could not read build verification artifacts: {e}")
        return out

    @staticmethod
    def _extract_result_record(logs: str) -> Dict[str, Any]:
        """Parse the SSD_RESULT marker and captured PoC output from container
        logs (same wrapper protocol as Phase 1's DockerManager)."""
        record: Dict[str, Any] = {"exit_code": None, "category": None,
                                  "poc_output": None, "marker_present": False}
        for line in reversed(logs.splitlines()):
            line = line.strip()
            if line.startswith("SSD_RESULT:"):
                record["marker_present"] = True
                for token in line[len("SSD_RESULT:"):].split():
                    if "=" in token:
                        k, _, v = token.partition("=")
                        record[k] = v
                if record.get("exit_code") is not None:
                    try:
                        record["exit_code"] = int(record["exit_code"])
                    except (ValueError, TypeError):
                        record["exit_code"] = None
                break
        begin_marker = "--- BEGIN POC OUTPUT ---"
        end_marker = "--- END POC OUTPUT ---"
        begin = logs.find(begin_marker)
        end = logs.find(end_marker)
        if begin != -1 and end != -1 and end > begin:
            record["poc_output"] = logs[begin + len(begin_marker):end].strip()
        else:
            record["poc_output"] = logs
        return record

    def run_poc(
        self,
        patch_info: PatchInfo,
        baseline_exit_code: int,
        run_timeout: int = 300,
        needs_privileged: bool = False,
    ) -> Tuple[bool, Optional[int], str, Dict[str, Any]]:
        """
        Re-run the Phase 1 PoC wrapper against the patched build and decide
        whether the exploit is genuinely blocked (methodology v2).

        This is the SYMMETRIC counterpart to Phase 1's reproduction proof:
        Phase 1 records a baseline only when the PoC output proves the exploit
        WORKED (its negative filter does not flag failure); Phase 3 declares the
        patch effective only when there is positive evidence the exploit NO
        LONGER works — not merely a different exit code. Concretely:

        - The same ``PoCAnalyzer.negative_filter`` is run on the patched output;
          if it flags an explicit failure, that is the strongest "blocked" proof.
        - A bare exit-code change is only trusted when the patched run exits
          CLEANLY (< 128). A patched run that still crashes with a signal
          (>= 128) or is OOM-killed (137) is NOT counted as a fix — the patch
          likely relocated the fault rather than removing it.
        - baseline == -1 (DoS/hang sentinel): the patch works iff the patched
          run COMPLETES (clean exit) instead of hanging or crashing.
        - A patched run that HANGS where the baseline had a deterministic exit
          code is a failed patch (a self-inflicted DoS), reported as
          ``POC_HANG`` and fed back to the loop — never a silent Execution Error.

        Returns ``(poc_blocked, exit_code, logs, verdict)`` where ``verdict`` is
        a dict the caller maps onto the result:
            error_message    – set ⇒ genuine harness/infra failure (no verdict)
            status_override  – explicit ValidationStatus value to force
            nf_failed/nf_reason/nf_source – negative-filter evidence
            confidence       – "confirmed" | "exit-change" | "completion-only"
        """
        self.logger.info(
            f"Running PoC for {patch_info.log_label} "
            f"(baseline exit code: {baseline_exit_code})..."
        )

        container = None
        try:
            _run_kwargs = dict(
                name=patch_info.container_name,
                detach=True,
                mem_limit=_CONTAINER_MEM_LIMIT,
                cpu_period=100000,
                cpu_quota=100000,
                network_disabled=True,
                remove=False,
            )
            # Mirror Phase 1 exactly: a namespace PoC reproduced under a
            # privileged container must be re-validated the same way, or it can
            # never set up its namespace and would look "blocked" spuriously.
            if needs_privileged:
                _run_kwargs["privileged"] = True
                self.logger.info(
                    f"  Running {patch_info.log_label} container --privileged "
                    f"(namespace PoC, matching Phase 1)"
                )
            try:
                container = self.client.containers.run(
                    patch_info.image_name,
                    security_opt=_CONTAINER_SECURITY_OPT,  # match Phase 1 (userns/syscalls)
                    **_run_kwargs,
                )
            except Exception as sec_exc:
                # Host may not support the relaxed profile — retry without it so
                # validation still runs (must mirror Phase 1's fallback).
                self.logger.warning(
                    f"Run with relaxed security_opt failed ({sec_exc}); retrying without it."
                )
                try:
                    self.client.containers.get(patch_info.container_name).remove(force=True)
                except Exception:
                    pass
                container = self.client.containers.run(patch_info.image_name, **_run_kwargs)

            timed_out = False
            try:
                result = container.wait(timeout=run_timeout)
                container_status = result.get('StatusCode', -1)
            except Exception:
                # requests.exceptions timeout — the patched run is hanging
                timed_out = True
                container_status = -1
                try:
                    container.kill()
                except Exception:
                    pass

            logs = container.logs(stdout=True, stderr=True).decode('utf-8', errors='replace')

            try:
                container.remove(force=True)
            except Exception:
                pass

            record = self._extract_result_record(logs)
            marker_present = record.get("marker_present", False)
            poc_exit_code = record.get("exit_code")
            if poc_exit_code is None and marker_present is False and not timed_out:
                poc_exit_code = container_status
            poc_output = record.get("poc_output") if marker_present else logs

            # Negative filter on the PATCHED output — the same evidence Phase 1
            # uses, read in the opposite direction: a flagged failure here is the
            # strongest proof the patch defeated the exploit. (Skipped on a
            # timeout: there is no completed output to read.)
            nf = {"failed": None, "reason": "not evaluated (timeout)", "source": None}
            if not timed_out:
                category = "DOS" if baseline_exit_code == -1 else "OTHER"
                nf = self.poc_analyzer.negative_filter(
                    poc_output or "", poc_exit_code, patch_info.cve_id, category
                )

            def _verdict(**kw) -> Dict[str, Any]:
                v = {"error_message": None, "status_override": None,
                     "nf_failed": nf.get("failed"), "nf_reason": nf.get("reason"),
                     "nf_source": nf.get("source"), "confidence": None}
                v.update(kw)
                return v

            crashed = isinstance(poc_exit_code, int) and poc_exit_code >= 128
            clean_exit = (isinstance(poc_exit_code, int)
                          and 0 <= poc_exit_code < 128 and poc_exit_code != 137)

            # --- Verdict (evidence-based, mirrors Phase 1; no per-CVE logic) ---
            if baseline_exit_code == -1:
                # Phase 1 baseline was a hang (DoS). The fix removes the hang.
                if timed_out:
                    self.logger.warning(
                        f"✗ {patch_info.cve_id}: patched run still hangs "
                        f"(timeout {run_timeout}s) — DoS still reproduces"
                    )
                    return False, None, logs, _verdict()
                if not marker_present:
                    return False, poc_exit_code, logs, _verdict(
                        error_message=("Run wrapper did not complete (no SSD_RESULT "
                                       "marker) — harness/infrastructure failure, not a verdict"))
                if crashed:
                    # Hang became a crash: not a clean fix — exploit still drives
                    # the vulnerable path into undefined behaviour.
                    self.logger.warning(
                        f"✗ {patch_info.cve_id}: DoS hang replaced by a crash "
                        f"(exit={poc_exit_code}) — not a clean fix")
                    return False, poc_exit_code, logs, _verdict(
                        status_override=ValidationStatus.POC_STILL_WORKS.value)
                confidence = "confirmed" if nf.get("failed") else "completion-only"
                self.logger.info(
                    f"✓ {patch_info.cve_id}: patched run completed cleanly "
                    f"(exit={poc_exit_code}) where baseline hung — PoC blocked "
                    f"[{confidence}]")
                return True, poc_exit_code, logs, _verdict(confidence=confidence)

            # Baseline is a real exit code.
            if timed_out:
                # The patch turned a deterministic exit into a hang — a failed
                # patch (self-inflicted DoS), retryable with hang feedback.
                self.logger.warning(
                    f"✗ {patch_info.cve_id}: patch caused a hang (timeout "
                    f"{run_timeout}s) where baseline exited {baseline_exit_code}")
                return False, None, logs, _verdict(
                    status_override=ValidationStatus.POC_HANG.value,
                    error_message=(
                        f"Patch caused a timeout/hang after {run_timeout}s where the "
                        f"vulnerable baseline exited deterministically with "
                        f"{baseline_exit_code} — the patch likely introduced an "
                        f"infinite loop or deadlock and does not fix the vulnerability"))

            if not marker_present:
                return False, poc_exit_code, logs, _verdict(
                    error_message=("Run wrapper did not complete (no SSD_RESULT marker) — "
                                   "harness/infrastructure failure, not a verdict"))

            if poc_exit_code == 137:
                # OOM/external SIGKILL — an unreliable signal (Phase 1 rejects it
                # as a baseline for the same reason). Inconclusive, not a fix.
                self.logger.warning(
                    f"✗ {patch_info.cve_id}: patched run SIGKILL'd (exit 137) — "
                    f"OOM/resource kill, verdict inconclusive")
                return False, poc_exit_code, logs, _verdict(
                    error_message=("Patched run was SIGKILL'd (exit 137) — almost "
                                   "certainly an OOM/resource kill, not a verdict the "
                                   "patch can be judged on"))

            # The exploit explicitly reported failure ⇒ strongest proof of a fix.
            if nf.get("failed"):
                self.logger.info(
                    f"✓ {patch_info.log_label}: patched output shows the exploit "
                    f"failed ({nf.get('source')}: {nf.get('reason')}) — PoC blocked [confirmed]")
                return True, poc_exit_code, logs, _verdict(confidence="confirmed")

            if poc_exit_code == baseline_exit_code:
                self.logger.warning(
                    f"✗ {patch_info.log_label}: patched exit={poc_exit_code} == "
                    f"baseline — vulnerability still reproduces")
                return False, poc_exit_code, logs, _verdict()

            # Exit code differs from baseline. Trust it ONLY as a clean exit; a
            # different crash signal means the bug was relocated, not removed.
            if crashed:
                self.logger.warning(
                    f"✗ {patch_info.log_label}: patched run still crashes "
                    f"(exit={poc_exit_code} vs baseline={baseline_exit_code}) — "
                    f"patch likely relocated the fault, not a fix")
                return False, poc_exit_code, logs, _verdict(
                    status_override=ValidationStatus.POC_STILL_WORKS.value)

            self.logger.info(
                f"✓ {patch_info.log_label}: patched exit={poc_exit_code} differs "
                f"from baseline={baseline_exit_code} and exits cleanly — PoC blocked "
                f"[exit-change]")
            return True, poc_exit_code, logs, _verdict(confidence="exit-change")

        except Exception as e:
            self.logger.error(f"Failed to run PoC: {e}")
            if container is not None:
                try:
                    container.remove(force=True)
                except Exception:
                    pass
            return False, None, str(e), {
                "error_message": f"Exception during PoC execution: {e}",
                "status_override": None, "nf_failed": None, "nf_reason": None,
                "nf_source": None, "confidence": None}

    def run_intree_test(
        self, patch_info: PatchInfo, run_timeout: int = 600,
    ) -> Tuple[bool, str, str, Optional[str]]:
        """Re-run the in-tree regression test against the patched build.

        Verdict (Option A): the test FAILED on the vulnerable build (Phase 1),
        so the patch is validated iff it now PASSES. Returns
        (validated, marker, logs, error) where marker is PASS|FAIL|NORESULT.
        """
        self.logger.info(f"Running in-tree test for {patch_info.log_label}...")
        container = None
        try:
            try:
                self.client.containers.get(patch_info.container_name).remove(force=True)
            except Exception:
                pass
            container = self.client.containers.run(
                patch_info.image_name, name=patch_info.container_name, detach=True,
                mem_limit=_CONTAINER_MEM_LIMIT, network_disabled=True, remove=False,
            )
            timed_out = False
            try:
                container.wait(timeout=run_timeout)
            except Exception:
                timed_out = True
                try:
                    container.kill()
                except Exception:
                    pass
            logs = container.logs(stdout=True, stderr=True).decode("utf-8", errors="replace")
            try:
                container.remove(force=True)
            except Exception:
                pass
            marker = "NORESULT"
            for line in logs.splitlines():
                if "SSD_TEST_RESULT=" in line:
                    marker = line.split("SSD_TEST_RESULT=", 1)[1].strip().split()[0]
            if timed_out:
                return False, "NORESULT", logs, f"In-tree test timed out after {run_timeout}s"
            if marker == "PASS":
                self.logger.info(f"✓ {patch_info.log_label}: in-tree test PASSES — patch validated")
                return True, marker, logs, None
            if marker == "FAIL":
                self.logger.warning(f"✗ {patch_info.log_label}: in-tree test still FAILS — not fixed")
                return False, marker, logs, None
            return False, "NORESULT", logs, (
                "In-tree test produced no PASS/FAIL result (build/run error) — not a verdict"
            )
        except Exception as e:
            self.logger.error(f"Failed to run in-tree test: {e}")
            if container is not None:
                try:
                    container.remove(force=True)
                except Exception:
                    pass
            return False, "NORESULT", str(e), f"Exception during in-tree test: {e}"

    def run_sast(
        self,
        patch_info: PatchInfo,
        patched_file: Path,
    ) -> Dict[str, Any]:
        """Run the configured SAST tools HOST-SIDE on `patched_file`.

        Static analysis of a single source file needs no container. Delegates to
        the shared ``master_pipeline.sast_runner`` so Phase 1 (baseline) and
        Phase 3 (patched) run identical tools/parsers. Returns
        ``{"findings": [...], "tool_results": [...]}``.
        """
        self.logger.info(f"Running SAST analysis for {patch_info.cve_id}/{patch_info.model_name}...")
        return sast_runner.run_sast_file(patched_file, self.sast_config, self.logger)

    
    def cleanup_image(self, patch_info: PatchInfo):
        """Remove Docker image"""
        try:
            self.client.images.remove(patch_info.image_name, force=True)
            self.logger.debug(f"Removed image: {patch_info.image_name}")
        except ImageNotFound:
            pass
        except Exception as e:
            self.logger.warning(f"Failed to remove image {patch_info.image_name}: {e}")
    
    def cleanup_container(self, patch_info: PatchInfo):
        """Remove Docker container if exists"""
        try:
            container = self.client.containers.get(patch_info.container_name)
            container.remove(force=True)
            self.logger.debug(f"Removed container: {patch_info.container_name}")
        except:
            pass


class ValidationReportGenerator:
    """Generates validation reports"""
    
    def __init__(self, results_dir: Path, logger: logging.Logger):
        self.results_dir = results_dir
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logger
        self.results: List[ValidationResult] = []
    
    def add_result(self, result: ValidationResult):
        """Add a validation result"""
        self.results.append(result)

        # Also save individual result immediately (for crash recovery)
        self._save_individual_result(result)

    def live_counts(self) -> dict:
        """Live Phase-3 breakdown for the dashboard (mirrors get_progress)."""
        def n(status):
            return sum(1 for r in self.results if r.status == status.value)
        return {
            "success": n(ValidationStatus.SUCCESS),
            "poc_still_works": n(ValidationStatus.POC_STILL_WORKS),
            "sast_failures": n(ValidationStatus.SAST_FAILED),
            "build_failures": sum(1 for r in self.results if not r.build_success),
            "execution_errors": n(ValidationStatus.EXECUTION_ERROR),
            "no_baseline": n(ValidationStatus.NO_BASELINE),
        }
    
    def _save_individual_result(self, result: ValidationResult):
        """Save individual result to file"""
        cve_dir = self.results_dir / result.cve_id.lower()
        cve_dir.mkdir(parents=True, exist_ok=True)
        
        safe_model = result.model_name.replace(":", "_").replace(".", "_")
        result_file = cve_dir / f"{safe_model}_validation.json"
        
        with open(result_file, 'w') as f:
            json.dump(result.to_dict(), f, indent=2)
    
    def generate_summary_report(self, phase_start: datetime = None, phase_end: datetime = None) -> Path:
        """Generate comprehensive summary report with phase timing information"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        report_path = self.results_dir / f"validation_summary_{timestamp}.json"
        
        # Calculate statistics
        total = len(self.results)
        successful = sum(1 for r in self.results if r.status == ValidationStatus.SUCCESS.value)
        poc_blocked = sum(1 for r in self.results if r.poc_blocked)
        sast_passed = sum(1 for r in self.results if r.sast_passed)
        build_failures = sum(1 for r in self.results if not r.build_success)
        
        # Count different failure types for better analysis
        poc_still_works = sum(1 for r in self.results if r.status == ValidationStatus.POC_STILL_WORKS.value)
        execution_errors = sum(1 for r in self.results if r.status == ValidationStatus.EXECUTION_ERROR.value)
        sast_failures = sum(1 for r in self.results if r.status == ValidationStatus.SAST_FAILED.value)
        invalid_patches = sum(1 for r in self.results if r.status == ValidationStatus.INVALID_PATCH.value)
        patch_not_found = sum(1 for r in self.results if r.status == ValidationStatus.PATCH_NOT_FOUND.value)
        unknown_errors = sum(1 for r in self.results if r.status == ValidationStatus.UNKNOWN_ERROR.value)
        
        # Patches discovered but deliberately NOT validated (test-file targets / no
        # usable patch). Recorded so total_validations + skipped reconciles with the
        # Phase 2 patch-task count (the funnel hand-off), instead of total_validations
        # silently shrinking.
        skipped = list(getattr(self, "skipped_patches", []) or [])
        skipped_cves = sorted({(s.get("cve") or "").upper() for s in skipped if s.get("cve")})
        skipped_by_reason: Dict[str, int] = {}
        for s in skipped:
            r = s.get("reason", "unknown")
            skipped_by_reason[r] = skipped_by_reason.get(r, 0) + 1

        # Calculate total execution time
        total_execution_time = sum(r.execution_time_seconds for r in self.results)
        
        # Group by CVE with timing
        by_cve = {}
        cve_timings = {}
        for r in self.results:
            if r.cve_id not in by_cve:
                by_cve[r.cve_id] = []
                cve_timings[r.cve_id] = {"total_duration_seconds": 0.0, "validation_count": 0}
            by_cve[r.cve_id].append(r.to_dict())
            cve_timings[r.cve_id]["total_duration_seconds"] += r.execution_time_seconds
            cve_timings[r.cve_id]["validation_count"] += 1
        
        # Group by model with timing
        by_model = {}
        model_timings = {}
        for r in self.results:
            if r.model_name not in by_model:
                by_model[r.model_name] = []
                model_timings[r.model_name] = {"total_duration_seconds": 0.0, "validation_count": 0}
            by_model[r.model_name].append(r.to_dict())
            model_timings[r.model_name]["total_duration_seconds"] += r.execution_time_seconds
            model_timings[r.model_name]["validation_count"] += 1
        
        report_data = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "phase": "Phase 3 - Multi-Layered Validation",
                "total_validations": total,
                "patches_skipped": len(skipped),
            },
            "phase_timing": {
                "start_time": phase_start.isoformat() if phase_start else None,
                "end_time": phase_end.isoformat() if phase_end else None,
                "total_duration_seconds": (phase_end - phase_start).total_seconds() if phase_start and phase_end else total_execution_time,
            },
            "summary": {
                "successful": successful,
                "poc_blocked": poc_blocked,
                "sast_passed": sast_passed,
                "build_failures": build_failures,
                "success_rate": f"{(successful/total*100):.1f}%" if total > 0 else "N/A",
                "total_execution_time_seconds": total_execution_time,
            },
            "failure_breakdown": {
                "poc_still_works": poc_still_works,
                "execution_errors": execution_errors,
                "sast_failures": sast_failures,
                "invalid_patches": invalid_patches,
                "patch_not_found": patch_not_found,
                "unknown_errors": unknown_errors,
                "total_failures": total - successful,
            },
            "skipped": {
                "total": len(skipped),
                "distinct_cves": len(skipped_cves),
                "by_reason": skipped_by_reason,
                "cves": skipped_cves,
                "detail": skipped,
            },
            "timing_by_cve": cve_timings,
            "timing_by_model": model_timings,
            "by_cve": by_cve,
            "by_model": by_model,
            "all_results": [r.to_dict() for r in self.results]
        }
        
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        self.logger.info(f"Summary report generated: {report_path}")
        return report_path
    
    def print_summary(self):
        """Print summary to console"""
        print("\n" + "=" * 70)
        print("PHASE 3: MULTI-LAYERED VALIDATION SUMMARY")
        print("=" * 70)
        
        # Calculate stats
        total = len(self.results)
        successful = sum(1 for r in self.results if r.status == ValidationStatus.SUCCESS.value)
        
        # Print by CVE
        by_cve = {}
        for r in self.results:
            if r.cve_id not in by_cve:
                by_cve[r.cve_id] = []
            by_cve[r.cve_id].append(r)
        
        for cve_id, results in sorted(by_cve.items()):
            print(f"\n{cve_id}:")
            print("-" * 40)
            for r in results:
                status_icon = "✓" if r.status == ValidationStatus.SUCCESS.value else "✗"
                poc_icon = "🛡" if r.poc_blocked else "⚠"
                sast_icon = "✓" if r.sast_passed else "✗"
                print(f"  {status_icon} {r.model_name:<25} | PoC: {poc_icon} | SAST: {sast_icon} | {r.status}")
        
        # Count different failure types
        poc_still_works = sum(1 for r in self.results if r.status == ValidationStatus.POC_STILL_WORKS.value)
        execution_errors = sum(1 for r in self.results if r.status == ValidationStatus.EXECUTION_ERROR.value)
        sast_failures = sum(1 for r in self.results if r.status == ValidationStatus.SAST_FAILED.value)
        
        print("\n" + "-" * 70)
        print(f"Total: {total} | Successful: {successful} | Failed: {total - successful}")
        if total - successful > 0:
            print(f"  Failure Breakdown:")
            if poc_still_works > 0:
                print(f"    - PoC Still Works: {poc_still_works}")
            if execution_errors > 0:
                print(f"    - Execution Errors: {execution_errors}")
            if sast_failures > 0:
                print(f"    - SAST Failures: {sast_failures}")
        print(f"Success Rate: {(successful/total*100):.1f}%" if total > 0 else "No results")
        print("=" * 70 + "\n")


# =============================================================================
# Main Validation Pipeline
# =============================================================================

class ValidationPipeline:
    """Main pipeline orchestrator for Phase 3 validation"""
    
    def __init__(self, args: argparse.Namespace):
        self.base_dir = Path(args.base_dir).resolve()
        # Per-cell/per-repeat Docker-name discriminator (the base_dir basename, e.g.
        # "glibc__openai-fast__rep2"). Threaded into every PatchInfo so the patched
        # image + container names are unique per cell/repeat — letting cells,
        # overlapping families and repeats run concurrently without colliding on
        # Docker names (they previously shared cve+model-only names).
        self.cell_disc = _docker_safe_name(self.base_dir.name)
        self.csv_path = Path(args.csv_file).resolve()
        self.patches_dir = Path(args.patches_dir).resolve()
        self.exploits_dir = Path(args.exploits_dir).resolve()
        self.build_timeout = args.build_timeout
        self.run_timeout = args.run_timeout
        # Patches validated concurrently. Each patch is an independent, CPU/IO-bound
        # Docker rebuild + PoC re-run on DISTINCT image/container/build-dir names
        # (cve+model), so they don't collide; results are merged on the main thread.
        # 1 = sequential (the default, byte-for-byte the prior behavior).
        self.max_workers = max(1, int(getattr(args, "max_workers", 1) or 1))
        self.cleanup = args.cleanup
        self.specific_cve = args.cve

        # Active project's Phase 0 YAML, passed by the orchestrator via
        # --phase0-config. Drives BOTH the Phase 1 manifest path AND the SAST
        # tooling, so a multi-project run validates against the right project
        # instead of silently falling back to the config.yaml (glibc) default.
        self.phase0_config_path = (
            Path(args.phase0_config).resolve()
            if getattr(args, "phase0_config", None)
            else None
        )

        # Project-/language-specific SAST policy (tools, fail_on, timeout) from
        # the active project's Phase 0 YAML. SAST is skipped if the CLI requests
        # it OR the project disables it (sast.enabled: false).
        self.sast_config = load_sast_config(
            pipeline_config_path=_BASE_DIR / "config.yaml",
            phase0_config_path=self.phase0_config_path,
        )
        self.skip_sast = bool(args.skip_sast) or not self.sast_config.enabled

        # Setup directories
        self.validation_builds_dir = self.base_dir / "validation_builds"
        self.results_dir = self.base_dir / "validation_results"
        self.logs_dir = self.base_dir / "logs"
        
        # Setup logging. The feedback loop passes args.log_file so its per-retry
        # re-validations append to its dedicated feedback_loop_<ts>.log instead of
        # creating a new validator_<ts>.log for each attempt.
        _explicit_log = getattr(args, "log_file", None)
        self.logger = setup_logging(
            self.logs_dir, args.verbose,
            Path(_explicit_log) if _explicit_log else None,
        )
        
        # Phase 1 image layout + manifest (methodology v2)
        self.phase1_layout = _resolve_phase1_layout(self.base_dir, self.phase0_config_path)

        # Initialize components
        self.csv_parser = CSVParser(self.csv_path, self.logger)
        self.patch_discovery = PatchDiscovery(self.patches_dir, self.logger, self.cell_disc)
        self.dockerfile_gen = PatchedDockerfileGenerator(self.logger, self.phase1_layout)
        self.docker_mgr = ValidationDockerManager(self.logger, self.build_timeout,
                                                  sast_config=self.sast_config)
        self.report_gen = ValidationReportGenerator(self.results_dir, self.logger)
        self.manifest = ImageManifest(
            self.phase1_layout["image_manifest_path"], self.logger
        )
    
    def run(self):
        """Execute the validation pipeline"""
        phase_start_time = datetime.now()
        
        self.logger.info("=" * 60)
        self.logger.info("Starting Phase 3: Multi-Layered Validation Pipeline")
        self.logger.info(f"Phase Start Time: {phase_start_time.isoformat()}")
        self.logger.info("=" * 60)
        self.logger.info(f"Base directory: {self.base_dir}")
        self.logger.info(f"Patches directory: {self.patches_dir}")
        self.logger.info(f"Exploits directory: {self.exploits_dir}")
        
        # Load vulnerability info from CSV
        try:
            vuln_info_map = self.csv_parser.parse()
        except FileNotFoundError as e:
            self.logger.error(str(e))
            sys.exit(1)
        
        # Discover patches
        patches = self.patch_discovery.discover_patches(self.specific_cve)
        # Carry the deliberately-skipped patches (test-file targets / no usable
        # patch) into the summary so the Phase 2 → Phase 3 hand-off is auditable.
        self.report_gen.skipped_patches = list(self.patch_discovery.skipped_patches)

        if not patches:
            self.logger.error("No patches found to validate")
            sys.exit(1)
        
        self.logger.info(f"Found {len(patches)} patches to validate")

        _live_dir = self.base_dir / "results"
        total_patches = len(patches)
        if live_progress:
            live_progress.emit(_live_dir, 3, total_patches, 0,
                               self.report_gen.live_counts())

        # Validate one patch: the heavy, CPU/IO-bound Docker rebuild + PoC re-run +
        # host-side SAST. Pure w.r.t. shared state — it only READS self.manifest /
        # the vuln map and works on image/container/build-dir names unique to
        # (cve, model), so it is safe to run concurrently. Returns (patch_info,
        # result) with result=None when the CVE has no vulnerability info.
        def _validate_one(patch_info):
            self.logger.info(
                f"\n{'='*60}\nValidating: {patch_info.cve_id} / {patch_info.model_name}\n{'='*60}"
            )
            vuln_info = vuln_info_map.get(patch_info.cve_id)
            if not vuln_info:
                self.logger.warning(f"No vulnerability info found for {patch_info.cve_id}")
                return patch_info, None
            result = self._validate_patch(patch_info, vuln_info)
            self.logger.info(
                f"Validation completed for {patch_info.cve_id}/{patch_info.model_name}: "
                f"{result.status} (duration: {result.execution_time_seconds:.1f}s)"
            )
            return patch_info, result

        # Merge a finished result. MAIN-THREAD ONLY (called sequentially below in
        # both modes), so report_gen / live_progress need no locking.
        def _merge(result, done):
            if result is not None:
                self.report_gen.add_result(result)
            if live_progress:
                live_progress.emit(_live_dir, 3, total_patches, done,
                                   self.report_gen.live_counts())

        if self.max_workers <= 1:
            # Sequential — identical to the prior behavior.
            for idx, patch_info in enumerate(patches, 1):
                _, result = _validate_one(patch_info)
                _merge(result, idx)
        else:
            # Parallel: workers run _validate_one (independent Docker work); the
            # main thread merges each result as it completes.
            self.logger.info(
                f"Validating {total_patches} patches with {self.max_workers} parallel workers "
                f"(Docker rebuild/PoC re-run is CPU/IO-bound)."
            )
            done = 0
            with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
                futures = {executor.submit(_validate_one, p): p for p in patches}
                for future in as_completed(futures):
                    done += 1
                    try:
                        _, result = future.result()
                    except Exception as exc:
                        p = futures[future]
                        self.logger.error(
                            f"Validation thread crashed for {p.cve_id}/{p.model_name}: {exc}"
                        )
                        result = None
                    _merge(result, done)

        if live_progress:
            live_progress.emit(_live_dir, 3, total_patches, total_patches,
                               self.report_gen.live_counts(), running=False)

        phase_end_time = datetime.now()
        phase_duration = (phase_end_time - phase_start_time).total_seconds()
        
        # Generate final report with phase timing
        report_path = self.report_gen.generate_summary_report(phase_start_time, phase_end_time)
        self.report_gen.print_summary()
        
        self.logger.info("=" * 60)
        self.logger.info(f"Phase 3 Complete")
        self.logger.info(f"Phase End Time: {phase_end_time.isoformat()}")
        self.logger.info(f"Phase Duration: {phase_duration:.1f}s ({phase_duration/60:.1f}m)")
        self.logger.info(f"Results saved to: {report_path}")
        self.logger.info("=" * 60)
    
    def _evaluate_sast(self, patch_info: "PatchInfo", result: "ValidationResult",
                       baseline_findings: List[Dict[str, Any]]) -> Tuple[bool, str]:
        """Run SAST on the patched file, classify against the Phase 1 baseline,
        and gate on the NEWLY-introduced findings only.

        Populates result.sast_results / sast_findings / sast_baseline_findings /
        sast_preexisting / sast_resolved / sast_new and result.sast_passed.
        Returns ``(passed, message)``. Pre-existing and resolved findings are
        documented but never fail the patch — only the delta the patch
        introduces gates (and later feeds back). When there is no baseline the
        baseline is empty, so every finding is treated as new (strict).
        """
        if self.skip_sast:
            result.sast_passed = True
            result.sast_results = [{"status": "skipped"}]
            return True, ""

        sast = self.docker_mgr.run_sast(patch_info, patch_info.patched_file)
        current = sast["findings"]
        result.sast_results = sast["tool_results"]
        result.sast_findings = current
        result.sast_baseline_findings = baseline_findings or []

        classified = sast_runner.classify(baseline_findings or [], current)
        result.sast_preexisting = classified["preexisting"]
        result.sast_resolved = classified["resolved"]
        result.sast_new = classified["new"]

        passed, msg = sast_runner.gate(result.sast_new,
                                       self.docker_mgr.sast_config.fail_on)
        result.sast_passed = passed
        self.logger.info(
            f"SAST {patch_info.cve_id}: baseline={len(result.sast_baseline_findings)} "
            f"preexisting={len(result.sast_preexisting)} resolved={len(result.sast_resolved)} "
            f"new={len(result.sast_new)} → {'PASS' if passed else 'FAIL'}"
        )
        return passed, msg

    def _apply_sast(self, patch_info: "PatchInfo", result: "ValidationResult",
                    baseline_findings: List[Dict[str, Any]]) -> None:
        """Run + classify SAST and set final status (in-tree validation path).

        Mirrors the standard Step 7 logic: SUCCESS only when the dynamic check
        passed AND the patch introduced no new findings in a ``fail_on`` class.
        """
        passed, msg = self._evaluate_sast(patch_info, result, baseline_findings)
        if not self.skip_sast and not passed \
                and result.status != ValidationStatus.POC_STILL_WORKS.value:
            if result.status not in (ValidationStatus.EXECUTION_ERROR.value,
                                     ValidationStatus.BUILD_ERROR.value):
                result.status = ValidationStatus.SAST_FAILED.value
                result.error_message = msg
        if result.poc_blocked and result.sast_passed:
            result.status = ValidationStatus.SUCCESS.value
            self.logger.info(f"✓✓ VALIDATION SUCCESSFUL for {patch_info.log_label}")

    def _validate_patch(
        self,
        patch_info: PatchInfo,
        vuln_info: VulnerabilityInfo,
        attempt_number: int = 1,
        is_retry: bool = False
    ) -> ValidationResult:
        """Validate a single patch
        
        Args:
            patch_info: Information about the patch to validate
            vuln_info: Information about the vulnerability
            attempt_number: Current attempt number (1-based)
            is_retry: Whether this is a retry validation
        
        Returns:
            ValidationResult with detailed failure information for feedback loop
        """
        start_time = datetime.now()
        
        # Initialize result with feedback loop support
        result = ValidationResult(
            cve_id=patch_info.cve_id,
            model_name=patch_info.model_name,
            status=ValidationStatus.UNKNOWN_ERROR.value,
            poc_blocked=False,
            build_success=False,
            sast_passed=False,
            sast_results=[],
            sast_findings=[],
            poc_exit_code=None,
            poc_output=None,
            error_message=None,
            execution_time_seconds=0,
            timestamp=start_time.isoformat(),
            patch_file=str(patch_info.patched_file) if patch_info.patched_file else "",
            build_logs=None,
            attempt_number=attempt_number,
            is_retry=is_retry
        )
        
        try:
            # Step 1: Verify patch file exists and is valid
            if not patch_info.patched_file or not patch_info.patched_file.exists():
                result.status = ValidationStatus.PATCH_NOT_FOUND.value
                result.error_message = "Patch file not found"
                return result
            
            # The Phase 2 host-side `gcc -fsyntax-only` flag (patch_info.is_valid
            # = False) is ADVISORY only — it false-negatives on project-internal
            # code it cannot see standalone (missing internal headers/types), which
            # silently dropped ~7 good glibc patches before they were ever built.
            # The authoritative arbiter is the in-container rebuild below: a real
            # compile failure surfaces as BUILD_ERROR and feeds the feedback loop.
            # So no longer hard-reject here; just note it and proceed to the build.
            if not patch_info.is_valid:
                self.logger.info(
                    f"{patch_info.log_label}: host syntax check flagged this patch; "
                    f"deferring the verdict to the in-container rebuild (real arbiter)"
                )

            # Step 2: Look up the Phase 1 baseline for this CVE (methodology
            # v2): the built CVE image tag + the deterministic baseline exit
            # code. Without them there is nothing to derive from or compare
            # against — the CVE was never reproduced.
            manifest_entry = self.manifest.get(patch_info.cve_id)
            baseline_exit_code = (manifest_entry or {}).get("baseline_exit_code")
            cve_image_tag = (manifest_entry or {}).get("tag")
            if (manifest_entry is None or baseline_exit_code is None
                    or not cve_image_tag
                    or manifest_entry.get("needs_manual_revision")):
                result.status = ValidationStatus.NO_BASELINE.value
                result.error_message = (
                    f"No Phase 1 baseline for {patch_info.cve_id} (not reproduced, "
                    f"manual revision, or image not built) — cannot validate dynamically"
                )
                return result
            result.baseline_exit_code = baseline_exit_code
            # Phase 1 SAST baseline for this CVE (findings on the UNPATCHED file).
            # Phase 3 classifies the patched-file findings against it; only the
            # delta gates. Missing/old manifests → empty → all findings are new.
            baseline_sast = (manifest_entry or {}).get("sast_baseline") or []

            # Option A: in-tree regression-test CVEs validate differently — rebuild
            # the Phase 1 in-tree image with the patch and re-run the project's OWN
            # test (it FAILED on the vulnerable build, so PASS = patch fixed it).
            # Self-contained branch that returns before the standard exit-code path.
            if vuln_info.is_intree_test:
                ctx = self.dockerfile_gen.generate_intree(
                    patch_info, vuln_info, cve_image_tag, self.validation_builds_dir
                )
                if ctx is None:
                    result.status = ValidationStatus.UNKNOWN_ERROR.value
                    result.error_message = "No vulnerable file path recorded — cannot apply patch"
                    return result
                shutil.copy2(patch_info.patched_file, ctx / "patched_source.c")
                build_success, build_logs = self.docker_mgr.build_image(patch_info, ctx)
                result.build_logs = build_logs
                if not build_success:
                    # The image itself failed to build (infrastructure / the
                    # project build script hard-erroring). A merely non-compiling
                    # patch does NOT land here — the build script is tolerant, so
                    # it surfaces as the test not PASSing below (project-agnostic:
                    # no compiler/object-file assumptions in the validator).
                    result.status = ValidationStatus.BUILD_ERROR.value
                    result.error_message = "Patched in-tree image failed to build"
                    result.poc_output = build_logs
                    return result
                result.build_success = True
                validated, marker, test_logs, test_err = self.docker_mgr.run_intree_test(
                    patch_info, max(self.run_timeout, 600)
                )
                result.poc_blocked = validated
                result.poc_exit_code = 0 if validated else 1
                result.poc_output = test_logs
                if test_err:
                    result.status = ValidationStatus.EXECUTION_ERROR.value
                    result.error_message = test_err
                    result.poc_blocked = False
                    self.logger.error(f"✗ in-tree test error for {patch_info.log_label}: {test_err}")
                elif not validated:
                    result.status = ValidationStatus.POC_STILL_WORKS.value
                    result.error_message = "In-tree regression test still FAILS on the patched build"
                # SAST + final status (shared helper)
                self._apply_sast(patch_info, result, baseline_sast)
                return result

            # Step 3: Generate Dockerfile (derived FROM the Phase 1 CVE image)
            build_context = self.dockerfile_gen.generate(
                patch_info, vuln_info, cve_image_tag, self.validation_builds_dir
            )
            if build_context is None:
                result.status = ValidationStatus.UNKNOWN_ERROR.value
                result.error_message = "No vulnerable file path recorded — cannot apply patch"
                return result

            # Step 4: Copy patch into build context (the PoC and wrapper are
            # already inside the parent image)
            patch_dest = build_context / "patched_source.c"
            shutil.copy2(patch_info.patched_file, patch_dest)

            # Step 5: Build patched image (incremental rebuild on top of the
            # Phase 1 image; a failure here is the patch failing to compile)
            build_success, build_logs = self.docker_mgr.build_image(patch_info, build_context)
            result.build_logs = build_logs  # Store for feedback loop

            if not build_success:
                result.status = ValidationStatus.BUILD_ERROR.value
                result.error_message = "Patched build failed (patch likely does not compile)"
                result.poc_output = build_logs
                return result

            # Step 5b: Verify the rebuild artifacts. The rebuild itself is
            # tolerant (-k, matching Phase 1), so patch-specific compile
            # failure shows up as the patched object NOT being rebuilt.
            verify = self.docker_mgr.read_build_verification(patch_info)

            if verify.get("obj_rebuilt", "") == "":
                result.status = ValidationStatus.BUILD_ERROR.value
                result.error_message = (
                    "Patched source failed to compile (its object file was not "
                    "rebuilt) — see build_logs for compiler output"
                )
                result.build_logs = verify.get("rebuild_log_tail") or build_logs
                result.poc_output = result.build_logs
                return result

            if verify.get("poc_uses_build") == "no":
                # The PoC does not exercise the project build at runtime (the
                # project loader cannot map the build's libc) — a source patch
                # cannot change its behavior, so dynamic validation cannot
                # assert anything. Non-retryable environment condition.
                result.status = ValidationStatus.EXECUTION_ERROR.value
                result.error_message = (
                    "PoC does not exercise the project build at runtime (project "
                    "loader could not map the build's libc) — dynamic validation "
                    "is not meaningful for this CVE; needs Phase 1 build fix"
                )
                self.logger.warning(
                    f"✗ {patch_info.cve_id}: {result.error_message}"
                )
                return result

            result.build_success = True

            # Step 6: Re-run PoC and compare with baseline (Dynamic Check A).
            # Mirror Phase 1's container privilege for namespace PoCs.
            poc_blocked, exit_code, poc_logs, verdict = self.docker_mgr.run_poc(
                patch_info, baseline_exit_code, self.run_timeout,
                needs_privileged=bool((manifest_entry or {}).get("needs_privileged", False)),
            )

            result.poc_blocked = poc_blocked
            result.poc_exit_code = exit_code
            result.poc_output = poc_logs
            # Record the negative-filter evidence behind the verdict (mirrors the
            # proof Phase 1 stores when establishing the baseline).
            result.nf_failed = verdict.get("nf_failed")
            result.nf_reason = verdict.get("nf_reason")
            result.nf_source = verdict.get("nf_source")
            result.poc_proof_confidence = verdict.get("confidence")

            poc_error = verdict.get("error_message")
            status_override = verdict.get("status_override")
            # Check for environment/harness errors (no verdict possible)
            if poc_error and not status_override:
                result.status = ValidationStatus.EXECUTION_ERROR.value
                result.error_message = poc_error
                result.poc_blocked = False  # Ensure not counted as success
                self.logger.error(f"✗ PoC execution error for {patch_info.cve_id}/{patch_info.model_name}: {poc_error}")
                # Continue to collect SAST results for complete feedback
            elif status_override:
                # An explicit verdict status (e.g. patch caused a hang, or the
                # patch only relocated the crash) — retryable patch failure, fed
                # back to the loop rather than dropped as an environment error.
                result.status = status_override
                result.error_message = poc_error or "PoC exploit still triggers the vulnerability"
                result.poc_blocked = False
                self.logger.warning(f"✗ {status_override} for {patch_info.log_label}: {result.error_message}")
            elif not poc_blocked:
                # PoC still works - vulnerability not fixed
                result.status = ValidationStatus.POC_STILL_WORKS.value
                result.error_message = "PoC exploit still triggers the vulnerability"
                # Don't return early - continue to collect SAST results for complete feedback
                self.logger.warning(f"✗ PoC still works for {patch_info.log_label}")
            else:
                self.logger.info(f"✓ PoC blocked for {patch_info.cve_id}/{patch_info.model_name}")
            
            # Step 7: Run SAST (Static Check B) - ALWAYS run for complete feedback.
            # Classify against the Phase 1 baseline; only patch-introduced
            # ("new") findings can fail Phase 3 — pre-existing debt does not.
            if not self.skip_sast:
                _passed, _sast_msg = self._evaluate_sast(patch_info, result, baseline_sast)

                if not result.sast_passed:
                    # Set status but don't return - we've already collected all data.
                    # A dynamic-check failure (still works / hang) is more
                    # important than SAST and must not be masked by it.
                    _dynamic_fail = (ValidationStatus.POC_STILL_WORKS.value,
                                     ValidationStatus.POC_HANG.value)
                    if result.status not in _dynamic_fail:
                        result.status = ValidationStatus.SAST_FAILED.value
                        result.error_message = _sast_msg
                    else:
                        # Both the dynamic check and SAST failed
                        result.error_message = (
                            f"{result.error_message} AND {_sast_msg}"
                        )
                    self.logger.warning(f"✗ SAST failed for {patch_info.cve_id}/{patch_info.model_name}")
                else:
                    self.logger.info(f"✓ SAST passed for {patch_info.cve_id}/{patch_info.model_name}")
            else:
                result.sast_passed = True  # Skipped
                result.sast_results = [{"status": "skipped"}]
            
            # Determine final status (only success if both checks passed)
            if result.poc_blocked and result.sast_passed:
                result.status = ValidationStatus.SUCCESS.value
                self.logger.info(
                    f"✓✓ VALIDATION SUCCESSFUL for {patch_info.cve_id}/{patch_info.model_name}"
                )
            
        except Exception as e:
            self.logger.exception(f"Error validating {patch_info.cve_id}/{patch_info.model_name}")
            result.status = ValidationStatus.UNKNOWN_ERROR.value
            result.error_message = str(e)
        
        finally:
            # Cleanup if requested
            if self.cleanup:
                self.docker_mgr.cleanup_container(patch_info)
                self.docker_mgr.cleanup_image(patch_info)
            
            # Calculate execution time
            end_time = datetime.now()
            result.execution_time_seconds = (end_time - start_time).total_seconds()
        
        return result
    
    def validate_single_patch_file(
        self,
        patch_file: Path,
        cve_id: str,
        model_name: str,
        vuln_info: VulnerabilityInfo,
        attempt_number: int = 1,
        is_retry: bool = False,
        generation_model: str = ""
    ) -> ValidationResult:
        """
        Validate a single patch file directly (for feedback loop retry).
        
        This method is used by the iterative feedback loop to validate
        newly generated patches without discovering from the patches directory.
        
        Args:
            patch_file: Path to the patch file to validate
            cve_id: CVE identifier
            model_name: Model name that generated the patch
            vuln_info: Vulnerability information
            attempt_number: Current attempt number (1-based)
            is_retry: Whether this is a retry validation
        
        Returns:
            ValidationResult with detailed failure context
        """
        _gen = f" (patch by {generation_model})" if generation_model and generation_model != model_name else ""
        self.logger.info(f"[FEEDBACK LOOP] Validating retry patch #{attempt_number} for {cve_id}/{model_name}{_gen}")

        # Create PatchInfo for the retry patch
        patch_info = PatchInfo(
            cve_id=cve_id,
            model_name=model_name,
            patch_dir=patch_file.parent,
            patched_file=patch_file,
            function_only_file=None,
            response_json=None,
            is_valid=True,  # Assume valid since it passed syntax check in generator
            original_filepath=vuln_info.file_path,
            generation_model=generation_model,
            cell=self.cell_disc,
        )
        
        return self._validate_patch(
            patch_info=patch_info,
            vuln_info=vuln_info,
            attempt_number=attempt_number,
            is_retry=is_retry
        )


# =============================================================================
# Main Entry Point
# =============================================================================

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="AI-SSD Phase 3: Multi-Layered Patch Validation Pipeline",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run validation for all patches
  python patch_validator.py
  
  # Validate specific CVE
  python patch_validator.py --cve CVE-2015-7547
  
  # Skip SAST analysis (faster)
  python patch_validator.py --skip-sast
  
  # Run with cleanup and verbose output
  python patch_validator.py --cleanup --verbose
  
  # Custom paths
  python patch_validator.py --patches-dir /path/to/patches --exploits-dir /path/to/exploits
        """
    )
    
    parser.add_argument(
        '--base-dir',
        type=str,
        default=os.path.dirname(os.path.abspath(__file__)),
        help='Base directory for the project (default: script directory)'
    )
    
    parser.add_argument(
        '--csv-file',
        type=str,
        default=None,
        help='Path to file-function.csv (default: <base-dir>/documentation/file-function.csv)'
    )
    
    parser.add_argument(
        '--patches-dir',
        type=str,
        default=None,
        help='Path to patches directory (default: <base-dir>/patches)'
    )
    
    parser.add_argument(
        '--exploits-dir',
        type=str,
        default=None,
        help='Path to exploits directory (default: <base-dir>/exploits)'
    )
    
    parser.add_argument(
        '--cve',
        type=str,
        default=None,
        help='Validate only this specific CVE'
    )
    
    _val_cfg = _cfg.get("validation", {}) if isinstance(_cfg.get("validation"), dict) else {}
    parser.add_argument(
        '--build-timeout',
        type=int,
        default=int(_val_cfg.get("build_timeout", _cfg.get("build_timeout", 3600))),
        help='Docker build timeout in seconds (default: from config.yaml)'
    )
    
    parser.add_argument(
        '--run-timeout',
        type=int,
        default=int(_val_cfg.get("poc_timeout", _cfg.get("run_timeout", 300))),
        help='Container run timeout in seconds (default: from config.yaml)'
    )

    parser.add_argument(
        '--max-workers',
        type=int,
        default=int(_val_cfg.get("max_workers", 1)),
        help='Validate this many patches concurrently (Docker rebuild + PoC re-run '
             'are CPU/IO-bound, not GPU). 1 = sequential (default). Raise on a '
             'multi-core host with enough RAM (each build is a full project compile).'
    )

    parser.add_argument(
        '--skip-sast',
        action='store_true',
        help='Skip SAST analysis (only run PoC validation)'
    )
    
    parser.add_argument(
        '--cleanup',
        action='store_true',
        help='Clean up Docker images and containers after validation'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )

    parser.add_argument(
        '--phase0-config',
        default=None,
        help="Active project's Phase 0 YAML (e.g. cve_aggregator/openssl_config.yaml). "
             "Resolves the Phase 1 image_manifest_path and the project's SAST tooling. "
             "Without it, Phase 3 falls back to config.yaml's phase0_config (glibc) and "
             "looks for the wrong manifest, reporting every CVE as 'No Phase 1 Baseline'."
    )

    args = parser.parse_args()
    
    # Set default paths from config.yaml, relative to base directory
    if args.csv_file is None:
        args.csv_file = os.path.join(args.base_dir, str(_paths.get('csv_file', 'documentation/file-function.csv')))
    
    if args.patches_dir is None:
        args.patches_dir = os.path.join(args.base_dir, str(_paths.get('patches', 'patches')))
    
    if args.exploits_dir is None:
        args.exploits_dir = os.path.join(args.base_dir, str(_paths.get('exploits_dir', 'exploits')))
    
    return args


def main():
    """Main entry point"""
    args = parse_arguments()
    
    try:
        pipeline = ValidationPipeline(args)
        pipeline.run()
    except KeyboardInterrupt:
        print("\nValidation interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"Fatal error: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    main()
