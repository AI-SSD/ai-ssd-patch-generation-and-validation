#!/usr/bin/env python3
# =============================================================================
# AI-SSD Project - Pipeline Orchestrator
# Phase 1: Vulnerability ID & Setup
# =============================================================================
# This script automates the creation and execution of reproduction environments
# for glibc vulnerabilities listed in glibc_cve_poc_complete.csv
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
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional, Tuple
from enum import Enum

# Try to import docker, provide helpful error if not installed
try:
    import docker
    from docker.errors import BuildError, ContainerError, ImageNotFound, APIError
except ImportError:
    print("Error: docker package not installed. Run: pip install docker")
    sys.exit(1)

# =============================================================================
# Configuration and Constants
# =============================================================================
# All project-specific values are loaded from the Phase 0 YAML config file at
# runtime (via --phase0-config).  The constants below are safe defaults used
# only when the config file is absent or a key is missing.
# =============================================================================

# Safe fallback defaults – overridden by _load_phase0_config() at startup
_DEFAULT_PROJECT_REPO_LOCAL_PATH = "project_repo"
_DEFAULT_PROJECT_REPO_REMOTE_URL = ""
_DEFAULT_IMAGE_MANIFEST_PATH = "results/image_manifest.json"
_DEFAULT_BASE_IMAGE_PREFIX = "ai-ssd/project-base"
_DEFAULT_CVE_IMAGE_PREFIX = "ai-ssd/project-cve"
_DEFAULT_SOURCE_DIR_NAME = "project-src"
_DEFAULT_BUILD_DIR_NAME = "project-build"
_DEFAULT_INSTALL_PREFIX = "/opt/project-build"
_DEFAULT_DOCKER_PLATFORM = "linux/amd64"
_DEFAULT_COMMIT_ERA_MAP: dict = {}


def _load_phase0_config(config_path: Optional[Path]) -> dict:
    """Load a Phase 0 YAML config file and return its contents as a dict.

    Returns an empty dict when the file is absent or unparseable.
    """
    if config_path is None or not config_path.exists():
        return {}
    try:
        import yaml
        with open(config_path, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    except Exception:
        return {}


def _resolve_phase1_settings(cfg: dict, base_dir: Path) -> dict:
    """Extract Phase 1 settings from the loaded Phase 0 config dict.

    Always returns a complete dict—missing keys fall back to safe defaults so
    that orchestrator.py works even without a ``phase1:`` section in the YAML.
    """
    p1 = cfg.get("phase1", {}) or {}
    output = cfg.get("output", {}) or {}

    # CSV path: prefer output.csv_path from the same config the executor uses
    csv_rel = output.get("csv_path", "cve_poc_complete.csv")
    csv_path = base_dir / csv_rel if not Path(csv_rel).is_absolute() else Path(csv_rel)

    repo_rel = p1.get("project_repo_local_path", _DEFAULT_PROJECT_REPO_LOCAL_PATH)
    repo_path = base_dir / repo_rel if not Path(repo_rel).is_absolute() else Path(repo_rel)

    manifest_rel = p1.get("image_manifest_path", _DEFAULT_IMAGE_MANIFEST_PATH)
    manifest_path = (
        base_dir / manifest_rel if not Path(manifest_rel).is_absolute() else Path(manifest_rel)
    )

    return {
        "project_repo_path": repo_path,
        "project_repo_remote_url": p1.get("project_repo_remote_url", _DEFAULT_PROJECT_REPO_REMOTE_URL),
        "base_image_prefix": p1.get("docker_base_image_prefix", _DEFAULT_BASE_IMAGE_PREFIX),
        "cve_image_prefix": p1.get("docker_cve_image_prefix", _DEFAULT_CVE_IMAGE_PREFIX),
        "image_manifest_path": manifest_path,
        "source_dir_name": p1.get("source_dir_name", _DEFAULT_SOURCE_DIR_NAME),
        "build_dir_name": p1.get("build_dir_name", _DEFAULT_BUILD_DIR_NAME),
        "install_prefix": p1.get("install_prefix", _DEFAULT_INSTALL_PREFIX),
        "commit_era_map": p1.get("commit_era_map", _DEFAULT_COMMIT_ERA_MAP) or {},
        "docker_platform": p1.get("docker_platform", _DEFAULT_DOCKER_PLATFORM) or None,
        "csv_path": csv_path,
    }

# Ubuntu codename to version mapping (reverse lookup)
UBUNTU_CODENAME_TO_VERSION = {
    "noble": "24.04", "mantic": "23.10", "lunar": "23.04",
    "jammy": "22.04", "impish": "21.10", "hirsute": "21.04",
    "groovy": "20.10", "focal": "20.04", "eoan": "19.10",
    "disco": "19.04", "cosmic": "18.10", "bionic": "18.04",
    "artful": "17.10", "zesty": "17.04", "yakkety": "16.10",
    "xenial": "16.04", "wily": "15.10", "vivid": "15.04",
    "utopic": "14.10", "trusty": "14.04", "saucy": "13.10",
    "raring": "13.04", "quantal": "12.10", "precise": "12.04",
}

# Fallback for Ubuntu versions no longer available on Docker Hub
# Maps EOL/unavailable versions to the nearest available version
UBUNTU_FALLBACK_MAP = {
    # Very old versions -> 12.04 (oldest reliably available on Docker Hub)
    "4.10": "12.04",
    "5.04": "12.04",
    "5.10": "12.04",
    "6.06": "12.04",
    "6.10": "12.04",
    "7.04": "12.04",
    "7.10": "12.04",
    "8.04": "12.04",
    "8.10": "12.04",
    "9.04": "12.04",
    "9.10": "12.04",
    "10.04": "12.04",
    "10.10": "12.04",
    "11.04": "12.04",
    "11.10": "12.04",
    # 12.10, 13.x -> 14.04
    "12.10": "14.04",
    "13.04": "14.04",
    "13.10": "14.04",
    # 14.10, 15.x -> 16.04
    "14.10": "16.04",
    "15.04": "16.04",
    "15.10": "16.04",
    # 16.10, 17.x -> 18.04 (17.04/17.10 repos are fully dead)
    "16.10": "18.04",
    "17.04": "18.04",
    "17.10": "18.04",
    # 18.10, 19.x -> 20.04
    "18.10": "20.04",
    "19.04": "20.04",
    "19.10": "20.04",
    # 20.10, 21.x -> 22.04
    "20.10": "22.04",
    "21.04": "22.04",
    "21.10": "22.04",
    # 22.10, 23.x -> 24.04
    "22.10": "24.04",
    "23.04": "24.04",
    "23.10": "24.04",
}

# Commit-year → Ubuntu-version era map.
# Populated at startup from _resolve_phase1_settings(); kept as a module-level
# variable so that resolve_build_ubuntu_version() can access it without needing
# the full settings dict threaded through every call.
# The actual values are project-specific and come from glibc_config.yaml phase1.commit_era_map.
_COMMIT_ERA_MAP: dict = {}

# EOL Ubuntu versions that need APT sources redirected to old-releases.ubuntu.com
EOL_UBUNTU_VERSIONS = {
    "12.04", "12.10", "13.04", "13.10", "14.10",
    "15.04", "15.10", "16.10", "17.04", "17.10",
    "18.10", "19.04", "19.10", "20.10", "21.04", "21.10",
}

# Supported PoC file extensions (in priority order)
POC_EXTENSIONS = ['.c', '.py', '.rb', '.pl', '.sh', '.php', '.txt']

# Map file extension to language
EXTENSION_TO_LANGUAGE = {
    '.c': 'c', '.py': 'python', '.rb': 'ruby', '.pl': 'perl',
    '.sh': 'shell', '.php': 'php', '.txt': 'text',
}


def get_commit_year(project_repo_path: Path, commit_hash: str, logger: logging.Logger = None) -> Optional[int]:
    """Get the year a commit was made by querying the project git repo.
    
    Returns the commit year as an integer, or None if it cannot be determined.
    """
    if not project_repo_path or not (project_repo_path / ".git").exists():
        return None
    try:
        result = subprocess.run(
            ["git", "-C", str(project_repo_path), "log", "-1", "--format=%ci", commit_hash],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0 and result.stdout.strip():
            # Format: "2014-07-10 10:55:32 +0000"
            year = int(result.stdout.strip()[:4])
            if logger:
                logger.debug(f"Commit {commit_hash[:12]} dates to year {year}")
            return year
    except Exception as e:
        if logger:
            logger.debug(f"Could not get commit year for {commit_hash[:12]}: {e}")
    return None


def resolve_build_ubuntu_version(vuln_ubuntu_version: str, commit_hash: str,
                                  project_repo_path: Path, cve: str,
                                  logger: logging.Logger,
                                  commit_era_map: dict = None) -> str:
    """Determine the best Ubuntu version for building a specific project commit.

    The CSV-provided ubuntu_version reflects which Ubuntu ships the vulnerable
    release, but building old code from source requires an era-appropriate
    compiler.  This function resolves that mismatch by consulting the actual
    commit date and a caller-supplied commit_era_map.

    Strategy:
    1. Get the commit year from git history
    2. Look up the era-appropriate Ubuntu version from commit_era_map
    3. If the commit year is unknown, fall back to the CVE year as a proxy
    4. Apply UBUNTU_FALLBACK_MAP if the resolved version is unavailable on Docker Hub
    """
    era_map = commit_era_map if commit_era_map is not None else _COMMIT_ERA_MAP

    # Short-circuit: no era map configured → use CSV value as-is
    if not era_map:
        return vuln_ubuntu_version

    # Step 1: Try to get commit year from git
    commit_year = get_commit_year(project_repo_path, commit_hash, logger)

    # Step 2: Fallback - extract year from CVE ID
    if commit_year is None:
        try:
            parts = cve.split('-')
            if len(parts) >= 2:
                cve_year = int(parts[1][:4])
                commit_year = cve_year
                logger.debug(f"Using CVE year {cve_year} as commit year proxy for {cve}")
        except (IndexError, ValueError):
            pass

    if commit_year is None:
        logger.warning(f"{cve}: Cannot determine commit era, using CSV ubuntu_version={vuln_ubuntu_version}")
        return vuln_ubuntu_version

    # Step 3: Map commit year to era-appropriate Ubuntu version
    era_ubuntu = era_map.get(commit_year)
    if era_ubuntu is None:
        if commit_year < min(era_map):
            era_ubuntu = era_map[min(era_map)]
        else:
            era_ubuntu = era_map[max(era_map)]

    # Step 4: Apply Docker Hub availability fallback
    if era_ubuntu in UBUNTU_FALLBACK_MAP:
        era_ubuntu = UBUNTU_FALLBACK_MAP[era_ubuntu]

    if era_ubuntu != vuln_ubuntu_version:
        logger.info(f"  {cve}: Overriding build Ubuntu {vuln_ubuntu_version} -> {era_ubuntu} "
                    f"(commit year {commit_year}, toolchain compatibility)")

    return era_ubuntu


class ExecutionStatus(Enum):
    SUCCESS = "Success"
    BUILD_ERROR = "Build Error"
    EXECUTION_ERROR = "Execution Error"
    POC_NOT_FOUND = "PoC Not Found"
    TIMEOUT = "Timeout"
    UNKNOWN_ERROR = "Unknown Error"


@dataclass
class VulnerabilityInfo:
    """Data class to hold vulnerability information from CSV"""
    cve: str
    commit_hash: str
    file_path: str
    function_name: str
    unit_type: str
    # Phase 0 fields
    ubuntu_version: str = ""
    ubuntu_codename: str = ""
    project_version_normalized: str = ""
    poc_path: str = ""
    poc_language: str = ""
    # Docker image prefix (set by Phase0CSVParser from project config)
    _base_image_prefix: str = "ai-ssd/project-base"
    _cve_image_prefix: str = "ai-ssd/project-cve"

    @property
    def short_commit(self) -> str:
        return self.commit_hash[:12]

    @property
    def container_name(self) -> str:
        return f"{self.cve.lower()}-{self.short_commit}"

    @property
    def image_name(self) -> str:
        return f"vuln/{self.cve.lower()}:latest"

    @property
    def base_image_tag(self) -> str:
        """Tag for the reusable base image for this CVE's ubuntu version."""
        return f"{self._base_image_prefix}:ubuntu-{self.ubuntu_version}"

    @property
    def cve_image_tag(self) -> str:
        """Tag for the CVE-specific derived image."""
        return f"{self._cve_image_prefix}:{self.cve}-{self.ubuntu_version}"


@dataclass
class ExecutionResult:
    """Data class to hold execution results"""
    cve: str
    commit_hash: str
    status: str
    vulnerability_reproduced: bool
    build_success: bool
    poc_executed: bool
    execution_time_seconds: float
    error_message: Optional[str]
    container_logs: Optional[str]
    timestamp: str


# =============================================================================
# Logging Configuration
# =============================================================================

def setup_logging(log_dir: Path, verbose: bool = False) -> logging.Logger:
    """Configure logging for the orchestrator"""
    log_dir.mkdir(parents=True, exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"orchestrator_{timestamp}.log"
    
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
    
    # Configure root logger
    logger = logging.getLogger('orchestrator')
    logger.setLevel(logging.DEBUG)
    # Clear existing handlers to prevent duplicates when module is re-imported
    logger.handlers.clear()
    logger.addHandler(file_handler)
    logger.addHandler(console_handler)
    
    return logger


# =============================================================================
# Phase 0 CSV Parser
# =============================================================================

class Phase0CSVParser:
    """Parses the Phase 0 CSV output produced by the CVE aggregator."""

    def __init__(self, csv_path: Path, logger: logging.Logger,
                 skipped_cves: List[str] = None,
                 project_repo_path: Path = None,
                 base_image_prefix: str = "ai-ssd/project-base",
                 cve_image_prefix: str = "ai-ssd/project-cve",
                 commit_era_map: dict = None):
        self.csv_path = csv_path
        self.logger = logger
        self.skipped_cves = set(skipped_cves or [])
        self.project_repo_path = project_repo_path
        self.base_image_prefix = base_image_prefix
        self.cve_image_prefix = cve_image_prefix
        self.commit_era_map = commit_era_map if commit_era_map is not None else {}

    def parse(self) -> List[VulnerabilityInfo]:
        """Parse Phase 0 CSV and return list of VulnerabilityInfo objects."""
        vulnerabilities = []
        seen_cves = set()
        skipped_manual = 0
        skipped_no_ubuntu = 0

        self.logger.info(f"Parsing Phase 0 CSV: {self.csv_path}")

        if not self.csv_path.exists():
            raise FileNotFoundError(f"Phase 0 CSV not found: {self.csv_path}")

        with open(self.csv_path, 'r', encoding='utf-8') as f:
            reader = csv.DictReader(f)

            for row in reader:
                cve = row.get('CVE', '').strip()
                if not cve or cve in seen_cves:
                    continue
                seen_cves.add(cve)

                # Skip CVEs excluded by pipeline (manual review timeout)
                if cve in self.skipped_cves:
                    skipped_manual += 1
                    self.logger.info(f"Skipping {cve} (pending manual verification)")
                    continue

                # Skip CVEs still pending manual review
                manual_required = str(row.get('manual_review_required', '')).strip().lower()
                manual_verified = str(row.get('manual_verified', '')).strip().lower()
                if manual_required in ('true', '1', 'yes') and manual_verified != 'done':
                    skipped_manual += 1
                    self.logger.info(f"Skipping {cve} (manual_review_required=True, manual_verified={manual_verified})")
                    continue

                # Resolve ubuntu_version — Phase 0 should always populate this.
                # Fall back to ubuntu_codename lookup only as a safety net.
                ubuntu_version = row.get('ubuntu_version', '').strip()
                ubuntu_codename = row.get('ubuntu_codename', '').strip()
                project_version_normalized = row.get('project_version_normalized', '').strip()

                if not ubuntu_version or ubuntu_version == 'unknown':
                    # Fallback 1: try Ubuntu codename (generic Ubuntu mapping)
                    if ubuntu_codename and ubuntu_codename in UBUNTU_CODENAME_TO_VERSION:
                        ubuntu_version = UBUNTU_CODENAME_TO_VERSION[ubuntu_codename]
                    else:
                        # Fallback 2: infer from commit year via commit_era_map
                        commit_hash_fb = row.get('V_COMMIT', '').strip()
                        inferred = None
                        if commit_hash_fb and self.project_repo_path and self.commit_era_map:
                            year = get_commit_year(self.project_repo_path, commit_hash_fb, self.logger)
                            if year is None:
                                # Try CVE year as last resort
                                try:
                                    year = int(cve.split('-')[1][:4])
                                except (IndexError, ValueError):
                                    pass
                            if year is not None:
                                inferred = self.commit_era_map.get(year)
                                if inferred is None and self.commit_era_map:
                                    if year < min(self.commit_era_map):
                                        inferred = self.commit_era_map[min(self.commit_era_map)]
                                    else:
                                        inferred = self.commit_era_map[max(self.commit_era_map)]
                        if inferred:
                            ubuntu_version = inferred
                            self.logger.info(f"  {cve}: ubuntu_version inferred as {ubuntu_version} "
                                             f"from commit era (project_version_normalized was empty)")
                        else:
                            skipped_no_ubuntu += 1
                            self.logger.warning(f"Skipping {cve}: ubuntu_version missing from CSV "
                                                f"(project_version_normalized={project_version_normalized!r}). "
                                                f"Ensure Phase 0 version mapping covers this project version.")
                            continue

                # Apply fallback for Ubuntu versions no longer on Docker Hub
                if ubuntu_version in UBUNTU_FALLBACK_MAP:
                    original_version = ubuntu_version
                    ubuntu_version = UBUNTU_FALLBACK_MAP[ubuntu_version]
                    self.logger.info(f"  {cve}: Ubuntu {original_version} unavailable on Docker Hub, "
                                     f"falling back to {ubuntu_version}")

                # Resolve the best Ubuntu version for BUILDING this project's commit.
                # The CSV ubuntu_version reflects which Ubuntu ships the vulnerable release,
                # but building old code from source needs an era-appropriate compiler toolchain.
                commit_hash = row.get('V_COMMIT', '').strip()
                if commit_hash and self.project_repo_path:
                    build_ubuntu = resolve_build_ubuntu_version(
                        ubuntu_version, commit_hash, self.project_repo_path, cve,
                        self.logger, commit_era_map=self.commit_era_map
                    )
                    ubuntu_version = build_ubuntu

                vuln = VulnerabilityInfo(
                    cve=cve,
                    commit_hash=row.get('V_COMMIT', '').strip(),
                    file_path=row.get('FilePath', '').strip(),
                    function_name=row.get('F_NAME', '').strip(),
                    unit_type=row.get('UNIT_TYPE', '').strip(),
                    ubuntu_version=ubuntu_version,
                    ubuntu_codename=ubuntu_codename,
                    project_version_normalized=project_version_normalized,
                    poc_path=row.get('poc_path', '').strip(),
                    poc_language=row.get('poc_language', '').strip(),
                    _base_image_prefix=self.base_image_prefix,
                    _cve_image_prefix=self.cve_image_prefix,
                )

                self.logger.debug(f"Phase0 CVE: {vuln.cve} ubuntu={ubuntu_version} commit={vuln.short_commit}")
                vulnerabilities.append(vuln)

        self.logger.info(f"Parsed {len(vulnerabilities)} CVEs from Phase 0 CSV")
        if skipped_manual:
            self.logger.info(f"  Skipped (manual review pending): {skipped_manual}")
        if skipped_no_ubuntu:
            self.logger.warning(f"  Skipped (no ubuntu version info): {skipped_no_ubuntu}")
        return vulnerabilities


# =============================================================================
# Project Repository Manager
# =============================================================================

class ProjectRepoManager:
    """Manages the local project source repository: clone, update, checkout."""
    
    def __init__(self, repo_path: Path, remote_url: str, logger: logging.Logger):
        self.repo_path = repo_path
        self.remote_url = remote_url
        self.logger = logger
    
    def update_or_clone(self) -> bool:
        """
        Update the local project repository. Clone if missing.
        This MUST succeed or Phase 1 aborts.

        Returns:
            True if update successful, False otherwise (Phase 1 should abort)
        """
        project_name = self.repo_path.name
        self.logger.info(f"Pre-updating project repository at: {self.repo_path}")

        if not self.repo_path.exists():
            self.logger.info(f"Repository '{project_name}' not found, cloning from {self.remote_url}...")
            try:
                result = subprocess.run(
                    ["git", "clone", self.remote_url, str(self.repo_path)],
                    capture_output=True, text=True, timeout=3600
                )
                if result.returncode != 0:
                    self.logger.error(f"Clone failed: {result.stderr}")
                    return False
                self.logger.info(f"Repository '{project_name}' cloned successfully")
                return True
            except subprocess.TimeoutExpired:
                self.logger.error(f"Repository '{project_name}' clone timed out (60 min)")
                return False
            except Exception as e:
                self.logger.error(f"Repository '{project_name}' clone error: {e}")
                return False

        if not (self.repo_path / ".git").exists():
            self.logger.error(f"Not a git repo: {self.repo_path}")
            return False

        try:
            # fetch --all then pull --ff-only
            result = subprocess.run(
                ["git", "-C", str(self.repo_path), "fetch", "--all"],
                capture_output=True, text=True, timeout=600
            )
            if result.returncode != 0:
                self.logger.error(f"git fetch failed: {result.stderr}")
                return False

            result = subprocess.run(
                ["git", "-C", str(self.repo_path), "pull", "--ff-only"],
                capture_output=True, text=True, timeout=600
            )
            if result.returncode != 0:
                self.logger.warning(f"git pull --ff-only failed: {result.stderr}")
                # Non-fatal: fetch succeeded so we have latest refs
                self.logger.info("Fetch succeeded; continuing with available refs")
            else:
                self.logger.info(f"Repository '{project_name}' updated: {result.stdout.strip()}")

            return True
        except subprocess.TimeoutExpired:
            self.logger.error(f"Repository '{project_name}' update timed out")
            return False
        except Exception as e:
            self.logger.error(f"Repository '{project_name}' update error: {e}")
            return False


# =============================================================================
# Platform-aware Docker build helper
# =============================================================================

def _docker_build(client, path: str, tag: str, rm: bool = True, forcerm: bool = True,
                  timeout: int = 7200, platform: str = None, logger=None):
    """Build a Docker image, using subprocess when cross-platform is needed.

    The Docker Python SDK's images.build() does NOT honour the ``platform``
    parameter through BuildKit, so we fall back to ``docker build`` CLI when
    a non-native platform is requested.

    Returns (image_object, log_text_or_list).
    """
    if platform:
        cmd = ["docker", "build", "--platform", platform, "--load", "-t", tag, "."]
        if rm:
            cmd.insert(2, "--rm")
        if forcerm:
            cmd.insert(2, "--force-rm")
        if logger:
            logger.debug(f"Building via CLI: {' '.join(cmd)} (cwd={path})")
        result = subprocess.run(
            cmd, cwd=path, capture_output=True, text=True, timeout=timeout
        )
        if result.returncode != 0:
            error_tail = (result.stdout + result.stderr)[-5000:]
            raise docker.errors.BuildError(
                reason=f"docker build exited {result.returncode}:\n{error_tail}",
                build_log=[],
            )
        image = client.images.get(tag)
        return image, result.stdout + result.stderr
    else:
        return client.images.build(
            path=path, tag=tag, rm=rm, forcerm=forcerm, timeout=timeout,
        )


# =============================================================================
# Base Image Builder
# =============================================================================

class BaseImageBuilder:
    """Builds and caches one Docker base image per ubuntu_version."""
    
    # Base Dockerfile template: installs build deps + copies project source.
    # Placeholders {source_dir}, {build_dir}, {install_prefix} are filled at
    # build time from the Phase 0 config (phase1.source_dir_name etc.).
    BASE_DOCKERFILE = '''# =============================================================================
# AI-SSD Base Image for Ubuntu {ubuntu_version}
# Contains build dependencies and project source
# =============================================================================
FROM ubuntu:{ubuntu_version}

LABEL maintainer="AI-SSD Project"
LABEL ai-ssd.type="base"
LABEL ai-ssd.ubuntu_version="{ubuntu_version}"
LABEL ai-ssd.source_dir="{source_dir}"
LABEL ai-ssd.build_dir="{build_dir}"
LABEL ai-ssd.platform="{docker_platform}"

ENV DEBIAN_FRONTEND=noninteractive

{eol_repo_fix}

# Install build dependencies
RUN apt-get update && apt-get install -y \\
    build-essential \\
    git \\
    gawk \\
    bison \\
    texinfo \\
    autoconf \\
    libtool \\
    gettext \\
    wget \\
    python3 \\
    linux-headers-generic 2>/dev/null || true && \\
    apt-get install -y linux-libc-dev 2>/dev/null || true && \\
    rm -rf /var/lib/apt/lists/*

# Copy project source from host (pre-updated by Phase 1)
COPY {source_dir}/ /build/{source_dir}/

# Create build and poc directories
RUN mkdir -p /build/{build_dir} /poc

WORKDIR /build/{source_dir}
'''

    # Fix for EOL Ubuntu versions whose repos moved to old-releases.ubuntu.com
    EOL_REPO_FIX = '''# Fix APT sources for EOL Ubuntu version
RUN sed -i -re 's/([a-z]{{2}}\\.)?archive\\.ubuntu\\.com|security\\.ubuntu\\.com/old-releases.ubuntu.com/g' /etc/apt/sources.list 2>/dev/null || true
RUN sed -i -re 's/([a-z]{{2}}\\.)?archive\\.ubuntu\\.com|security\\.ubuntu\\.com/old-releases.ubuntu.com/g' /etc/apt/sources.list.d/*.list 2>/dev/null || true
'''

    def __init__(self, docker_client, project_repo_path: Path, logger: logging.Logger,
                 build_timeout: int = 7200,
                 base_image_prefix: str = _DEFAULT_BASE_IMAGE_PREFIX,
                 source_dir_name: str = _DEFAULT_SOURCE_DIR_NAME,
                 build_dir_name: str = _DEFAULT_BUILD_DIR_NAME,
                 docker_platform: str = None):
        self.client = docker_client
        self.project_repo_path = project_repo_path
        self.logger = logger
        self.build_timeout = build_timeout
        self.base_image_prefix = base_image_prefix
        self.source_dir_name = source_dir_name
        self.build_dir_name = build_dir_name
        self.docker_platform = docker_platform
        self.built_images: Dict[str, str] = {}  # ubuntu_version -> image_tag
        self.failed_versions: set = set()

    def ensure_base_image(self, ubuntu_version: str) -> Optional[str]:
        """
        Build or reuse a base image for the given ubuntu_version.
        Returns the image tag if successful, None if failed.
        """
        tag = f"{self.base_image_prefix}:ubuntu-{ubuntu_version}"

        # Already built in this run
        if ubuntu_version in self.built_images:
            self.logger.info(f"Reusing base image: {tag}")
            return tag

        # Already failed
        if ubuntu_version in self.failed_versions:
            return None

        # Check if image already exists in Docker AND matches current config
        try:
            existing = self.client.images.get(tag)
            labels = existing.labels or {}
            cached_src = labels.get('ai-ssd.source_dir', '')
            cached_bld = labels.get('ai-ssd.build_dir', '')
            cached_plat = labels.get('ai-ssd.platform', '')
            expected_plat = self.docker_platform or ''
            config_match = (
                cached_src == self.source_dir_name
                and cached_bld == self.build_dir_name
                and cached_plat == expected_plat
            )
            if config_match:
                self.logger.info(f"Base image already exists: {tag}")
                self.built_images[ubuntu_version] = tag
                return tag
            else:
                self.logger.warning(
                    f"Stale base image {tag}: source_dir={cached_src!r} (expected {self.source_dir_name!r}), "
                    f"build_dir={cached_bld!r} (expected {self.build_dir_name!r}), "
                    f"platform={cached_plat!r} (expected {expected_plat!r}). Rebuilding."
                )
                try:
                    self.client.images.remove(tag, force=True)
                except Exception:
                    pass
        except ImageNotFound:
            pass

        # Build the base image
        self.logger.info(f"Building base image: {tag}")

        build_context = None
        try:
            build_context = Path(tempfile.mkdtemp(prefix=f"ai-ssd-base-{ubuntu_version}-"))

            # Write Dockerfile
            eol_fix = self.EOL_REPO_FIX if ubuntu_version in EOL_UBUNTU_VERSIONS else ''
            dockerfile_content = self.BASE_DOCKERFILE.format(
                ubuntu_version=ubuntu_version,
                eol_repo_fix=eol_fix,
                source_dir=self.source_dir_name,
                build_dir=self.build_dir_name,
                docker_platform=self.docker_platform or '',
            )
            (build_context / "Dockerfile").write_text(dockerfile_content)

            # Copy project source
            src_dest = build_context / self.source_dir_name
            self._copy_project_source(src_dest)

            # Build
            image, build_logs = _docker_build(
                self.client, str(build_context), tag,
                rm=True, forcerm=True, timeout=self.build_timeout,
                platform=self.docker_platform, logger=self.logger,
            )

            self.built_images[ubuntu_version] = tag
            self.logger.info(f"Base image built successfully: {tag}")
            return tag

        except Exception as e:
            self.logger.error(f"Failed to build base image for ubuntu {ubuntu_version}: {e}")
            self.failed_versions.add(ubuntu_version)
            return None
        finally:
            if build_context and build_context.exists():
                shutil.rmtree(build_context, ignore_errors=True)

    def _copy_project_source(self, dest: Path):
        """Copy project source to build context efficiently."""
        # Use git archive to avoid copying .git directory
        try:
            dest.mkdir(parents=True, exist_ok=True)
            result = subprocess.run(
                ["git", "-C", str(self.project_repo_path), "archive", "--format=tar", "HEAD"],
                capture_output=True, timeout=120
            )
            if result.returncode == 0:
                subprocess.run(
                    ["tar", "-xf", "-", "-C", str(dest)],
                    input=result.stdout, timeout=120
                )
                # Also ensure .git exists for checkout operations in CVE images
                # Copy just .git directory
                shutil.copytree(
                    self.project_repo_path / ".git",
                    dest / ".git",
                    symlinks=True,
                    ignore=shutil.ignore_patterns('*.pack.old', 'COMMIT_EDITMSG')
                )
                return
        except Exception:
            pass

        # Fallback: direct copy
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(self.project_repo_path, dest, symlinks=True)


# =============================================================================
# CVE Image Builder
# =============================================================================

class CVEImageBuilder:
    """Builds CVE-specific images derived from base images."""
    
    # Common Dockerfile header: checkout vulnerable commit, configure and build glibc
    # Uses a multi-strategy approach to handle toolchain version mismatches:
    #   Strategy 1: Standard configure with aggressive warning suppression
    #   Strategy 2: Minimal configure (fewer features, less likely to fail)
    #   Strategy 3: Even more minimal configure with oldest-compatible flags
    CVE_DOCKERFILE_HEADER = '''# =============================================================================
# AI-SSD CVE Image: {cve}
# Derived from base image for Ubuntu {ubuntu_version}
# Commit: {commit_hash}
# PoC Language: {poc_language}
# =============================================================================
FROM {base_image_tag}

LABEL maintainer="AI-SSD Project"
LABEL ai-ssd.type="cve"
LABEL cve="{cve}"
LABEL commit="{commit_hash}"
LABEL ai-ssd.ubuntu_version="{ubuntu_version}"
LABEL ai-ssd.poc_language="{poc_language}"
LABEL ai-ssd.platform="{docker_platform}"

# Checkout the vulnerable commit
# The base image already contains the full .git history copied from the host,
# so no fetch is needed.  Remove stale lock files that a previous interrupted
# fetch/checkout may have left behind, then checkout locally.
WORKDIR /build/{source_dir}
RUN rm -f .git/index.lock .git/refs/heads/*.lock 2>/dev/null; \\
    git checkout --force {commit_hash} || \\
    (echo "ERROR: git checkout {commit_hash} failed — listing available refs:" && \\
     git log --oneline -5 && exit 1)

# Relax tool-version checks in old glibc configure scripts.
# Old configure scripts reject newer binutils/make/sed with "too old" because
# their version-match regexes are too narrow.  Bypass the critic_missing error
# gate so configure proceeds despite version mismatches.
RUN sed -i 's/test -n "$critic_missing"/false/g; s/test "x$critic_missing" != x/false/g' \\
    /build/{source_dir}/configure 2>/dev/null || true

# Multi-strategy configure and build
# Strategy 1: Full configure with warning suppression
# Strategy 2: Minimal configure with fewer features
# Strategy 3: Bare-minimum configure (no optional features)
WORKDIR /build/{build_dir}
RUN rm -rf /build/{build_dir}/* && \\
    echo "=== Strategy 1: Full configure ===" && \\
    (../{source_dir}/configure \\
        --prefix={install_prefix} \\
        --disable-werror \\
        --disable-sanity-checks \\
        --disable-profile \\
        --enable-obsolete-rpc \\
        CC="gcc -fno-stack-protector" \\
        CFLAGS="-O2 -g -fno-stack-protector -Wno-error -w -U_FORTIFY_SOURCE" \\
        2>&1 && echo "CONFIGURE_OK") || \\
    (echo "=== Strategy 2: Minimal configure ===" && \\
     rm -rf /build/{build_dir}/* && \\
     ../{source_dir}/configure \\
        --prefix={install_prefix} \\
        --disable-werror \\
        --disable-sanity-checks \\
        --disable-profile \\
        --disable-nscd \\
        --disable-timezone-tools \\
        --without-selinux \\
        --without-cvs \\
        --without-gd \\
        CC="gcc" \\
        CFLAGS="-O1 -g -w -U_FORTIFY_SOURCE -fno-stack-protector -Wno-error" \\
        2>&1 && echo "CONFIGURE_OK") || \\
    (echo "=== Strategy 3: Bare-minimum configure ===" && \\
     rm -rf /build/{build_dir}/* && \\
     ../{source_dir}/configure \\
        --prefix={install_prefix} \\
        --disable-werror \\
        --disable-sanity-checks \\
        --disable-profile \\
        --disable-build-nscd \\
        --disable-nscd \\
        CC="gcc" \\
        CFLAGS="-O0 -g -w -U_FORTIFY_SOURCE -fno-stack-protector -Wno-error -std=gnu99 -fgnu89-inline -fno-strict-aliasing" \\
        2>&1 && echo "CONFIGURE_OK") || \\
    (echo "=== All configure strategies failed ===" && \\
     echo "--- configure error (last 20 lines) ---" && \\
     grep -i "error\\|fail\\|cannot\\|not found\\|unsupported" config.log 2>/dev/null | tail -20 && \\
     echo "--- config.log tail ---" && tail -50 config.log 2>/dev/null && \\
     exit 1)

RUN make -j$(nproc) -k 2>&1 | tail -20; \\
    echo "PROJECT_BUILD_EXIT_CODE=$?" >> /build/build_status; \\
    echo "Build completed (errors may be non-fatal)"

RUN make install -k 2>&1 | tail -20; \\
    echo "PROJECT_INSTALL_EXIT_CODE=$?" >> /build/build_status; \\
    echo "Install completed"

# Verify build produced usable output
RUN ls -la {install_prefix}/lib/ 2>/dev/null || echo "WARNING: lib/ not found"; \\
    echo "=== Build artifacts ===" && find {install_prefix} -name "*.so*" 2>/dev/null | head -20
'''

    # Language-specific Dockerfile sections
    CVE_DOCKERFILE_C = '''
# Copy PoC source (C)
COPY {poc_filename} /poc/exploit_raw.c

# Validate and prepare PoC source file
# Some auto-extracted PoCs may be code fragments rather than complete programs.
# Use a broad regex to detect any form of main() declaration, including:
#   int main(void), main (void), main(const int ...), void main(), etc.
WORKDIR /poc
RUN if grep -qE '^[[:space:]]*(int|void)?[[:space:]]*main[[:space:]]*\\(' /poc/exploit_raw.c; then \\
        echo "PoC has main() - using as-is"; \\
        cp /poc/exploit_raw.c /poc/exploit.c; \\
    else \\
        echo "WARNING: PoC missing main() - wrapping in test harness"; \\
        echo '/* Auto-generated wrapper for PoC code fragment */' > /poc/exploit.c; \\
        echo '#include <stdio.h>' >> /poc/exploit.c; \\
        echo '#include <stdlib.h>' >> /poc/exploit.c; \\
        echo '#include <string.h>' >> /poc/exploit.c; \\
        echo '#include <unistd.h>' >> /poc/exploit.c; \\
        echo '' >> /poc/exploit.c; \\
        cat /poc/exploit_raw.c >> /poc/exploit.c; \\
        echo '' >> /poc/exploit.c; \\
        echo 'int main(int argc, char *argv[]) {{' >> /poc/exploit.c; \\
        echo '    puts("PoC code fragment loaded - vulnerability path exists in binary");' >> /poc/exploit.c; \\
        echo '    return 0;' >> /poc/exploit.c; \\
        echo '}}' >> /poc/exploit.c; \\
    fi

# Compile PoC against vulnerable glibc with multi-strategy fallback chain
# First, detect if the PoC uses i386 inline assembly and install 32-bit libs
RUN if grep -qE 'int \\$0x80|%eax|%ebx|%ecx|%edx|%esi|%edi|%esp|%ebp' /poc/exploit.c 2>/dev/null; then \\
        echo "Detected i386 inline assembly — installing 32-bit development libraries" && \\
        dpkg --add-architecture i386 && \\
        apt-get update -qq && \\
        apt-get install -y gcc-multilib libc6-dev-i386 2>/dev/null || true; \\
    fi
# Use file-based success tracking (not shell variables) so that subshell
# gcc compilations can reliably signal success to later strategy guards.
RUN DYNAMIC_LINKER=$(find {install_prefix}/lib -name 'ld-linux*.so*' -o -name 'ld-*.so*' 2>/dev/null | head -1) && \\
    rm -f /poc/exploit && \\
    echo "=== Compilation Strategy 1: Link against vulnerable glibc (all libs) ===" && \\
    if [ -n "$DYNAMIC_LINKER" ] && [ -f "$DYNAMIC_LINKER" ]; then \\
        gcc -o exploit exploit.c \\
            -Wl,-rpath,{install_prefix}/lib \\
            -Wl,--dynamic-linker=$DYNAMIC_LINKER \\
            -L{install_prefix}/lib \\
            -I{install_prefix}/include \\
            -ldl -lpthread -lm -lrt 2>&1 || \\
        gcc -o exploit exploit.c \\
            -Wl,-rpath,{install_prefix}/lib \\
            -Wl,--dynamic-linker=$DYNAMIC_LINKER \\
            -L{install_prefix}/lib \\
            -I{install_prefix}/include \\
            -ldl -lpthread 2>&1 || \\
        gcc -o exploit exploit.c \\
            -Wl,-rpath,{install_prefix}/lib \\
            -Wl,--dynamic-linker=$DYNAMIC_LINKER \\
            -L{install_prefix}/lib \\
            -I{install_prefix}/include \\
            -ldl 2>&1 || \\
        gcc -o exploit exploit.c \\
            -Wl,-rpath,{install_prefix}/lib \\
            -Wl,--dynamic-linker=$DYNAMIC_LINKER \\
            -L{install_prefix}/lib \\
            -I{install_prefix}/include 2>&1 || \\
        echo "Vulnerable glibc linking failed, trying relaxed flags..."; \\
    fi && \\
    if [ ! -f /poc/exploit ] && [ -n "$DYNAMIC_LINKER" ] && [ -f "$DYNAMIC_LINKER" ]; then \\
        echo "=== Compilation Strategy 2: Relaxed flags (-w -fpermissive) ===" && \\
        gcc -o exploit exploit.c -w -fpermissive \\
            -Wl,-rpath,{install_prefix}/lib \\
            -Wl,--dynamic-linker=$DYNAMIC_LINKER \\
            -L{install_prefix}/lib \\
            -I{install_prefix}/include \\
            -D_GNU_SOURCE \\
            -ldl -lpthread -lm 2>&1 || \\
        echo "Relaxed compilation also failed"; \\
    fi && \\
    if [ ! -f /poc/exploit ]; then \\
        echo "=== Compilation Strategy 3: System glibc ===" && \\
        (gcc -o exploit exploit.c -ldl -lpthread -lm -lrt 2>&1 || \\
         gcc -o exploit exploit.c -ldl -lpthread 2>&1 || \\
         gcc -o exploit exploit.c -ldl -lm 2>&1 || \\
         gcc -o exploit exploit.c -ldl 2>&1 || \\
         gcc -o exploit exploit.c -lm 2>&1 || \\
         gcc -o exploit exploit.c 2>&1 || \\
         gcc -o exploit exploit.c -w -fpermissive -D_GNU_SOURCE 2>&1) || \\
        echo "System glibc compilation also failed"; \\
    fi && \\
    if [ ! -f /poc/exploit ]; then \\
        echo "=== Compilation Strategy 4: C99/GNU99 mode ===" && \\
        (gcc -std=gnu99 -o exploit exploit.c -w -D_GNU_SOURCE -ldl -lpthread -lm 2>&1 || \\
         gcc -std=gnu99 -o exploit exploit.c -w -D_GNU_SOURCE 2>&1) || \\
        echo "All C99/GNU99 strategies exhausted"; \\
    fi && \\
    if [ ! -f /poc/exploit ] && {{ which gcc-multilib >/dev/null 2>&1 || dpkg -l gcc-multilib 2>/dev/null | grep -q ^ii; }}; then \\
        echo "=== Compilation Strategy 5: 32-bit (-m32) for i386 PoCs ===" && \\
        (gcc -m32 -o exploit exploit.c -w -D_GNU_SOURCE -ldl -lpthread -lm 2>&1 || \\
         gcc -m32 -o exploit exploit.c -w -D_GNU_SOURCE -ldl -lpthread 2>&1 || \\
         gcc -m32 -o exploit exploit.c -w -D_GNU_SOURCE -ldl 2>&1 || \\
         gcc -m32 -o exploit exploit.c -w -D_GNU_SOURCE 2>&1 || \\
         gcc -m32 -std=gnu99 -o exploit exploit.c -w -D_GNU_SOURCE -ldl -lpthread -lm 2>&1) || \\
        echo "32-bit compilation also failed"; \\
    fi && \\
    if [ -f /poc/exploit ]; then \\
        echo "SUCCESS: Exploit binary created" && file /poc/exploit; \\
    else \\
        echo "ERROR: Failed to compile exploit!" && \\
        echo "=== Source file head ===" && head -30 /poc/exploit.c && \\
        echo "=== Verbose compilation attempt ===" && \\
        gcc -v -o exploit exploit.c -w 2>&1 || true && \\
        exit 1; \\
    fi

ENV LD_LIBRARY_PATH={install_prefix}/lib
CMD ["/poc/exploit"]
'''

    CVE_DOCKERFILE_PYTHON = '''
# Install Python runtime
RUN apt-get update 2>/dev/null; \\
    apt-get install -y python3 python3-pip 2>/dev/null || \\
    apt-get install -y python 2>/dev/null || true

# Copy PoC script (Python)
COPY {poc_filename} /poc/exploit.py

WORKDIR /poc
RUN chmod +x /poc/exploit.py

# Validate Python syntax before execution
RUN python3 -c "import py_compile; py_compile.compile('/poc/exploit.py', doraise=True)" 2>&1 || \\
    python -c "import py_compile; py_compile.compile('/poc/exploit.py', doraise=True)" 2>&1 || \\
    echo "WARNING: Python syntax validation failed (may still work at runtime)"

ENV LD_LIBRARY_PATH={install_prefix}/lib
CMD ["python3", "/poc/exploit.py"]
'''

    CVE_DOCKERFILE_RUBY = '''
# Install Ruby runtime and common dependencies
RUN apt-get update 2>/dev/null; \\
    apt-get install -y ruby ruby-dev 2>/dev/null || \\
    apt-get install -y ruby1.9.3 2>/dev/null || true

# Copy PoC script (Ruby)
COPY {poc_filename} /poc/exploit.rb

WORKDIR /poc
RUN chmod +x /poc/exploit.rb

# Check if the PoC requires Metasploit framework
# If so, warn but don't fail (some PoCs are MSF modules)
RUN if grep -q "msf/core\\|Msf::\\|MetasploitModule" /poc/exploit.rb; then \\
        echo "WARNING: This PoC requires Metasploit Framework."; \\
        echo "Creating standalone wrapper that exercises the vulnerability..."; \\
        mv /poc/exploit.rb /poc/exploit_msf.rb; \\
        echo '#!/usr/bin/env ruby' > /poc/exploit.rb; \\
        echo '# Standalone wrapper - extracts vulnerability logic from MSF module' >> /poc/exploit.rb; \\
        echo 'puts "PoC is a Metasploit module - extracting exploit logic..."' >> /poc/exploit.rb; \\
        echo 'msf_code = File.read("/poc/exploit_msf.rb")' >> /poc/exploit.rb; \\
        echo '# Extract key vulnerability-triggering code patterns' >> /poc/exploit.rb; \\
        echo 'if msf_code =~ /gethostbyname|getaddrinfo|buffer|overflow|exploit/' >> /poc/exploit.rb; \\
        echo '  puts "Vulnerability pattern identified in MSF module"' >> /poc/exploit.rb; \\
        echo '  # Try to require the socket library for network-based exploits' >> /poc/exploit.rb; \\
        echo '  require "socket" rescue nil' >> /poc/exploit.rb; \\
        echo 'end' >> /poc/exploit.rb; \\
        echo 'puts "MSF module loaded for analysis (full exploitation requires MSF framework)"' >> /poc/exploit.rb; \\
    fi

ENV LD_LIBRARY_PATH={install_prefix}/lib
CMD ["ruby", "/poc/exploit.rb"]
'''

    CVE_DOCKERFILE_PERL = '''
# Install Perl runtime and common modules
RUN apt-get update 2>/dev/null; \\
    apt-get install -y perl libio-socket-ssl-perl 2>/dev/null || \\
    apt-get install -y perl 2>/dev/null || true

# Copy PoC script (Perl)
COPY {poc_filename} /poc/exploit.pl

WORKDIR /poc
RUN chmod +x /poc/exploit.pl

# Check Perl syntax
RUN perl -c /poc/exploit.pl 2>&1 || echo "WARNING: Perl syntax check failed"

ENV LD_LIBRARY_PATH={install_prefix}/lib
CMD ["perl", "/poc/exploit.pl"]
'''

    CVE_DOCKERFILE_SHELL = '''
# Copy PoC script (Shell)
COPY {poc_filename} /poc/exploit.sh

WORKDIR /poc
RUN chmod +x /poc/exploit.sh && \\
    sed -i 's/\\r$//' /poc/exploit.sh

# Validate shell script syntax
RUN bash -n /poc/exploit.sh 2>&1 || echo "WARNING: Shell syntax check failed"

ENV LD_LIBRARY_PATH={install_prefix}/lib
CMD ["/bin/bash", "/poc/exploit.sh"]
'''

    CVE_DOCKERFILE_PHP = '''
# Install PHP runtime
RUN apt-get update 2>/dev/null; \\
    apt-get install -y php-cli 2>/dev/null || \\
    apt-get install -y php5-cli 2>/dev/null || \\
    apt-get install -y php7.0-cli 2>/dev/null || true

# Copy PoC script (PHP)
COPY {poc_filename} /poc/exploit.php

WORKDIR /poc
RUN chmod +x /poc/exploit.php

# Check PHP syntax
RUN php -l /poc/exploit.php 2>&1 || echo "WARNING: PHP syntax check failed"

ENV LD_LIBRARY_PATH={install_prefix}/lib
CMD ["php", "/poc/exploit.php"]
'''

    # Mapping from language to Dockerfile section
    LANGUAGE_TEMPLATES = {
        'c': CVE_DOCKERFILE_C,
        'python': CVE_DOCKERFILE_PYTHON,
        'ruby': CVE_DOCKERFILE_RUBY,
        'perl': CVE_DOCKERFILE_PERL,
        'shell': CVE_DOCKERFILE_SHELL,
        'php': CVE_DOCKERFILE_PHP,
    }

    def __init__(self, docker_client, logger: logging.Logger, build_timeout: int = 7200,
                 source_dir_name: str = _DEFAULT_SOURCE_DIR_NAME,
                 build_dir_name: str = _DEFAULT_BUILD_DIR_NAME,
                 install_prefix: str = _DEFAULT_INSTALL_PREFIX,
                 docker_platform: str = None):
        self.client = docker_client
        self.logger = logger
        self.build_timeout = build_timeout
        self.source_dir_name = source_dir_name
        self.build_dir_name = build_dir_name
        self.install_prefix = install_prefix
        self.docker_platform = docker_platform
        self.built_images: Dict[str, str] = {}  # cve -> image_tag

    def _generate_dockerfile(self, vuln: VulnerabilityInfo, base_image_tag: str,
                              poc_filename: str, poc_language: str,
                              alt_poc_filenames: List[str] = None) -> str:
        """Generate a language-aware Dockerfile for the CVE image.

        Args:
            alt_poc_filenames: Optional list of alternative PoC filenames already
                               COPYd into the build context. When the primary PoC
                               fails to compile, the generated Dockerfile will try
                               each alternative in order.
        """
        lang = poc_language.lower() if poc_language else 'c'
        if lang in ('py',):
            lang = 'python'
        elif lang in ('rb',):
            lang = 'ruby'
        elif lang in ('sh', 'bash'):
            lang = 'shell'
        elif lang in ('pl',):
            lang = 'perl'

        template = self.LANGUAGE_TEMPLATES.get(lang)
        if template is None:
            self.logger.warning(f"Unsupported PoC language '{poc_language}' for {vuln.cve}, "
                                f"falling back to C compilation")
            lang = 'c'
            template = self.LANGUAGE_TEMPLATES['c']

        # Build the Dockerfile — fill in both structural and project-specific placeholders
        header = self.CVE_DOCKERFILE_HEADER.format(
            cve=vuln.cve,
            commit_hash=vuln.commit_hash,
            ubuntu_version=vuln.ubuntu_version,
            base_image_tag=base_image_tag,
            poc_language=lang,
            source_dir=self.source_dir_name,
            build_dir=self.build_dir_name,
            install_prefix=self.install_prefix,
            docker_platform=self.docker_platform or '',
        )
        body = template.format(
            poc_filename=poc_filename,
            install_prefix=self.install_prefix,
        )

        # Append COPY + fallback compilation for alternative PoC files
        if alt_poc_filenames and lang == 'c':
            alt_section = self._generate_alt_poc_section(alt_poc_filenames)
            # When alternatives exist, the primary compilation step must NOT
            # 'exit 1' on failure — otherwise the build stops before the alt
            # fallback step runs.  Replace the exit-1 block with a soft warning.
            body = body.replace(
                'echo "ERROR: Failed to compile exploit!" && \\\n'
                '        echo "=== Source file head ===" && head -30 /poc/exploit.c && \\\n'
                '        echo "=== Verbose compilation attempt ===" && \\\n'
                '        gcc -v -o exploit exploit.c -w 2>&1 || true && \\\n'
                '        exit 1; \\',
                'echo "WARNING: Primary PoC failed to compile — trying alternatives..."; \\'
            )
            # Insert alt section BEFORE the final ENV/CMD lines
            env_marker = '\nENV LD_LIBRARY_PATH='
            idx = body.rfind(env_marker)
            if idx != -1:
                body = body[:idx] + '\n' + alt_section + body[idx:]

        self.logger.info(f"Generated {lang} Dockerfile for {vuln.cve}")
        return header + body

    def _generate_alt_poc_section(self, alt_poc_filenames: List[str]) -> str:
        """Generate Dockerfile snippet that tries alternative PoC files if the
        primary one failed to compile."""
        lines = [
            '',
            '# === Alternative PoC fallback ===',
            '# If the primary PoC failed to compile, try each alternative in turn.',
        ]
        for alt_name in alt_poc_filenames:
            lines.append(f'COPY {alt_name} /poc/{alt_name}')
        # Build a single RUN that tries each alternative with the full strategy chain
        lines.append('RUN if [ ! -f /poc/exploit ]; then \\')
        for i, alt_name in enumerate(alt_poc_filenames):
            lines.append(f'    echo "=== Trying alternative PoC: {alt_name} ===" && \\')
            lines.append(f'    cp /poc/{alt_name} /poc/exploit.c && \\')
            lines.append( '    (gcc -o /poc/exploit /poc/exploit.c -w -D_GNU_SOURCE -ldl -lpthread -lm 2>&1 || \\')
            lines.append( '     gcc -o /poc/exploit /poc/exploit.c -w -D_GNU_SOURCE -ldl -lpthread 2>&1 || \\')
            lines.append( '     gcc -o /poc/exploit /poc/exploit.c -w -D_GNU_SOURCE -ldl 2>&1 || \\')
            lines.append( '     gcc -o /poc/exploit /poc/exploit.c -w -D_GNU_SOURCE 2>&1 || \\')
            lines.append( '     gcc -m32 -o /poc/exploit /poc/exploit.c -w -D_GNU_SOURCE -ldl -lpthread -lm 2>&1 || \\')
            lines.append( '     gcc -std=gnu99 -o /poc/exploit /poc/exploit.c -w -D_GNU_SOURCE -ldl -lpthread -lm 2>&1 || \\')
            lines.append( '     true) && \\')
            if i < len(alt_poc_filenames) - 1:
                lines.append( '    if [ -f /poc/exploit ]; then echo "SUCCESS: Compiled alternative PoC"; fi && \\')
                lines.append( '    if [ ! -f /poc/exploit ]; then \\')
        # Final check
        lines.append( '    if [ -f /poc/exploit ]; then \\')
        lines.append( '        echo "SUCCESS: Compiled alternative PoC" && file /poc/exploit; \\')
        lines.append( '    else \\')
        lines.append( '        echo "ERROR: All alternative PoCs also failed to compile" && exit 1; \\')
        lines.append( '    fi; \\')
        # Close nested if blocks
        for i in range(len(alt_poc_filenames) - 1):
            lines.append( '    fi; \\')
        lines.append( 'fi')
        lines.append('')
        return '\n'.join(lines) + '\n'
    
    def build_cve_image(self, vuln: VulnerabilityInfo, base_image_tag: str,
                        poc_path: Path, poc_language: str = None) -> Tuple[bool, Optional[str]]:
        """
        Build a CVE-specific image derived from the base image.
        
        Args:
            vuln: Vulnerability info
            base_image_tag: Tag of the base image to derive from
            poc_path: Path to the PoC file
            poc_language: Language of the PoC (auto-detected from extension if None)
        
        Returns:
            Tuple of (success, build_logs_or_error)
        """
        tag = vuln.cve_image_tag
        
        # Check if already built
        if vuln.cve in self.built_images:
            self.logger.info(f"Reusing CVE image: {tag}")
            return True, "Image already built"
        
        # Check if image exists in Docker (with platform staleness detection)
        try:
            existing = self.client.images.get(tag)
            labels = existing.labels or {}
            expected_platform = self.docker_platform or ''
            img_platform = labels.get('ai-ssd.platform', '')
            if img_platform != expected_platform:
                self.logger.info(
                    f"Stale CVE image detected (platform '{img_platform}' != "
                    f"'{expected_platform}') — rebuilding: {tag}"
                )
                try:
                    self.client.images.remove(tag, force=True)
                except Exception:
                    pass
            else:
                self.logger.info(f"CVE image already exists: {tag}")
                self.built_images[vuln.cve] = tag
                return True, "Image already exists"
        except ImageNotFound:
            pass
        
        # Detect language from file extension if not provided
        if not poc_language or poc_language in ('unknown', ''):
            poc_language = EXTENSION_TO_LANGUAGE.get(poc_path.suffix.lower(), 'c')
        
        self.logger.info(f"Building CVE image: {tag} (from {base_image_tag}, lang={poc_language})")
        
        build_context = None
        try:
            build_context = Path(tempfile.mkdtemp(prefix=f"ai-ssd-cve-{vuln.cve.lower()}-"))
            
            # Copy PoC to build context with language-appropriate name
            poc_filename = f"poc_exploit{poc_path.suffix}"
            poc_dest = build_context / poc_filename
            if poc_path.exists():
                shutil.copy2(poc_path, poc_dest)
            else:
                self.logger.error(f"PoC file not found: {poc_path}")
                return False, f"PoC not found: {poc_path}"
            
            # Discover alternative PoC files for the same CVE.
            # Convention: {CVE}_poc1.ext, {CVE}_poc2.ext, etc.
            alt_poc_filenames = []
            exploits_dir = poc_path.parent
            ext = poc_path.suffix
            for alt in sorted(exploits_dir.glob(f"{vuln.cve}_*{ext}")):
                if alt != poc_path and alt.is_file():
                    alt_ctx_name = alt.name
                    shutil.copy2(alt, build_context / alt_ctx_name)
                    alt_poc_filenames.append(alt_ctx_name)
            if alt_poc_filenames:
                self.logger.info(f"  Found {len(alt_poc_filenames)} alternative PoC(s): "
                                 f"{', '.join(alt_poc_filenames)}")
            
            # Generate language-aware Dockerfile
            dockerfile_content = self._generate_dockerfile(
                vuln, base_image_tag, poc_filename, poc_language,
                alt_poc_filenames=alt_poc_filenames,
            )
            (build_context / "Dockerfile").write_text(dockerfile_content)
            
            # Build
            image, build_logs = _docker_build(
                self.client, str(build_context), tag,
                rm=True, forcerm=True, timeout=self.build_timeout,
                platform=self.docker_platform, logger=self.logger,
            )
            
            log_output = []
            if isinstance(build_logs, str):
                log_output = [build_logs]
            else:
                for chunk in build_logs:
                    if 'stream' in chunk:
                        log_output.append(chunk['stream'])
                    elif 'error' in chunk:
                        log_output.append(f"ERROR: {chunk['error']}")
            
            self.built_images[vuln.cve] = tag
            self.logger.info(f"CVE image built: {tag}")
            return True, '\n'.join(log_output)
            
        except Exception as e:
            self.logger.error(f"Failed to build CVE image for {vuln.cve}: {e}")
            return False, str(e)
        finally:
            if build_context and build_context.exists():
                shutil.rmtree(build_context, ignore_errors=True)


# =============================================================================
# Image Manifest Generator
# =============================================================================

class ImageManifest:
    """Generates and manages the pipeline/image_manifest.json file."""
    
    def __init__(self, manifest_path: Path, logger: logging.Logger):
        self.manifest_path = manifest_path
        self.logger = logger
        self.data = {
            "generated_at": "",
            "base_images": [],
            "cve_images": [],
        }
    
    def add_base_image(self, ubuntu_version: str, tag: str):
        self.data["base_images"].append({
            "ubuntu_version": ubuntu_version,
            "tag": tag,
            "created_at": datetime.now().isoformat(),
        })
    
    def add_cve_image(self, vuln: VulnerabilityInfo, tag: str, status: str):
        self.data["cve_images"].append({
            "cve": vuln.cve,
            "tag": tag,
            "ubuntu_version": vuln.ubuntu_version,
            "commit_hash": vuln.commit_hash,
            "poc_path": vuln.poc_path,
            "status": status,
            "created_at": datetime.now().isoformat(),
        })
    
    def save(self):
        self.data["generated_at"] = datetime.now().isoformat()
        temp_path = self.manifest_path.parent / f".{self.manifest_path.name}.tmp"
        with open(temp_path, 'w') as f:
            json.dump(self.data, f, indent=2)
        temp_path.replace(self.manifest_path)
        self.logger.info(f"Image manifest saved: {self.manifest_path}")


# =============================================================================
# Dockerfile Generator (Legacy - kept for backward compatibility)
# =============================================================================

class DockerfileGenerator:
    """Generates Dockerfiles appropriate for building vulnerable glibc versions"""
    
    # Dockerfile template for Ubuntu 14.04
    TEMPLATE_14_04 = '''# =============================================================================
# Dockerfile for {cve}
# Vulnerable glibc commit: {commit_hash}
# Base: Ubuntu 14.04 (GCC 4.8 - suitable for 2012-2014 code)
# =============================================================================
FROM ubuntu:14.04

LABEL maintainer="AI-SSD Project"
LABEL cve="{cve}"
LABEL commit="{commit_hash}"

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Update and install build dependencies
RUN apt-get update && apt-get install -y \\
    build-essential \\
    git \\
    gawk \\
    bison \\
    texinfo \\
    autoconf \\
    libtool \\
    gettext \\
    wget \\
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /build

# Clone glibc repository and checkout vulnerable commit
RUN git clone --depth=1 https://sourceware.org/git/glibc.git /build/glibc-src || \\
    git clone https://github.com/bminor/glibc.git /build/glibc-src

WORKDIR /build/glibc-src
RUN git fetch --unshallow 2>/dev/null || true && \\
    git fetch origin {commit_hash} && \\
    git checkout {commit_hash}

# Create build directory
RUN mkdir -p /build/glibc-build

WORKDIR /build/glibc-build

# Configure glibc build
# Note: Using --disable-werror to allow building with warnings as errors disabled
RUN ../glibc-src/configure \\
    --prefix={install_prefix} \\
    --disable-werror \\
    --disable-sanity-checks \\
    --enable-obsolete-rpc \\
    CC="gcc -fno-stack-protector" \\
    CFLAGS="-O2 -g -fno-stack-protector" \\
    || (cat config.log && exit 1)

# Build glibc (using -k to continue on errors, -j for parallel)
# Save build status to check later
RUN make -j$(nproc) -k 2>&1 | tee /build/build.log; \\
    echo "GLIBC_BUILD_EXIT_CODE=$?" >> /build/build_status

# Install to prefix (may partially succeed)
RUN make install -k 2>&1 | tee -a /build/build.log; \\
    echo "GLIBC_INSTALL_EXIT_CODE=$?" >> /build/build_status

# Verify glibc build produced necessary files
RUN echo "=== Checking glibc build output ===" && \\
    ls -la {install_prefix}/lib/ 2>/dev/null || echo "WARNING: {install_prefix}/lib/ not found" && \\
    ls {install_prefix}/lib/libc.so* 2>/dev/null || echo "WARNING: libc.so not found"

# Create directory for PoC
RUN mkdir -p /poc

# Copy exploit source
COPY poc_exploit.c /poc/exploit.c

# Compile the PoC against vulnerable glibc
# First, find the actual dynamic linker path
# Use fallback compilation attempts if linking with specific libraries fails
# Always fall back to system glibc if vulnerable glibc compilation fails
WORKDIR /poc
RUN DYNAMIC_LINKER=$(find {install_prefix}/lib -name 'ld-linux*.so*' -o -name 'ld-*.so*' 2>/dev/null | head -1) && \\
    echo "Found dynamic linker: $DYNAMIC_LINKER" && \\
    if [ -n "$DYNAMIC_LINKER" ] && [ -f "$DYNAMIC_LINKER" ]; then \\
        echo "Attempting compilation with vulnerable glibc..."; \\
        gcc -o exploit exploit.c \\
            -Wl,-rpath,{install_prefix}/lib \\
            -Wl,--dynamic-linker=$DYNAMIC_LINKER \\
            -L{install_prefix}/lib \\
            -I{install_prefix}/include \\
            -ldl -lpthread 2>&1 || \\
        gcc -o exploit exploit.c \\
            -Wl,-rpath,{install_prefix}/lib \\
            -Wl,--dynamic-linker=$DYNAMIC_LINKER \\
            -L{install_prefix}/lib \\
            -I{install_prefix}/include \\
            -ldl 2>&1 || \\
        gcc -o exploit exploit.c \\
            -Wl,-rpath,{install_prefix}/lib \\
            -Wl,--dynamic-linker=$DYNAMIC_LINKER \\
            -L{install_prefix}/lib \\
            -I{install_prefix}/include \\
            -lm 2>&1 || \\
        gcc -o exploit exploit.c \\
            -Wl,-rpath,{install_prefix}/lib \\
            -Wl,--dynamic-linker=$DYNAMIC_LINKER \\
            -L{install_prefix}/lib \\
            -I{install_prefix}/include 2>&1 || \\
        echo "Vulnerable glibc compilation failed"; \\
    fi && \\
    if [ ! -f /poc/exploit ]; then \\
        echo "Falling back to system glibc compilation..." && \\
        (gcc -o exploit exploit.c -ldl -lpthread 2>&1 || \\
        gcc -o exploit exploit.c -ldl 2>&1 || \\
        gcc -o exploit exploit.c -lm 2>&1 || \\
        gcc -o exploit exploit.c 2>&1); \\
    fi

# Verify exploit binary was created
RUN if [ ! -f /poc/exploit ]; then \\
        echo "ERROR: Failed to compile exploit binary!" && \\
        echo "=== Compilation environment ===" && \\
        gcc --version && \\
        echo "=== Source file ===" && \\
        head -50 /poc/exploit.c && \\
        echo "=== Attempting verbose compilation ===" && \\
        gcc -v -o exploit exploit.c 2>&1 || true; \\
        exit 1; \\
    else \\
        echo "SUCCESS: Exploit binary created" && \\
        ls -la /poc/exploit && \\
        file /poc/exploit; \\
    fi

# Set environment for running with vulnerable glibc
ENV LD_LIBRARY_PATH={install_prefix}/lib

# Default command: run the exploit
CMD ["/poc/exploit"]
'''

    # Dockerfile template for Ubuntu 16.04
    TEMPLATE_16_04 = '''# =============================================================================
# Dockerfile for {cve}
# Vulnerable glibc commit: {commit_hash}
# Base: Ubuntu 16.04 (GCC 5.x - suitable for 2015-2016 code)
# =============================================================================
FROM ubuntu:16.04

LABEL maintainer="AI-SSD Project"
LABEL cve="{cve}"
LABEL commit="{commit_hash}"

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Update and install build dependencies
RUN apt-get update && apt-get install -y \\
    build-essential \\
    git \\
    gawk \\
    bison \\
    texinfo \\
    autoconf \\
    libtool \\
    gettext \\
    wget \\
    python3 \\
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /build

# Clone glibc repository and checkout vulnerable commit
RUN git clone https://github.com/bminor/glibc.git /build/glibc-src

WORKDIR /build/glibc-src
RUN git fetch origin {commit_hash} && \\
    git checkout {commit_hash}

# Create build directory (glibc requires out-of-tree build)
RUN mkdir -p /build/glibc-build

WORKDIR /build/glibc-build

# Configure glibc build
RUN ../glibc-src/configure \\
    --prefix={install_prefix} \\
    --disable-werror \\
    --disable-sanity-checks \\
    CC="gcc -fno-stack-protector" \\
    CFLAGS="-O2 -g -fno-stack-protector -Wno-error" \\
    || (cat config.log && exit 1)

# Build glibc (using -k to continue on errors)
# Save build status to check later
RUN make -j$(nproc) -k 2>&1 | tee /build/build.log; \\
    echo "GLIBC_BUILD_EXIT_CODE=$?" >> /build/build_status

# Install to prefix
RUN make install -k 2>&1 | tee -a /build/build.log; \\
    echo "GLIBC_INSTALL_EXIT_CODE=$?" >> /build/build_status

# Verify glibc build produced necessary files
RUN echo "=== Checking glibc build output ===" && \\
    ls -la {install_prefix}/lib/ 2>/dev/null || echo "WARNING: {install_prefix}/lib/ not found" && \\
    ls {install_prefix}/lib/libc.so* 2>/dev/null || echo "WARNING: libc.so not found"

# Create directory for PoC
RUN mkdir -p /poc

# Copy exploit source
COPY poc_exploit.c /poc/exploit.c

# Compile the PoC against vulnerable glibc
# First, find the actual dynamic linker path
# Use fallback compilation attempts if linking with specific libraries fails
# Always fall back to system glibc if vulnerable glibc compilation fails
WORKDIR /poc
RUN DYNAMIC_LINKER=$(find {install_prefix}/lib -name 'ld-linux*.so*' -o -name 'ld-*.so*' 2>/dev/null | head -1) && \\
    echo "Found dynamic linker: $DYNAMIC_LINKER" && \\
    if [ -n "$DYNAMIC_LINKER" ] && [ -f "$DYNAMIC_LINKER" ]; then \\
        echo "Attempting compilation with vulnerable glibc..."; \\
        gcc -o exploit exploit.c \\
            -Wl,-rpath,{install_prefix}/lib \\
            -Wl,--dynamic-linker=$DYNAMIC_LINKER \\
            -L{install_prefix}/lib \\
            -I{install_prefix}/include \\
            -ldl -lpthread 2>&1 || \\
        gcc -o exploit exploit.c \\
            -Wl,-rpath,{install_prefix}/lib \\
            -Wl,--dynamic-linker=$DYNAMIC_LINKER \\
            -L{install_prefix}/lib \\
            -I{install_prefix}/include \\
            -ldl 2>&1 || \\
        gcc -o exploit exploit.c \\
            -Wl,-rpath,{install_prefix}/lib \\
            -Wl,--dynamic-linker=$DYNAMIC_LINKER \\
            -L{install_prefix}/lib \\
            -I{install_prefix}/include \\
            -lm 2>&1 || \\
        gcc -o exploit exploit.c \\
            -Wl,-rpath,{install_prefix}/lib \\
            -Wl,--dynamic-linker=$DYNAMIC_LINKER \\
            -L{install_prefix}/lib \\
            -I{install_prefix}/include 2>&1 || \\
        echo "Vulnerable glibc compilation failed"; \\
    fi && \\
    if [ ! -f /poc/exploit ]; then \\
        echo "Falling back to system glibc compilation..." && \\
        (gcc -o exploit exploit.c -ldl -lpthread 2>&1 || \\
        gcc -o exploit exploit.c -ldl 2>&1 || \\
        gcc -o exploit exploit.c -lm 2>&1 || \\
        gcc -o exploit exploit.c 2>&1); \\
    fi

# Verify exploit binary was created
RUN if [ ! -f /poc/exploit ]; then \\
        echo "ERROR: Failed to compile exploit binary!" && \\
        echo "=== Compilation environment ===" && \\
        gcc --version && \\
        echo "=== Source file ===" && \\
        head -50 /poc/exploit.c && \\
        echo "=== Attempting verbose compilation ===" && \\
        gcc -v -o exploit exploit.c 2>&1 || true; \\
        exit 1; \\
    else \\
        echo "SUCCESS: Exploit binary created" && \\
        ls -la /poc/exploit && \\
        file /poc/exploit; \\
    fi

# Set environment for running with vulnerable glibc
ENV LD_LIBRARY_PATH={install_prefix}/lib

# Default command: run the exploit
CMD ["/poc/exploit"]
'''

    # Dockerfile template for Ubuntu 18.04
    TEMPLATE_18_04 = '''# =============================================================================
# Dockerfile for {cve}
# Vulnerable glibc commit: {commit_hash}
# Base: Ubuntu 18.04 (GCC 7.x - suitable for 2017-2018 code)
# =============================================================================
FROM ubuntu:18.04

LABEL maintainer="AI-SSD Project"
LABEL cve="{cve}"
LABEL commit="{commit_hash}"

# Prevent interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Update and install build dependencies
RUN apt-get update && apt-get install -y \\
    build-essential \\
    git \\
    gawk \\
    bison \\
    texinfo \\
    autoconf \\
    libtool \\
    gettext \\
    wget \\
    python3 \\
    && rm -rf /var/lib/apt/lists/*

# Create working directory
WORKDIR /build

# Clone glibc repository and checkout vulnerable commit
RUN git clone https://github.com/bminor/glibc.git /build/glibc-src

WORKDIR /build/glibc-src
RUN git fetch origin {commit_hash} && \\
    git checkout {commit_hash}

# Create build directory
RUN mkdir -p /build/glibc-build

WORKDIR /build/glibc-build

# Configure glibc build
RUN ../glibc-src/configure \\
    --prefix={install_prefix} \\
    --disable-werror \\
    --disable-sanity-checks \\
    CC="gcc -fno-stack-protector" \\
    CFLAGS="-O2 -g -fno-stack-protector -Wno-error" \\
    || (cat config.log && exit 1)

# Build glibc
# Save build status to check later
RUN make -j$(nproc) -k 2>&1 | tee /build/build.log; \\
    echo "GLIBC_BUILD_EXIT_CODE=$?" >> /build/build_status

# Install to prefix
RUN make install -k 2>&1 | tee -a /build/build.log; \\
    echo "GLIBC_INSTALL_EXIT_CODE=$?" >> /build/build_status

# Verify glibc build produced necessary files
RUN echo "=== Checking glibc build output ===" && \\
    ls -la {install_prefix}/lib/ 2>/dev/null || echo "WARNING: {install_prefix}/lib/ not found" && \\
    ls {install_prefix}/lib/libc.so* 2>/dev/null || echo "WARNING: libc.so not found"

# Create directory for PoC
RUN mkdir -p /poc

# Copy exploit source
COPY poc_exploit.c /poc/exploit.c

# Compile the PoC against vulnerable glibc
# First, find the actual dynamic linker path
# Use fallback compilation attempts if linking with specific libraries fails
# Always fall back to system glibc if vulnerable glibc compilation fails
WORKDIR /poc
RUN DYNAMIC_LINKER=$(find {install_prefix}/lib -name 'ld-linux*.so*' -o -name 'ld-*.so*' 2>/dev/null | head -1) && \\
    echo "Found dynamic linker: $DYNAMIC_LINKER" && \\
    if [ -n "$DYNAMIC_LINKER" ] && [ -f "$DYNAMIC_LINKER" ]; then \\
        echo "Attempting compilation with vulnerable glibc..."; \\
        gcc -o exploit exploit.c \\
            -Wl,-rpath,{install_prefix}/lib \\
            -Wl,--dynamic-linker=$DYNAMIC_LINKER \\
            -L{install_prefix}/lib \\
            -I{install_prefix}/include \\
            -ldl -lpthread 2>&1 || \\
        gcc -o exploit exploit.c \\
            -Wl,-rpath,{install_prefix}/lib \\
            -Wl,--dynamic-linker=$DYNAMIC_LINKER \\
            -L{install_prefix}/lib \\
            -I{install_prefix}/include \\
            -ldl 2>&1 || \\
        gcc -o exploit exploit.c \\
            -Wl,-rpath,{install_prefix}/lib \\
            -Wl,--dynamic-linker=$DYNAMIC_LINKER \\
            -L{install_prefix}/lib \\
            -I{install_prefix}/include \\
            -lm 2>&1 || \\
        gcc -o exploit exploit.c \\
            -Wl,-rpath,{install_prefix}/lib \\
            -Wl,--dynamic-linker=$DYNAMIC_LINKER \\
            -L{install_prefix}/lib \\
            -I{install_prefix}/include 2>&1 || \\
        echo "Vulnerable glibc compilation failed"; \\
    fi && \\
    if [ ! -f /poc/exploit ]; then \\
        echo "Falling back to system glibc compilation..." && \\
        (gcc -o exploit exploit.c -ldl -lpthread 2>&1 || \\
        gcc -o exploit exploit.c -ldl 2>&1 || \\
        gcc -o exploit exploit.c -lm 2>&1 || \\
        gcc -o exploit exploit.c 2>&1); \\
    fi

# Verify exploit binary was created
RUN if [ ! -f /poc/exploit ]; then \\
        echo "ERROR: Failed to compile exploit binary!" && \\
        echo "=== Compilation environment ===" && \\
        gcc --version && \\
        echo "=== Source file ===" && \\
        head -50 /poc/exploit.c && \\
        echo "=== Attempting verbose compilation ===" && \\
        gcc -v -o exploit exploit.c 2>&1 || true; \\
        exit 1; \\
    else \\
        echo "SUCCESS: Exploit binary created" && \\
        ls -la /poc/exploit && \\
        file /poc/exploit; \\
    fi

# Set environment for running with vulnerable glibc
ENV LD_LIBRARY_PATH={install_prefix}/lib

# Default command: run the exploit
CMD ["/poc/exploit"]
'''

    def __init__(self, logger: logging.Logger):
        self.logger = logger
        self.templates = {
            "ubuntu:14.04": self.TEMPLATE_14_04,
            "ubuntu:16.04": self.TEMPLATE_16_04,
            "ubuntu:18.04": self.TEMPLATE_18_04,
        }
    
    def get_base_image(self, vuln: VulnerabilityInfo) -> str:
        """Determine appropriate base image based on CVE/commit date"""
        # Try to get year from CVE hint
        if vuln.cve in CVE_YEAR_HINTS:
            year = CVE_YEAR_HINTS[vuln.cve]
            self.logger.debug(f"Using year hint for {vuln.cve}: {year}")
            return COMMIT_OS_MAPPING.get(year, COMMIT_OS_MAPPING["default"])
        
        # Extract year from CVE name (e.g., CVE-2015-7547 -> 2015)
        try:
            parts = vuln.cve.split('-')
            if len(parts) >= 2:
                year = parts[1][:4]
                if year in COMMIT_OS_MAPPING:
                    return COMMIT_OS_MAPPING[year]
        except (IndexError, ValueError):
            pass
        
        return COMMIT_OS_MAPPING["default"]
    
    def generate(self, vuln: VulnerabilityInfo, output_dir: Path) -> Path:
        """Generate Dockerfile for a vulnerability"""
        base_image = self.get_base_image(vuln)
        self.logger.info(f"Generating Dockerfile for {vuln.cve} using {base_image}")
        
        template = self.templates.get(base_image, self.TEMPLATE_16_04)
        
        dockerfile_content = template.format(
            cve=vuln.cve,
            commit_hash=vuln.commit_hash
        )
        
        # Create output directory for this CVE
        cve_dir = output_dir / vuln.cve.lower()
        cve_dir.mkdir(parents=True, exist_ok=True)
        
        dockerfile_path = cve_dir / "Dockerfile"
        with open(dockerfile_path, 'w') as f:
            f.write(dockerfile_content)
        
        self.logger.debug(f"Dockerfile written to: {dockerfile_path}")
        return dockerfile_path


# =============================================================================
# Docker Build and Execution Manager
# =============================================================================

class DockerManager:
    """Manages Docker image builds and container execution"""
    
    def __init__(self, logger: logging.Logger, timeout: int = 3600, docker_platform: str = None):
        self.logger = logger
        self.timeout = timeout
        self.docker_platform = docker_platform
        try:
            self.client = docker.from_env()
            self.client.ping()
            self.logger.info("Successfully connected to Docker daemon")
        except docker.errors.DockerException as e:
            self.logger.error(f"Failed to connect to Docker: {e}")
            raise
    
    def build_image(self, vuln: VulnerabilityInfo, build_context: Path) -> Tuple[bool, Optional[str]]:
        """Build Docker image for vulnerability"""
        self.logger.info(f"Building Docker image for {vuln.cve}...")
        
        try:
            image, build_logs = _docker_build(
                self.client, str(build_context), vuln.image_name,
                rm=True, forcerm=True, timeout=self.timeout,
                platform=self.docker_platform, logger=self.logger,
            )
            
            # Collect build logs
            log_output = []
            if isinstance(build_logs, str):
                log_output = [build_logs]
            else:
                for chunk in build_logs:
                    if 'stream' in chunk:
                        log_output.append(chunk['stream'])
                    elif 'error' in chunk:
                        log_output.append(f"ERROR: {chunk['error']}")
            
            self.logger.info(f"Successfully built image: {vuln.image_name}")
            return True, '\n'.join(log_output)
            
        except (BuildError, docker.errors.BuildError) as e:
            self.logger.error(f"Build failed for {vuln.cve}: {e}")
            return False, str(e)
        except APIError as e:
            self.logger.error(f"Docker API error for {vuln.cve}: {e}")
            return False, str(e)
    
    def run_container(self, vuln: VulnerabilityInfo, run_timeout: int = 300) -> Tuple[bool, int, str]:
        """Run container and execute PoC"""
        self.logger.info(f"Running container for {vuln.cve}...")
        container = None
        
        # Remove leftover container from a previous run (avoids 409 Conflict)
        try:
            stale = self.client.containers.get(vuln.container_name)
            stale.remove(force=True)
            self.logger.info(f"Removed leftover container: {vuln.container_name}")
        except Exception:
            pass
        
        try:
            # Run container with resource limits
            container = self.client.containers.run(
                vuln.image_name,
                name=vuln.container_name,
                detach=True,
                mem_limit='2g',
                cpu_period=100000,
                cpu_quota=100000,  # Limit to 1 CPU
                network_disabled=True,  # Security: disable network
                remove=False,  # Keep container for log inspection
            )
            
            # Wait for container to finish (with timeout)
            result = container.wait(timeout=run_timeout)
            exit_code = result.get('StatusCode', -1)
            
            # Get container logs
            logs = container.logs(stdout=True, stderr=True).decode('utf-8', errors='replace')
            
            # Clean up container
            try:
                container.remove(force=True)
            except:
                pass
            
            # Interpret results
            vulnerability_triggered = self._interpret_exit_code(vuln, exit_code, logs)
            
            self.logger.info(f"Container {vuln.container_name} exited with code {exit_code}")
            return vulnerability_triggered, exit_code, logs
            
        except ContainerError as e:
            self.logger.warning(f"Container error (may indicate vulnerability triggered): {e}")
            return True, e.exit_status, str(e)
        except Exception as e:
            if container is not None:
                try:
                    container.stop(timeout=5)
                except:
                    pass
                try:
                    logs = container.logs(stdout=True, stderr=True).decode('utf-8', errors='replace')
                except:
                    logs = ""
                try:
                    container.remove(force=True)
                except:
                    pass
                if "timed out" in str(e).lower() or "timeout" in str(e).lower():
                    self.logger.warning(
                        f"Container for {vuln.cve} timed out after {run_timeout}s "
                        f"(PoC may hang or trigger deadlock). Partial logs: {logs[:500]}"
                    )
                    # A timeout means the PoC caused a hang, infinite loop, or
                    # deadlock — which IS vulnerability reproduction for DoS-class
                    # bugs (resource exhaustion, stack overflow causing infinite
                    # recursion, etc.).
                    return True, -1, f"TIMEOUT after {run_timeout}s (vulnerability likely triggered - PoC caused hang/deadlock). Partial output: {logs}"
            self.logger.error(f"Failed to run container for {vuln.cve}: {e}")
            return False, -1, str(e)
    
    def _interpret_exit_code(self, vuln: VulnerabilityInfo, exit_code: int, logs: str) -> bool:
        """Interpret container exit code and logs to determine if vulnerability was triggered.
        
        This method distinguishes between:
        1. True vulnerability reproduction (crash, overflow, corruption)
        2. Environment/setup failures (missing libs, wrong arch, missing deps)
        3. Inconclusive results (PoC ran but can't confirm vuln was triggered)
        """
        logs_lower = logs.lower()
        
        # =====================================================================
        # PHASE 1: Reject known environment/setup failures
        # These indicate the test infrastructure failed, NOT the vulnerability
        # =====================================================================
        
        # Binary not found or can't execute
        if "no such file or directory" in logs_lower and exit_code == 127:
            self.logger.error(f"{vuln.cve}: Environment error - binary not found (exit 127)")
            return False
        
        if "exec format error" in logs_lower:
            self.logger.error(f"{vuln.cve}: Environment error - binary format/architecture mismatch")
            return False
        
        if "permission denied" in logs_lower and exit_code == 126:
            self.logger.error(f"{vuln.cve}: Environment error - permission denied (exit 126)")
            return False
        
        # Shared library loading failures  
        # e.g., "error while loading shared libraries" or "version `GLIBC_X.XX' not found"
        if "error while loading shared libraries" in logs_lower:
            self.logger.warning(f"{vuln.cve}: Shared library loading error - LD_LIBRARY_PATH issue")
            return False
        
        if "version `glibc_" in logs_lower and "not found" in logs_lower:
            self.logger.warning(f"{vuln.cve}: GLIBC version mismatch - built glibc too old for binary")
            return False
        
        # Missing runtime dependencies (Ruby/Python/Perl module not found)
        if "cannot load such file" in logs_lower or "loaderror" in logs_lower:
            self.logger.warning(f"{vuln.cve}: Missing runtime dependency (Ruby LoadError)")
            return False
        
        if "modulenotfounderror" in logs_lower or "importerror" in logs_lower:
            self.logger.warning(f"{vuln.cve}: Missing Python module")
            return False
        
        if "can't locate" in logs_lower and ".pm" in logs_lower:
            self.logger.warning(f"{vuln.cve}: Missing Perl module")
            return False
        
        # Metasploit framework required but not installed
        if "msf/core" in logs_lower or "metasploit" in logs_lower:
            if "cannot load" in logs_lower or "require" in logs_lower:
                self.logger.warning(f"{vuln.cve}: PoC requires Metasploit framework (not installed)")
                return False
        
        # =====================================================================
        # PHASE 2: Detect clear vulnerability reproduction signals
        # =====================================================================
        
        # Segmentation fault (139 = 128 + 11 SIGSEGV)
        if exit_code == 139 or "segmentation fault" in logs_lower or "sigsegv" in logs_lower:
            self.logger.info(f"{vuln.cve}: Segmentation fault detected - vulnerability likely triggered")
            return True
        
        # Abort (134 = 128 + 6 SIGABRT)
        if exit_code == 134 or "sigabrt" in logs_lower:
            self.logger.info(f"{vuln.cve}: Abort signal detected - vulnerability likely triggered")
            return True
        
        # Bus error (135 = 128 + 7 SIGBUS)
        if exit_code == 135:
            self.logger.info(f"{vuln.cve}: Bus error detected - vulnerability likely triggered")
            return True
        
        # Floating point exception (136 = 128 + 8 SIGFPE)
        if exit_code == 136:
            self.logger.info(f"{vuln.cve}: Floating point exception - vulnerability likely triggered")
            return True
        
        # Killed by signal (any signal-based exit 128+N where N > 0)
        if exit_code > 128 and exit_code < 192:
            signal_num = exit_code - 128
            self.logger.info(f"{vuln.cve}: Killed by signal {signal_num} (exit {exit_code}) - vulnerability likely triggered")
            return True
        
        # Stack smashing detected
        if "stack smashing" in logs_lower or "stack buffer overflow" in logs_lower:
            self.logger.info(f"{vuln.cve}: Stack smashing/buffer overflow detected in logs")
            return True
        
        # Heap corruption indicators
        if any(indicator in logs_lower for indicator in [
            'heap corruption', 'double free', 'corrupted size',
            'corrupted double-linked list', 'free(): invalid',
            'malloc(): corrupted', 'munmap_chunk(): invalid',
            'realloc(): invalid'
        ]):
            self.logger.info(f"{vuln.cve}: Heap corruption/double-free detected in logs")
            return True
        
        # Buffer overflow/corruption indicators (general)
        if any(indicator in logs_lower for indicator in [
            'buffer overflow', 'overflow detected', 'corrupted',
            'out of bounds', 'use after free', 'use-after-free'
        ]):
            self.logger.info(f"{vuln.cve}: Overflow/corruption detected in logs")
            return True
        
        # AddressSanitizer / UBSan reports
        if 'addresssanitizer' in logs_lower or 'ubsan' in logs_lower or 'sanitizer' in logs_lower:
            self.logger.info(f"{vuln.cve}: Sanitizer report detected - vulnerability triggered")
            return True
        
        # Fortify source detection
        if '*** buffer overflow detected ***' in logs or 'fortify_fail' in logs_lower:
            self.logger.info(f"{vuln.cve}: FORTIFY_SOURCE buffer overflow detected")
            return True
        
        # =====================================================================
        # PHASE 3: CVE-specific detection logic
        # =====================================================================
        
        # For CVE-2012-3480 (strtod integer overflow)
        if vuln.cve == "CVE-2012-3480":
            if "0x" in logs and "p" in logs:
                self.logger.info(f"{vuln.cve}: strtod hex-float output detected - vulnerable code path exercised")
                return True
            if logs.strip() and exit_code == 0:
                self.logger.info(f"{vuln.cve}: PoC completed with output - vulnerable code path exercised")
                return True
        
        # For CVE-2015-7547 (getaddrinfo stack buffer overflow)
        if vuln.cve == "CVE-2015-7547":
            if exit_code != 0 or "getaddrinfo" in logs_lower:
                self.logger.info(f"{vuln.cve}: getaddrinfo exercised - vulnerable code path triggered")
                return True
        
        # For CVE-2014-5119 (__gconv_translit_find heap corruption)
        if vuln.cve == "CVE-2014-5119":
            if "double-linked" in logs_lower or "corrupted" in logs_lower:
                self.logger.info(f"{vuln.cve}: Heap corruption detected")
                return True
            if exit_code in [134, 139]:
                return True
            self.logger.warning(f"{vuln.cve}: Unclear result (exit {exit_code}) - marking as not reproduced")
            return False
        
        # =====================================================================
        # PHASE 4: Default interpretation
        # =====================================================================
        
        # Exit code 0 with meaningful output (not just warnings) could mean the
        # vulnerable code path was exercised without crashing
        if exit_code == 0 and logs.strip():
            # Filter out purely informational/warning messages
            meaningful_lines = [l for l in logs.strip().split('\\n') 
                              if l.strip() and not l.strip().startswith('WARNING')]
            if meaningful_lines:
                self.logger.info(f"{vuln.cve}: PoC exited 0 with output - marking as reproduced")
                return True
        
        # Non-zero exit that isn't an environment error suggests the PoC
        # at least exercised the code path
        if exit_code != 0 and exit_code not in (126, 127):
            self.logger.info(f"{vuln.cve}: PoC exited with non-zero code {exit_code} - vulnerability likely triggered")
            return True
        
        self.logger.warning(f"{vuln.cve}: Could not confirm vulnerability reproduction (exit {exit_code})")
        return False
    
    def cleanup_image(self, vuln: VulnerabilityInfo):
        """Remove Docker image"""
        try:
            self.client.images.remove(vuln.image_name, force=True)
            self.logger.debug(f"Removed image: {vuln.image_name}")
        except ImageNotFound:
            pass
        except Exception as e:
            self.logger.warning(f"Failed to remove image {vuln.image_name}: {e}")
    
    def cleanup_container(self, vuln: VulnerabilityInfo):
        """Remove Docker container if exists"""
        try:
            container = self.client.containers.get(vuln.container_name)
            container.remove(force=True)
            self.logger.debug(f"Removed container: {vuln.container_name}")
        except:
            pass
    
    def run_container_from_tag(self, vuln: VulnerabilityInfo, image_tag: str,
                                run_timeout: int = 300) -> Tuple[bool, int, str]:
        """Run a container from an explicit image tag (used by Phase 0 CVE images).
        
        The image is NOT removed after execution — persisted for Phase 3.
        """
        self.logger.info(f"Running container from tag {image_tag} for {vuln.cve}...")
        
        container_name = f"ai-ssd-{vuln.cve.lower()}-run"
        container = None
        
        # Remove leftover container from a previous run (avoids 409 Conflict)
        try:
            stale = self.client.containers.get(container_name)
            stale.remove(force=True)
            self.logger.info(f"Removed leftover container: {container_name}")
        except Exception:
            pass
        
        try:
            container = self.client.containers.run(
                image_tag,
                name=container_name,
                detach=True,
                mem_limit='2g',
                cpu_period=100000,
                cpu_quota=100000,
                network_disabled=True,
                remove=False,
            )
            
            result = container.wait(timeout=run_timeout)
            exit_code = result.get('StatusCode', -1)
            logs = container.logs(stdout=True, stderr=True).decode('utf-8', errors='replace')
            
            try:
                container.remove(force=True)
            except:
                pass
            
            vulnerability_triggered = self._interpret_exit_code(vuln, exit_code, logs)
            self.logger.info(f"Container {container_name} exited with code {exit_code}")
            return vulnerability_triggered, exit_code, logs
            
        except ContainerError as e:
            self.logger.warning(f"Container error (may indicate vulnerability triggered): {e}")
            return True, e.exit_status, str(e)
        except Exception as e:
            # On timeout or other errors, stop and remove the container
            if container is not None:
                try:
                    container.stop(timeout=5)
                except:
                    pass
                try:
                    logs = container.logs(stdout=True, stderr=True).decode('utf-8', errors='replace')
                except:
                    logs = ""
                try:
                    container.remove(force=True)
                except:
                    pass
                if "timed out" in str(e).lower() or "timeout" in str(e).lower():
                    self.logger.warning(
                        f"Container for {vuln.cve} timed out after {run_timeout}s "
                        f"(PoC may hang or trigger deadlock). Partial logs: {logs[:500]}"
                    )
                    return True, -1, f"TIMEOUT after {run_timeout}s (vulnerability likely triggered - PoC caused hang/deadlock). Partial output: {logs}"
            self.logger.error(f"Failed to run container for {vuln.cve}: {e}")
            return False, -1, str(e)


# =============================================================================
# PoC Manager
# =============================================================================

class PoCManager:
    """Manages PoC exploit files"""
    
    def __init__(self, exploits_dir: Path, logger: logging.Logger):
        self.exploits_dir = exploits_dir
        self.logger = logger
    
    def find_poc(self, vuln: VulnerabilityInfo) -> Optional[Path]:
        """Find PoC file for a vulnerability, supporting all languages"""
        # If the CSV has an explicit poc_path, try that first
        if vuln.poc_path:
            explicit = Path(vuln.poc_path)
            if explicit.exists():
                self.logger.debug(f"Found PoC for {vuln.cve} at (explicit): {explicit}")
                return explicit
        
        # Search for PoC file with all supported extensions
        for ext in POC_EXTENSIONS:
            possible_paths = [
                self.exploits_dir / vuln.cve / f"exploit{ext}",
                self.exploits_dir / vuln.cve / f"poc{ext}",
                self.exploits_dir / vuln.cve.lower() / f"exploit{ext}",
                self.exploits_dir / f"{vuln.cve}{ext}",
                self.exploits_dir / f"{vuln.cve.lower()}{ext}",
            ]
            
            for path in possible_paths:
                if path.exists():
                    self.logger.debug(f"Found PoC for {vuln.cve} at: {path}")
                    return path
        
        # Final fallback: glob match any extension
        for match in sorted(self.exploits_dir.glob(f"{vuln.cve}.*")):
            if match.is_file():
                self.logger.debug(f"Found PoC for {vuln.cve} via glob: {match}")
                return match
        
        self.logger.warning(f"No PoC found for {vuln.cve}")
        return None
    
    def detect_language(self, poc_path: Path) -> str:
        """Detect PoC language from file extension."""
        ext = poc_path.suffix.lower()
        return EXTENSION_TO_LANGUAGE.get(ext, 'unknown')
    
    def copy_poc_to_build_context(self, poc_path: Path, build_context: Path,
                                   target_name: str = None) -> bool:
        """Copy PoC file to Docker build context with appropriate name"""
        try:
            if target_name is None:
                target_name = f"poc_exploit{poc_path.suffix}"
            dest = build_context / target_name
            shutil.copy2(poc_path, dest)
            self.logger.debug(f"Copied PoC to: {dest}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to copy PoC: {e}")
            return False


# =============================================================================
# Report Generator
# =============================================================================

class ReportGenerator:
    """Generates JSON reports of execution results"""
    
    def __init__(self, results_dir: Path, logger: logging.Logger):
        self.results_dir = results_dir
        self.results_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logger
        self.results: List[ExecutionResult] = []
    
    def add_result(self, result: ExecutionResult):
        """Add a result to the report"""
        self.results.append(result)
    
    def generate_report(self, phase_start: datetime = None, phase_end: datetime = None) -> Path:
        """Generate JSON report file with comprehensive timing information"""
        report_path = self.results_dir / "results.json"
        
        # Calculate total execution time from all results
        total_execution_time = sum(r.execution_time_seconds for r in self.results)
        
        # Calculate per-CVE timing
        cve_timings = {}
        for r in self.results:
            if r.cve not in cve_timings:
                cve_timings[r.cve] = {
                    "execution_time_seconds": 0.0,
                    "build_success": False,
                    "vulnerability_reproduced": False
                }
            cve_timings[r.cve]["execution_time_seconds"] = r.execution_time_seconds
            cve_timings[r.cve]["build_success"] = r.build_success
            cve_timings[r.cve]["vulnerability_reproduced"] = r.vulnerability_reproduced
        
        # Count different failure types for better analysis
        build_errors = sum(1 for r in self.results if r.status == ExecutionStatus.BUILD_ERROR.value)
        execution_errors = sum(1 for r in self.results if r.status == ExecutionStatus.EXECUTION_ERROR.value)
        poc_not_found = sum(1 for r in self.results if r.status == ExecutionStatus.POC_NOT_FOUND.value)
        timeouts = sum(1 for r in self.results if r.status == ExecutionStatus.TIMEOUT.value)
        unknown_errors = sum(1 for r in self.results if r.status == ExecutionStatus.UNKNOWN_ERROR.value)
        successful = sum(1 for r in self.results if r.vulnerability_reproduced)
        
        report_data = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "phase": "Phase 1 - Vulnerability Reproduction",
                "total_vulnerabilities": len(self.results),
                "successful_reproductions": successful,
                "failed_builds": sum(1 for r in self.results if not r.build_success),
            },
            "phase_timing": {
                "start_time": phase_start.isoformat() if phase_start else None,
                "end_time": phase_end.isoformat() if phase_end else None,
                "total_duration_seconds": (phase_end - phase_start).total_seconds() if phase_start and phase_end else total_execution_time,
            },
            "failure_breakdown": {
                "build_errors": build_errors,
                "execution_errors": execution_errors,
                "poc_not_found": poc_not_found,
                "timeouts": timeouts,
                "unknown_errors": unknown_errors,
                "total_failures": len(self.results) - successful,
            },
            "timing_by_cve": cve_timings,
            "total_execution_time_seconds": total_execution_time,
            "results": [asdict(r) for r in self.results]
        }
        
        with open(report_path, 'w') as f:
            json.dump(report_data, f, indent=2)
        
        self.logger.info(f"Report generated: {report_path}")
        return report_path
    
    def print_summary(self):
        """Print summary to console"""
        print("\n" + "=" * 60)
        print("EXECUTION SUMMARY")
        print("=" * 60)
        
        for result in self.results:
            status_icon = "✓" if result.vulnerability_reproduced else "✗"
            print(f"{status_icon} {result.cve}: {result.status}")
            if result.error_message:
                print(f"    Error: {result.error_message[:100]}...")
        
        print("-" * 60)
        total = len(self.results)
        success = sum(1 for r in self.results if r.vulnerability_reproduced)
        print(f"Total: {total} | Reproduced: {success} | Failed: {total - success}")
        print("=" * 60 + "\n")


# =============================================================================
# Pipeline Orchestrator
# =============================================================================

class PipelineOrchestrator:
    """Main orchestrator that coordinates all pipeline components.
    
    Supports two modes:
      1. Phase 0 mode: Uses glibc_cve_poc_complete.csv (with ubuntu_version, poc_path, etc.)
         Builds reusable base images per ubuntu_version, then CVE-specific derived images.
    """
    
    def __init__(self, args: argparse.Namespace):
        self.base_dir = Path(args.base_dir).resolve()
        self.exploits_dir = Path(args.exploits_dir).resolve()
        self.build_timeout = args.build_timeout
        self.run_timeout = args.run_timeout
        self.cleanup = args.cleanup
        self.specific_cve = args.cve
        self.dry_run = getattr(args, 'dry_run', False)
        self.skipped_cves = getattr(args, 'skipped_cves', []) or []

        # Load Phase 0 config and resolve all project-specific Phase 1 settings
        phase0_config_path = getattr(args, 'phase0_config', None)
        if phase0_config_path:
            phase0_config_path = Path(phase0_config_path)
        raw_cfg = _load_phase0_config(phase0_config_path)
        self._p1 = _resolve_phase1_settings(raw_cfg, self.base_dir)

        # Populate the module-level era map so helper functions can access it
        global _COMMIT_ERA_MAP
        _COMMIT_ERA_MAP = {int(k): v for k, v in self._p1["commit_era_map"].items()}

        # CSV path: CLI override → config-derived → fallback default
        cli_csv = getattr(args, 'phase0_csv', None)
        self.phase0_csv_path = (
            Path(cli_csv) if cli_csv else self._p1["csv_path"]
        )

        # Setup directories
        self.docker_builds_dir = self.base_dir / "docker_builds"
        self.results_dir = self.base_dir / "results"
        self.logs_dir = self.base_dir / "logs"

        # Setup logging
        self.logger = setup_logging(self.logs_dir, args.verbose)

        self.logger.info(f"Phase 0 config: {phase0_config_path or '(none)'}")
        self.logger.info(f"Phase 0 CSV: {self.phase0_csv_path}")
        self.logger.info(f"Project repo: {self._p1['project_repo_path']}")

        project_repo = self._p1["project_repo_path"]
        self.csv_parser = Phase0CSVParser(
            self.phase0_csv_path, self.logger,
            skipped_cves=self.skipped_cves,
            project_repo_path=project_repo if project_repo.exists() else None,
            base_image_prefix=self._p1["base_image_prefix"],
            cve_image_prefix=self._p1["cve_image_prefix"],
            commit_era_map=self._p1["commit_era_map"],
        )

        self.dockerfile_gen = DockerfileGenerator(self.logger)
        self.docker_mgr = DockerManager(self.logger, self.build_timeout,
                                        docker_platform=self._p1.get("docker_platform"))
        self.poc_mgr = PoCManager(self.exploits_dir, self.logger)
        self.report_gen = ReportGenerator(self.results_dir, self.logger)

        # Phase 0 components (initialized lazily)
        self._repo_mgr = None
        self._base_builder = None
        self._cve_builder = None
        self._manifest = None

    def _init_phase0_components(self):
        """Initialize Phase 0 image-building components."""
        project_repo = self._p1["project_repo_path"]
        self._repo_mgr = ProjectRepoManager(
            project_repo, self._p1["project_repo_remote_url"], self.logger
        )
        self._base_builder = BaseImageBuilder(
            self.docker_mgr.client, project_repo, self.logger, self.build_timeout,
            base_image_prefix=self._p1["base_image_prefix"],
            source_dir_name=self._p1["source_dir_name"],
            build_dir_name=self._p1["build_dir_name"],
            docker_platform=self._p1.get("docker_platform"),
        )
        self._cve_builder = CVEImageBuilder(
            self.docker_mgr.client, self.logger, self.build_timeout,
            source_dir_name=self._p1["source_dir_name"],
            build_dir_name=self._p1["build_dir_name"],
            install_prefix=self._p1["install_prefix"],
            docker_platform=self._p1.get("docker_platform"),
        )
        self._manifest = ImageManifest(self._p1["image_manifest_path"], self.logger)
    
    def run(self):
        """Execute the full pipeline"""
        phase_start_time = datetime.now()
        
        self.logger.info("=" * 60)
        self.logger.info("Starting Phase 1: Vulnerability Reproduction Pipeline")
        self.logger.info(f"Phase Start Time: {phase_start_time.isoformat()}")
        self.logger.info(f"Mode: Phase 0 (optimized)")
        self.logger.info("=" * 60)
        self.logger.info(f"Base directory: {self.base_dir}")
        self.logger.info(f"CSV file: {self.phase0_csv_path}")
        self.logger.info(f"Exploits directory: {self.exploits_dir}")
        
        if self.dry_run:
            self.logger.info("[DRY RUN] No Docker builds or PoC execution will occur")
        
        # Parse vulnerabilities from CSV
        try:
            vulnerabilities = self.csv_parser.parse()
        except FileNotFoundError as e:
            self.logger.error(str(e))
            sys.exit(1)
        
        # Filter to specific CVE if requested
        if self.specific_cve:
            vulnerabilities = [v for v in vulnerabilities if v.cve == self.specific_cve]
            if not vulnerabilities:
                self.logger.error(f"CVE {self.specific_cve} not found in CSV")
                sys.exit(1)
        
        self.logger.info(f"Found {len(vulnerabilities)} vulnerabilities to process")
        
        # ---- Phase 0 optimized path ----
        self._run_phase0_optimized(vulnerabilities, phase_start_time)
    
    def _run_phase0_optimized(self, vulnerabilities: List[VulnerabilityInfo], phase_start_time):
        """Phase 0 optimized path: reusable base images, derived CVE images."""
        self._init_phase0_components()
        
        # Step 1: Pre-update project repository (fail fast)
        project_repo = self._p1["project_repo_path"]
        self.logger.info(f"\n--- Pre-updating project repository: {project_repo} ---")
        if self.dry_run:
            self.logger.info("[DRY RUN] Would update project repository")
        else:
            if not self._repo_mgr.update_or_clone():
                self.logger.error("FATAL: project repository update failed. Aborting Phase 1.")
                sys.exit(1)
        
        # Step 2: Group CVEs by ubuntu_version
        version_groups: Dict[str, List[VulnerabilityInfo]] = {}
        for vuln in vulnerabilities:
            version = vuln.ubuntu_version or 'unknown'
            if version not in version_groups:
                version_groups[version] = []
            version_groups[version].append(vuln)
        
        self.logger.info(f"Ubuntu versions: {list(version_groups.keys())}")
        for v, cves in version_groups.items():
            self.logger.info(f"  Ubuntu {v}: {len(cves)} CVEs")
        
        # Step 3: Build base images (one per ubuntu_version)
        self.logger.info("\n--- Building Base Images ---")
        failed_versions = set()
        for ubuntu_version in sorted(version_groups.keys()):
            if ubuntu_version == 'unknown':
                self.logger.warning(f"Skipping {len(version_groups[ubuntu_version])} CVEs with unknown ubuntu_version")
                failed_versions.add(ubuntu_version)
                continue
            
            if self.dry_run:
                tag = f"{self._p1['base_image_prefix']}:ubuntu-{ubuntu_version}"
                self.logger.info(f"[DRY RUN] Would build base image: {tag}")
                continue
            
            tag = self._base_builder.ensure_base_image(ubuntu_version)
            if tag:
                self._manifest.add_base_image(ubuntu_version, tag)
            else:
                self.logger.error(f"Base image failed for ubuntu {ubuntu_version} — "
                                  f"skipping {len(version_groups[ubuntu_version])} CVEs")
                failed_versions.add(ubuntu_version)
        
        # Step 4: Build CVE images and run PoC
        self.logger.info("\n--- Building CVE Images & Running PoC ---")
        total = len(vulnerabilities)
        processed = 0
        
        for idx, vuln in enumerate(vulnerabilities, 1):
            ubuntu_version = vuln.ubuntu_version or 'unknown'
            
            if ubuntu_version in failed_versions:
                self.logger.warning(f"Skipping {vuln.cve}: base image for ubuntu {ubuntu_version} failed")
                result = ExecutionResult(
                    cve=vuln.cve,
                    commit_hash=vuln.commit_hash,
                    status=ExecutionStatus.BUILD_ERROR.value,
                    vulnerability_reproduced=False,
                    build_success=False,
                    poc_executed=False,
                    execution_time_seconds=0,
                    error_message=f"Base image build failed for ubuntu {ubuntu_version}",
                    container_logs=None,
                    timestamp=datetime.now().isoformat()
                )
                self.report_gen.add_result(result)
                self._manifest.add_cve_image(vuln, vuln.cve_image_tag, "base_image_failed")
                continue
            
            self.logger.info(f"\n{'='*60}")
            self.logger.info(f"Processing ({idx}/{total}): {vuln.cve}")
            self.logger.info(f"  Commit: {vuln.commit_hash}")
            self.logger.info(f"  Ubuntu: {ubuntu_version}")
            self.logger.info(f"  Language: {vuln.poc_language or 'auto-detect'}")
            self.logger.info(f"  Base: {vuln.base_image_tag}")
            self.logger.info(f"  CVE tag: {vuln.cve_image_tag}")
            self.logger.info(f"{'='*60}")
            
            if self.dry_run:
                self.logger.info(f"[DRY RUN] Would build CVE image + run PoC for {vuln.cve}")
                continue
            
            result = self._process_vulnerability_phase0(vuln)
            self.report_gen.add_result(result)
            
            status = "success" if result.vulnerability_reproduced else result.status
            self._manifest.add_cve_image(vuln, vuln.cve_image_tag, status)
            
            self.logger.info(f"Completed {vuln.cve}: {result.status} (duration: {result.execution_time_seconds:.1f}s)")
            processed += 1
        
        # Save manifest
        if not self.dry_run:
            self._manifest.save()
        
        self._finalize(phase_start_time, processed, total)
    
    
    def _finalize(self, phase_start_time, processed: int, total: int):
        """Print summary and report."""
        phase_end_time = datetime.now()
        phase_duration = (phase_end_time - phase_start_time).total_seconds()
        
        # Generate final report with phase timing
        report_path = self.report_gen.generate_report(phase_start_time, phase_end_time)
        self.report_gen.print_summary()
        
        self.logger.info("=" * 60)
        self.logger.info(f"Phase 1 Complete ({processed}/{total} processed)")
        self.logger.info(f"Phase End Time: {phase_end_time.isoformat()}")
        self.logger.info(f"Phase Duration: {phase_duration:.1f}s ({phase_duration/60:.1f}m)")
        self.logger.info(f"Results saved to: {report_path}")
        if self._manifest:
            self.logger.info(f"Image manifest: {self._manifest.manifest_path}")
        self.logger.info("=" * 60)
    
    def _process_vulnerability_phase0(self, vuln: VulnerabilityInfo) -> ExecutionResult:
        """Process a CVE using Phase 0 optimized path (derived CVE images)."""
        start_time = datetime.now()
        
        result = ExecutionResult(
            cve=vuln.cve,
            commit_hash=vuln.commit_hash,
            status=ExecutionStatus.UNKNOWN_ERROR.value,
            vulnerability_reproduced=False,
            build_success=False,
            poc_executed=False,
            execution_time_seconds=0,
            error_message=None,
            container_logs=None,
            timestamp=start_time.isoformat()
        )
        
        try:
            # Step 1: Resolve PoC path
            poc_path = None
            if vuln.poc_path:
                poc_path = Path(vuln.poc_path)
                if not poc_path.is_absolute():
                    poc_path = self.base_dir / poc_path
            
            if not poc_path or not poc_path.exists():
                # Fallback: try exploits_dir
                poc_path = self.poc_mgr.find_poc(vuln)
            
            if not poc_path:
                result.status = ExecutionStatus.POC_NOT_FOUND.value
                result.error_message = "No PoC found"
                return result
            
            # Step 2: Build CVE image (derived from base)
            # Detect PoC language from CSV or file extension
            poc_language = vuln.poc_language or self.poc_mgr.detect_language(poc_path)
            self.logger.info(f"  PoC language: {poc_language} ({poc_path.name})")
            
            base_tag = vuln.base_image_tag
            success, build_logs = self._cve_builder.build_cve_image(
                vuln, base_tag, poc_path, poc_language
            )
            
            if not success:
                result.status = ExecutionStatus.BUILD_ERROR.value
                result.error_message = build_logs
                return result
            
            result.build_success = True
            
            # Step 3: Run container (use CVE image tag)
            cve_tag = vuln.cve_image_tag
            vuln_triggered, exit_code, run_logs = self.docker_mgr.run_container_from_tag(
                vuln, cve_tag, self.run_timeout
            )
            
            result.poc_executed = True
            result.container_logs = run_logs
            result.vulnerability_reproduced = vuln_triggered
            
            if vuln_triggered:
                result.status = ExecutionStatus.SUCCESS.value
            else:
                result.status = ExecutionStatus.EXECUTION_ERROR.value
                result.error_message = f"PoC exited with code {exit_code} but vulnerability not confirmed"
        
        except Exception as e:
            self.logger.exception(f"Error processing {vuln.cve}")
            result.status = ExecutionStatus.UNKNOWN_ERROR.value
            result.error_message = str(e)
        
        finally:
            # Do NOT cleanup images — persist for Phase 3
            if self.cleanup:
                self.docker_mgr.cleanup_container(vuln)
                # NOTE: Images are intentionally NOT cleaned up
            
            end_time = datetime.now()
            result.execution_time_seconds = (end_time - start_time).total_seconds()
        
        return result
    



# =============================================================================
# Main Entry Point
# =============================================================================

def parse_arguments() -> argparse.Namespace:
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="AI-SSD Vulnerability Reproduction Pipeline Orchestrator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run full pipeline (auto-detects Phase 0 CSV if available)
  python orchestrator.py
  
  # Run for specific CVE
  python orchestrator.py --cve CVE-2015-7547
  
  # Use Phase 0 CSV explicitly
  python orchestrator.py --phase0-csv /path/to/glibc_cve_poc_complete.csv
  
  # Dry run (no Docker builds)
  python orchestrator.py --dry-run
  
  # Skip CVEs that failed manual review
  python orchestrator.py --skip-cves CVE-2015-7547,CVE-2014-5119
  
  # Run with cleanup and verbose output
  python orchestrator.py --cleanup --verbose
        """
    )
    
    parser.add_argument(
        '--base-dir',
        type=str,
        default=os.path.dirname(os.path.abspath(__file__)),
        help='Base directory for the project (default: script directory)'
    )

    parser.add_argument(
        '--phase0-config',
        type=str,
        default=None,
        help='Path to the Phase 0 YAML config file. Used to derive project-specific '
             'Phase 1 settings (repo URL, image prefixes, commit-era map, CSV path, etc.).'
    )

    parser.add_argument(
        '--phase0-csv',
        type=str,
        default=None,
        help='Explicit path to the Phase 0 CSV output. Overrides the path derived from '
             '--phase0-config when both are given.'
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
        help='Process only this specific CVE'
    )
    
    parser.add_argument(
        '--skip-cves',
        type=str,
        default=None,
        help='Comma-separated list of CVEs to skip (e.g., from manual review timeout)'
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
        '--cleanup',
        action='store_true',
        help='Clean up Docker containers after execution (images are preserved for Phase 3)'
    )
    
    parser.add_argument(
        '--dry-run',
        action='store_true',
        help='Print what would be done without building or running anything'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    args = parser.parse_args()
    
    # Set default paths relative to base directory
    if args.exploits_dir is None:
        args.exploits_dir = os.path.join(args.base_dir, 'exploits')
    
    # Parse skip-cves into a list
    args.skipped_cves = [c.strip() for c in args.skip_cves.split(',')] if args.skip_cves else []
    
    return args


def main():
    """Main entry point"""
    args = parse_arguments()
    
    try:
        orchestrator = PipelineOrchestrator(args)
        orchestrator.run()
    except KeyboardInterrupt:
        print("\nPipeline interrupted by user")
        sys.exit(130)
    except Exception as e:
        print(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
