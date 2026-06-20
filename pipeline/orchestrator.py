#!/usr/bin/env python3
# =============================================================================
# AI-SSD Project - Pipeline Orchestrator
# Phase 1: Vulnerability ID & Setup
# =============================================================================
# This script automates the creation and execution of reproduction environments
# for glibc vulnerabilities listed in glibc_cve_poc_complete.csv
# =============================================================================

import os
import re
import sys
import csv
import json
import shutil
import logging
import argparse
import subprocess
import tempfile
import hashlib

# Increase CSV field size limit to handle large PoC content fields
csv.field_size_limit(sys.maxsize)
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum
from poc_analyzer import PoCAnalyzer

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

# Unprivileged account that runs the PoC inside the container. Privilege-
# escalation exploits must actually escalate from a non-root user rather than
# short-circuiting ("already root") — running them as root yields a meaningless
# baseline. Created in the base image (best-effort); the run wrapper drops to it
# for the exploit execution only (setup still runs as root).
_POC_RUN_USER = "ssduser"

# Recipe version for the base image. Bump this whenever BASE_DOCKERFILE changes
# in a way that must invalidate already-built base images (e.g. adding the
# unprivileged user or extra locales) — ensure_base_image rebuilds when the
# baked ai-ssd.recipe_version label differs from this value. (CVE images have
# their own WRAPPER_CONTRACT_VERSION fingerprint.)
# v2: add unprivileged ssduser + broad locale set.
# v3: add 32-bit (multilib + libc6-dev-i386) toolchain for the i386 arch fallback.
_BASE_RECIPE_VERSION = "v4"

# Security options for PoC containers. The default Docker seccomp/AppArmor
# profiles block syscalls some exploits legitimately need — notably
# unshare(CLONE_NEWUSER) for unprivileged user namespaces (observed:
# CVE-2018-1000001's PoC printed "USERNS clone failed: Operation not
# permitted" when run as the non-root user). Relaxing them lets such PoCs
# exercise their real code path. Safe here: containers run known exploits with
# the network disabled and are discarded after the run. (Requires the host to
# permit unprivileged user namespaces, e.g. kernel.unprivileged_userns_clone=1,
# which is the default on modern Ubuntu.)
_CONTAINER_SECURITY_OPT = ["seccomp=unconfined", "apparmor=unconfined"]

# PoCs that build their own namespaces (mount/user/pid) need more than the
# relaxed seccomp/apparmor profile: on a host that restricts unprivileged user
# namespaces (e.g. Ubuntu 24's kernel.apparmor_restrict_unprivileged_userns=1,
# or kernel.unprivileged_userns_clone=0) the unshare(CLONE_NEWUSER) call fails
# and the exploit aborts before reaching the vulnerable code path (observed:
# CVE-2018-1000001's realpath LPE printed the "unprivileged_userns_clone must be
# 1" CAVEAT and asserted). For such PoCs the container is run --privileged so
# the namespace can be created, and the run wrapper best-effort enables the
# governing sysctls (writable only under privileged). General, source-detected,
# no per-CVE logic.
_PRIVILEGED_POC_RE = re.compile(
    r"\bunshare\s*\(|\bsetns\s*\(|\bCLONE_NEWUSER\b|\bCLONE_NEWNS\b|"
    r"\bCLONE_NEWPID\b|\bCLONE_NEWUTS\b|\bCLONE_NEWNET\b|"
    r"/proc/self/uid_map|/proc/self/setgroups|unprivileged_userns",
    re.IGNORECASE,
)


def poc_needs_privileged(content: str) -> bool:
    """True when the PoC creates namespaces and so needs a privileged container.

    Detected purely from PoC source (namespace syscalls / uid_map writes), so it
    stays general — no per-CVE knowledge. A false positive only means the
    container runs with more capability than strictly necessary, which is safe
    here (known exploit, network disabled, discarded after the run)."""
    if not content:
        return False
    return bool(_PRIVILEGED_POC_RE.search(content))


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


def _load_container_mem_limit() -> str:
    """Read docker.memory_limit from the unified config.yaml (default '6g').

    The PoC-execution containers (Phase 1 baseline) use this ceiling. It is a
    runtime flag, not baked into any image, so changing it needs no rebuild.
    """
    try:
        import yaml
        cfg_path = Path(__file__).parent / "config.yaml"
        with open(cfg_path, "r", encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh) or {}
        dk = cfg.get("docker", {})
        if isinstance(dk, dict) and dk.get("memory_limit"):
            return str(dk["memory_limit"])
    except Exception:
        pass
    return "6g"


# Per-container memory ceiling for PoC execution (shared with Phase 3).
_CONTAINER_MEM_LIMIT = _load_container_mem_limit()


def _load_baseline_policy() -> Tuple[int, int]:
    """Read (baseline_runs, baseline_min_agree) from config.yaml.

    Controls the Phase 1 determinism guard: run the baseline PoC up to
    ``baseline_runs`` times and accept it only once ``baseline_min_agree`` runs
    agree on the exit-code signature. Defaults (3, 2) on any read failure.
    """
    runs, agree = 3, 2
    try:
        import yaml
        cfg_path = Path(__file__).parent / "config.yaml"
        with open(cfg_path, "r", encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh) or {}
        runs = int(cfg.get("baseline_runs", runs) or runs)
        agree = int(cfg.get("baseline_min_agree", agree) or agree)
    except Exception:
        pass
    # Sanity: at least one run, and agreement never exceeds the run budget.
    runs = max(1, runs)
    agree = max(1, min(agree, runs))
    return runs, agree


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
        # Generic, project-configured environment exported when running a PoC
        # (e.g. glibc sets MALLOC_CHECK_ to surface silent heap corruption). The
        # pipeline applies whatever is here with no built-in project knowledge.
        "poc_run_env": p1.get("poc_run_env", {}) or {},
        # When a 64-bit build can't establish a baseline (PoC won't link the
        # project libc, or exits cleanly with no signal), retry the build as
        # 32-bit (i386) for bugs that only manifest on 32-bit (integer-overflow
        # width, i686 multiarch asm paths). One bounded extra build per CVE;
        # general, no per-CVE logic. Requires a multilib base image.
        "enable_arch_fallback": p1.get("enable_arch_fallback", True),
        # Option A (in-tree regression-test reproducer) — OPTIONAL project
        # overrides. When absent the orchestrator uses its autotools/Make-test
        # defaults (DEFAULT_INTREE_BUILD_SCRIPT / DEFAULT_INTREE_RUN_SCRIPT). A
        # non-autotools project supplies its own build/run scripts here so no
        # project-specific commands live in orchestrator.py. Scripts are
        # env-driven (BUILD_DIR/SOURCE_DIR/INSTALL_PREFIX/TEST_SUBDIR/TEST_NAME/
        # TEST_PATH) and the run script must emit SSD_TEST_RESULT=PASS|FAIL|NORESULT.
        "intree_build_script": (p1.get("intree_test", {}) or {}).get("build_script") or None,
        "intree_run_script": (p1.get("intree_test", {}) or {}).get("run_script") or None,
        # Optional project loader/runtime sanity probe (Gate A). A shell snippet,
        # env-driven like the build/run scripts, that exits 0 iff the *built*
        # runtime can start a trivial process. Used to reject false in-tree
        # baselines caused by a miscompiled loader (e.g. old glibc on a too-new
        # base SIGSEGVs at vDSO setup before the test runs). Empty → gate off.
        "intree_sanity_check": (p1.get("intree_test", {}) or {}).get("sanity_check") or None,
        # Version-based era selection (Gate B). Reads version_file from the
        # checked-out tree at COMMIT_HASH, regex-extracts the version, and maps
        # it via version_era_map (closest-older). Takes precedence over the
        # commit-date commit_era_map, which mis-eras backport commits. Empty
        # version_file → disabled (commit date only).
        "version_file": p1.get("version_file", "") or "",
        "version_regex": p1.get("version_regex", "") or "",
        "version_era_map": p1.get("version_era_map", {}) or {},
        # Base-image packages + setup hook (project-supplied; the pipeline only
        # hardcodes `git`). base_packages = required (install fails the build);
        # base_packages_optional = best-effort; base_setup = post-install shell.
        "base_packages": p1.get("base_packages", []) or [],
        "base_packages_optional": p1.get("base_packages_optional", []) or [],
        "base_setup": p1.get("base_setup", "") or "",
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
                                  commit_era_map: dict = None,
                                  commit_year: Optional[int] = None) -> str:
    """Determine the best Ubuntu version for building a specific project commit.

    The CSV-provided ubuntu_version reflects which Ubuntu ships the vulnerable
    release, but building old code from source requires an era-appropriate
    compiler.  This function resolves that mismatch by consulting the actual
    commit date and a caller-supplied commit_era_map.

    Strategy:
    1. Get the commit year from git history (or provided argument)
    2. Look up the era-appropriate Ubuntu version from commit_era_map
    3. If the commit year is unknown, fall back to the CVE year as a proxy
    4. Apply UBUNTU_FALLBACK_MAP if the resolved version is unavailable on Docker Hub
    """
    era_map = commit_era_map if commit_era_map is not None else _COMMIT_ERA_MAP

    # Short-circuit: no era map configured → use CSV value as-is
    if not era_map:
        return vuln_ubuntu_version

    # Step 1: Try to get commit year from git (if not provided)
    if commit_year is None:
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


def get_tree_version(project_repo_path: Path, commit_hash: str,
                     version_file: str, version_regex: str,
                     logger: logging.Logger = None) -> Optional[str]:
    """Read the project's version string from the checked-out tree at a commit.

    Reads ``version_file`` (relative to the repo root) as it exists *at*
    ``commit_hash`` via ``git show`` and applies ``version_regex`` (first
    capture group = version). This is the ground truth for what will actually
    be built, unlike the commit date, which lies for backport commits.

    Returns the version string, or None if anything is unavailable.
    """
    if not (project_repo_path and version_file and version_regex and commit_hash):
        return None
    if not (project_repo_path / ".git").exists():
        return None
    try:
        result = subprocess.run(
            ["git", "-C", str(project_repo_path), "show", f"{commit_hash}:{version_file}"],
            capture_output=True, text=True, timeout=30
        )
        if result.returncode != 0:
            return None
        m = re.search(version_regex, result.stdout)
        if not m:
            return None
        version = m.group(1).strip()
        if logger:
            logger.debug(f"Tree version at {commit_hash[:12]} = {version} (from {version_file})")
        return version or None
    except Exception as e:
        if logger:
            logger.debug(f"Could not read tree version at {commit_hash[:12]}: {e}")
        return None


def map_version_to_era(version: str, version_era_map: dict) -> Optional[str]:
    """Map a project version to an Ubuntu era via closest-older match.

    The tree version maps to the era of the largest map key that is <= it
    (e.g. 2.33 -> 2.31 -> "20.04"). Returns None when no key is <= version or
    the version/map is unparseable.
    """
    if not version or not version_era_map:
        return None

    def _tup(s: str):
        return tuple(int(p) for p in str(s).split("."))

    try:
        target = _tup(version)
    except ValueError:
        return None

    best = None
    for ver_str in sorted(version_era_map, key=_tup):
        try:
            if _tup(ver_str) <= target:
                best = version_era_map[ver_str]
            else:
                break
        except ValueError:
            continue
    return best


def resolve_build_ubuntu_version_by_version(
        commit_hash: str, project_repo_path: Path, cve: str,
        logger: logging.Logger, version_file: str, version_regex: str,
        version_era_map: dict) -> Optional[str]:
    """Gate B: resolve the build era from the checked-out tree's version.

    Takes precedence over the commit-date era map. Returns the era-appropriate
    Ubuntu version (after Docker-Hub availability fallback), or None when the
    version cannot be read/mapped so the caller can fall back to commit dates.
    """
    if not (version_file and version_era_map):
        return None
    version = get_tree_version(project_repo_path, commit_hash, version_file,
                               version_regex, logger)
    if not version:
        return None
    era_ubuntu = map_version_to_era(version, version_era_map)
    if not era_ubuntu:
        return None
    if era_ubuntu in UBUNTU_FALLBACK_MAP:
        era_ubuntu = UBUNTU_FALLBACK_MAP[era_ubuntu]
    logger.info(f"  {cve}: build Ubuntu resolved to {era_ubuntu} "
                f"from tree version {version} ({version_file})")
    return era_ubuntu


def next_older_ubuntu_version(current: str) -> Optional[str]:
    """Return the next-older Ubuntu version among those used by the era map.

    Used for the era-fallback: when a project tree fails to produce a usable
    build on its mapped era (e.g. a 2012 glibc tree whose link stage breaks
    under Ubuntu 14.04's binutils), one rebuild is attempted on the previous
    era's toolchain. Returns None when *current* is already the oldest (or
    unknown).
    """
    versions = sorted(
        set(_COMMIT_ERA_MAP.values()),
        key=lambda s: tuple(int(p) for p in s.split(".")),
    )
    try:
        idx = versions.index(current)
    except ValueError:
        return None
    return versions[idx - 1] if idx > 0 else None


class ExecutionStatus(Enum):
    SUCCESS = "Success"
    BUILD_ERROR = "Build Error"
    EXECUTION_ERROR = "Execution Error"
    POC_NOT_FOUND = "PoC Not Found"
    TIMEOUT = "Timeout"
    UNKNOWN_ERROR = "Unknown Error"
    # Methodology v2: the LLM-assisted negative filter flagged the run (or the
    # baseline could not be established) — routed to manual revision rather than
    # silently labelled reproduced/failed.
    NEEDS_REVIEW = "Needs Manual Revision"


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
    # Option A (regression-test-as-PoC): when poc_language == "intree-test" the
    # "PoC" is a test the fixing commit shipped. fix_commit = the fixing commit
    # (the test is overlaid from it); test_path = the test's in-repo path
    # (e.g. iconvdata/tst-iconv-iso-2022-cn-ext.c). commit_hash stays the
    # vulnerable parent (built as usual); the test is run in-tree via `make test`.
    fix_commit: str = ""
    test_path: str = ""
    # The test's build subdir as resolved by Phase 0 (the dir whose Makefile
    # registers the test) — authoritative when present; the test_subdir property
    # falls back to the test path's first component when this is empty.
    test_subdir_csv: str = ""
    # Runtime flags set during Phase 1 processing (not from CSV).
    # needs_privileged: PoC builds namespaces → run its container --privileged.
    # build_arch: target build architecture ("amd64" default; "i386" when the
    #   32-bit arch fallback kicks in for a bug that only manifests on 32-bit).
    needs_privileged: bool = False
    build_arch: str = "amd64"
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
        """Tag for the CVE-specific derived image.

        The architecture is appended only for non-default (i386) builds so the
        amd64 tag layout — and every already-built/cached image — is unchanged,
        while a 32-bit arch-fallback build gets its own distinct tag.
        """
        arch_suffix = "" if self.build_arch in ("", "amd64") else f"-{self.build_arch}"
        return f"{self._cve_image_prefix}:{self.cve}-{self.ubuntu_version}{arch_suffix}"

    @property
    def is_intree_test(self) -> bool:
        """True when this CVE's reproducer is a project regression test (Option A)."""
        return (self.poc_language or "").lower() == "intree-test"

    @property
    def test_subdir(self) -> str:
        """The test's build subdir (the dir whose Makefile registers the test).

        Prefers Phase 0's resolved value (TEST_SUBDIR), which correctly handles
        tests registered outside their source path's first component (e.g. a
        sysdeps/ test registered in math/Makefile). Falls back to the test path's
        first component for older CSVs without the column.
        """
        if (self.test_subdir_csv or "").strip():
            return self.test_subdir_csv.strip()
        p = (self.test_path or "").split("/")
        return p[0] if len(p) > 1 else ""

    @property
    def test_name(self) -> str:
        """The test's base name without extension (e.g. 'tst-foo')."""
        base = (self.test_path or "").rsplit("/", 1)[-1]
        return base.rsplit(".", 1)[0] if base else ""


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
    # Methodology v2 — deterministic baseline + negative filter
    baseline_exit_code: Optional[int] = None      # PoC exit code on the known-vulnerable build
    negative_filter_flagged: bool = False         # True if the negative filter saw a failure
    negative_filter_reason: Optional[str] = None  # short justification from the filter
    negative_filter_source: Optional[str] = None  # "llm" | "regex" | "regex-fallback"
    needs_manual_revision: bool = False           # routed to manual revision
    poc_uses_project_build: Optional[str] = None  # "yes" | "no" (C PoCs) | None (interpreted/unknown)
    baseline_cache_key: Optional[str] = None      # fingerprint for baseline memoization (image sig + runtime policy)


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
                 commit_era_map: dict = None,
                 version_file: str = "",
                 version_regex: str = "",
                 version_era_map: dict = None):
        self.csv_path = csv_path
        self.logger = logger
        self.skipped_cves = set(skipped_cves or [])
        self.project_repo_path = project_repo_path
        self.base_image_prefix = base_image_prefix
        self.cve_image_prefix = cve_image_prefix
        self.commit_era_map = commit_era_map if commit_era_map is not None else {}
        self.version_file = version_file or ""
        self.version_regex = version_regex or ""
        self.version_era_map = version_era_map if version_era_map is not None else {}

    def parse(self) -> List[VulnerabilityInfo]:
        """Parse Phase 0 CSV and return list of VulnerabilityInfo objects."""
        vulnerabilities = []
        seen_cves = set()
        skipped_manual = 0
        skipped_no_ubuntu = 0
        skipped_not_ready = 0

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

                # Phase-1 readiness gate: require BOTH a fixing commit (V_COMMIT)
                # and a runnable PoC. V_COMMIT is checked out to build the
                # known-vulnerable glibc — without it there is only stock distro
                # glibc, so no deterministic baseline is possible (the CVE would
                # only ever reach "No fixing commit recorded → manual revision").
                # Without a PoC there is nothing to run. Skipping here keeps these
                # un-reproducible CVEs out of the Phase 1 denominator instead of
                # building images for them only to fail.
                if not row.get('V_COMMIT', '').strip() or not row.get('poc_path', '').strip():
                    skipped_not_ready += 1
                    self.logger.info(
                        f"Skipping {cve} (not Phase-1-ready: "
                        f"V_COMMIT={'set' if row.get('V_COMMIT', '').strip() else 'MISSING'}, "
                        f"poc_path={'set' if row.get('poc_path', '').strip() else 'MISSING'})"
                    )
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
                        v_commit_year_str = row.get('V_COMMIT_YEAR', '').strip()
                        year = None
                        if v_commit_year_str.isdigit():
                            year = int(v_commit_year_str)
                        
                        inferred = None
                        if (commit_hash_fb or year) and self.commit_era_map:
                            if year is None and self.project_repo_path:
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
                v_commit_year_str = row.get('V_COMMIT_YEAR', '').strip()
                commit_year = int(v_commit_year_str) if v_commit_year_str.isdigit() else None

                if commit_hash and self.project_repo_path:
                    # Gate B: prefer the era derived from the checked-out tree's
                    # actual version (correct for backports); fall back to the
                    # commit-date era map when the version can't be read.
                    build_ubuntu = resolve_build_ubuntu_version_by_version(
                        commit_hash, self.project_repo_path, cve, self.logger,
                        self.version_file, self.version_regex, self.version_era_map,
                    )
                    if not build_ubuntu:
                        build_ubuntu = resolve_build_ubuntu_version(
                            ubuntu_version, commit_hash, self.project_repo_path, cve,
                            self.logger, commit_era_map=self.commit_era_map,
                            commit_year=commit_year,
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
                    fix_commit=row.get('FIX_COMMIT', '').strip(),
                    test_path=row.get('TEST_PATH', '').strip(),
                    test_subdir_csv=row.get('TEST_SUBDIR', '').strip(),
                    _base_image_prefix=self.base_image_prefix,
                    _cve_image_prefix=self.cve_image_prefix,
                )

                self.logger.debug(f"Phase0 CVE: {vuln.cve} ubuntu={ubuntu_version} commit={vuln.short_commit}")
                vulnerabilities.append(vuln)

        self.logger.info(f"Parsed {len(vulnerabilities)} CVEs from Phase 0 CSV")
        if skipped_manual:
            self.logger.info(f"  Skipped (manual review pending): {skipped_manual}")
        if skipped_not_ready:
            self.logger.info(f"  Skipped (not Phase-1-ready: missing V_COMMIT or PoC): {skipped_not_ready}")
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
LABEL ai-ssd.recipe_version="{recipe_version}"

ENV DEBIAN_FRONTEND=noninteractive

{eol_repo_fix}

# PROJECT-AGNOSTIC package install. Only `git` (needed by the pipeline's own
# checkout) is hardcoded; every build dependency comes from the project's
# phase1.base_packages (required — install fails the build) and
# phase1.base_packages_optional (best-effort). Combined update+install in one
# RUN so the Docker layer cache never serves stale package lists (EOL mirrors).
RUN for i in 1 2 3; do apt-get update && break || (echo "apt update retry $i" && sleep 5); done \
    && apt-get install -y git ca-certificates {required_packages}

# Optional packages — best-effort (a 404 on an EOL mirror is non-fatal).
RUN apt-get install -y {optional_packages} 2>/dev/null || true

# Project-supplied base setup hook (e.g. extra architectures, locale generation).
# Best-effort and project-agnostic — the pipeline runs whatever the config gives.
RUN ({base_setup}) 2>/dev/null || true; rm -rf /var/lib/apt/lists/*

# Unprivileged account used to RUN PoCs (see _POC_RUN_USER). Build steps stay
# root; only the exploit execution is dropped to this user by the run wrapper.
RUN useradd -m -s /bin/bash {poc_run_user} 2>/dev/null \
    || adduser --disabled-password --gecos '' {poc_run_user} 2>/dev/null \
    || true

# Copy project source from host (pre-updated by Phase 1)
COPY {source_dir}/ /build/{source_dir}/

# Create build and poc directories
RUN mkdir -p /build/{build_dir} /poc

WORKDIR /build/{source_dir}
'''

    # Fix for EOL Ubuntu versions whose repos moved to old-releases.ubuntu.com.
    # NOTE: this string is injected via .format() as a VALUE, so {{ }} escapes
    # are NOT collapsed — the regex must avoid brace quantifiers entirely.
    EOL_REPO_FIX = '''# Fix APT sources for EOL Ubuntu version
RUN sed -i -re 's/([a-z][a-z]\\.)?(archive|security)\\.ubuntu\\.com/old-releases.ubuntu.com/g' /etc/apt/sources.list 2>/dev/null || true
RUN sed -i -re 's/([a-z][a-z]\\.)?(archive|security)\\.ubuntu\\.com/old-releases.ubuntu.com/g' /etc/apt/sources.list.d/*.list 2>/dev/null || true
'''

    def __init__(self, docker_client, project_repo_path: Path, logger: logging.Logger,
                 build_timeout: int = 7200,
                 base_image_prefix: str = _DEFAULT_BASE_IMAGE_PREFIX,
                 source_dir_name: str = _DEFAULT_SOURCE_DIR_NAME,
                 build_dir_name: str = _DEFAULT_BUILD_DIR_NAME,
                 docker_platform: str = None,
                 base_packages: Optional[List[str]] = None,
                 base_packages_optional: Optional[List[str]] = None,
                 base_setup: str = ""):
        self.client = docker_client
        self.project_repo_path = project_repo_path
        self.logger = logger
        self.build_timeout = build_timeout
        self.base_image_prefix = base_image_prefix
        self.source_dir_name = source_dir_name
        self.build_dir_name = build_dir_name
        self.docker_platform = docker_platform
        # Project-supplied package lists + setup hook (no project-specific
        # packages are hardcoded in the pipeline).
        self.base_packages = base_packages or []
        self.base_packages_optional = base_packages_optional or []
        self.base_setup = base_setup or ""
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
            cached_recipe = labels.get('ai-ssd.recipe_version', '')
            expected_plat = self.docker_platform or ''
            config_match = (
                cached_src == self.source_dir_name
                and cached_bld == self.build_dir_name
                and cached_plat == expected_plat
                and cached_recipe == _BASE_RECIPE_VERSION
            )
            if config_match:
                self.logger.info(f"Base image already exists: {tag}")
                self.built_images[ubuntu_version] = tag
                return tag
            else:
                self.logger.warning(
                    f"Stale base image {tag}: source_dir={cached_src!r} (expected {self.source_dir_name!r}), "
                    f"build_dir={cached_bld!r} (expected {self.build_dir_name!r}), "
                    f"platform={cached_plat!r} (expected {expected_plat!r}), "
                    f"recipe_version={cached_recipe!r} (expected {_BASE_RECIPE_VERSION!r}). Rebuilding."
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
            # Join base_setup into a single best-effort RUN line ('; '-separated)
            # so multi-line YAML recipes embed cleanly; default to a no-op.
            setup_line = " ; ".join(
                ln.strip() for ln in (self.base_setup or "").splitlines() if ln.strip()
            ) or "true"
            dockerfile_content = self.BASE_DOCKERFILE.format(
                ubuntu_version=ubuntu_version,
                eol_repo_fix=eol_fix,
                source_dir=self.source_dir_name,
                build_dir=self.build_dir_name,
                docker_platform=self.docker_platform or '',
                poc_run_user=_POC_RUN_USER,
                recipe_version=_BASE_RECIPE_VERSION,
                required_packages=" ".join(self.base_packages),
                optional_packages=" ".join(self.base_packages_optional) or "ca-certificates",
                base_setup=setup_line,
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
    # v6: Language-aware glibc subshell — C PoCs only; interpreted PoCs run
    # without LD_LIBRARY_PATH so the interpreter stays on the stable system glibc.
    # v8: C PoCs run through the project's own loader (ld.so --library-path) as
    # an unprivileged user; honesty marker is a runtime (not build-time) check.
    # v9: bridge the system locale-archive into the project build's locale dir.
    # v10: run binaries with a project PT_INTERP directly (preserve argv[0] /
    #      self-re-exec); generate locales with the build's own localedef.
    # v11: export project-configured phase1.poc_run_env before the PoC runs.
    # v12: best-effort enable unprivileged-userns sysctls in the wrapper (for
    #      privileged namespace PoCs); compile companion helper files; 32-bit
    #      (i386) arch-fallback build path.
    # v13: fully suppress the step-0 userns-sysctl writes (a failed '>' on a
    #      read-only /proc/sys leaked "Read-only file system" to stderr and the
    #      negative filter misread it as exploit failure — regressed CVE-2009-5029).
    # v14: capture make/make-install REAL exit codes (was masked by `| tail`,
    #      always 0 under dash) and record a definitive PROJECT_LIBC_INSTALLED
    #      marker. Header build steps aren't hashed into the signature, so this
    #      bump is what forces cached CVE images to rebuild with the new recipe.
    WRAPPER_CONTRACT_VERSION = "phase1-wrapper-v14"
    
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
# PoC Signature: {poc_signature}
# =============================================================================
FROM {base_image_tag}

LABEL maintainer="AI-SSD Project"
LABEL ai-ssd.type="cve"
LABEL cve="{cve}"
LABEL commit="{commit_hash}"
LABEL ai-ssd.ubuntu_version="{ubuntu_version}"
LABEL ai-ssd.poc_language="{poc_language}"
LABEL ai-ssd.poc_signature="{poc_signature}"
LABEL ai-ssd.platform="{docker_platform}"

# Checkout the vulnerable commit
# The base image already contains the full .git history copied from the host,
# so no fetch is needed.  Remove stale lock files that a previous interrupted
# fetch/checkout may have left behind, then checkout locally.
WORKDIR /build/{source_dir}
RUN rm -f .git/index.lock .git/refs/heads/*.lock 2>/dev/null; \\
    if [ -n "{commit_hash}" ]; then \\
        git checkout --force {commit_hash} || \\
        (echo "ERROR: git checkout {commit_hash} failed — listing available refs:" && \\
         git log --oneline -5 && exit 1); \\
    else \\
        echo "No commit hash provided, using current HEAD"; \\
    fi

# Relax tool-version checks in old glibc configure scripts.
# Old configure scripts reject newer binutils/make/sed with "too old" because
# their version-match regexes are too narrow.  Bypass the critic_missing error
# gate so configure proceeds despite version mismatches.
RUN sed -i 's/test -n "$critic_missing"/false/g; s/test "x$critic_missing" != x/false/g' \\
    /build/{source_dir}/configure 2>/dev/null || true

# Generic compat for old trees referencing the linker-script symbol `_begin`:
# binutils >= 2.21 changed the default linker script so the Makefile sed that
# injected `_begin = . - SIZEOF_HEADERS;` no longer matches, leaving ld.so
# with an undefined hidden `_begin` (R_X86_64_PC32 link failure).  `_begin`
# is just the runtime address of the ELF header, i.e. the load bias —
# substitute the documented in-source equivalents (era-general, no per-CVE
# logic; the guard makes this a no-op on trees that no longer use `_begin`).
RUN if grep -q 'GL(dl_rtld_map).l_map_start = (ElfW(Addr)) _begin;' \\
        /build/{source_dir}/elf/rtld.c 2>/dev/null; then \\
      sed -i \\
        -e 's|GL(dl_rtld_map).l_map_start = (ElfW(Addr)) _begin;|GL(dl_rtld_map).l_map_start = (ElfW(Addr)) GL(dl_rtld_map).l_addr;|' \\
        -e 's|= (ElfW(Ehdr) \\*) \\&_begin;|= (ElfW(Ehdr) *) bootstrap_map.l_addr;|' \\
        /build/{source_dir}/elf/rtld.c && \\
      echo "Applied generic _begin compat fix to elf/rtld.c"; \\
    fi

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
        CC="gcc -fno-stack-protector -fgnu89-inline" \\
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
        CC="gcc -fgnu89-inline" \\
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

# Capture make's REAL exit code. The output is redirected to a log file (not
# piped to tail) because the container shell is /bin/sh (dash), where `$?`
# after `make ... | tail` is tail's exit code (always 0) and `set -o pipefail`
# is unavailable — that masked failed glibc builds as success. We grab `$?`
# straight after make, then tail the log for the build trace.
RUN make -j$(nproc) -k > /build/make.log 2>&1; \\
    echo "PROJECT_BUILD_EXIT_CODE=$?" >> /build/build_status; \\
    tail -20 /build/make.log; \\
    echo "Build completed (errors may be non-fatal)"

RUN make install -k > /build/make_install.log 2>&1; \\
    echo "PROJECT_INSTALL_EXIT_CODE=$?" >> /build/build_status; \\
    tail -20 /build/make_install.log; \\
    echo "Install completed"

# Best-effort: generate common locales into the project glibc's OWN locale
# store using the build's OWN localedef + the in-tree locale/charmap sources.
# The project glibc (configured --prefix={install_prefix}) reads
# {install_prefix}/lib/locale, which ships only C/POSIX — so locale-dependent
# PoCs (setlocale/strcoll/strxfrm) abort with "setlocale failed" before reaching
# the bug. Using the build's own localedef avoids any cross-version archive
# incompatibility. General: a fixed common locale set, no per-CVE knowledge.
RUN if [ -x {install_prefix}/bin/localedef ]; then \\
        mkdir -p {install_prefix}/lib/locale; \\
        I18N=/build/{source_dir}/localedata; \\
        for loc in en_US en_GB de_DE fr_FR es_ES it_IT ja_JP zh_CN ru_RU C; do \\
            I18NPATH=$I18N {install_prefix}/bin/localedef -i $loc -f UTF-8 $loc.UTF-8 2>/dev/null || true; \\
        done; \\
        for loc in en_US en_GB de_DE fr_FR; do \\
            I18NPATH=$I18N {install_prefix}/bin/localedef -i $loc -f ISO-8859-1 $loc.ISO-8859-1 2>/dev/null || true; \\
        done; \\
        echo "Project locales now available:"; \\
        {install_prefix}/bin/locale -a 2>/dev/null | head -25 || true; \\
    else \\
        echo "No project localedef found — skipping locale generation"; \\
    fi; true

# Verify build produced usable output and record a DEFINITIVE marker of whether
# the project libc was actually installed into the prefix. PROJECT_BUILD/INSTALL
# exit codes can be 0 even when -k skipped a fatal target, so the presence of
# {install_prefix}/lib/libc.so.6 is the ground-truth signal that the source tree
# is patch-validatable (the honesty gate then confirms the PoC links it).
RUN ls -la {install_prefix}/lib/ 2>/dev/null || echo "WARNING: lib/ not found"; \\
    echo "=== Build artifacts ===" && find {install_prefix} -name "*.so*" 2>/dev/null | head -20; \\
    if ls {install_prefix}/lib/libc.so.6 >/dev/null 2>&1 || ls {install_prefix}/lib*/libc.so.6 >/dev/null 2>&1; then \\
        echo "PROJECT_LIBC_INSTALLED=yes" >> /build/build_status; \\
        echo "Project libc installed: OK"; \\
    else \\
        echo "PROJECT_LIBC_INSTALLED=no" >> /build/build_status; \\
        echo "WARNING: project libc.so.6 NOT found in {install_prefix} — build did not produce a usable libc"; \\
    fi
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

# Record whether the PoC actually exercises the project build at RUNTIME.
# The run wrapper launches the PoC through the project's OWN dynamic loader
# (ld.so --library-path {install_prefix}/lib), so the honest question is not
# "what did the binary link at compile time" but "does running it under that
# loader map the project libc". We check exactly that (with an LD_LIBRARY_PATH
# ldd fallback). When neither resolves the project build, no source patch can
# change the PoC's behavior, so the orchestrator routes the CVE to manual
# revision. NOTE: keep this logic in sync with read_poc_uses_build() and the
# Phase 3 marker in patch_validator.py.
RUN LOADER=$(find {install_prefix}/lib -maxdepth 1 -name 'ld-*.so*' 2>/dev/null | head -1); \\
    USES=no; \\
    if [ -n "$LOADER" ] && "$LOADER" --library-path {install_prefix}/lib --list /poc/exploit 2>/dev/null | grep -q "{install_prefix}"; then \\
        USES=yes; \\
    elif LD_LIBRARY_PATH={install_prefix}/lib ldd /poc/exploit 2>/dev/null | grep -q "{install_prefix}"; then \\
        USES=yes; \\
    fi; \\
    echo "$USES" > /poc/.ssd_poc_uses_build; \\
    echo "poc_uses_project_build: $USES"

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
        echo "Phase 1 cannot auto-verify this module without a real Metasploit execution path."; \\
        mv /poc/exploit.rb /poc/exploit_msf.rb; \\
        echo '#!/usr/bin/env ruby' > /poc/exploit.rb; \\
        echo '# Auto-generated failure wrapper for unsupported Metasploit module' >> /poc/exploit.rb; \\
        echo 'warn "Metasploit module detected: /poc/exploit_msf.rb"' >> /poc/exploit.rb; \\
        echo 'warn "Phase 1 requires an explicit shell/session proof, which this wrapper cannot produce."' >> /poc/exploit.rb; \\
        echo 'exit 43' >> /poc/exploit.rb; \\
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
                 docker_platform: str = None,
                 poc_run_env: Optional[Dict[str, Any]] = None):
        self.client = docker_client
        self.logger = logger
        self.build_timeout = build_timeout
        self.source_dir_name = source_dir_name
        self.build_dir_name = build_dir_name
        self.install_prefix = install_prefix
        self.docker_platform = docker_platform
        # Project-configured environment for PoC execution (Phase 0 YAML
        # phase1.poc_run_env). Generic: the pipeline bakes these exports into the
        # run wrapper without any built-in project knowledge. Lets a project
        # surface "silent" vulnerability triggers (e.g. glibc sets MALLOC_CHECK_
        # so heap corruption aborts instead of exiting 0). Empty for projects
        # that don't need it.
        self.poc_run_env: Dict[str, Any] = poc_run_env or {}
        self.built_images: Dict[str, str] = {}  # cve -> image_tag

    def _compute_poc_signature(self, poc_path: Path, poc_language: str,
                               poc_metadata: dict, commit_hash: str = "",
                               build_arch: str = "amd64") -> str:
        """Create a rebuild fingerprint for the CVE image wrapper contract."""
        hasher = hashlib.sha256()
        hasher.update(self.WRAPPER_CONTRACT_VERSION.encode("utf-8"))
        hasher.update((poc_language or "").encode("utf-8"))
        # The build architecture changes the configure/compile flags baked into
        # the image, so a 32-bit (i386) build must not reuse a cached 64-bit one.
        hasher.update((build_arch or "amd64").encode("utf-8"))
        # The image is built at this commit (git checkout), so a change to it
        # (e.g. Phase 0 now records the vulnerable parent instead of the fix, or
        # a corrected fix commit) MUST invalidate the cached image — otherwise a
        # stale image built at the old commit would be silently reused.
        hasher.update((commit_hash or "").encode("utf-8"))
        if poc_path and poc_path.exists():
            hasher.update(poc_path.read_bytes())
        hasher.update(json.dumps(
            poc_metadata or {},
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8"))
        # The project's PoC-run env is baked into the wrapper, so a change to it
        # must invalidate the cached image.
        hasher.update(json.dumps(
            self.poc_run_env or {}, sort_keys=True, separators=(",", ":"), default=str
        ).encode("utf-8"))
        return hasher.hexdigest()

    def _generate_dockerfile(self, vuln: VulnerabilityInfo, base_image_tag: str,
                              poc_filename: str, poc_language: str,
                              alt_poc_filenames: List[str] = None, poc_metadata: dict = None,
                              poc_signature: str = "", companion_filenames: List[str] = None,
                              build_arch: str = "amd64") -> str:
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
            poc_signature=poc_signature,
            source_dir=self.source_dir_name,
            build_dir=self.build_dir_name,
            install_prefix=self.install_prefix,
            docker_platform=self.docker_platform or '',
        )

        # 32-bit (i386) arch fallback: build the project glibc and compile the
        # PoC as 32-bit for bugs that only manifest on 32-bit (integer-overflow
        # width, i686 multiarch asm). Applied as targeted transforms so the
        # amd64 path — the common case — is byte-for-byte unchanged. Requires a
        # multilib base image (gcc-multilib + libc6-dev-i386, installed in v3).
        if (build_arch or "amd64") == "i386":
            # Configure the project build 32-bit: force the i686 host triplet and
            # -m32 into every configure strategy's CC/CFLAGS.
            header = header.replace('CC="gcc', 'CC="gcc -m32')
            header = header.replace('CFLAGS="', 'CFLAGS="-m32 ')
            header = header.replace(
                f'--prefix={self.install_prefix} ',
                f'--prefix={self.install_prefix} --host=i686-linux-gnu --build=i686-linux-gnu ',
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

        # 32-bit arch fallback: compile the PoC -m32 so it links the 32-bit
        # project glibc. Done before the companion section is inserted so only
        # the main-PoC compile commands are rewritten (companions keep their own
        # arch handling). C PoCs only.
        if (build_arch or "amd64") == "i386" and lang == 'c':
            body = body.replace('gcc -o exploit', 'gcc -m32 -o exploit')
            body = body.replace('gcc -std=gnu99 -o exploit', 'gcc -m32 -std=gnu99 -o exploit')

        # Append COPY + compilation for companion/helper files (multi-file PoCs).
        if companion_filenames:
            companion_section = self._generate_companion_section(companion_filenames)
            env_marker = '\nENV LD_LIBRARY_PATH='
            idx = body.rfind(env_marker)
            if idx != -1:
                body = body[:idx] + '\n' + companion_section + body[idx:]
            else:
                body = body + '\n' + companion_section

        self.logger.info(f"Generated {lang} Dockerfile for {vuln.cve}"
                         + (f" [arch={build_arch}]" if build_arch != 'amd64' else ''))

        # Determine the base execution command from the original CMD to pass context if needed
        import re
        cmd_match = re.search(r'CMD \["(.*?)\"(?:, \"(.*?)\")?\]', body)
        base_cmd = "./exploit"
        if cmd_match:
            if cmd_match.group(2):
                base_cmd = f"{cmd_match.group(1)} {cmd_match.group(2)}"
            else:
                base_cmd = cmd_match.group(1)
            # Remove original CMD
            body = re.sub(r'CMD \[.*?\]\n?', '', body)

        # Get dynamic wrapper parameters from LLM/heuristic analysis
        poc_category = poc_metadata.get("poc_category", "OTHER") if poc_metadata else "OTHER"
        setup_cmd = poc_metadata.get("setup_command", "") if poc_metadata else ""

        # Resolve execution wrapper: the heuristic fallback always returns
        # "./exploit …" which is only valid for compiled C PoCs.  For interpreted
        # languages (shell, python, ruby, perl, php) use the base_cmd extracted
        # from the language-specific Dockerfile CMD instead.
        _ew_meta = poc_metadata.get("execution_wrapper", "") if poc_metadata else ""
        if _ew_meta and (lang == "c" or not _ew_meta.startswith("./exploit")):
            exec_wrap = _ew_meta
        else:
            exec_wrap = f"{base_cmd} > /tmp/out 2>&1"

        # Methodology v2: the baseline "success code" IS the PoC's own exit code,
        # so the wrapper must not mask it. A trailing '|| true' / '|| :' (carried
        # over from the old gate design, where the verdict came from probes, not
        # the exit code) would force `exit_code=$?` to 0 and erase the signal.
        # The wrapper runs without `set -e`, so removing it is safe — the script
        # continues regardless of the PoC's exit status.
        exec_wrap = re.sub(r'\s*\|\|\s*(?:true|:)\s*$', '', exec_wrap)

        # Path to the freshly-built (vulnerable) glibc.
        lib_path = f"{self.install_prefix}/lib"
        # For C PoCs the wrapper launches the binary through the project's OWN
        # dynamic loader (ld.so --library-path <lib_path>) — the glibc-canonical
        # way to run a binary against a freshly-built libc (this is what glibc's
        # testrun.sh does). It guarantees BOTH the build's loader AND libc are
        # exercised regardless of how the binary linked (even if a compile
        # fallback linked it against the system libc).
        #
        # For INTERPRETED languages (ruby, python, shell, perl, php) the
        # INTERPRETER itself would be the first process to load from
        # LD_LIBRARY_PATH. When the built glibc is ABI-incompatible with the
        # base userland, the interpreter SIGSEGVs before the PoC script even
        # starts — producing a false exit-139 baseline (observed: ruby crashing
        # under CVE-2018-1000001's glibc). Interpreted PoCs test *behaviour*
        # via syscalls and do not need the vulnerable glibc loaded into the
        # interpreter, so the loader/LD_LIBRARY_PATH path must NOT apply to them.
        is_c_poc = (lang == "c")

        # Strip the language template's global `ENV LD_LIBRARY_PATH=...`. If it
        # stayed, the CMD `bash`/`base64`/`cat` in the wrapper would run under the
        # freshly-built, possibly ABI-incompatible glibc and SIGSEGV before the
        # wrapper could emit its SSD_RESULT marker — observed as the
        # CVE-2009-5029 / CVE-2018-1000001 harness crashes (and the build-time
        # base64 SIGSEGV). The PoC itself still gets the vulnerable libs via the
        # execution subshell above; removing the global ENV does NOT change the
        # PoC's runtime environment, only the harness's.
        body = re.sub(r'\nENV LD_LIBRARY_PATH=[^\n]*', '', body)

        # Append the run-and-capture wrapper (methodology v2) — see helper.
        body += self._build_run_wrapper(
            poc_category=poc_category,
            setup_cmd=setup_cmd,
            exec_wrap=exec_wrap,
            is_c_poc=is_c_poc,
            lib_path=lib_path,
        )

        return header + body

    def _build_run_wrapper(self, *, poc_category: str, setup_cmd: str,
                           exec_wrap: str, is_c_poc: bool,
                           lib_path: str) -> str:
        """Build the run-and-capture wrapper tail (methodology v2).

        The wrapper makes no verdict — it runs any setup, executes the PoC
        (stdout+stderr → /tmp/out), surfaces that output on the container's own
        stdout for the host-side negative filter, emits a structured SSD_RESULT
        marker, and exits with the PoC's OWN exit code (the deterministic
        baseline success code).  Returned as the Dockerfile tail: the base64
        wrapper-install RUN plus the CMD.

        For C PoCs the exploit is launched through the project's OWN dynamic
        loader (``ld.so --library-path <lib_path>``) as an unprivileged user, so
        (a) the freshly-built loader+libc are always exercised regardless of how
        the binary linked, and (b) privilege-escalation exploits have to actually
        escalate rather than short-circuiting as root. Interpreted PoCs keep the
        previous behaviour (system glibc, root) — the loader path does not apply.

        Any project-configured PoC-run env (Phase 0 YAML ``phase1.poc_run_env``)
        is exported just before the exploit runs — a generic hook with no
        built-in project knowledge (e.g. glibc sets MALLOC_CHECK_ so silent heap
        corruption aborts instead of exiting 0).
        """
        # Project-configured environment, exported immediately before the PoC.
        def _squote(v) -> str:
            return "'" + str(v).replace("'", "'\\''") + "'"
        env_exports = [
            f"export {k}={_squote(v)}"
            for k, v in (self.poc_run_env or {}).items()
            if str(k).strip()
        ]

        if is_c_poc:
            # Replace every ./exploit invocation with the loader-prefixed form.
            # $LOADER_PREFIX is empty when the binary already embeds the project
            # loader (see PT_INTERP check below), so this collapses to a direct
            # ./exploit run in that case.
            exec_loader = exec_wrap.replace("./exploit", "$LOADER_PREFIX ./exploit")
            exec_lines = [
                "# 2. Execution — run the C PoC against the project glibc, unprivileged.",
                "echo '--- Running exploit ---'",
                f"RUN_LIB='{lib_path}'",
                "LOADER=$(find \"$RUN_LIB\" -maxdepth 1 -name 'ld-*.so*' 2>/dev/null | head -1)",
                "# Decide HOW to reach the project glibc. If the binary's ELF",
                "# interpreter (PT_INTERP) already points into the project build",
                "# (compile baked -Wl,--dynamic-linker + rpath), run it DIRECTLY so",
                "# argv[0] and any self-re-exec (/proc/self/exe) stay correct — LPE",
                "# PoCs that re-invoke themselves break under an explicit 'ld.so",
                "# ./exploit'. Otherwise (system/empty interpreter, e.g. a compile",
                "# fallback or a runtime-built driver) force the project loader so",
                "# the project libc is still exercised. General, no per-CVE logic.",
                "INTERP=$(readelf -l /poc/exploit 2>/dev/null | "
                "sed -n 's/.*program interpreter: \\(.*\\)]/\\1/p' | head -1)",
                "case \"$INTERP\" in",
                "    \"$RUN_LIB\"/*) LOADER_PREFIX=; "
                "echo \"  PoC uses project interpreter ($INTERP) — running directly\" ;;",
                "    *) if [ -n \"$LOADER\" ] && [ -x \"$LOADER\" ]; then "
                "LOADER_PREFIX=\"$LOADER --library-path $RUN_LIB\"; "
                "echo \"  Forcing project loader (binary interpreter: ${INTERP:-none})\"; "
                "else LOADER_PREFIX=; fi ;;",
                "esac",
                f"POC_USER='{_POC_RUN_USER}'",
                "# Materialize the exploit invocation into a script so dropping",
                "# privileges (su) does not mangle quoting / redirection / pipes.",
                "cat > /poc/.ssd_run.sh <<EOF",
                "cd /poc",
                "export LD_LIBRARY_PATH=$RUN_LIB",
                *env_exports,
                exec_loader,
                "EOF",
                "chmod 755 /poc/.ssd_run.sh",
                "if id \"$POC_USER\" >/dev/null 2>&1; then",
                "    chown -R \"$POC_USER\" /poc 2>/dev/null || chmod -R a+rwX /poc 2>/dev/null || true",
                "    su \"$POC_USER\" -s /bin/bash -c 'bash /poc/.ssd_run.sh'",
                "else",
                "    /bin/bash /poc/.ssd_run.sh",
                "fi",
            ]
        else:
            exec_lines = [
                "# 2. Execution (interpreted PoC runs under the stable system glibc, as root).",
                "echo '--- Running exploit ---'",
                *env_exports,
                exec_wrap,
            ]

        wrapper_sh = [
            "#!/bin/bash",
            "set -o pipefail 2>/dev/null || true",
            f"CATEGORY='{poc_category}'",
            "",
            f"echo '--- Executing PoC (category: {poc_category}) ---'",
            "",
            "# 0. Best-effort: permit unprivileged user namespaces so namespace-",
            "#    building PoCs (unshare/CLONE_NEWUSER) can run. These /proc/sys",
            "#    knobs are writable only in a privileged container (set for such",
            "#    PoCs); elsewhere this is a harmless no-op. The writes are wrapped",
            "#    in a subshell with ALL output suppressed — otherwise a failed '>'",
            "#    redirection on a read-only /proc/sys prints 'Read-only file",
            "#    system' to stderr, which the host-side negative filter would",
            "#    misread as an exploit failure (regressed CVE-2009-5029's DoS",
            "#    hang). General, no per-CVE logic — non-namespace PoCs unaffected.",
            "( echo 1 > /proc/sys/kernel/unprivileged_userns_clone ) >/dev/null 2>&1 || true",
            "( echo 0 > /proc/sys/kernel/apparmor_restrict_unprivileged_userns ) >/dev/null 2>&1 || true",
            "sysctl -w user.max_user_namespaces=15000 >/dev/null 2>&1 || true",
            "",
            "# 1. Setup (runs as root; never the exploit itself)",
            setup_cmd,
            "",
            *exec_lines,
            "exit_code=$?",
            'echo "--- Exploit finished (exit=$exit_code) ---"',
            "",
            "# 3. Surface captured output for the host-side negative filter.",
            'if [ -f /tmp/out ]; then',
            "    echo '--- BEGIN POC OUTPUT ---'",
            '    cat /tmp/out',
            "    echo '--- END POC OUTPUT ---'",
            'fi',
            "",
            "# 4. Structured marker parsed by the host (DockerManager).",
            'echo "SSD_RESULT: category=$CATEGORY exit_code=$exit_code"',
            "",
            "# 5. Propagate the PoC's real exit code as the container status code.",
            'exit $exit_code',
        ]
        import base64
        wrapper_b64 = base64.b64encode("\n".join(wrapper_sh).encode("utf-8")).decode("utf-8")
        return (
            f'\nRUN echo "{wrapper_b64}" | base64 -d > /poc/wrapper.sh && '
            'chmod +x /poc/wrapper.sh\n'
            'CMD ["/bin/bash", "/poc/wrapper.sh"]\n'
        )

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
    
    def _generate_companion_section(self, companion_filenames: List[str]) -> str:
        """Dockerfile snippet that stages + builds companion helper files.

        Some real-world PoCs are multi-file: the main exploit invokes a helper it
        expects to find next to itself (e.g. CVE-2014-5119's `popen("./pty")`).
        The pipeline stages such helpers from a per-CVE directory
        ``exploits/<CVE>.d/`` (general convention, no per-CVE code): every file is
        copied into /poc/, each C/C++ source is compiled to a binary of the same
        stem (so ``./pty`` resolves to a built ``pty``), and scripts are made
        executable. A helper that fails to build is a soft warning — the main PoC
        still runs and the negative filter reports any missing-helper error.
        """
        lines = ['', '# === Companion / helper files (multi-file PoC support) ===']
        for name in companion_filenames:
            lines.append(f'COPY {name} /poc/{name}')
        cmds: List[str] = []
        for name in companion_filenames:
            low = name.lower()
            stem = name.rsplit('.', 1)[0]
            if low.endswith('.c'):
                cmds.append(
                    f'(gcc -O0 -g -w -o /poc/{stem} /poc/{name} -ldl -lpthread -lm 2>&1 || '
                    f'gcc -O0 -g -w -o /poc/{stem} /poc/{name} 2>&1 || '
                    f'echo "WARN: companion {name} failed to build")'
                )
            elif low.endswith(('.cpp', '.cc', '.cxx', '.c++')):
                cmds.append(
                    f'(g++ -O0 -g -w -o /poc/{stem} /poc/{name} 2>&1 || '
                    f'echo "WARN: companion {name} failed to build")'
                )
            elif low.endswith(('.sh', '.py', '.pl', '.rb')):
                cmds.append(f'chmod +x /poc/{name} 2>/dev/null || true')
        if cmds:
            lines.append('RUN cd /poc && \\')
            for i, c in enumerate(cmds):
                # NOTE: keep the backslash OUT of the f-string expression — a
                # backslash inside `{...}` is a SyntaxError on Python < 3.12
                # (the VM runs 3.10). Build the continuation separately.
                cont = " && \\" if i < len(cmds) - 1 else ""
                lines.append(f'    {c}{cont}')
        return '\n'.join(lines) + '\n'

    # =========================================================================
    # Option A — in-tree regression-test image (poc_language == "intree-test")
    # =========================================================================
    # Recipe version: bump to invalidate cached intree-test images when the
    # template changes.
    INTREE_RECIPE_VERSION = "intree-v7"

    # -------------------------------------------------------------------------
    # PROJECT-AGNOSTIC by design. The orchestrator only knows how to:
    #   (a) check out the vulnerable parent commit (git),
    #   (b) overlay the files the fixing commit ADDED — the test + any helper/
    #       sibling files it needs — leaving MODIFIED files (the source fix)
    #       intact (git),
    #   (c) export a generic env contract and run a project-supplied BUILD
    #       script then a project-supplied RUN script,
    #   (d) read an `SSD_TEST_RESULT=PASS|FAIL|NORESULT` marker from the run.
    # There are NO build-system / compiler / test-framework commands in this
    # code. Each project supplies build_script + run_script via the Phase 0 YAML
    # (phase1.intree_test.{build_script,run_script}); env vars available to them:
    #   BUILD_DIR SOURCE_DIR INSTALL_PREFIX TEST_SUBDIR TEST_NAME TEST_PATH
    #   FIX_COMMIT COMMIT_HASH
    # If a project does not configure these, the in-tree-test reproducer is
    # simply unavailable for it (those CVEs route to manual) — no project gets
    # another project's assumptions.
    # -------------------------------------------------------------------------
    INTREE_TEST_DOCKERFILE = '''# =============================================================================
# AI-SSD in-tree regression-test image: {cve}
# Vulnerable commit: {commit_hash}   Test from fix: {fix_commit}
# Test: {test_path}
# =============================================================================
FROM {base_image_tag}

LABEL ai-ssd.type="cve-intree-test"
LABEL cve="{cve}"
LABEL ai-ssd.test_path="{test_path}"
LABEL ai-ssd.platform="{docker_platform}"
LABEL ai-ssd.intree_signature="{signature}"

# Generic env contract consumed by the project-supplied build/run scripts.
ENV BUILD_DIR=/build/{build_dir}
ENV SOURCE_DIR=/build/{source_dir}
ENV INSTALL_PREFIX={install_prefix}
ENV TEST_SUBDIR={test_subdir}
ENV TEST_NAME={test_name}
ENV TEST_PATH={test_path}
ENV FIX_COMMIT={fix_commit}
ENV COMMIT_HASH={commit_hash}

WORKDIR /build/{source_dir}
# Checkout the VULNERABLE parent commit (bug present). Generic git, no project
# assumptions.
RUN rm -f .git/index.lock .git/refs/heads/*.lock 2>/dev/null; \\
    git checkout --force {commit_hash} 2>&1 | tail -2 || \\
    (echo "ERROR: git checkout {commit_hash} failed" && git log --oneline -3 && exit 1)
# Overlay every file the FIXING commit ADDED (the test + any sibling/helper it
# needs), leaving MODIFIED files alone so the vulnerable source still has the
# bug. Pure git — project-agnostic. Any project-specific test REGISTRATION
# (e.g. an autotools subdir Makefile edit) is the build script's job, via
# $FIX_COMMIT.
# THEN overlay the reproducer TEST itself from the fix commit even when it was
# MODIFIED (not added): the fix routinely strengthens the test (adds the
# assertion/overflow-check that detects the bug), so the vulnerable parent's
# weaker test would trivially PASS and hide the vulnerability. The TEST is the
# oracle and must be the fix's version; the vulnerable SOURCE stays untouched.
RUN added=$(git diff-tree --no-commit-id --name-only --diff-filter=A -r {fix_commit}); \\
    for f in $added; do git checkout {fix_commit} -- "$f" 2>/dev/null && echo "overlaid added: $f"; done; \\
    if [ -n "{test_path}" ]; then \\
        git checkout {fix_commit} -- "{test_path}" 2>/dev/null && echo "overlaid reproducer test from fix: {test_path}"; \\
    fi; \\
    if [ ! -e {test_path} ]; then echo "ERROR: test {test_path} not present after overlay" && exit 1; fi; \\
    echo "Overlay complete (test {test_path} present)"

# Project-supplied build + run scripts (the ONLY place build-system/compiler/
# test-framework commands live).
COPY build_intree.sh /build_intree.sh
RUN bash /build_intree.sh
COPY run_intree_test.sh /run_intree_test.sh
RUN chmod +x /run_intree_test.sh
CMD ["/run_intree_test.sh"]
'''

    def _compute_intree_signature(self, vuln: VulnerabilityInfo,
                                  build_script: str, run_script: str) -> str:
        h = hashlib.sha256()
        for part in (self.INTREE_RECIPE_VERSION, vuln.commit_hash, vuln.fix_commit,
                     vuln.test_path, vuln.test_subdir, self.install_prefix,
                     build_script, run_script):
            h.update((part or "").encode("utf-8"))
        return h.hexdigest()

    def build_intree_test_image(self, vuln: VulnerabilityInfo, base_image_tag: str,
                                build_script: str = None,
                                run_script: str = None) -> Tuple[bool, Optional[str]]:
        """Build an in-tree regression-test image (Option A).

        Checks out the vulnerable parent, overlays the files the fixing commit
        added (test + helpers), then runs the PROJECT-SUPPLIED build script and
        bakes the PROJECT-SUPPLIED run script. Project-agnostic: this method (and
        the Dockerfile) embed no build-system/compiler/test-framework commands —
        those come entirely from the Phase 0 YAML. Returns (False, reason) when a
        project has not configured the scripts.
        """
        if not build_script or not run_script:
            return False, ("no in-tree-test recipe configured for this project "
                           "(set phase1.intree_test.build_script / run_script)")
        tag = vuln.cve_image_tag
        signature = self._compute_intree_signature(vuln, build_script, run_script)

        # Reuse if an image with this signature already exists.
        try:
            existing = self.client.images.get(tag)
            labels = existing.labels or {}
            if (labels.get("ai-ssd.intree_signature") == signature
                    and labels.get("ai-ssd.platform", "") == (self.docker_platform or "")):
                self.logger.info(f"In-tree test image already exists: {tag}")
                self.built_images[vuln.cve] = tag
                return True, "Image already exists"
            self.client.images.remove(tag, force=True)
        except ImageNotFound:
            pass
        except Exception:
            pass

        self.logger.info(f"Building in-tree test image: {tag} (from {base_image_tag})")
        build_context = None
        try:
            build_context = Path(tempfile.mkdtemp(prefix=f"ai-ssd-intree-{vuln.cve.lower()}-"))
            (build_context / "build_intree.sh").write_text(build_script)
            (build_context / "run_intree_test.sh").write_text(run_script)
            dockerfile = self.INTREE_TEST_DOCKERFILE.format(
                cve=vuln.cve, commit_hash=vuln.commit_hash, fix_commit=vuln.fix_commit,
                test_path=vuln.test_path, test_subdir=vuln.test_subdir,
                test_name=vuln.test_name, base_image_tag=base_image_tag,
                source_dir=self.source_dir_name, build_dir=self.build_dir_name,
                install_prefix=self.install_prefix,
                docker_platform=self.docker_platform or "", signature=signature,
            )
            (build_context / "Dockerfile").write_text(dockerfile)
            image, logs = _docker_build(
                self.client, str(build_context), tag, rm=True, forcerm=True,
                timeout=self.build_timeout, platform=self.docker_platform, logger=self.logger,
            )
            self.built_images[vuln.cve] = tag
            self.logger.info(f"In-tree test image built: {tag}")
            return True, (logs if isinstance(logs, str) else "")
        except Exception as e:
            self.logger.error(f"Failed to build in-tree test image for {vuln.cve}: {e}")
            return False, str(e)
        finally:
            if build_context and build_context.exists():
                shutil.rmtree(build_context, ignore_errors=True)

    def build_cve_image(self, vuln: VulnerabilityInfo, base_image_tag: str,
                        poc_path: Path, poc_language: str = None, poc_metadata: dict = None) -> Tuple[bool, Optional[str]]:
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

        # Detect language from file extension if not provided
        if not poc_language or poc_language in ('unknown', ''):
            poc_language = EXTENSION_TO_LANGUAGE.get(poc_path.suffix.lower(), 'c')

        poc_signature = self._compute_poc_signature(
            poc_path, poc_language, poc_metadata, commit_hash=vuln.commit_hash,
            build_arch=vuln.build_arch,
        )

        # Check if already built — must match the TAG, not just the CVE:
        # the era fallback rebuilds the same CVE on a different Ubuntu
        # version, producing a different tag that the memo must not satisfy.
        if self.built_images.get(vuln.cve) == tag:
            self.logger.info(f"Reusing CVE image: {tag}")
            return True, "Image already built"
        
        # Check if image exists in Docker (with platform staleness detection)
        try:
            existing = self.client.images.get(tag)
            labels = existing.labels or {}
            expected_platform = self.docker_platform or ''
            img_platform = labels.get('ai-ssd.platform', '')
            cached_signature = labels.get('ai-ssd.poc_signature', '')
            if img_platform != expected_platform or cached_signature != poc_signature:
                self.logger.info(
                    f"Stale CVE image detected (platform '{img_platform}' != "
                    f"'{expected_platform}' or poc_signature mismatch) — rebuilding: {tag}"
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

            # Discover companion/helper files for multi-file PoCs.
            # Convention: every file under exploits/<CVE>.d/ is staged into /poc/
            # and (for C/C++) compiled to a same-stem binary so the main PoC's
            # helper invocations (e.g. ./pty) resolve. General, no per-CVE code.
            companion_filenames = []
            companion_dir = exploits_dir / f"{vuln.cve}.d"
            if companion_dir.is_dir():
                for comp in sorted(companion_dir.iterdir()):
                    if comp.is_file():
                        shutil.copy2(comp, build_context / comp.name)
                        companion_filenames.append(comp.name)
                if companion_filenames:
                    self.logger.info(
                        f"  Found {len(companion_filenames)} companion file(s) in "
                        f"{companion_dir.name}/: {', '.join(companion_filenames)}"
                    )

            # Generate language-aware Dockerfile
            dockerfile_content = self._generate_dockerfile(
                vuln, base_image_tag, poc_filename, poc_language,
                alt_poc_filenames=alt_poc_filenames,
                poc_metadata=poc_metadata,
                poc_signature=poc_signature,
                companion_filenames=companion_filenames,
                build_arch=vuln.build_arch,
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
        # Load existing manifest so that a standalone run (e.g. a single-CVE
        # test) does not destroy results written by a prior full-pipeline run.
        if manifest_path.exists():
            try:
                with open(manifest_path) as f:
                    existing = json.load(f)
                self.data["base_images"] = existing.get("base_images", [])
                self.data["cve_images"] = existing.get("cve_images", [])
            except Exception as e:
                logger.warning(f"Could not load existing manifest {manifest_path}: {e}")

    def add_base_image(self, ubuntu_version: str, tag: str):
        entry = {
            "ubuntu_version": ubuntu_version,
            "tag": tag,
            "created_at": datetime.now().isoformat(),
        }
        for i, existing in enumerate(self.data["base_images"]):
            if existing.get("ubuntu_version") == ubuntu_version:
                self.data["base_images"][i] = entry
                return
        self.data["base_images"].append(entry)

    def add_cve_image(self, vuln: VulnerabilityInfo, tag: str, status: str,
                      baseline_exit_code: Optional[int] = None,
                      needs_manual_revision: bool = False,
                      poc_uses_project_build: Optional[str] = None,
                      baseline_cache_key: Optional[str] = None):
        """Record a CVE image entry.

        ``baseline_exit_code`` is the PoC exit code captured on the
        known-vulnerable build — the deterministic "success code" that Phase 3
        compares against after applying a patch (a patched build should NO
        LONGER produce this code).

        ``poc_uses_project_build`` records whether the compiled PoC binary
        links against the project build ("yes"/"no" for C PoCs, None for
        interpreted PoCs where the check does not apply).
        """
        entry = {
            "cve": vuln.cve,
            "tag": tag,
            "ubuntu_version": vuln.ubuntu_version,
            "commit_hash": vuln.commit_hash,
            "poc_path": vuln.poc_path,
            "status": status,
            "baseline_exit_code": baseline_exit_code,
            "needs_manual_revision": needs_manual_revision,
            "poc_uses_project_build": poc_uses_project_build,
            # Baseline-memoization fingerprint: identifies the exact image
            # (baked poc_signature) + runtime policy (run_timeout, memory
            # ceiling, determinism budget) the baseline was measured under, so a
            # later run can reuse it iff nothing that affects the verdict changed.
            "baseline_cache_key": baseline_cache_key,
            # Phase 3 must re-run the inherited PoC the SAME way Phase 1 did, or
            # the exit-code comparison is invalid: privileged for namespace PoCs,
            # and the build arch (i386 images derive 32-bit automatically, but
            # the flag lets Phase 3 log/branch on it).
            "needs_privileged": getattr(vuln, "needs_privileged", False),
            "build_arch": getattr(vuln, "build_arch", "amd64"),
            "created_at": datetime.now().isoformat(),
        }
        for i, existing in enumerate(self.data["cve_images"]):
            if existing.get("cve") == vuln.cve:
                self.data["cve_images"][i] = entry
                return
        self.data["cve_images"].append(entry)

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
    
    def run_container(self, vuln: VulnerabilityInfo, run_timeout: int = 300) -> Tuple[int, str]:
        """Run a container from the CVE image and return (exit_code, logs).

        Methodology v2: no verdict is computed here. wrapper.sh exits with the
        PoC's own exit code, and the host decides reproduction via baseline
        matching + the negative filter (see
        PipelineOrchestrator._process_vulnerability_phase0). A timeout is
        reported as exit code -1.
        """
        return self._run_image(vuln.image_name, vuln.container_name, vuln, run_timeout)

    def _run_image(self, image_ref: str, container_name: str,
                   vuln: VulnerabilityInfo, run_timeout: int) -> Tuple[int, str]:
        """Shared container runner. Returns (exit_code, logs).

        exit_code is the container StatusCode (== the PoC's own exit code, as
        propagated by wrapper.sh). A timeout returns exit_code -1.
        """
        self.logger.info(f"Running container {container_name} from {image_ref} for {vuln.cve}...")
        container = None

        # Remove leftover container from a previous run (avoids 409 Conflict)
        try:
            stale = self.client.containers.get(container_name)
            stale.remove(force=True)
            self.logger.info(f"Removed leftover container: {container_name}")
        except Exception:
            pass

        try:
            _run_kwargs = dict(
                name=container_name,
                detach=True,
                mem_limit=_CONTAINER_MEM_LIMIT,
                cpu_period=100000,
                cpu_quota=100000,  # Limit to 1 CPU
                network_disabled=True,  # Security: disable network
                remove=False,  # Keep container for log inspection
            )
            # Namespace-building PoCs (unshare/CLONE_NEWUSER) need a privileged
            # container so the namespace can be created on hosts that restrict
            # unprivileged user namespaces. Source-detected upstream; safe here
            # (known exploit, no network, container discarded after the run).
            if getattr(vuln, "needs_privileged", False):
                _run_kwargs["privileged"] = True
                self.logger.info(
                    f"  Running {vuln.cve} container --privileged (namespace PoC)"
                )
            try:
                container = self.client.containers.run(
                    image_ref,
                    security_opt=_CONTAINER_SECURITY_OPT,  # allow userns/restricted syscalls
                    **_run_kwargs,
                )
            except Exception as sec_exc:
                # Host may not support the relaxed profile (e.g. AppArmor not
                # loaded). Don't let that break every run — retry without it
                # (userns-based PoCs just won't work on this host).
                self.logger.warning(
                    f"Run with relaxed security_opt failed ({sec_exc}); retrying "
                    f"without it for {vuln.cve}."
                )
                try:
                    self.client.containers.get(container_name).remove(force=True)
                except Exception:
                    pass
                container = self.client.containers.run(image_ref, **_run_kwargs)

            result = container.wait(timeout=run_timeout)
            exit_code = result.get('StatusCode', -1)
            logs = container.logs(stdout=True, stderr=True).decode('utf-8', errors='replace')

            try:
                container.remove(force=True)
            except Exception:
                pass

            self.logger.info(f"Container {container_name} exited with code {exit_code}")
            return exit_code, logs

        except ContainerError as e:
            self.logger.warning(f"Container error for {vuln.cve}: {e}")
            return (e.exit_status if e.exit_status is not None else -1), str(e)
        except Exception as e:
            logs = ""
            if container is not None:
                try:
                    container.stop(timeout=5)
                except Exception:
                    pass
                try:
                    logs = container.logs(stdout=True, stderr=True).decode('utf-8', errors='replace')
                except Exception:
                    logs = ""
                try:
                    container.remove(force=True)
                except Exception:
                    pass
            if "timed out" in str(e).lower() or "timeout" in str(e).lower():
                self.logger.warning(
                    f"Container for {vuln.cve} timed out after {run_timeout}s "
                    f"(PoC may hang or trigger deadlock). Partial logs: {logs[:500]}"
                )
                # A timeout (exit -1) is surfaced to the caller. For DoS-class
                # CVEs a hang/deadlock is itself the reproduction; the caller
                # routes ambiguous timeouts to manual revision.
                return -1, f"TIMEOUT after {run_timeout}s (PoC caused hang/deadlock). Partial output: {logs}"
            self.logger.error(f"Failed to run container for {vuln.cve}: {e}")
            return -1, str(e)

    def _extract_result_record(self, logs: str) -> dict:
        """Parse the SSD_RESULT marker and captured PoC output from container logs.

        Returns a dict with keys:
            exit_code     – int or None (parsed from the marker, if present)
            category      – str or None
            poc_output    – text between the BEGIN/END POC OUTPUT markers, or the
                            full logs when the markers are absent (e.g. the
                            wrapper crashed before emitting them).
            marker_present – True if the wrapper ran to completion and emitted
                            its SSD_RESULT marker. When False, the container
                            exit code is NOT a trustworthy baseline (the harness
                            itself did not finish — crash, container error, etc.).
        """
        record = {"exit_code": None, "category": None, "poc_output": None,
                  "marker_present": False}

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
                                run_timeout: int = 300) -> Tuple[int, str]:
        """Run a container from an explicit image tag (used by Phase 0 CVE images).

        Returns (exit_code, logs). The image is NOT removed after execution —
        persisted for Phase 3. No verdict is computed here (methodology v2);
        the host decides reproduction via baseline matching + negative filter.
        """
        container_name = f"ai-ssd-{vuln.cve.lower()}-run"
        return self._run_image(image_tag, container_name, vuln, run_timeout)

    def read_poc_uses_build(self, image_tag: str,
                            install_prefix: str = "/opt/project-build") -> Optional[str]:
        """Read the /poc/.ssd_poc_uses_build marker baked into C-PoC images.

        Falls back to a live ldd check when the marker file is absent (cached
        images built before this check was introduced).  Returns "yes"/"no",
        or None when the check cannot be determined (interpreted PoCs, missing
        binary, etc.).
        """
        try:
            raw = self.client.containers.run(
                image_tag,
                command="cat /poc/.ssd_poc_uses_build",
                entrypoint="",
                remove=True,
                network_disabled=True,
            ).decode("utf-8", errors="replace").strip()
            if raw in ("yes", "no"):
                return raw
        except Exception:
            pass
        # Marker absent (image pre-dates the marker) — run the SAME runtime check
        # live so cached CVE images are still gated consistently: does running
        # the PoC under the project's own loader (or LD_LIBRARY_PATH) map the
        # project libc? Keep in sync with the Dockerfile marker + Phase 3.
        try:
            cmd = (
                f"LOADER=$(find {install_prefix}/lib -maxdepth 1 -name 'ld-*.so*' "
                f"2>/dev/null | head -1); USES=no; "
                f"if [ -n \"$LOADER\" ] && \"$LOADER\" --library-path {install_prefix}/lib "
                f"--list /poc/exploit 2>/dev/null | grep -q {install_prefix}; then USES=yes; "
                f"elif LD_LIBRARY_PATH={install_prefix}/lib ldd /poc/exploit 2>/dev/null "
                f"| grep -q {install_prefix}; then USES=yes; fi; echo $USES"
            )
            raw = self.client.containers.run(
                image_tag,
                command=["sh", "-c", cmd],
                entrypoint="",
                remove=True,
                network_disabled=True,
            ).decode("utf-8", errors="replace").strip()
            return raw if raw in ("yes", "no") else None
        except Exception:
            return None

    def read_build_status(self, image_tag: str) -> Dict[str, str]:
        """Read key=value build markers baked into the image, if present."""
        try:
            raw = self.client.containers.run(
                image_tag,
                command="cat /build/build_status",
                entrypoint="",
                remove=True,
                network_disabled=True,
            ).decode("utf-8", errors="replace")
        except Exception:
            return {}

        status: Dict[str, str] = {}
        for line in raw.splitlines():
            if "=" not in line:
                continue
            key, _, value = line.partition("=")
            key = key.strip()
            value = value.strip()
            if key:
                status[key] = value
        return status

    def run_intree_sanity(self, image_tag: str, sanity_check: str,
                          run_timeout: int = 120) -> Tuple[Optional[bool], str]:
        """Gate A: run the project's loader/runtime sanity probe in the image.

        The probe (a project-supplied shell snippet, env-driven like the
        build/run scripts) must exit 0 iff the *built* runtime can start a
        trivial process. Returns (ok, logs): ok=True (exit 0), ok=False
        (non-zero — runtime broken, e.g. a miscompiled loader that SIGSEGVs at
        startup), or ok=None if the probe could not be run (treated as "skip
        gate"). Project-agnostic: the command lives entirely in YAML.
        """
        container = None
        try:
            container = self.client.containers.run(
                image_tag,
                command=["bash", "-c", sanity_check],
                entrypoint="",
                detach=True,
                network_disabled=True,
            )
            res = container.wait(timeout=run_timeout)
            exit_code = res.get("StatusCode", 1) if isinstance(res, dict) else 1
            logs = container.logs().decode("utf-8", errors="replace")
            return (exit_code == 0), logs
        except Exception as e:
            return None, f"sanity probe could not run: {e}"
        finally:
            if container is not None:
                try:
                    container.remove(force=True)
                except Exception:
                    pass


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
        needs_review = sum(1 for r in self.results if r.status == ExecutionStatus.NEEDS_REVIEW.value)
        successful = sum(1 for r in self.results if r.vulnerability_reproduced)

        report_data = {
            "metadata": {
                "generated_at": datetime.now().isoformat(),
                "phase": "Phase 1 - Vulnerability Reproduction",
                "total_vulnerabilities": len(self.results),
                "successful_reproductions": successful,
                "needs_manual_revision": needs_review,
                # Hard build failures only (base-image/toolchain construction
                # errors → BUILD_ERROR status). Per-CVE compile failures now
                # route to manual revision, so `not build_success` would
                # double-count manual-revision/no-commit CVEs that never
                # attempted (or were diverted from) a build.
                "failed_builds": build_errors,
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
                "needs_manual_revision": needs_review,
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
            if result.vulnerability_reproduced:
                status_icon = "✓"
            elif result.status == ExecutionStatus.NEEDS_REVIEW.value:
                status_icon = "⚠"
            else:
                status_icon = "✗"
            extra = ""
            if result.vulnerability_reproduced and result.baseline_exit_code is not None:
                extra = f" (baseline exit={result.baseline_exit_code})"
            print(f"{status_icon} {result.cve}: {result.status}{extra}")
            if result.error_message:
                print(f"    Error: {result.error_message[:100]}...")

        print("-" * 60)
        total = len(self.results)
        success = sum(1 for r in self.results if r.vulnerability_reproduced)
        review = sum(1 for r in self.results if r.status == ExecutionStatus.NEEDS_REVIEW.value)
        print(f"Total: {total} | Reproduced: {success} | "
              f"Manual revision: {review} | Failed: {total - success - review}")
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
        # Baseline memoization is ON by default; --force-baseline re-measures
        # even when an identical-image/identical-policy baseline already exists.
        self.force_baseline = getattr(args, 'force_baseline', False)
        self.specific_cve = args.cve
        self.dry_run = getattr(args, 'dry_run', False)
        self.skipped_cves = getattr(args, 'skipped_cves', []) or []

        # Load Phase 0 config and resolve all project-specific Phase 1 settings
        phase0_config_path = getattr(args, 'phase0_config', None)
        if phase0_config_path:
            phase0_config_path = Path(phase0_config_path)
        raw_cfg = _load_phase0_config(phase0_config_path)
        self._p1 = _resolve_phase1_settings(raw_cfg, self.base_dir)
        self._arch_fallback_enabled = bool(self._p1.get("enable_arch_fallback", True))
        # Phase 1 determinism guard: run the baseline PoC multiple times and
        # require agreement before trusting the exit code (kills flaky baselines).
        self._baseline_runs, self._baseline_min_agree = _load_baseline_policy()


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
            version_file=self._p1["version_file"],
            version_regex=self._p1["version_regex"],
            version_era_map=self._p1["version_era_map"],
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
            base_packages=self._p1.get("base_packages"),
            base_packages_optional=self._p1.get("base_packages_optional"),
            base_setup=self._p1.get("base_setup"),
        )
        self._cve_builder = CVEImageBuilder(
            self.docker_mgr.client, self.logger, self.build_timeout,
            source_dir_name=self._p1["source_dir_name"],
            build_dir_name=self._p1["build_dir_name"],
            install_prefix=self._p1["install_prefix"],
            docker_platform=self._p1.get("docker_platform"),
            poc_run_env=self._p1.get("poc_run_env", {}),
        )
        self._manifest = ImageManifest(self._p1["image_manifest_path"], self.logger)
        self.poc_analyzer = PoCAnalyzer(self.logger)
        # Manual-revision queue for PoCs the negative filter flags or for which
        # no baseline exit code could be established (methodology v2).
        self._manual_dir = self.base_dir / "manual_supervision"
    
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
            self._manifest.add_cve_image(
                vuln, vuln.cve_image_tag, status,
                baseline_exit_code=result.baseline_exit_code,
                needs_manual_revision=result.needs_manual_revision,
                poc_uses_project_build=result.poc_uses_project_build,
                baseline_cache_key=result.baseline_cache_key,
            )
            
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
    
    def _flag_for_manual_revision(self, vuln: VulnerabilityInfo, reason: str,
                                  poc_output: str, exit_code: Optional[int]) -> None:
        """Write a manual-revision marker for a flagged PoC (methodology v2).

        A human reviewer inspects the captured output to decide whether the run
        is a true non-reproduction, a recoverable environment issue, or a PoC
        that needs adaptation. Approving works the same way as Phase 0 review:
        remove/annotate the marker (or touch ``<CVE>.ok``).
        """
        try:
            manual_dir = getattr(self, "_manual_dir", None) or (self.base_dir / "manual_supervision")
            manual_dir.mkdir(parents=True, exist_ok=True)
            marker = manual_dir / f"{vuln.cve}.phase1-review.txt"
            snippet = (poc_output or "")[:4000]
            marker.write_text(
                f"CVE: {vuln.cve}\n"
                f"Phase: 1 (reproduction / baseline)\n"
                f"Flagged at: {datetime.now().isoformat()}\n"
                f"PoC exit code: {exit_code}\n"
                f"Reason: {reason}\n"
                f"Commit: {vuln.commit_hash}\n"
                f"PoC path: {vuln.poc_path}\n"
                f"\n--- Captured PoC output (truncated) ---\n{snippet}\n"
            )
            self.logger.warning(
                f"  {vuln.cve}: routed to MANUAL REVISION → {marker}"
            )
        except Exception as e:
            self.logger.error(f"Failed to write manual-revision marker for {vuln.cve}: {e}")

    def _try_i386_rebuild(self, vuln: VulnerabilityInfo, poc_path: Path,
                          poc_language: str, poc_metadata: dict) -> Optional[str]:
        """Rebuild this CVE's image 32-bit (i386) and re-check the honesty gate.

        Used as a general arch fallback when a 64-bit build cannot establish a
        baseline (PoC won't link the project libc, or runs without any signal):
        some glibc bugs only manifest on 32-bit (integer-overflow width, i686
        multiarch asm paths). Mutates ``vuln.build_arch`` to "i386" so the
        derived image tag, configure flags, and PoC compile all switch to 32-bit.

        Returns the new ``poc_uses_project_build`` value ("yes"/"no"/None) on a
        successful build, or None when the fallback does not apply or the 32-bit
        build itself fails (in which case ``build_arch`` is reverted to amd64 so
        the caller keeps the original 64-bit image/result).
        """
        if (poc_language or "").lower() != "c":
            return None
        if not self._arch_fallback_enabled or vuln.build_arch == "i386":
            return None
        self.logger.warning(
            f"  {vuln.cve}: 64-bit baseline inconclusive — trying 32-bit (i386) build"
        )
        original_arch = vuln.build_arch
        vuln.build_arch = "i386"
        base_tag = vuln.base_image_tag  # same Ubuntu era; base carries multilib
        ok, _logs = self._cve_builder.build_cve_image(
            vuln, base_tag, poc_path, poc_language, poc_metadata
        )
        if not ok:
            self.logger.warning(
                f"  {vuln.cve}: 32-bit build failed — reverting to amd64 result"
            )
            vuln.build_arch = original_arch
            return None
        install_prefix = self._p1.get("install_prefix", _DEFAULT_INSTALL_PREFIX)
        uses = self.docker_mgr.read_poc_uses_build(
            vuln.cve_image_tag, install_prefix=install_prefix
        )
        self.logger.info(f"  {vuln.cve}: 32-bit build poc_uses_project_build={uses}")
        return uses

    @staticmethod
    def _fmt_sig_counts(sig_counts: dict) -> str:
        """Render observed baseline run signatures for logs/markers."""
        parts = []
        for (exit_code, marker, is_timeout), n in sig_counts.items():
            if is_timeout:
                label = "timeout"
            elif not marker:
                label = f"exit={exit_code}(no-marker)"
            else:
                label = f"exit={exit_code}"
            parts.append(f"{label}×{n}")
        return ", ".join(parts) if parts else "(none)"

    def _baseline_cache_key(self, cve_tag: str) -> str:
        """Fingerprint that says when a captured baseline may be reused.

        Combines the image's baked ``poc_signature`` (an identical signature
        means identical vulnerable build + PoC + run wrapper) with the runtime
        policy that shapes the verdict: ``run_timeout`` (a shorter/longer
        timeout can flip a hang into a completion or vice-versa), the container
        memory ceiling (an OOM-kill at a lower limit changes the exit code) and
        the determinism budget (``baseline_runs``/``baseline_min_agree``). A
        change to ANY of these can legitimately change the baseline, so it must
        invalidate the memo. Returns ``""`` when the signature is unavailable
        (older/missing image), which disables memoization for that CVE.
        """
        try:
            labels = self.docker_mgr.client.images.get(cve_tag).labels or {}
        except Exception:
            return ""
        sig = labels.get("ai-ssd.poc_signature", "")
        if not sig:
            return ""
        return (
            f"sig={sig}|rt={self.run_timeout}|mem={_CONTAINER_MEM_LIMIT}"
            f"|runs={self._baseline_runs}|agree={self._baseline_min_agree}"
        )

    def _lookup_memoized_baseline(self, vuln: VulnerabilityInfo, cve_tag: str,
                                  current_key: str) -> Optional[dict]:
        """Return a prior manifest entry whose baseline can be reused, else None.

        Conservative by design: only a prior *reproduced* baseline — one with a
        concrete ``baseline_exit_code`` that was NOT routed to manual revision —
        for the SAME image tag (so Phase 3 still derives from it) under an
        identical cache key is reused. Non-reproduced / manual-revision outcomes
        are always re-measured (they are usually cheap, and re-running keeps the
        door open for a flaky PoC to stabilize). The manifest is loaded from the
        previous run in ``ImageManifest.__init__``; ``add_cve_image`` only
        overwrites this CVE's entry AFTER this method runs.
        """
        if not current_key:
            return None
        for entry in self._manifest.data.get("cve_images", []):
            if entry.get("cve") != vuln.cve:
                continue
            if entry.get("needs_manual_revision"):
                return None
            if entry.get("baseline_exit_code") is None:
                return None
            if entry.get("tag") != cve_tag:
                return None
            if entry.get("baseline_cache_key") != current_key:
                return None
            return entry
        return None

    def _capture_baseline(self, vuln: VulnerabilityInfo, cve_tag: str):
        """Run the baseline PoC repeatedly until its exit-code signature is
        stable, so Phase 3 is never seeded with a flaky baseline.

        A run's *signature* is ``(poc_exit_code, marker_present, is_timeout)``.
        The PoC runs up to ``self._baseline_runs`` times. Acceptance is
        signature-dependent:

        * **Crash / explicit exit codes** (non-timeout): accepted as soon as
          ``self._baseline_min_agree`` runs share the signature (early-stop).
        * **Timeout / ``-1`` baselines**: the weakest, coarsest signal, so they
          require **unanimity** — *every* run must time out. A single non-hang
          run (e.g. the container dying, or a one-off slow run) demotes the CVE
          to manual revision. (Never early-stops on a timeout.)

        With ``baseline_runs: 1`` both rules collapse to the original single-run
        behaviour. General — no per-CVE logic.

        Returns ``(chosen, sig_counts, runs)``: ``chosen`` is the agreed run
        dict, or ``None`` when no signature met its acceptance bar
        (flaky/non-deterministic); ``runs`` holds every run for fallback
        reporting.
        """
        from collections import Counter
        runs: List[dict] = []
        sig_counts: Counter = Counter()
        max_runs = self._baseline_runs
        min_agree = self._baseline_min_agree

        for i in range(max_runs):
            exit_code, run_logs = self.docker_mgr.run_container_from_tag(
                vuln, cve_tag, self.run_timeout
            )
            record = self.docker_mgr._extract_result_record(run_logs)
            marker_present = record.get("marker_present", False)
            poc_exit = record.get("exit_code")
            if poc_exit is None:
                poc_exit = exit_code
            is_timeout = (not marker_present) and ("TIMEOUT" in run_logs)
            sig = (poc_exit, marker_present, is_timeout)
            run = {
                "poc_exit_code": poc_exit, "run_logs": run_logs, "record": record,
                "marker_present": marker_present, "is_timeout": is_timeout, "sig": sig,
            }
            runs.append(run)
            sig_counts[sig] += 1
            self.logger.info(
                f"  Baseline run {i + 1}/{max_runs}: exit={poc_exit} "
                f"marker={marker_present} timeout={is_timeout}"
            )
            # Early-accept ONLY a signature where the wrapper actually completed
            # and reported a verdict (marker_present): a reproducible crash /
            # explicit exit is trustworthy at min_agree. Timeouts (marker absent)
            # need unanimity, and infra failures (marker absent, not a timeout —
            # e.g. the container dying) are never a valid baseline on their own;
            # both fall through to the stricter end-of-loop logic.
            if marker_present and sig_counts[sig] >= min_agree:
                chosen = next(r for r in runs if r["sig"] == sig)
                if max_runs > 1:
                    self.logger.info(
                        f"  {vuln.cve}: baseline stable after {i + 1} run(s) "
                        f"(signature seen {sig_counts[sig]}×)"
                    )
                return chosen, dict(sig_counts), runs

        # Loop exhausted without an early-accepted crash signature. The only
        # remaining way to accept is a UNANIMOUS timeout (every run hung).
        timeout_sig = (-1, False, True)
        if sig_counts.get(timeout_sig, 0) == max_runs and max_runs >= 1:
            chosen = next(r for r in runs if r["sig"] == timeout_sig)
            self.logger.info(
                f"  {vuln.cve}: baseline is a UNANIMOUS timeout "
                f"({max_runs}/{max_runs} runs hung)"
            )
            return chosen, dict(sig_counts), runs

        return None, dict(sig_counts), runs

    def _process_intree_test(self, vuln: VulnerabilityInfo,
                             result: ExecutionResult, start_time) -> ExecutionResult:
        """Option A: reproduce via the fixing commit's regression test, run in-tree.

        Builds the vulnerable tree, overlays the test, runs `make test`. The test
        FAILING on the vulnerable build IS the reproduction; if it PASSES it does
        not discriminate under this build config → manual (no false baseline).
        """
        try:
            if not (vuln.commit_hash or "").strip() or not vuln.fix_commit or not vuln.test_path:
                reason = ("In-tree test missing commit/fix/test metadata — cannot "
                          "build the regression-test reproducer")
                self.logger.warning(f"  {vuln.cve}: {reason} → manual revision")
                result.status = ExecutionStatus.NEEDS_REVIEW.value
                result.needs_manual_revision = True
                result.error_message = reason
                self._flag_for_manual_revision(vuln, reason, "", None)
                return result

            base_tag = self._base_builder.ensure_base_image(vuln.ubuntu_version)
            if not base_tag:
                reason = f"Base image unavailable for ubuntu {vuln.ubuntu_version}"
                self.logger.warning(f"  {vuln.cve}: {reason} → manual revision")
                result.status = ExecutionStatus.NEEDS_REVIEW.value
                result.needs_manual_revision = True
                result.error_message = reason
                self._flag_for_manual_revision(vuln, reason, "", None)
                return result

            self.logger.info(
                f"  [intree-test] {vuln.test_path} (fix {vuln.fix_commit[:12]}) "
                f"on ubuntu {vuln.ubuntu_version}"
            )
            ok, logs = self._cve_builder.build_intree_test_image(
                vuln, base_tag,
                build_script=self._p1.get("intree_build_script"),
                run_script=self._p1.get("intree_run_script"),
            )
            if not ok:
                reason = (f"In-tree test image could not be built: {logs or 'build/overlay failed'}"
                          if logs and "no in-tree-test recipe" in (logs or "")
                          else "In-tree test image build failed (build script or test overlay)")
                self.logger.warning(f"  {vuln.cve}: {reason} → manual revision")
                result.status = ExecutionStatus.NEEDS_REVIEW.value
                result.needs_manual_revision = True
                result.error_message = logs
                self._flag_for_manual_revision(vuln, reason, (logs or "")[-4000:], None)
                return result

            result.build_success = True
            result.poc_uses_project_build = "yes"

            exit_code, run_logs = self.docker_mgr.run_container_from_tag(
                vuln, vuln.cve_image_tag, self.run_timeout
            )
            result.poc_executed = True
            result.container_logs = run_logs

            marker = None
            for line in run_logs.splitlines():
                if "SSD_TEST_RESULT=" in line:
                    marker = line.split("SSD_TEST_RESULT=", 1)[1].strip().split()[0]
            self.logger.info(f"  [intree-test] result={marker} (container exit={exit_code})")

            # Gate A: a "FAIL" only reproduces the bug if the test actually ran.
            # A miscompiled loader (e.g. old glibc built on a too-new base) can
            # SIGSEGV at startup before main, producing a FAIL that has nothing
            # to do with the CVE. Verify the built runtime can start a trivial
            # process; if not, the baseline is untrustworthy → manual revision.
            sanity_check = self._p1.get("intree_sanity_check")
            if marker == "FAIL" and sanity_check:
                ok, sanity_logs = self.docker_mgr.run_intree_sanity(
                    vuln.cve_image_tag, sanity_check, self.run_timeout
                )
                if ok is False:
                    reason = ("Built runtime fails a trivial-process sanity check "
                              "(loader/runtime broken — likely an era/toolchain "
                              "mismatch); the test's FAIL is not the CVE. No baseline.")
                    self.logger.warning(f"  {vuln.cve}: {reason} → manual revision")
                    result.status = ExecutionStatus.NEEDS_REVIEW.value
                    result.needs_manual_revision = True
                    result.error_message = reason
                    self._flag_for_manual_revision(
                        vuln, reason, (sanity_logs or "")[-4000:], exit_code)
                    result.execution_time_seconds = (datetime.now() - start_time).total_seconds()
                    return result
                if ok is None:
                    self.logger.info(
                        f"  {vuln.cve}: runtime sanity probe could not run "
                        f"(continuing without gate)")

            if marker == "FAIL":
                result.baseline_exit_code = 1  # sentinel: test FAILS on vulnerable
                result.vulnerability_reproduced = True
                result.status = ExecutionStatus.SUCCESS.value
                self.logger.info(
                    f"  {vuln.cve}: reproduced — regression test FAILS on the "
                    f"vulnerable build (Phase 3: a correct patch makes it PASS)"
                )
            elif marker == "PASS":
                reason = ("Regression test PASSES on the vulnerable build — it does "
                          "not reproduce the bug under this build config (crash-reliant "
                          "test with protections disabled, or wrong commit). No baseline.")
                self.logger.warning(f"  {vuln.cve}: {reason} → manual revision")
                result.status = ExecutionStatus.NEEDS_REVIEW.value
                result.needs_manual_revision = True
                result.error_message = reason
                self._flag_for_manual_revision(vuln, reason, run_logs[-4000:], exit_code)
            else:
                reason = (f"In-tree test produced no PASS/FAIL result "
                          f"(marker={marker}, exit={exit_code}) — build/run error")
                self.logger.warning(f"  {vuln.cve}: {reason} → manual revision")
                result.status = ExecutionStatus.NEEDS_REVIEW.value
                result.needs_manual_revision = True
                result.error_message = reason
                self._flag_for_manual_revision(vuln, reason, run_logs[-4000:], exit_code)

        except Exception as e:
            self.logger.exception(f"Error processing in-tree test {vuln.cve}")
            result.status = ExecutionStatus.UNKNOWN_ERROR.value
            result.error_message = str(e)
        finally:
            result.execution_time_seconds = (datetime.now() - start_time).total_seconds()
        return result

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
        
        # Option A: in-tree regression-test reproducer takes a dedicated path
        # (build vulnerable tree + overlay the fix's test + `make test`).
        if vuln.is_intree_test:
            return self._process_intree_test(vuln, result, start_time)

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

            # Step 1b: Static pre-flight validation (Phase 1.3 gate)
            preflight = self.poc_analyzer.validate_poc_static(poc_path, vuln.cve)
            self.logger.info(
                f"  Static validation: valid={preflight['is_valid']} "
                f"type={preflight['file_type']} intent={preflight['has_exploit_intent']} "
                f"entrypoint={preflight['has_entrypoint']} cve_match={preflight['cve_match']} "
                f"reason={preflight['reason']!r}"
            )
            if not preflight["is_valid"]:
                # The static pre-flight is heuristic (min line count, keyword
                # "exploit intent", entrypoint regex) and can REJECT a terse but
                # legitimate PoC. Route to manual revision so a human sees it,
                # rather than silently dropping the CVE as "PoC not found".
                reason = f"Pre-flight validation flagged the PoC: {preflight['reason']}"
                self.logger.warning(
                    f"  {vuln.cve}: {reason} → manual revision"
                )
                result.status = ExecutionStatus.NEEDS_REVIEW.value
                result.needs_manual_revision = True
                result.vulnerability_reproduced = False
                result.error_message = reason
                self._flag_for_manual_revision(vuln, reason, "", None)
                return result

            # Detect (from PoC source) whether this exploit builds namespaces and
            # so needs a privileged container to run (general, no per-CVE logic).
            try:
                _poc_src = poc_path.read_text(errors="ignore")
            except Exception:
                _poc_src = ""
            vuln.needs_privileged = poc_needs_privileged(_poc_src)
            if vuln.needs_privileged:
                self.logger.info(
                    f"  {vuln.cve}: PoC builds namespaces — container will run privileged"
                )

            # Step 2: Build CVE image (derived from base)
            # Detect PoC language from CSV or file extension, then reconcile
            # against the content-aware type from pre-flight validation.
            poc_language = vuln.poc_language or self.poc_mgr.detect_language(poc_path)

            # Defense-in-depth: if pre-flight found a different file type via
            # shebang/content inspection, trust that over the extension/CSV value.
            # Handles EDB mislabeled files (e.g. tcsh script saved as .php).
            _FILETYPE_TO_LANGUAGE = {
                "shell": "shell", "ruby_msf": "ruby", "ruby": "ruby",
                "python": "python", "php": "php", "c": "c",
            }
            preflight_lang = _FILETYPE_TO_LANGUAGE.get(preflight.get("file_type", ""), "")
            if preflight_lang and preflight_lang != poc_language:
                self.logger.info(
                    f"  Correcting poc_language: '{poc_language}' → '{preflight_lang}' "
                    f"(content-based, file_type={preflight['file_type']!r})"
                )
                poc_language = preflight_lang

            self.logger.info(f"  PoC language: {poc_language} ({poc_path.name})")

            # Extract PoC metadata via LLM (or heuristics). Pass the vulnerable-
            # function context so the analyzer can synthesize a driver for
            # payload-generator PoCs that don't self-trigger the bug.
            poc_metadata = self.poc_analyzer.analyze_poc(
                poc_path, cve=vuln.cve,
                vuln_function=vuln.function_name, vuln_file=vuln.file_path,
            )

            self.logger.info(f"  PoC category: {poc_metadata.get('poc_category', 'UNKNOWN')}")

            # Methodology guard: a deterministic baseline requires a *known-
            # vulnerable* build, which requires the fixing commit's vulnerable
            # parent. With no commit hash the CVE image would fall back to
            # building project HEAD (a patched, arbitrary version) — which both
            # fails to configure on old toolchains AND is methodologically
            # invalid. Route to manual revision instead of a doomed build.
            if not (vuln.commit_hash or "").strip():
                reason = ("No fixing commit recorded by Phase 0 — cannot establish "
                          "a known-vulnerable build for a deterministic baseline")
                self.logger.warning(f"  {vuln.cve}: {reason} → manual revision")
                result.status = ExecutionStatus.NEEDS_REVIEW.value
                result.needs_manual_revision = True
                result.vulnerability_reproduced = False
                result.error_message = reason
                self._flag_for_manual_revision(vuln, reason, "", None)
                return result

            base_tag = vuln.base_image_tag
            success, build_logs = self._cve_builder.build_cve_image(
                vuln, base_tag, poc_path, poc_language, poc_metadata
            )
            
            if not success:
                # A known-vulnerable build that cannot be CONSTRUCTED (toolchain/
                # arch mismatch, all compile strategies exhausted, missing libs)
                # is the same methodological dead-end as a missing fixing commit:
                # without a buildable vulnerable image there is no deterministic
                # baseline to establish. Route to manual revision (with the build
                # logs attached) rather than leaving a silent terminal error that
                # no human is told to inspect.
                reason = ("Could not construct a known-vulnerable build "
                          "(compilation/environment failure) — cannot establish "
                          "a deterministic baseline")
                self.logger.warning(f"  {vuln.cve}: {reason} → manual revision")
                result.status = ExecutionStatus.NEEDS_REVIEW.value
                result.needs_manual_revision = True
                result.vulnerability_reproduced = False
                result.error_message = build_logs
                self._flag_for_manual_revision(vuln, reason, build_logs or "", None)
                return result

            build_status = self.docker_mgr.read_build_status(vuln.cve_image_tag)
            if build_status.get("PROJECT_LIBC_INSTALLED") == "no":
                status_bits = []
                for key in ("PROJECT_BUILD_EXIT_CODE", "PROJECT_INSTALL_EXIT_CODE"):
                    if build_status.get(key):
                        status_bits.append(f"{key}={build_status[key]}")
                reason = (
                    "Known-vulnerable image built, but the project did not install "
                    "a usable shared libc into the image, so the PoC cannot be "
                    "trusted to exercise the project build"
                )
                if status_bits:
                    reason = f"{reason} ({', '.join(status_bits)})"
                self.logger.warning(f"  {vuln.cve}: {reason} → manual revision")
                result.status = ExecutionStatus.NEEDS_REVIEW.value
                result.needs_manual_revision = True
                result.vulnerability_reproduced = False
                result.error_message = reason
                self._flag_for_manual_revision(
                    vuln,
                    reason,
                    (build_logs or "")[-4000:],
                    None,
                )
                return result

            result.build_success = True

            # Step 2b: Honesty gate — does the PoC actually exercise the project
            # build at RUNTIME? The run wrapper launches C PoCs through the
            # project's own loader (ld.so --library-path), so the marker records
            # whether that loader maps the project libc. If it cannot (e.g. a
            # static binary, or symbols irreconcilable with the build), no source
            # patch can ever change the PoC's behavior and any baseline captured
            # from it would be methodologically meaningless.
            _install_prefix = self._p1.get("install_prefix", _DEFAULT_INSTALL_PREFIX)
            result.poc_uses_project_build = self.docker_mgr.read_poc_uses_build(
                vuln.cve_image_tag, install_prefix=_install_prefix
            )

            # Era fallback: a tree that fails to produce a usable build on its
            # mapped era may build on the previous era's toolchain (e.g. 2012
            # glibc links fine under Ubuntu 12.04's binutils but not 14.04's).
            # One general retry, no per-CVE logic.
            if result.poc_uses_project_build == "no":
                fallback_version = next_older_ubuntu_version(vuln.ubuntu_version)
                if fallback_version:
                    self.logger.warning(
                        f"  {vuln.cve}: PoC fell back to system libraries on "
                        f"Ubuntu {vuln.ubuntu_version} — retrying build on the "
                        f"previous era (Ubuntu {fallback_version})"
                    )
                    fb_base_tag = self._base_builder.ensure_base_image(fallback_version)
                    if fb_base_tag:
                        if not any(b.get("ubuntu_version") == fallback_version
                                   for b in self._manifest.data["base_images"]):
                            self._manifest.add_base_image(fallback_version, fb_base_tag)
                        original_version = vuln.ubuntu_version
                        vuln.ubuntu_version = fallback_version
                        fb_success, _fb_logs = self._cve_builder.build_cve_image(
                            vuln, fb_base_tag, poc_path, poc_language, poc_metadata
                        )
                        if fb_success:
                            result.poc_uses_project_build = (
                                self.docker_mgr.read_poc_uses_build(
                                    vuln.cve_image_tag, install_prefix=_install_prefix
                                )
                            )
                        else:
                            # Keep the manifest pointing at the image that exists
                            vuln.ubuntu_version = original_version

            # Arch fallback: a PoC that still won't link the 64-bit project libc
            # may be 32-bit (i686 multiarch asm / 32-bit ABI). Rebuild i386 and
            # re-check the honesty gate. General, one bounded extra build.
            if result.poc_uses_project_build == "no":
                arch_uses = self._try_i386_rebuild(
                    vuln, poc_path, poc_language, poc_metadata
                )
                if arch_uses is not None:
                    result.poc_uses_project_build = arch_uses

            if result.poc_uses_project_build == "no":
                reason = ("PoC does not exercise the project build at runtime "
                          "(the project loader could not map the build's libc, on "
                          "the era image, the previous-era fallback, and a 32-bit "
                          "build) — a baseline captured from it cannot validate "
                          "source patches")
                self.logger.warning(f"  {vuln.cve}: {reason} → manual revision")
                result.status = ExecutionStatus.NEEDS_REVIEW.value
                result.needs_manual_revision = True
                result.vulnerability_reproduced = False
                result.error_message = reason
                self._flag_for_manual_revision(vuln, reason, "", None)
                return result
            if result.poc_uses_project_build == "yes":
                self.logger.info(f"  PoC links against the project build ✓")

            # Step 3: Run the PoC against the known-vulnerable build and capture
            # its exit code + output. The container computes no verdict.
            # (recomputed here: the era fallback may have changed the tag)
            #
            # Determinism guard: a memory bug can exit non-deterministically
            # (ASLR / heap layout / timing), so a single run could seed Phase 3
            # with a flaky baseline that makes the verdict a coin-flip. Run
            # repeatedly and require a stable exit-code signature before trusting
            # it; a PoC that never stabilizes is routed to manual revision.
            cve_tag = vuln.cve_image_tag

            # ---- Baseline memoization -----------------------------------------
            # Capturing the baseline re-runs the PoC up to ``baseline_runs``
            # times, each bounded by ``run_timeout`` — for a hang/timeout PoC
            # that is baseline_runs × run_timeout of pure waiting, the dominant
            # Phase 1 cost. When a prior run already established a baseline for an
            # IDENTICAL image (same baked poc_signature) under an identical
            # runtime policy, the verdict is reproducible by construction, so
            # reuse it instead of paying that cost again on every warm re-run.
            # --force-baseline skips the memo and re-measures from scratch.
            result.baseline_cache_key = self._baseline_cache_key(cve_tag)
            if not self.force_baseline:
                memo = self._lookup_memoized_baseline(
                    vuln, cve_tag, result.baseline_cache_key
                )
                if memo is not None:
                    result.poc_executed = True
                    result.baseline_exit_code = memo.get("baseline_exit_code")
                    result.vulnerability_reproduced = True
                    result.status = ExecutionStatus.SUCCESS.value
                    self.logger.info(
                        f"  {vuln.cve}: reusing memoized baseline "
                        f"(exit={result.baseline_exit_code}) — identical image + "
                        f"runtime policy; skipped up to "
                        f"{self._baseline_runs}×{self.run_timeout}s PoC re-run "
                        f"[--force-baseline to re-measure]"
                    )
                    return result
            # -------------------------------------------------------------------
            chosen, sig_counts, baseline_runs = self._capture_baseline(vuln, cve_tag)

            result.poc_executed = True

            if chosen is None:
                last_run = baseline_runs[-1] if baseline_runs else {}
                last_rec = last_run.get("record", {}) or {}
                fallback_output = (
                    (last_rec.get("poc_output") or "")
                    if last_run.get("marker_present")
                    else last_run.get("run_logs", "")
                )
                result.container_logs = last_run.get("run_logs")
                reason = (
                    f"Non-deterministic PoC — the exit-code signature did not "
                    f"stabilize across {self._baseline_runs} runs "
                    f"(observed {self._fmt_sig_counts(sig_counts)}); a single run "
                    f"cannot be trusted as a baseline for Phase 3 comparison"
                )
                self.logger.warning(f"  {vuln.cve}: {reason} → manual revision")
                result.status = ExecutionStatus.NEEDS_REVIEW.value
                result.needs_manual_revision = True
                result.vulnerability_reproduced = False
                result.error_message = reason
                self._flag_for_manual_revision(
                    vuln, reason, fallback_output,
                    last_run.get("poc_exit_code"),
                )
                return result

            run_logs = chosen["run_logs"]
            record = chosen["record"]
            marker_present = chosen["marker_present"]
            # When the wrapper completed (marker_present), pass ONLY the PoC's
            # own captured stdout to the negative filter — never the harness
            # wrapper text (which contains bash's "Killed" or other shell
            # diagnostics that the LLM would misread as exploit failure).
            # When the wrapper did NOT complete, fall back to the full logs so
            # the filter can see any environment error messages.
            if marker_present:
                poc_output = record.get("poc_output", "") or ""
            else:
                poc_output = run_logs
            # The wrapper-reported exit code (the PoC's own code), already
            # reconciled with the container StatusCode inside _capture_baseline.
            poc_exit_code = chosen["poc_exit_code"]

            result.container_logs = run_logs
            self.logger.info(
                f"  PoC exit code (baseline candidate): {poc_exit_code} "
                f"[stable across ≥{self._baseline_min_agree}/{self._baseline_runs} runs]"
            )

            # Step 4: LLM-assisted negative filter (safety net). It can only flag
            # an explicit failure → manual revision; it never asserts success.
            nf = self.poc_analyzer.negative_filter(
                poc_output, poc_exit_code, vuln.cve,
                poc_metadata.get("poc_category", "OTHER"),
            )
            result.negative_filter_flagged = nf["failed"]
            result.negative_filter_reason = nf["reason"]
            result.negative_filter_source = nf["source"]
            self.logger.info(
                f"  Negative filter [{nf['source']}]: "
                f"{'FLAGGED' if nf['failed'] else 'clear'} — {nf['reason']}"
            )

            if nf["failed"]:
                # Explicit failure detected → manual revision; no baseline registered.
                result.status = ExecutionStatus.NEEDS_REVIEW.value
                result.needs_manual_revision = True
                result.vulnerability_reproduced = False
                result.error_message = f"Negative filter flagged failure: {nf['reason']}"
                self._flag_for_manual_revision(
                    vuln, nf["reason"], poc_output, poc_exit_code
                )
            elif (not marker_present and poc_exit_code == -1
                    and "TIMEOUT" in run_logs
                    and poc_metadata.get("poc_category") in ("DOS", "FORMAT_STRING")):
                # Special case: the PoC caused a container timeout (run_timeout
                # exhausted, Docker killed the process). For DoS/FORMAT_STRING
                # categories a hang or infinite loop IS the vulnerability being
                # triggered (e.g. CVE-2012-3480 strtod infinite-loop). Register
                # the timeout as the baseline "success code" (-1 = timeout) so
                # Phase 3 can verify the patch stops the hang.
                result.baseline_exit_code = -1  # sentinel: "timed out"
                result.vulnerability_reproduced = True
                result.status = ExecutionStatus.SUCCESS.value
                self.logger.info(
                    f"  {vuln.cve}: DoS hang reproduced — PoC caused container "
                    f"timeout (baseline = -1/timeout)"
                )
            elif not marker_present or poc_exit_code is None or poc_exit_code < 0:
                # The wrapper did NOT run to completion for a non-DoS reason:
                # harness/container infrastructure failure, or exit -1 for a
                # non-timeout cause. Registering the raw container exit code as a
                # baseline here would be a false positive.
                if not marker_present and "TIMEOUT" in run_logs:
                    reason = ("Container timeout — PoC caused hang/deadlock (non-DoS "
                              "category; routing to manual revision for human confirmation)")
                elif not marker_present:
                    reason = ("Wrapper did not complete (no SSD_RESULT marker) — "
                              "harness/infrastructure failure, not a PoC verdict")
                else:
                    reason = "No baseline exit code (timeout / infrastructure error)"
                result.status = ExecutionStatus.NEEDS_REVIEW.value
                result.needs_manual_revision = True
                result.vulnerability_reproduced = False
                result.error_message = f"{reason} (exit={poc_exit_code})"
                self._flag_for_manual_revision(
                    vuln, reason, poc_output, poc_exit_code,
                )
            elif poc_exit_code == 137:
                # SIGKILL (128+9): the process was killed by the kernel/cgroup,
                # not by the bug. In this sandbox that is almost always an
                # OOM-kill — a memory-amplifying PoC exhausts the container memory
                # limit BEFORE the vulnerable code path diverges between the
                # vulnerable and patched builds (observed: CVE-2012-4412 feeds a
                # ~410 MB string into strcoll). A raw external kill is an
                # unreliable baseline: a correct patch may not change it (both
                # builds OOM at the same ceiling), so a 137==137 comparison can
                # never confirm a fix. Route to manual revision. Raising
                # docker.memory_limit lets genuine corruption bugs crash with a
                # real signal (SIGSEGV/SIGABRT) instead of hitting this path.
                reason = (
                    "PoC process was SIGKILL'd (exit 137) — almost certainly an "
                    "OOM/resource kill from the container memory limit, not a crash "
                    "caused by the bug. A baseline from an external kill is "
                    "unreliable (a patch may not change it). Raise "
                    "docker.memory_limit so the bug can crash with a real signal, "
                    "or confirm manually."
                )
                self.logger.warning(f"  {vuln.cve}: {reason} → manual revision")
                result.status = ExecutionStatus.NEEDS_REVIEW.value
                result.needs_manual_revision = True
                result.vulnerability_reproduced = False
                result.error_message = reason
                self._flag_for_manual_revision(vuln, reason, poc_output, poc_exit_code)
            elif (isinstance(poc_exit_code, int) and 0 <= poc_exit_code < 128
                  and result.negative_filter_source == "binary-abstain"):
                # Suspect/unconfirmed baseline: the PoC exited *voluntarily* (a
                # normal exit, not a crash signal) AND produced only non-textual
                # output, so the negative filter had zero readable evidence of
                # what happened. We cannot distinguish "vulnerability triggered"
                # from "PoC just ran and exited" — recording this would be a
                # FALSE reproduction that no patch can ever change (observed:
                # CVE-2009-5029's payload-generator PoC exits 65 with a binary
                # dump and never calls the vulnerable function). When a driver
                # could not be synthesized for such a PoC, route to manual
                # revision rather than register a meaningless baseline.
                reason = (
                    f"Unconfirmed baseline — the PoC produced only non-textual "
                    f"output and exited normally (exit={poc_exit_code}), so there "
                    f"is no evidence the vulnerable code path was exercised. Likely "
                    f"a payload generator that does not self-trigger the bug; a "
                    f"driver that feeds its output into the vulnerable subsystem is "
                    f"needed before a baseline can be trusted."
                )
                self.logger.warning(f"  {vuln.cve}: {reason} → manual revision")
                result.status = ExecutionStatus.NEEDS_REVIEW.value
                result.needs_manual_revision = True
                result.vulnerability_reproduced = False
                result.error_message = reason
                self._flag_for_manual_revision(vuln, reason, poc_output, poc_exit_code)
            elif poc_exit_code == 0:
                # A *clean* exit (0) on the known-vulnerable build is an
                # unvalidatable baseline: the PoC ran to completion with no crash,
                # hang, or error, so the vulnerability produced NO observable
                # signal — and a fix (which only makes the code more correct)
                # can't make the exit code differ from 0 either. So baseline==0
                # leads to a guaranteed 0==0 "PoC Still Works" no matter how good
                # the patch (observed: CVE-2012-4412's silent strcoll overflow,
                # whose recorded "vulnerable" commit is itself already mitigated).
                # Route to manual review instead of recording a false reproduction.
                #
                # Arch fallback first: a clean 0 on a 64-bit build can mean the
                # bug only manifests on 32-bit (integer-overflow width differs:
                # observed CVE-2012-4412's strcoll overflow needs i386). Rebuild
                # i386, re-run, and if the PoC now crashes/aborts with no explicit
                # failure, that 32-bit signal IS the baseline.
                arch_reproduced = False
                if (self._arch_fallback_enabled
                        and (poc_language or "").lower() == "c"
                        and vuln.build_arch != "i386"):
                    arch_uses = self._try_i386_rebuild(
                        vuln, poc_path, poc_language, poc_metadata
                    )
                    if arch_uses == "yes":
                        a_exit, a_logs = self.docker_mgr.run_container_from_tag(
                            vuln, vuln.cve_image_tag, self.run_timeout
                        )
                        a_rec = self.docker_mgr._extract_result_record(a_logs)
                        a_marker = a_rec.get("marker_present", False)
                        a_out = a_rec.get("poc_output", "") if a_marker else a_logs
                        a_code = a_rec.get("exit_code")
                        if a_code is None:
                            a_code = a_exit
                        a_nf = self.poc_analyzer.negative_filter(
                            a_out, a_code, vuln.cve,
                            poc_metadata.get("poc_category", "OTHER"),
                        )
                        result.container_logs = a_logs
                        if (a_marker and isinstance(a_code, int)
                                and 0 < a_code < 256 and a_code != 137
                                and not a_nf["failed"]):
                            result.baseline_exit_code = a_code
                            result.vulnerability_reproduced = True
                            result.status = ExecutionStatus.SUCCESS.value
                            result.poc_uses_project_build = "yes"
                            result.negative_filter_flagged = a_nf["failed"]
                            result.negative_filter_reason = a_nf["reason"]
                            result.negative_filter_source = a_nf["source"]
                            self.logger.info(
                                f"  {vuln.cve}: reproduced on 32-bit build — "
                                f"baseline success code = {a_code}"
                            )
                            arch_reproduced = True

                if not arch_reproduced:
                    reason = (
                        "PoC exits cleanly (0) on the vulnerable build — no observable "
                        "vulnerability signal (no crash/hang/error), so a patch cannot "
                        "be validated by exit-code difference. Likely the recorded "
                        "vulnerable commit is not genuinely vulnerable, or the bug is "
                        "silent (needs a sanitizer/assertion to surface)."
                    )
                    self.logger.warning(f"  {vuln.cve}: {reason} → manual revision")
                    result.status = ExecutionStatus.NEEDS_REVIEW.value
                    result.needs_manual_revision = True
                    result.vulnerability_reproduced = False
                    result.error_message = reason
                    self._flag_for_manual_revision(vuln, reason, poc_output, poc_exit_code)
            else:
                # Primary validation: the captured exit code IS the baseline
                # "success code" for this PoC on the known-vulnerable build.
                result.baseline_exit_code = poc_exit_code
                result.vulnerability_reproduced = True
                result.status = ExecutionStatus.SUCCESS.value
                self.logger.info(
                    f"  {vuln.cve}: reproduced — baseline success code = {poc_exit_code}"
                )
        
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

    parser.add_argument(
        '--force-baseline',
        action='store_true',
        help='Re-measure the Phase 1 baseline even when an identical-image, '
             'identical-policy baseline is already recorded (disables baseline '
             'memoization for this run)'
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
