"""
Git utility functions for the CVE Aggregator pipeline.

Provides generic helpers for cloning, pulling, searching commit history,
reading file content at specific commits, etc.  All operations take the
repository path as an explicit argument so they are project-agnostic.
"""

from __future__ import annotations

import logging
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Repository management
# ---------------------------------------------------------------------------

def _cleanup_failed_clone(local_path: Path) -> None:
    """Remove a partially-cloned directory so the next run starts fresh."""
    import shutil
    if local_path.exists():
        try:
            shutil.rmtree(local_path)
            logger.info("Removed incomplete clone at %s", local_path)
        except Exception as exc:
            logger.warning("Could not remove %s: %s", local_path, exc)


def clone_or_update_repo(
    local_path: Path,
    remote_url: str,
    *,
    clone_timeout: int = 1800,
    pull_timeout: int = 600,
) -> bool:
    """Clone a repo if it doesn't exist, or ``git pull`` if it does.

    Returns True on success, False otherwise.
    """
    local_path = Path(local_path)

    if not local_path.exists():
        logger.info("Repository not found at %s – cloning from %s …", local_path, remote_url)
        try:
            result = subprocess.run(
                ["git", "clone", remote_url, str(local_path)],
                capture_output=True, text=True, timeout=clone_timeout,
            )
            if result.returncode != 0:
                logger.error("Clone failed: %s", result.stderr)
                # Remove the partially-cloned directory so the next run
                # starts fresh instead of finding a broken repo.
                _cleanup_failed_clone(local_path)
                return False

            logger.info("Full clone successful")
            return True
        except subprocess.TimeoutExpired:
            logger.error("Clone timed out after %ds", clone_timeout)
            _cleanup_failed_clone(local_path)
            return False
        except Exception as exc:
            logger.error("Clone error: %s", exc)
            _cleanup_failed_clone(local_path)
            return False

    # Existing repo – pull
    if not (local_path / ".git").exists():
        logger.error("Path is not a git repository: %s", local_path)
        return False

    # Detect a broken clone (e.g. interrupted clone left an unborn branch).
    # In this state ``git pull`` will always fail with "Updating an unborn
    # branch …", so we remove the directory and fall through to a fresh clone.
    try:
        head_check = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=local_path, capture_output=True, text=True, timeout=10,
        )
        if head_check.returncode != 0:
            logger.warning(
                "Repository at %s appears corrupted (HEAD unresolvable). "
                "Removing and re-cloning …",
                local_path,
            )
            import shutil
            shutil.rmtree(local_path)
            return clone_or_update_repo(
                local_path, remote_url,
                clone_timeout=clone_timeout, pull_timeout=pull_timeout,
            )
    except Exception as exc:
        logger.warning("HEAD check failed (%s) – attempting pull anyway", exc)

    try:
        # Stash any local/unstaged changes so pull --rebase can proceed
        stash_result = subprocess.run(
            ["git", "stash", "--include-untracked"],
            cwd=local_path, capture_output=True, text=True, timeout=30,
        )
        stashed = stash_result.returncode == 0 and "No local changes" not in stash_result.stdout

        result = subprocess.run(
            ["git", "pull", "--rebase"],
            cwd=local_path, capture_output=True, text=True, timeout=pull_timeout,
        )

        # Restore stashed changes
        if stashed:
            subprocess.run(
                ["git", "stash", "pop"],
                cwd=local_path, capture_output=True, text=True, timeout=30,
            )

        if result.returncode == 0:
            logger.info("git pull OK: %s", result.stdout.strip())
            return True
        logger.error("git pull failed: %s", result.stderr.strip())
        return False
    except subprocess.TimeoutExpired:
        logger.error("git pull timed out after %ds", pull_timeout)
        return False
    except FileNotFoundError:
        logger.error("git not found – please install git")
        return False
    except Exception as exc:
        logger.error("git pull error: %s", exc)
        return False


# ---------------------------------------------------------------------------
# Commit message index (replaces repeated git-log subprocess calls)
# ---------------------------------------------------------------------------

def build_commit_message_index(
    repo_path: Path,
    *,
    timeout: int = 180,
) -> Optional[List[Tuple[str, str]]]:
    """Build an in-memory index of all commit messages for fast searching.

    Returns a list of ``(hash, full_message)`` tuples, or ``None`` on
    failure.  This replaces repeated ``git log --all --grep=...``
    subprocess calls with a single ``git log`` pass and in-memory
    string matching — typically reducing commit search from minutes
    to under a second.
    """
    if not repo_path.exists():
        return None
    try:
        result = subprocess.run(
            ["git", "log", "--all", "--format=%x00%H%x01%B"],
            cwd=repo_path, capture_output=True,
            encoding="utf-8", errors="replace", timeout=timeout,
        )
        if result.returncode != 0:
            logger.warning("Failed to build commit index: %s", result.stderr[:200])
            return None

        index: List[Tuple[str, str]] = []
        for record in result.stdout.split("\x00"):
            record = record.strip()
            if not record:
                continue
            parts = record.split("\x01", 1)
            if len(parts) != 2:
                continue
            commit_hash = parts[0].strip()
            message = parts[1]
            if len(commit_hash) >= 7:
                index.append((commit_hash, message))

        logger.info("Built commit message index: %d commits", len(index))
        return index
    except subprocess.TimeoutExpired:
        logger.error("Commit index build timed out after %ds", timeout)
        return None
    except Exception as exc:
        logger.error("Commit index build error: %s", exc)
        return None


def _search_commit_index(
    index: List[Tuple[str, str]],
    search_term: str,
    *,
    use_regex: bool = False,
) -> Optional[str]:
    """Search the in-memory commit index for a matching message.

    Returns the first matching commit hash, or ``None``.
    """
    if use_regex:
        try:
            pattern = re.compile(search_term)
        except re.error:
            return None
        for commit_hash, message in index:
            if pattern.search(message):
                return commit_hash
    else:
        for commit_hash, message in index:
            if search_term in message:
                return commit_hash
    return None


# ---------------------------------------------------------------------------
# Commit search
# ---------------------------------------------------------------------------

# Patterns to extract a commit hash from common Git hosting URL formats
_COMMIT_URL_PATTERNS = [
    # sourceware / savannah gitweb: …;h=<hash> or …?h=<hash>
    re.compile(r"[;?&]h=([0-9a-f]{7,40})"),
    # cgit / git.kernel.org: …/commit/?id=<hash> or …&id=<hash>
    re.compile(r"[;?&]id=([0-9a-f]{7,40})"),
    # git.kernel.org stable shorthand: …/stable/c/<hash>
    re.compile(r"/stable/c/([0-9a-f]{7,40})"),
    # GitHub / GitLab: …/commit/<hash>
    re.compile(r"/commit/([0-9a-f]{7,40})"),
]


def _validate_commit_in_repo(
    repo_path: Path,
    commit_hash: str,
    *,
    timeout: int = 10,
) -> bool:
    """Return True if *commit_hash* exists in the local repo as a commit object."""
    try:
        result = subprocess.run(
            ["git", "cat-file", "-t", commit_hash],
            cwd=repo_path, capture_output=True,
            encoding="utf-8", errors="replace", timeout=timeout,
        )
        return result.returncode == 0 and result.stdout.strip() == "commit"
    except Exception:
        return False


def extract_commit_from_references(
    repo_path: Path,
    reference_urls: List[str],
) -> Optional[str]:
    """Extract and validate a commit hash from NVD reference URLs.

    Tries each URL against known Git hosting patterns.  The first hash
    that is verified to exist in the local repository is returned.
    """
    import urllib.parse

    candidates: List[str] = []
    for url in reference_urls:
        decoded = urllib.parse.unquote(url)
        for pattern in _COMMIT_URL_PATTERNS:
            m = pattern.search(decoded)
            if m:
                h = m.group(1)
                if h not in candidates:
                    candidates.append(h)

    for h in candidates:
        if _validate_commit_in_repo(repo_path, h):
            logger.info("Commit %s extracted from NVD reference URL", h)
            return h

    return None

def find_commit_by_message(
    repo_path: Path,
    search_term: str,
    *,
    use_regex: bool = False,
    timeout: int = 60,
    commit_index: Optional[List[Tuple[str, str]]] = None,
) -> Optional[str]:
    """Search git history for a commit whose message contains *search_term*.

    Returns the full commit hash or ``None``.

    When *commit_index* is provided, searches in-memory instead of
    spawning a ``git log`` subprocess (much faster for repeated calls).

    When *use_regex* is True the search term is interpreted as an
    extended regular expression (``-E``) instead of a fixed string.
    """
    # Fast path: use pre-built in-memory index
    if commit_index is not None:
        return _search_commit_index(commit_index, search_term, use_regex=use_regex)
    try:
        cmd = ["git", "log", "--all", f"--grep={search_term}", "--format=%H", "-n", "1"]
        if use_regex:
            cmd.insert(3, "-E")  # enable extended regex before --grep
        result = subprocess.run(
            cmd,
            cwd=repo_path, capture_output=True,
            encoding="utf-8", errors="replace", timeout=timeout,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip().split("\n")[0]
    except (subprocess.TimeoutExpired, Exception) as exc:
        logger.warning("commit search (%s) failed: %s", search_term, exc)
    return None


def find_cve_fix_commit(
    repo_path: Path,
    cve_id: str,
    *,
    reference_urls: Optional[List[str]] = None,
    extra_grep_patterns: Optional[List[str]] = None,
    enable_bz_fallback: bool = True,
    allow_unscoped_extra_patterns: bool = False,
    timeout: int = 60,
    commit_index: Optional[List[Tuple[str, str]]] = None,
) -> Optional[str]:
    """Multi-strategy search for a fix commit associated with *cve_id*.

    Strategies tried in order:
      0. Commit hash embedded in NVD reference URLs
      1. Exact CVE-ID in commit message
      2. CVE-ID without dashes (e.g. CVE20231234)
      3. Bug-tracker references (BZ#<number>)
      4. Any user-supplied *extra_grep_patterns*
    """
    if not repo_path.exists():
        logger.warning("Repository not found: %s", repo_path)
        return None

    # Strategy 0 – commit hash from NVD reference URLs
    if reference_urls:
        commit = extract_commit_from_references(repo_path, reference_urls)
        if commit:
            return commit

    # Strategy 1 – exact CVE ID
    commit = find_commit_by_message(repo_path, cve_id, timeout=timeout, commit_index=commit_index)
    if commit:
        return commit

    # Strategy 2 – without dashes
    commit = find_commit_by_message(repo_path, cve_id.replace("-", ""), timeout=timeout, commit_index=commit_index)
    if commit:
        return commit

    # Strategy 3 – bug-tracker reference (optional)
    m = re.match(r"CVE-(\d{4})-(\d+)", cve_id)
    cve_number = m.group(2) if m else ""
    if enable_bz_fallback and cve_number:
        commit = find_commit_by_message(
            repo_path, f"BZ[^0-9]*{cve_number}([^0-9]|$)",
            use_regex=True, timeout=timeout, commit_index=commit_index,
        )
        if commit:
            return commit

    # Strategy 4 – extra patterns
    for pattern in (extra_grep_patterns or []):
        scoped = pattern
        if "{cve}" in pattern:
            scoped = pattern.replace("{cve}", cve_id)
        elif "{cve_num}" in pattern and cve_number:
            scoped = pattern.replace("{cve_num}", cve_number)
        elif not allow_unscoped_extra_patterns:
            logger.debug(
                "Skipping unscoped extra pattern '%s' for %s; use {cve}/{cve_num} or allow_unscoped_extra_patterns=true",
                pattern,
                cve_id,
            )
            continue

        commit = find_commit_by_message(repo_path, scoped, timeout=timeout, commit_index=commit_index)
        if commit:
            return commit

    logger.debug("No fix commit found for %s", cve_id)
    return None


def get_parent_commit(repo_path: Path, commit_hash: str, *, timeout: int = 30) -> Optional[str]:
    """Return the first-parent of *commit_hash* (i.e. the vulnerable state)."""
    if not commit_hash or not repo_path.exists():
        return None
    try:
        result = subprocess.run(
            ["git", "rev-parse", f"{commit_hash}^1"],
            cwd=repo_path, capture_output=True,
            encoding="utf-8", errors="replace", timeout=timeout,
        )
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
    except (subprocess.TimeoutExpired, Exception) as exc:
        logger.warning("parent-commit lookup failed for %s: %s", commit_hash, exc)
    return None


# ---------------------------------------------------------------------------
# Commit metadata
# ---------------------------------------------------------------------------

def get_commit_metadata(repo_path: Path, commit_hash: str, *, timeout: int = 30) -> Optional[Dict[str, str]]:
    """Return ``{hash, date, author, subject}`` for *commit_hash*."""
    if not commit_hash or not repo_path.exists():
        return None
    try:
        result = subprocess.run(
            ["git", "log", "-1", "--format=%H|%ai|%an|%s", commit_hash],
            cwd=repo_path, capture_output=True,
            encoding="utf-8", errors="replace", timeout=timeout,
        )
        if result.returncode == 0 and result.stdout.strip():
            parts = result.stdout.strip().split("|", 3)
            if len(parts) == 4:
                return {
                    "hash": parts[0],
                    "date": parts[1],
                    "author": parts[2],
                    "subject": parts[3],
                }
    except (subprocess.TimeoutExpired, Exception) as exc:
        logger.warning("commit metadata failed for %s: %s", commit_hash, exc)
    return None


def get_commit_changed_files(repo_path: Path, commit_hash: str, *, timeout: int = 30) -> List[Dict[str, str]]:
    """List files changed in *commit_hash* with their change type."""
    files: List[Dict[str, str]] = []
    if not commit_hash or not repo_path.exists():
        return files
    try:
        result = subprocess.run(
            ["git", "diff-tree", "--no-commit-id", "-r", "--name-status", commit_hash],
            cwd=repo_path, capture_output=True,
            encoding="utf-8", errors="replace", timeout=timeout,
        )
        if result.returncode == 0:
            for line in result.stdout.strip().splitlines():
                parts = line.split("\t")
                if len(parts) == 2:
                    # Normal add/modify/delete: status\tpath
                    files.append({"status": parts[0], "file_path": parts[1]})
                elif len(parts) == 3:
                    # Rename or copy: R100\told_path\tnew_path
                    files.append({
                        "status": parts[0][0],          # 'R' or 'C'
                        "file_path": parts[2],          # new (patched) path
                        "old_file_path": parts[1],      # old (vulnerable) path
                    })
    except (subprocess.TimeoutExpired, Exception) as exc:
        logger.warning("changed-files failed for %s: %s", commit_hash, exc)
    return files


def get_file_content_at_commit(
    repo_path: Path,
    file_path: str,
    commit_hash: str,
    *,
    timeout: int = 30,
) -> Optional[str]:
    """Return the content of *file_path* as of *commit_hash*."""
    if not commit_hash or not repo_path.exists():
        return None
    try:
        result = subprocess.run(
            ["git", "show", f"{commit_hash}:{file_path}"],
            cwd=repo_path, capture_output=True, timeout=timeout,
        )
        if result.returncode == 0:
            return result.stdout.decode("utf-8", errors="ignore")
    except (subprocess.TimeoutExpired, Exception) as exc:
        logger.warning("file-at-commit failed for %s@%s: %s", file_path, commit_hash, exc)
    return None


def get_changed_functions_in_commit(
    repo_path: Path,
    commit_hash: str,
    file_path: str,
    *,
    timeout: int = 60,
) -> List[str]:
    """Return a list of function names that were touched by *commit_hash* in *file_path*.

    Uses ``git log -1 -p -U0 --format='' -- <file>`` and parses ``@@`` hunk
    headers that GCC annotates with the enclosing function name.
    """
    functions: List[str] = []
    if not commit_hash or not repo_path.exists():
        return functions

    try:
        result = subprocess.run(
            ["git", "log", "-1", "-p", "-U0", "--format=", commit_hash, "--", file_path],
            cwd=repo_path, capture_output=True,
            encoding="utf-8", errors="replace", timeout=timeout,
        )
        if result.returncode == 0:
            for line in result.stdout.splitlines():
                m = re.match(r"^@@.*@@\s*(.*)", line)
                if m:
                    func_ctx = m.group(1).strip()
                    # Extract function name from context (e.g. "int foo(…)")
                    fm = re.search(r"\b(\w+)\s*\(", func_ctx)
                    if fm:
                        fname = fm.group(1)
                        if fname not in functions:
                            functions.append(fname)
    except (subprocess.TimeoutExpired, Exception) as exc:
        logger.warning("changed-functions failed for %s:%s: %s", commit_hash, file_path, exc)

    return functions
