"""
Commit Discovery module.

Searches a local Git repository for fix commits and identifies the
corresponding vulnerable (parent) commits.  Extracts changed-file
metadata, file contents (both vulnerable **and** patched), and
function-level diffs by comparing extracted code units from both
versions – mirroring the approach in ``extract_patches.py``.
"""

from __future__ import annotations

import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..models import ProjectState
from ..utils.git_utils import (
    build_commit_message_index,
    clone_or_update_repo,
    find_cve_fix_commit,
    get_commit_changed_files,
    get_commit_metadata,
    get_file_content_at_commit,
    get_parent_commit,
)
from ..utils.code_parser import find_changed_units
from ..utils.file_utils import classify_file_type
from .base import PipelineModule

logger = logging.getLogger(__name__)


class CommitDiscovery(PipelineModule):
    """Pipeline module: *Commit Discovery*.

    Reads ``context["raw_cves"]`` and enriches each entry with
    ``project_state`` information (fix commit, vulnerable commit,
    changed files, vulnerable source code).
    """

    def validate_config(self) -> bool:
        cfg = self.config.get("commit_discovery", {})
        if not cfg.get("repo_url"):
            self.logger.error("commit_discovery.repo_url is required")
            return False
        return True

    # ----- main entry point -----

    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        cfg = self.config.get("commit_discovery", {})
        repo_url: str = cfg["repo_url"]
        repo_path = Path(cfg.get("repo_local_path", "./source_repo"))
        extra_patterns: List[str] = cfg.get("extra_grep_patterns", [])
        clone_timeout: int = cfg.get("clone_timeout", 1800)

        # Step 1 – Ensure repo is up-to-date
        if cfg.get("auto_update", True):
            self.logger.info("Updating source repository …")
            ok = clone_or_update_repo(repo_path, repo_url, clone_timeout=clone_timeout)
            if not ok:
                self.logger.warning("Repository update failed – continuing with existing data")

        # Step 1b – Build in-memory commit message index for fast searching.
        # Replaces O(N×4) subprocess calls with 1 git-log + in-memory matching.
        index_timeout: int = cfg.get("commit_index_timeout", 180)
        commit_index = build_commit_message_index(repo_path, timeout=index_timeout)
        if commit_index:
            self.logger.info(
                "Using in-memory commit index (%d commits) for fast discovery",
                len(commit_index),
            )

        # Step 2 – For each CVE, discover fix/vulnerable commits
        raw_cves: List[Dict[str, Any]] = context.get("raw_cves", [])

        # Abort early with a clear warning when the repo is missing.
        if not repo_path.exists():
            self.logger.error(
                "Source repository not found at '%s' (clone may have failed "
                "or timed out).  Commit discovery will be skipped entirely.  "
                "Ensure the repository is accessible and there is sufficient "
                "disk space for a full clone.",
                repo_path,
            )
            context["raw_cves"] = raw_cves
            return context
        commits_found = 0
        max_workers = cfg.get("max_workers", 4)

        def _process_cve(idx_cve: Tuple[int, Dict[str, Any]]) -> Optional[Tuple[int, "ProjectState"]]:
            idx, cve = idx_cve
            cve_id = cve.get("cve_id", "")
            if not cve_id:
                return None
            ps = self._discover(
                cve_id, repo_path, repo_url, extra_patterns, cfg,
                reference_urls=cve.get("references", []),
                commit_index=commit_index,
            )
            return idx, ps

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_process_cve, (i, cve)): i
                for i, cve in enumerate(raw_cves)
            }
            done_count = 0
            for future in as_completed(futures):
                result = future.result()
                if result is None:
                    done_count += 1
                    continue
                idx, ps = result
                raw_cves[idx]["project_state"] = ps.to_dict()
                if ps.fix_commit_hash:
                    commits_found += 1
                done_count += 1
                if done_count % 25 == 0:
                    self.logger.info("  Commit discovery: %d / %d …", done_count, len(raw_cves))

        self.logger.info("Commit Discovery: found commits for %d / %d CVEs", commits_found, len(raw_cves))
        context["raw_cves"] = raw_cves
        return context

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _discover(
        self,
        cve_id: str,
        repo_path: Path,
        repo_url: str,
        extra_patterns: List[str],
        cfg: Dict,
        *,
        reference_urls: Optional[List[str]] = None,
        commit_index: Optional[List[Tuple[str, str]]] = None,
    ) -> ProjectState:
        ps = ProjectState(repository_url=repo_url)

        if not repo_path.exists():
            return ps

        # Find fix commit
        fix = find_cve_fix_commit(
            repo_path,
            cve_id,
            reference_urls=reference_urls,
            extra_grep_patterns=extra_patterns,
            enable_bz_fallback=cfg.get("enable_bz_fallback", True),
            allow_unscoped_extra_patterns=cfg.get("allow_unscoped_extra_patterns", False),
            commit_index=commit_index,
        )
        if not fix:
            return ps

        ps.fix_commit_hash = fix
        ps.fix_commit_metadata = get_commit_metadata(repo_path, fix)

        # Vulnerable commit (parent of fix)
        vuln = get_parent_commit(repo_path, fix)
        ps.vulnerable_commit_hash = vuln

        # Changed files
        changed = get_commit_changed_files(repo_path, fix)
        ps.changed_files = [
            {**f, "file_type": classify_file_type(f["file_path"])}
            for f in changed
        ]

        # ---------------------------------------------------------------
        # Extract BOTH vulnerable AND patched file content, then compare
        # functions/macros between them (like extract_patches.py).
        # ---------------------------------------------------------------
        source_exts = cfg.get("source_extensions", [".c", ".h"])

        if vuln:
            ps.vulnerable_files_content = {}
            ps.patched_files_content = {}
            ps.vulnerable_functions = {}
            ps.changed_code_units = {}

            for finfo in (ps.changed_files or []):
                fpath = finfo["file_path"]              # new (patched) path
                old_path = finfo.get("old_file_path", fpath)  # old (vulnerable) path

                if not any(fpath.endswith(ext) for ext in source_exts):
                    # Also check old path for renames (.c → .c is typical,
                    # but the extension filter should still be applied)
                    if not any(old_path.endswith(ext) for ext in source_exts):
                        continue

                # Get full file content at BOTH commits, using the
                # correct path for each version (handles renames).
                vuln_content = get_file_content_at_commit(repo_path, old_path, vuln)
                patched_content = get_file_content_at_commit(repo_path, fpath, fix)

                # Handle new / deleted files
                if vuln_content is None and patched_content is not None:
                    vuln_content = ""
                elif vuln_content is not None and patched_content is None:
                    patched_content = ""
                elif vuln_content is None and patched_content is None:
                    continue

                ps.vulnerable_files_content[fpath] = vuln_content
                ps.patched_files_content[fpath] = patched_content

                # Find changed code units by extracting from both versions
                # and comparing (filters out comment/whitespace-only changes)
                units = find_changed_units(vuln_content, patched_content, file_path=fpath)
                ps.changed_code_units[fpath] = units

                # Also populate vulnerable_functions for backward compat
                ps.vulnerable_functions[fpath] = {
                    "changed_functions": [
                        u["name"] for u in units
                    ],
                    "changed_function_bodies": {
                        u["name"]: u["vuln_body"] for u in units
                    },
                }

                self.logger.debug(
                    "  %s: %d changed code units", fpath, len(units),
                )

        return ps
