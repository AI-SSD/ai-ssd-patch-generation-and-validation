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
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..models import ProjectState
import base64

from ..utils.git_utils import (
    build_commit_message_index,
    clone_or_update_repo,
    find_cve_fix_commit,
    get_commit_changed_files,
    get_commit_metadata,
    get_file_content_at_commit,
    get_file_bytes_at_commit,
    get_parent_commit,
)
from ..utils.code_parser import find_changed_units
from ..utils.file_utils import (
    classify_file_type,
    is_regression_test_path,
    resolve_test_build_subdir,
)
try:  # best-effort live-progress heartbeat for the dashboard (never fatal)
    from ..utils import live_progress
except Exception:  # pragma: no cover
    live_progress = None
from .base import PipelineModule, resolve_input_path

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
        # Shared INPUT clone: resolve against the pipeline root, not the Phase-0
        # CWD (the per-project base_dir under projects/<name>).
        repo_path = resolve_input_path(cfg.get("repo_local_path", "./source_repo"))
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

        # Abort early when the repo exists but has no usable history
        # (e.g. corrupted clone that was not auto-recovered).
        if not commit_index or len(commit_index) == 0:
            # Double-check: is the repo actually functional?
            import subprocess as _sp
            try:
                rev = _sp.run(
                    ["git", "rev-parse", "HEAD"],
                    cwd=repo_path, capture_output=True, text=True, timeout=10,
                )
                if rev.returncode != 0:
                    self.logger.error(
                        "Repository at '%s' has no usable commit history "
                        "(HEAD unresolvable).  Commit discovery will be "
                        "skipped entirely.  Delete the directory and re-run "
                        "to trigger a fresh clone.",
                        repo_path,
                    )
                    context["raw_cves"] = raw_cves
                    return context
            except Exception:
                pass  # git not available; fall through and try anyway
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

        total_cves = len(raw_cves)
        csv_path = self.config.get("output", {}).get(
            "csv_path", "results/cve_poc_complete.csv")
        live_dir = Path(csv_path).parent
        if str(live_dir) in (".", ""):
            live_dir = Path("results")

        def _emit(done, running=True):
            if live_progress:
                live_progress.emit(
                    live_dir, 0, total_cves, done,
                    {"stage": "commit discovery", "commits_found": commits_found},
                    running=running)

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {
                executor.submit(_process_cve, (i, cve)): i
                for i, cve in enumerate(raw_cves)
            }
            done_count = 0
            _emit(0)
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
                if done_count % 5 == 0:
                    _emit(done_count)
                if done_count % 25 == 0:
                    self.logger.info("  Commit discovery: %d / %d …", done_count, len(raw_cves))

        _emit(total_cves, running=False)
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

        # Find fix commit. Pass source_extensions so primary-fix selection can
        # prefer the commit that actually modifies project source (over a
        # ChangeLog/test-only follow-up that shares the bug reference).
        fix = find_cve_fix_commit(
            repo_path,
            cve_id,
            reference_urls=reference_urls,
            extra_grep_patterns=extra_patterns,
            enable_bz_fallback=cfg.get("enable_bz_fallback", True),
            allow_unscoped_extra_patterns=cfg.get("allow_unscoped_extra_patterns", False),
            commit_index=commit_index,
            source_exts=cfg.get("source_extensions", [".c", ".h"]),
            # Only trust bug ids from the project's native tracker host(s); skip
            # cross-vendor distro trackers (Red Hat/SUSE/…) whose ids are unrelated
            # to the repo. Empty/unset → built-in foreign-tracker denylist.
            native_bug_hosts=cfg.get("bugzilla_hosts"),
            # Opt-in network step: follow a distro Bugzilla reference to the
            # upstream (native) bug id and find its fix commit. Off by default.
            enable_online_bug_resolution=cfg.get("enable_online_bug_resolution", False),
        )
        if not fix:
            return ps

        ps.fix_commit_hash = fix
        ps.fix_commit_metadata = get_commit_metadata(repo_path, fix)

        # Vulnerable commit (parent of fix)
        vuln = get_parent_commit(repo_path, fix)
        ps.vulnerable_commit_hash = vuln
        
        if vuln:
            ps.vulnerable_commit_metadata = get_commit_metadata(repo_path, vuln)

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

        # ---------------------------------------------------------------
        # Option A: harvest the regression test(s) the fixing commit ships,
        # so Phase 1 can use the project's OWN reproducer (run in-tree on the
        # vulnerable build). The test source is read at the FIX commit; Phase 1
        # overlays it onto the vulnerable parent tree. General — no per-CVE code.
        # ---------------------------------------------------------------
        # Makefiles the fixing commit touched, used to resolve each test's REAL
        # build subdir (the dir whose Makefile registers the test) — not always
        # the test source's first path component (e.g. a sysdeps/ test gets
        # registered in math/Makefile). Read once at the fix commit.
        # Harvest the fix-commit's regression test (Option A) only when the
        # active reproduction_strategy includes "intree". One knob drives both
        # Phase 0 (what to harvest/emit) and the per-CVE priority; the legacy
        # commit_discovery.harvest_regression_tests flag still works as a bridge.
        from .base import parse_reproduction_strategy
        harvest_regression_tests = "intree" in parse_reproduction_strategy(self.config)

        # Projects whose reproducer is a DATA file (e.g. tcpdump's crafted
        # tests/*.pcap) rather than a compilable C test opt in here. Empty for
        # source-test projects (glibc/openssl) ⇒ no behaviour change.
        data_test_exts = list(
            self.config.get("commit_discovery", {}).get("regression_test_data_extensions", [])
            or []
        )

        regression_tests: List[Dict[str, str]] = []
        if harvest_regression_tests:
            # Makefiles the fixing commit touched, used to resolve each test's REAL
            # build subdir (the dir whose Makefile registers the test).
            changed_makefiles = [
                f["file_path"] for f in (ps.changed_files or [])
                if f["file_path"].replace("\\", "/").rsplit("/", 1)[-1] == "Makefile"
            ]
            makefile_contents = [
                (m, get_file_content_at_commit(repo_path, m, fix) or "")
                for m in changed_makefiles
            ]
            for finfo in (ps.changed_files or []):
                tpath = finfo["file_path"]
                if not is_regression_test_path(tpath, data_test_exts):
                    continue
                entry = self._harvest_test_entry(
                    repo_path, tpath, fix, data_test_exts, makefile_contents)
                if entry:
                    regression_tests.append(entry)

            # Supplement: in-tree tests that reference THIS CVE by filename or
            # content but were committed SEPARATELY from the fix (so the
            # fix-commit scan above can't see them). Common: libtasn1 ships
            # tests/CVE-XXXX.c, oss-fuzz projects add CVE/issue-tagged regression
            # inputs. Project-agnostic — matched on the CVE id, read from the
            # checked-out tree (HEAD). De-duped against the fix-commit harvest.
            seen_paths = {t["repo_path"] for t in regression_tests}
            for tpath in self._find_cve_tagged_tests(repo_path, cve_id, data_test_exts):
                if tpath in seen_paths:
                    continue
                entry = self._harvest_test_entry(
                    repo_path, tpath, "HEAD", data_test_exts, makefile_contents)
                if not entry:
                    continue
                regression_tests.append(entry)
                seen_paths.add(tpath)
                self.logger.info(
                    "  %s: found CVE-tagged in-tree test (outside fix commit): %s",
                    cve_id, tpath,
                )
        if regression_tests:
            ps.regression_tests = regression_tests
            self.logger.info(
                "  %s: fixing commit ships %d regression test(s): %s",
                cve_id, len(regression_tests),
                ", ".join(t["repo_path"] for t in regression_tests),
            )

        return ps

    def _harvest_test_entry(self, repo_path, tpath, ref, data_test_exts, makefile_contents):
        """Build one ``regression_tests[]`` entry for a harvested test at *ref*.

        Handles both compilable SOURCE tests (UTF-8 text content) and DATA
        reproducers (a crafted input file such as a ``.pcap``). Data files are
        read binary-safe and carried as base64 (``content_b64`` + ``is_data``)
        so the global JSON map / CSV survive a non-UTF-8 file; the authoritative
        copy is still re-checked-out by Phase 1 via TEST_PATH at the fix commit.
        Returns ``None`` when the file can't be read at *ref*.
        """
        p = tpath.lower()
        exts = {e.lower() if e.startswith(".") else "." + e.lower() for e in (data_test_exts or [])}
        is_data = bool(exts) and any(p.endswith(e) for e in exts)
        parts = tpath.split("/")
        name = parts[-1].rsplit(".", 1)[0]
        default_subdir = parts[0] if len(parts) > 1 else ""
        subdir = resolve_test_build_subdir(name, makefile_contents, default_subdir)
        entry: Dict[str, Any] = {"repo_path": tpath, "subdir": subdir, "name": name}
        if is_data:
            raw = get_file_bytes_at_commit(repo_path, tpath, ref)
            if not raw:
                return None
            entry["content"] = ""
            entry["content_b64"] = base64.b64encode(raw).decode("ascii")
            entry["is_data"] = True
        else:
            content = get_file_content_at_commit(repo_path, tpath, ref)
            if not content:
                return None
            entry["content"] = content
        return entry

    def _find_cve_tagged_tests(self, repo_path: Path, cve_id: str,
                               extra_test_exts=None) -> List[str]:
        """Return repo-relative paths of in-tree TEST sources that reference
        *cve_id* by filename or content, searched in the checked-out tree (HEAD).

        Option-A supplement for tests committed SEPARATELY from the fix commit
        (which the fix-commit scan in :meth:`_discover` cannot see). Fully
        project-agnostic: it matches only on the CVE id, then keeps just the
        results that :func:`is_regression_test_path` accepts as compilable test
        sources under a test directory — so the vulnerable lib source is excluded
        even when it mentions the CVE in a comment. Best-effort: any git failure
        yields an empty list (the fix-commit harvest still applies).
        """
        cve = (cve_id or "").strip()
        if not cve:
            return []
        cands: set[str] = set()
        try:
            # Filename match: tracked files whose path contains the CVE id.
            r = subprocess.run(
                ["git", "-C", str(repo_path), "ls-files", f"*{cve}*"],
                capture_output=True, text=True, timeout=30,
            )
            cands.update(l.strip() for l in r.stdout.splitlines() if l.strip())
            # Content match: tracked files mentioning the CVE id (case-insensitive,
            # both dashed and undashed forms). `git grep <ref>` prints "HEAD:path".
            r = subprocess.run(
                ["git", "-C", str(repo_path), "grep", "-l", "-i",
                 "-e", cve, "-e", cve.replace("-", ""), "HEAD"],
                capture_output=True, text=True, timeout=60,
            )
            for line in r.stdout.splitlines():
                line = line.strip()
                if line.startswith("HEAD:"):
                    line = line[len("HEAD:"):]
                if line:
                    cands.add(line)
        except Exception as exc:  # noqa: BLE001 — best-effort; never fail discovery
            self.logger.debug("CVE-tagged test search failed for %s: %s", cve, exc)
        return sorted(p for p in cands if is_regression_test_path(p, extra_test_exts))

