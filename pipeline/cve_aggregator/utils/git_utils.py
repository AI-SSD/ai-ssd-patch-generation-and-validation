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

from .file_utils import is_regression_test_path

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


# Bug-tracker id patterns inside NVD reference URLs (sourceware / RedHat / etc.).
_BUG_ID_URL_PATTERNS = [
    re.compile(r"show_bug\.cgi\?(?:[^#\s]*&)?id=(\d+)", re.IGNORECASE),
    re.compile(r"bugzilla[^?#\s]*[?&]id=(\d+)", re.IGNORECASE),
]


# Distro / cross-vendor bug trackers. A bug id from one of these lives in a
# DIFFERENT namespace than the upstream project's own commits (e.g. a Red Hat
# Bugzilla id like 645672 is unrelated to glibc's sourceware "[BZ #NNNN]"
# numbers). Searching the project repo for such an id finds nothing — or, worse,
# a coincidental same-number match for an unrelated change. So these are skipped
# when harvesting native bug ids (observed: CVE-2010-3856/-4052, whose only
# bug-tracker references are bugzilla.redhat.com).
_FOREIGN_BUG_TRACKER_HOSTS = (
    "redhat.com", "suse.com", "novell.com", "launchpad.net",
    "debian.org", "ubuntu.com", "mageia.org", "gentoo.org",
    "bugzilla.mozilla.org", "chromium.org",
)


def extract_bug_ids_from_references(
    reference_urls: Optional[List[str]],
    *,
    native_hosts: Optional[List[str]] = None,
) -> List[str]:
    """Extract real upstream bug-tracker ids from a CVE's NVD reference URLs.

    These are the ACTUAL project bug numbers (e.g. a sourceware Bugzilla id),
    curated by NVD for this specific CVE — unlike the CVE's own numeric suffix,
    which has NO relationship to the project's bug tracker. Used to find and
    validate fix commits that reference the bug rather than the CVE id.

    Bug ids hosted on a cross-vendor distro tracker are excluded: their numbers
    are not the upstream project's and matching them against the repo is unsound.
    When *native_hosts* is given (project config), ONLY those hosts are trusted;
    otherwise a built-in foreign-tracker denylist is applied.
    """
    import urllib.parse
    ids: List[str] = []
    for url in reference_urls or []:
        decoded = urllib.parse.unquote(url)
        host = urllib.parse.urlparse(decoded).netloc.lower()
        if native_hosts:
            if not any(nh.lower() in host for nh in native_hosts):
                continue
        elif any(fh in host for fh in _FOREIGN_BUG_TRACKER_HOSTS):
            continue
        for pat in _BUG_ID_URL_PATTERNS:
            for m in pat.finditer(decoded):
                if m.group(1) not in ids:
                    ids.append(m.group(1))
    return ids


def _message_for_commit(
    commit_index: Optional[List[Tuple[str, str]]], commit_hash: str
) -> Optional[str]:
    """Return the commit message for *commit_hash* from the in-memory index."""
    if not commit_index or not commit_hash:
        return None
    for h, msg in commit_index:
        if h == commit_hash or h.startswith(commit_hash) or commit_hash.startswith(h):
            return msg
    return None


def commit_relates_to_cve(
    repo_path: Path,
    commit_hash: str,
    cve_id: str,
    bug_ids: List[str],
    *,
    commit_index: Optional[List[Tuple[str, str]]] = None,
    timeout: int = 30,
) -> bool:
    """True when *commit_hash*'s message genuinely references this CVE.

    A match counts when the message contains the exact CVE id (dashed or
    dash-less) or a real Bugzilla id taken from the CVE's NVD references. This is
    the gate that stops a loose search from silently returning an unrelated
    commit (e.g. another CVE's fix, or a same-era but irrelevant change).
    """
    if not commit_hash:
        return False
    msg = _message_for_commit(commit_index, commit_hash)
    if msg is None:
        try:
            r = subprocess.run(
                ["git", "log", "-1", "--format=%B", commit_hash],
                cwd=repo_path, capture_output=True,
                encoding="utf-8", errors="replace", timeout=timeout,
            )
            msg = r.stdout if r.returncode == 0 else ""
        except Exception:
            msg = ""
    if not msg:
        return False
    up = msg.upper()
    if cve_id.upper() in up or cve_id.replace("-", "").upper() in up:
        return True
    for bz in bug_ids:
        if re.search(rf"\b(?:BZ|BUG)[\s#]*0*{re.escape(bz)}\b", msg, re.IGNORECASE):
            return True
    return False


def _search_commit_index_all(
    index: List[Tuple[str, str]], search_term: str, *, use_regex: bool = False,
) -> List[str]:
    """Return ALL commit hashes whose message matches *search_term* (index order)."""
    out: List[str] = []
    if use_regex:
        try:
            pattern = re.compile(search_term)
        except re.error:
            return out
        for h, m in index:
            if pattern.search(m):
                out.append(h)
    else:
        for h, m in index:
            if search_term in m:
                out.append(h)
    return out


def _gather_matches(
    repo_path: Path, term: str, *, use_regex: bool = False,
    commit_index: Optional[List[Tuple[str, str]]] = None, timeout: int = 60,
) -> List[str]:
    """All commits matching *term* — from the in-memory index when available,
    else a single subprocess match (the no-index fallback keeps old behaviour)."""
    if commit_index is not None:
        return _search_commit_index_all(commit_index, term, use_regex=use_regex)
    one = find_commit_by_message(repo_path, term, use_regex=use_regex, timeout=timeout)
    return [one] if one else []


def _commit_changed_paths(
    repo_path: Path, commit_hash: str, *, timeout: int = 20,
) -> List[str]:
    """Repo-relative paths the commit's diff modifies (empty list on failure)."""
    try:
        r = subprocess.run(
            ["git", "show", "--name-only", "--format=", "--no-renames", commit_hash],
            cwd=repo_path, capture_output=True, encoding="utf-8", errors="replace", timeout=timeout,
        )
        if r.returncode != 0:
            return []
        return [line.strip() for line in r.stdout.splitlines() if line.strip()]
    except Exception:
        return []


# Documentation / metadata files that, like tests, are NOT a code fix: a commit
# touching only these (ChangeLog/NEWS follow-ups, release notes) must never
# outrank the real fix. Generic, project-agnostic — basename or extension.
_DOC_META_EXTS = (".md", ".rst", ".txt", ".po", ".pot", ".man", ".html", ".tex")
_DOC_META_NAMES = (
    "changelog", "news", "readme", "authors", "copying", "license", "licence",
    "notice", "thanks", "todo", "install", "maintainers", "contributors",
)


def _is_doc_or_meta(path: str) -> bool:
    """True for documentation/changelog/metadata files (never a code fix)."""
    name = path.replace("\\", "/").rsplit("/", 1)[-1].lower()
    stem = name.split(".", 1)[0]
    return name.endswith(_DOC_META_EXTS) or stem in _DOC_META_NAMES


def _commit_fix_tier(paths: List[str], source_exts: List[str]) -> int:
    """Rank a commit as a primary-fix candidate by the files it changes.

    Lower is better:
      0 — touches a NON-TEST file with a *source* extension (the patchable code
          fix, e.g. a ``.c``/``.h`` outside a test directory);
      1 — touches a NON-TEST, non-doc file of another extension (a real fix the
          C machinery may not be able to patch, e.g. OpenSSL's Perl-assembly
          ``crypto/bn/asm/*.pl``) — still the right commit, just not C;
      2 — touches ONLY test and/or documentation files (a regression-test or
          ChangeLog follow-up committed separately from the actual fix).

    This is what stops a test the project commits SEPARATELY from the fix (both
    citing the same CVE) from winning primary-fix selection: the test commit is
    tier 2, the real fix tier 0/1. Keys only off the generic test-path and
    doc/meta conventions — never a per-project rule.
    """
    has_src = has_code = False
    for f in paths:
        if is_regression_test_path(f) or _is_doc_or_meta(f):
            continue
        has_code = True
        if any(f.endswith(ext) for ext in source_exts):
            has_src = True
    if has_src:
        return 0
    if has_code:
        return 1
    return 2


def _commit_timestamp(repo_path: Path, commit_hash: str, *, timeout: int = 20) -> Optional[int]:
    """Return the commit's author UNIX timestamp (for ordering), or None."""
    try:
        r = subprocess.run(
            ["git", "show", "-s", "--format=%at", commit_hash],
            cwd=repo_path, capture_output=True, encoding="utf-8", errors="replace", timeout=timeout,
        )
        if r.returncode == 0 and r.stdout.strip():
            return int(r.stdout.strip().split("\n")[0])
    except Exception:
        pass
    return None


def _pick_primary_fix(
    repo_path: Path, candidates: List[str], source_exts: List[str], *, timeout: int = 30,
) -> Optional[str]:
    """From commits that all reference the bug, pick the PRIMARY code fix.

    Ranks candidates by :func:`_commit_fix_tier` (a non-test source fix beats a
    non-test non-source fix beats a test-/doc-only commit), then by EARLIEST
    timestamp within the best tier, so the recorded fix's PARENT is genuinely the
    last vulnerable state. Two failure modes this prevents:
      * a later follow-up commit whose parent is ALREADY the real fix (a patched
        tree) — observed for CVE-2012-4412; the earliest source fix wins instead;
      * a regression test the project commits SEPARATELY from the fix but with the
        same CVE id in its message (e.g. OpenSSL CVE-2016-7055's ``test/bntest.c``)
        — the test is tier 2 and never outranks the real
        ``crypto/bn/asm/x86_64-mont.pl`` fix (tier 1).
    Falls back to the earliest candidate, then the first.
    """
    # De-dup while preserving order; bound the work for pathological matches.
    seen: List[str] = []
    for c in candidates:
        if c and c not in seen:
            seen.append(c)
    if not seen:
        return None
    if len(seen) == 1:
        return seen[0]
    scored = []
    for c in seen[:25]:
        paths = _commit_changed_paths(repo_path, c, timeout=timeout)
        scored.append((c, _commit_timestamp(repo_path, c, timeout=timeout),
                       _commit_fix_tier(paths, source_exts)))
    best_tier = min(s[2] for s in scored)
    pool = [s for s in scored if s[2] == best_tier]
    pool.sort(key=lambda s: (s[1] is None, s[1] if s[1] is not None else 0))
    chosen = pool[0][0]
    logger.debug(
        "Primary-fix selection among %d candidates (tier %d) -> %s",
        len(seen), best_tier, chosen[:12],
    )
    return chosen


# Red Hat Bugzilla ids whose "external trackers" often point at the upstream
# (sourceware) bug for glibc and other GNU projects.
_REDHAT_BUG_RE = re.compile(r"redhat\.com/show_bug\.cgi\?(?:[^#\s]*&)?id=(\d+)", re.IGNORECASE)


def _resolve_upstream_bug_ids_online(
    reference_urls: List[str],
    native_hosts: List[str],
    *,
    timeout: int = 15,
) -> List[str]:
    """Best-effort, NETWORK: map a distro Bugzilla reference to upstream bug id(s).

    Uses the Red Hat Bugzilla REST API (a cross-project distro tracker with a
    public, no-auth API) to read a bug's ``external_bugs`` / ``see_also`` and
    harvest any bug id whose tracker host matches the PROJECT's own native bug
    host(s) — passed in from config (``commit_discovery.bugzilla_hosts``), never
    hardcoded. So this works for any project: glibc → sourceware.org, another
    project → its own tracker. Returns de-duplicated upstream ids, or [] on any
    failure (the caller then routes the CVE to manual review). urllib only.
    """
    if not native_hosts:
        return []
    import json as _json
    import urllib.parse
    import urllib.request

    hosts = [h.lower() for h in native_hosts]
    rh_ids: List[str] = []
    for url in reference_urls or []:
        m = _REDHAT_BUG_RE.search(urllib.parse.unquote(url))
        if m and m.group(1) not in rh_ids:
            rh_ids.append(m.group(1))
    if not rh_ids:
        return []

    def _host_native(text: str) -> bool:
        return any(h in (text or "").lower() for h in hosts)

    upstream: List[str] = []
    for rh in rh_ids:
        api = (
            f"https://bugzilla.redhat.com/rest/bug/{rh}"
            "?include_fields=external_bugs,see_also"
        )
        try:
            req = urllib.request.Request(api, headers={"User-Agent": "ai-ssd-pipeline"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = _json.loads(resp.read().decode("utf-8", errors="replace"))
        except Exception as exc:  # network/parse/anything — stay best-effort
            logger.debug("RH Bugzilla lookup for %s failed: %s", rh, exc)
            continue
        bugs = (data or {}).get("bugs") or []
        for bug in bugs:
            for ext in bug.get("external_bugs", []) or []:
                bz_id = str(ext.get("ext_bz_bug_id", "")).strip()
                tracker_url = str(ext.get("type", {}).get("url", "")).lower()
                if bz_id and _host_native(tracker_url) and bz_id not in upstream:
                    upstream.append(bz_id)
            for sa in bug.get("see_also", []) or []:
                sa = str(sa)
                if _host_native(sa):
                    m = re.search(r"[?&]id=(\d+)", sa)
                    if m and m.group(1) not in upstream:
                        upstream.append(m.group(1))
    return upstream


def find_cve_referencing_commits(
    repo_path: Path,
    cve_id: str,
    *,
    commit_index: Optional[List[Tuple[str, str]]] = None,
    timeout: int = 60,
) -> List[str]:
    """All commits whose message contains *cve_id* (dashed or dash-less form).

    Used by Option-A test harvesting to find a regression test the project
    committed SEPARATELY from the code fix but referencing the same CVE in its
    commit message — which a tree/content grep can't see (the test body need not
    mention the CVE). Without this, fixing the primary-fix selection to record
    the CODE commit (e.g. OpenSSL CVE-2016-7055's ``.pl`` fix) would LOSE the
    in-tree reproducer that lives in the sibling ``test/bntest.c`` commit.
    De-duplicated, order-preserving. Project-agnostic — matches only the CVE id.
    """
    if not repo_path.exists():
        return []
    out: List[str] = []
    for term in (cve_id, cve_id.replace("-", "")):
        for h in _gather_matches(repo_path, term, commit_index=commit_index, timeout=timeout):
            if h and h not in out:
                out.append(h)
    return out


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
    source_exts: Optional[List[str]] = None,
    native_bug_hosts: Optional[List[str]] = None,
    enable_online_bug_resolution: bool = False,
) -> Optional[str]:
    """Multi-strategy search for a fix commit associated with *cve_id*, with a
    validation gate AND primary-fix selection.

    Strategies (first one producing a validated candidate wins):
      0. Commit hash embedded in this CVE's NVD reference URLs — trusted as-is
         (NVD curated the reference for this specific CVE).
      1. Exact CVE-ID in the commit message (dashed or dash-less) — self-validating.
      2. A REAL Bugzilla id taken from this CVE's NVD references — NOT the CVE's
         numeric suffix (which is unrelated to the project's bug tracker).
      3. Project-supplied *extra_grep_patterns*, scoped to the CVE.

    Strategies 1–3 gather ALL matching commits and pick the PRIMARY code fix via
    :func:`_pick_primary_fix` (best :func:`_commit_fix_tier`, then earliest), so a
    test/ChangeLog follow-up committed separately can't be mistaken for the fix and
    the recorded fix's PARENT is genuinely the vulnerable state. Candidates from
    strategies 2–3 must also pass :func:`commit_relates_to_cve`. When nothing
    validates, returns ``None`` so the CVE is routed to manual review.

    NOTE: the previous "BZ == CVE number" fallback was REMOVED — CVE ids and
    project Bugzilla ids are unrelated namespaces, so it produced false positives.
    """
    source_exts = source_exts or [".c", ".h"]
    if not repo_path.exists():
        logger.warning("Repository not found: %s", repo_path)
        return None

    # Strategy 0 – commit hash from this CVE's NVD reference URLs (strongest).
    if reference_urls:
        commit = extract_commit_from_references(repo_path, reference_urls)
        if commit:
            return commit

    bug_ids = extract_bug_ids_from_references(
        reference_urls, native_hosts=native_bug_hosts
    )

    # Strategy 1 – exact CVE ID (with and without dashes). A commit message that
    # contains the CVE id is inherently about this CVE; pick the primary among them.
    cve_candidates: List[str] = []
    for term in (cve_id, cve_id.replace("-", "")):
        cve_candidates.extend(
            _gather_matches(repo_path, term, commit_index=commit_index, timeout=timeout)
        )
    primary = _pick_primary_fix(repo_path, cve_candidates, source_exts, timeout=timeout)
    if primary:
        return primary

    # Strategy 2 – a REAL Bugzilla id from this CVE's references (sound). Gather
    # all, validate each, then pick the primary code fix.
    if enable_bz_fallback:
        bz_candidates: List[str] = []
        for bz in bug_ids:
            for h in _gather_matches(
                repo_path, rf"\b(?:BZ|bug)[\s#]*0*{re.escape(bz)}\b",
                use_regex=True, commit_index=commit_index, timeout=timeout,
            ):
                if commit_relates_to_cve(
                    repo_path, h, cve_id, bug_ids, commit_index=commit_index, timeout=timeout,
                ):
                    bz_candidates.append(h)
        primary = _pick_primary_fix(repo_path, bz_candidates, source_exts, timeout=timeout)
        if primary:
            return primary

    # Strategy 3 – extra patterns. Scoped patterns ({cve}/{cve_num}) are the
    # project author's responsibility; an unscoped pattern (opt-in) must still
    # validate against the CVE before it is accepted.
    m = re.match(r"CVE-\d{4}-(\d+)", cve_id)
    cve_number = m.group(1) if m else ""
    for pattern in (extra_grep_patterns or []):
        scoped = pattern
        is_scoped = "{cve}" in pattern or ("{cve_num}" in pattern and cve_number)
        if "{cve}" in pattern:
            scoped = pattern.replace("{cve}", cve_id)
        elif "{cve_num}" in pattern and cve_number:
            scoped = pattern.replace("{cve_num}", cve_number)
        elif not allow_unscoped_extra_patterns:
            logger.debug(
                "Skipping unscoped extra pattern '%s' for %s; use {cve}/{cve_num} "
                "or allow_unscoped_extra_patterns=true", pattern, cve_id,
            )
            continue

        matches = _gather_matches(repo_path, scoped, commit_index=commit_index, timeout=timeout)
        if not is_scoped:
            matches = [h for h in matches if commit_relates_to_cve(
                repo_path, h, cve_id, bug_ids, commit_index=commit_index, timeout=timeout)]
        primary = _pick_primary_fix(repo_path, matches, source_exts, timeout=timeout)
        if primary:
            return primary

    # Strategy 4 (opt-in, network) – follow a distro Bugzilla reference to the
    # UPSTREAM bug, then find that bug's "[BZ #NNNN]" commit. Many old CVEs cite
    # only a Red Hat bug (e.g. CVE-2010-3856/-4052) whose NVD references carry no
    # native bug id and whose fix commit never mentions the CVE id — undiscoverable
    # offline. The upstream bug id (sourceware) IS native, so this stays sound.
    if enable_online_bug_resolution and reference_urls:
        upstream = _resolve_upstream_bug_ids_online(
            reference_urls, native_bug_hosts or [], timeout=timeout
        )
        if upstream:
            logger.info(
                "%s: resolved upstream bug id(s) %s via online bug tracker",
                cve_id, ",".join(upstream),
            )
            up_candidates: List[str] = []
            for bz in upstream:
                for h in _gather_matches(
                    repo_path, rf"\b(?:BZ|bug)[\s#]*0*{re.escape(bz)}\b",
                    use_regex=True, commit_index=commit_index, timeout=timeout,
                ):
                    up_candidates.append(h)
            primary = _pick_primary_fix(repo_path, up_candidates, source_exts, timeout=timeout)
            if primary:
                return primary

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


def get_file_bytes_at_commit(
    repo_path: Path,
    file_path: str,
    commit_hash: str,
    *,
    timeout: int = 30,
) -> Optional[bytes]:
    """Return the RAW bytes of *file_path* as of *commit_hash*.

    Binary-safe twin of :func:`get_file_content_at_commit`. Required for harvested
    test reproducers that are DATA, not source (e.g. a crafted ``.pcap``): a
    UTF-8 decode would lossily corrupt them. Returns ``None`` when the file does
    not exist at the commit (so callers can use truthiness as an existence test)."""
    if not commit_hash or not repo_path.exists():
        return None
    try:
        result = subprocess.run(
            ["git", "show", f"{commit_hash}:{file_path}"],
            cwd=repo_path, capture_output=True, timeout=timeout,
        )
        if result.returncode == 0:
            return result.stdout
    except (subprocess.TimeoutExpired, Exception) as exc:
        logger.warning("file-bytes-at-commit failed for %s@%s: %s", file_path, commit_hash, exc)
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
