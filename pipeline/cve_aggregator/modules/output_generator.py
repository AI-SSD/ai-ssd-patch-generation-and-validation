"""
Output Generation module.

Produces all final artefacts:
  1. **Global JSON** – full dataset (``cve_poc_map.json``)
  2. **Filtered JSON** – only CVEs with commits + PoC (``cve_poc_map_filtered.json``)
  3. **Complete CSV** – tabular view for pipeline consumption
  4. **PoC files** – individual exploit files saved to disk (``exploits/``)
"""

from __future__ import annotations

import base64
import csv
import io
import json
import logging
import shutil
import tarfile
import zipfile
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import requests

from ..models import CVEEntry, Dataset
from .base import parse_reproduction_strategy
from ..utils.cwe_lookup import get_cwe_descriptions
from ..utils.file_utils import (
    clean_poc_content,
    detect_language_from_content,
    get_file_extension_for_language,
    is_valid_poc_content,
)
from ..utils.version_mapping import (
    extract_project_version_from_cpe,
    get_ubuntu_version,
)
from .base import PipelineModule

logger = logging.getLogger(__name__)


def _is_test_file(path: str) -> bool:
    """Heuristic: does *path* point at a test/harness file rather than
    production source?  Fix commits routinely ADD a regression test next to
    the real fix; the vulnerable code is never in the test file.  Patterns
    are project-agnostic naming conventions (glibc ``tst-*``, generic
    ``test_*``/``*_test``, ``tests/`` directories).
    """
    p = path.lower()
    name = p.rsplit("/", 1)[-1]
    if name.startswith(("tst-", "tst_", "test-", "test_", "bug-")):
        return True
    stem = name.rsplit(".", 1)[0]
    if stem.endswith(("-test", "_test", "-tests", "_tests")):
        return True
    parts = p.split("/")
    return any(d in ("test", "tests", "testsuite", "testing") for d in parts[:-1])


class OutputGenerator(PipelineModule):
    """Pipeline module: *Output Generation*.

    Reads ``context["dataset"]`` (and optionally ``context["syntax_results"]``)
    and writes all output files.
    """

    # ----- main entry point -----

    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        cfg = self.config.get("output", {})
        dataset: Dataset = context.get("dataset", Dataset())

        # 1. Save global JSON
        global_path = Path(cfg.get("global_json_path", "cve_poc_map.json"))
        self._save_json(dataset, global_path, "global")

        # 2. Create & save filtered dataset
        filtered_path = Path(cfg.get("filtered_json_path", "cve_poc_map_filtered.json"))
        filtered = self._create_filtered(dataset, cfg)
        self._save_json(filtered, filtered_path, "filtered")

        # 3. Export CSV + PoC files
        csv_path = Path(cfg.get("csv_path", "cve_poc_complete.csv"))
        poc_dir = Path(cfg.get("poc_dir", "exploits"))
        syntax_results = context.get("syntax_results", {})
        poc_repair_report = context.get("poc_repair_report", {})
        total, complete, saved = self._export_csv_and_pocs(
            filtered, csv_path, poc_dir, syntax_results, poc_repair_report, cfg,
        )

        # Summary
        context["output_summary"] = {
            "global_json": str(global_path),
            "filtered_json": str(filtered_path),
            "csv": str(csv_path),
            "poc_dir": str(poc_dir),
            "total_processed": total,
            "complete_entries": complete,
            "poc_files_saved": saved,
        }
        return context

    # ------------------------------------------------------------------
    # JSON persistence
    # ------------------------------------------------------------------

    def _save_json(self, dataset: Dataset, path: Path, label: str) -> bool:
        dataset.compute_statistics()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            tmp = path.parent / f".{path.name}.tmp"
            with open(tmp, "w", encoding="utf-8") as fh:
                json.dump(dataset.to_dict(), fh, indent=2, ensure_ascii=False)
            tmp.replace(path)
            self.logger.info("Saved %s dataset (%d CVEs) → %s",
                             label, len(dataset.cves), path)
            return True
        except IOError as exc:
            self.logger.error("Failed to save %s dataset: %s", label, exc)
            return False

    # ------------------------------------------------------------------
    # Filtered dataset
    # ------------------------------------------------------------------

    @staticmethod
    def _manual_poc_sourcing_needed(entry: CVEEntry, cfg: Dict) -> bool:
        """True when a CVE should be routed to manual supervision to source a PoC.

        The CVE meets every requirement except a runnable PoC: it has a fix
        commit and extracted vulnerable functions, and at least one *verified*
        ExploitDB entry was mapped to it but dropped by the runnability filter
        (a write-up / non-runnable artifact, recorded as a ``manual_poc_leads``
        entry). Such CVEs are flagged for manual review instead of discarded.
        Gated by ``flag_unvalidated_edb_for_manual_review`` (default on).
        """
        if not cfg.get("flag_unvalidated_edb_for_manual_review", True):
            return False
        if entry.has_poc:
            return False
        if not (entry.has_commits and entry.has_vulnerable_functions):
            return False
        return bool(getattr(entry, "manual_poc_leads", None))

    def _write_manual_poc_report(self, cve_id: str, entry: CVEEntry, cfg: Dict) -> None:
        """Write a human-facing manual-supervision report for a CVE that needs a
        PoC sourced. Uses the ``<CVE>_syntax_report.txt`` name the Phase 0
        manual-verification menu already recognises (so it shows under [V] View
        and suppresses the orchestrator's generic missing-PoC report)."""
        supervision_dir = Path(cfg.get("manual_supervision_dir", "manual_supervision"))
        try:
            supervision_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            self.logger.warning("Could not create manual_supervision dir: %s", exc)
            return
        leads = getattr(entry, "manual_poc_leads", None) or []
        ps = entry.project_state
        lines = [
            f"MANUAL POC SOURCING REQUIRED — {cve_id}",
            "=" * 70,
            "",
            "This CVE has everything needed to patch and validate EXCEPT a runnable",
            "PoC: a fix commit and vulnerable functions were extracted, and a",
            "verified ExploitDB entry exists — but that entry failed runnability",
            "validation (it is a prose write-up / non-runnable artifact that links",
            "to the real exploit rather than containing it).",
            "",
            f"Fix commit:        {ps.fix_commit_hash or 'N/A'}",
            f"Vulnerable commit: {ps.vulnerable_commit_hash or 'N/A'}",
            "",
            "Verified ExploitDB lead(s) — fetch the real PoC from here:",
        ]
        for lead in leads:
            lines.append(f"  - {lead.get('exploit_id') or '(no EDB id)'} "
                         f"[{lead.get('drop_reason', '')}]")
            if lead.get("exploitdb_url"):
                lines.append(f"      ExploitDB: {lead['exploitdb_url']}")
            if lead.get("source_url"):
                lines.append(f"      Source:    {lead['source_url']}")
            if lead.get("description"):
                lines.append(f"      Title:     {lead['description']}")
        lines += [
            "",
            "To approve:",
            f"  1. Obtain a runnable PoC and save it as manual_supervision/{cve_id}.<ext>",
            "     (or directly into exploits/).",
            f"  2. Approve via the Phase 0 menu, or run: touch manual_supervision/{cve_id}.ok",
            "",
            "If no runnable PoC can be produced, exclude the CVE from the menu.",
        ]
        try:
            (supervision_dir / f"{cve_id}_syntax_report.txt").write_text(
                "\n".join(lines) + "\n", encoding="utf-8")
            self.logger.info(
                "%s: no runnable PoC but verified ExploitDB lead exists — "
                "routed to manual supervision (PoC sourcing)", cve_id)
        except OSError as exc:
            self.logger.warning("Failed to write manual PoC report for %s: %s",
                                cve_id, exc)

    def _create_filtered(self, full: Dataset, cfg: Dict) -> Dataset:
        """Create filtered dataset according to configurable criteria."""
        project_name = self.config.get("project", {}).get("name", "custom")
        require_commit = cfg.get("filtered_require_commit", True)
        require_poc = cfg.get("filtered_require_poc", True)
        require_verified_poc = cfg.get("filtered_require_verified_poc", True)

        def include_entry(entry: CVEEntry) -> bool:
            if require_commit and not entry.has_commits:
                return False
            # Manual-supervision lead: the CVE has everything needed (commit +
            # extracted vulnerable functions) AND a verified ExploitDB entry, but
            # that entry failed runnability validation (a prose write-up, etc.) so
            # no runnable PoC survived. Rather than discard it, keep it so the CSV
            # carries a manual-review row and a human can supply the real PoC.
            if self._manual_poc_sourcing_needed(entry, cfg):
                return True
            # Option A: a regression test the fixing commit ships is a valid,
            # authoritative reproducer — so a CVE with one is kept even when it
            # has no ExploitDB PoC (the majority of glibc CVEs). Phase 1 runs it
            # in-tree and self-validates (test must FAIL on the vulnerable build).
            if getattr(entry.project_state, "regression_tests", None):
                return True
            if require_poc and not entry.has_poc:
                return False
            if require_verified_poc:
                # Require at least one *verified* PoC with extractable content
                has_verified_poc = any(
                    e.verified and e.source_code_content
                    for e in entry.exploits
                )
                if not has_verified_poc:
                    return False
            return True

        filtered_cves = {
            cid: entry for cid, entry in full.cves.items()
            if include_entry(entry)
        }
        criteria_parts: List[str] = []
        if require_commit:
            criteria_parts.append("git commits")
        if require_poc:
            criteria_parts.append("PoC")
        criteria = " and ".join(criteria_parts) if criteria_parts else "no filters"

        ds = Dataset(
            dataset_info={
                "name": f"{project_name}-cve-poc-dataset-filtered",
                "version": "1.0.0",
                "purpose": "Filtered Code-Ready dataset (commits + PoC only)",
                "filter_criteria": f"CVEs with {criteria}",
                "created_at": full.dataset_info.get("created_at", datetime.now().isoformat()),
                "last_updated": datetime.now().isoformat(),
            },
            cves=filtered_cves,
        )
        ds.compute_statistics()
        self.logger.info("Filtered dataset: %d / %d CVEs", len(filtered_cves), len(full.cves))
        return ds

    # ------------------------------------------------------------------
    # CSV export & PoC file writing
    # ------------------------------------------------------------------

    def _export_csv_and_pocs(
        self,
        dataset: Dataset,
        csv_path: Path,
        poc_dir: Path,
        syntax_results: Dict,
        poc_repair_report: Dict,
        cfg: Dict,
    ) -> Tuple[int, int, int]:
        poc_dir.mkdir(parents=True, exist_ok=True)

        # Column names (customisable via config)
        default_fields = [
            "CVE", "V_COMMIT", "V_COMMIT_TIMESTAMP", "V_COMMIT_YEAR", "FilePath", "F_NAME", "UNIT_TYPE",
            "V_FILE", "V_FUNCTION",
            "CVE_Description", "CWE", "CWE_Description",
            "project_version", "project_version_normalized", "ubuntu_version",
            "poc_index", "poc_path", "poc_language",
            "FIX_COMMIT", "TEST_PATH", "TEST_SUBDIR",
            "manual_review_required", "manual_verified",
        ]
        fieldnames = cfg.get("csv_fields", default_fields)

        # Make sure V_COMMIT_TIMESTAMP and V_COMMIT_YEAR are in fieldnames if we are going to provide them
        for f in ["V_COMMIT_TIMESTAMP", "V_COMMIT_YEAR"]:
            if f not in fieldnames:
                fieldnames.insert(2, f)  # Insert after V_COMMIT

        rows: List[Dict[str, Any]] = []
        total = 0
        poc_saved = 0

        for cve_id, entry in dataset.cves.items():
            total += 1
            result = self._build_csv_row(cve_id, entry, poc_dir, syntax_results, poc_repair_report, cfg)
            if result is None:
                continue

            # result is now a list of row dicts (one per changed unit)
            for row in result:
                rows.append(row)

            # Count distinct PoC files saved for this CVE
            saved_paths = {r["poc_path"] for r in result if r.get("_poc_saved")}
            poc_saved += len(saved_paths)

        # Write CSV
        try:
            csv_path.parent.mkdir(parents=True, exist_ok=True)
            tmp = csv_path.parent / f".{csv_path.name}.tmp"
            with open(tmp, "w", encoding="utf-8", newline="") as fh:
                writer = csv.DictWriter(
                    fh, fieldnames=fieldnames,
                    quoting=csv.QUOTE_ALL, extrasaction="ignore",
                )
                writer.writeheader()
                writer.writerows(rows)
            tmp.replace(csv_path)
            self.logger.info("CSV saved: %d rows → %s", len(rows), csv_path)
        except IOError as exc:
            self.logger.error("CSV write failed: %s", exc)

        self.logger.info(
            "Export: %d processed, %d complete rows, %d PoC files saved",
            total, len(rows), poc_saved,
        )
        return total, len(rows), poc_saved

    # ------------------------------------------------------------------
    # Companion archive fetch (multi-file PoCs)
    # ------------------------------------------------------------------

    def _fetch_companion_archive(
        self, cve_id: str, exploit: Any, dest_dir: Path, cfg: Dict,
    ) -> None:
        """Download and extract a multi-file PoC's companion archive.

        ExploitDB stores attachments in the separate ``exploitdb-bin-sploits``
        repo as ``bin-sploits/<edb-id>.<ext>``. We extract every member into
        ``exploits/<CVE>.d/`` (flattened — Phase 1 only reads top-level files),
        skipping any ``exploit.*`` member so it can't clobber the primary PoC
        binary Phase 1 compiles. General and best-effort: any failure (offline,
        404, bad archive) leaves the single-file PoC untouched.
        """
        edb_id = str(getattr(exploit, "exploit_id", "")).replace("EDB-", "").strip()
        archive_name = getattr(exploit, "companion_archive", "")
        if not edb_id or not archive_name:
            return

        # Extension drives the parser; the remote file is keyed by EDB id.
        low = archive_name.lower()
        if low.endswith(".tar.gz") or low.endswith(".tgz"):
            ext, kind = ".tar.gz", "tar"
        elif low.endswith(".tar"):
            ext, kind = ".tar", "tar"
        elif low.endswith(".zip"):
            ext, kind = ".zip", "zip"
        else:
            return

        url_template = cfg.get(
            "bin_sploits_url_template",
            "https://gitlab.com/exploit-database/exploitdb-bin-sploits/-/raw/main/bin-sploits/{id}{ext}",
        )
        url = url_template.format(id=edb_id, ext=ext)

        try:
            resp = requests.get(url, timeout=60)
            if resp.status_code != 200 or not resp.content:
                self.logger.warning(
                    "%s: companion archive fetch failed (HTTP %s) %s",
                    cve_id, resp.status_code, url,
                )
                return
            data = resp.content
        except Exception as exc:  # network error, timeout, etc.
            self.logger.warning("%s: companion archive download error: %s", cve_id, exc)
            return

        # Collect (basename -> bytes), skipping directories, the main exploit
        # (avoids clobbering /poc/exploit), and path-traversal names.
        members: Dict[str, bytes] = {}
        try:
            if kind == "tar":
                with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as tf:
                    for m in tf.getmembers():
                        if not m.isfile():
                            continue
                        base = Path(m.name).name
                        if not base or base.startswith(".."):
                            continue
                        if Path(base).stem.lower() == "exploit":
                            continue
                        fh = tf.extractfile(m)
                        if fh is not None:
                            members[base] = fh.read()
            else:  # zip
                with zipfile.ZipFile(io.BytesIO(data)) as zf:
                    for name in zf.namelist():
                        if name.endswith("/"):
                            continue
                        base = Path(name).name
                        if not base or base.startswith(".."):
                            continue
                        if Path(base).stem.lower() == "exploit":
                            continue
                        members[base] = zf.read(name)
        except Exception as exc:
            self.logger.warning("%s: companion archive extraction error: %s", cve_id, exc)
            return

        if not members:
            return

        try:
            dest_dir.mkdir(parents=True, exist_ok=True)
            for base, blob in members.items():
                (dest_dir / base).write_bytes(blob)
        except OSError as exc:
            self.logger.warning("%s: failed writing companion files: %s", cve_id, exc)
            return

        self.logger.info(
            "%s: extracted %d companion file(s) to %s/: %s",
            cve_id, len(members), dest_dir.name, ", ".join(sorted(members)),
        )

    # ------------------------------------------------------------------
    # Single-row builder
    # ------------------------------------------------------------------

    def _build_csv_row(
        self,
        cve_id: str,
        entry: CVEEntry,
        poc_dir: Path,
        syntax_results: Dict,
        poc_repair_report: Dict,
        cfg: Dict,
    ) -> Optional[List[Dict[str, Any]]]:
        """Build CSV rows per **(changed code unit × exploit)** combination.

        Every exploit (PoC) for the CVE is saved to disk with an indexed
        filename (e.g. ``CVE-2023-1234_poc0.c``, ``CVE-2023-1234_poc1.c``)
        and each code unit is paired with each PoC so that downstream
        consumers can test every PoC individually.

        Returns a list of row dicts.  Returns ``None`` when the entry
        cannot produce any usable row (e.g. no fix commit or no PoC).
        """
        ps = entry.project_state
        meta = entry.metadata

        require_commit = cfg.get("filtered_require_commit", True)
        require_verified_poc = cfg.get("filtered_require_verified_poc", True)

        # Respect the same commit requirement used when building the
        # filtered dataset.  Previously ``allow_poc_without_commit`` was
        # checked independently of ``filtered_require_commit``, which
        # could silently discard every CVE that passed the filter but
        # lacked a fix commit — producing an empty CSV.
        if require_commit and not ps.fix_commit_hash:
            return None

        # Require at least a PoC — an ExploitDB exploit OR a regression test the
        # fixing commit ships (Option A). The latter lets CVEs with no ExploitDB
        # entry (the majority of glibc CVEs) still reach Phase 1.
        reg_tests = list(getattr(ps, "regression_tests", None) or [])
        # ...unless the CVE qualifies for manual PoC sourcing: it has the commit +
        # vulnerable functions and a verified-but-unrunnable ExploitDB lead. Then
        # we still emit a row (flagged for manual review) so it isn't discarded.
        manual_poc_sourcing = self._manual_poc_sourcing_needed(entry, cfg)
        if not entry.exploits and not reg_tests:
            if not manual_poc_sourcing:
                return None
            self._write_manual_poc_report(cve_id, entry, cfg)

        # ---- Save PoC files per the reproduction_strategy (ordered priority) ----
        # Each source emits into its own list; only sources in the strategy run
        # (gated via the loop iterable, so the loop bodies are untouched). The two
        # lists are then assembled in strategy order so the PRIMARY reproducer
        # (poc_index 0, the one Phase 1 uses) is the prioritised source.
        strategy = parse_reproduction_strategy(self.config)
        do_exploitdb = "exploitdb" in strategy
        do_intree = "intree" in strategy
        exploitdb_infos: List[Dict[str, Any]] = []
        intree_infos: List[Dict[str, Any]] = []
        any_poc_saved = False

        saved_idx = 0  # sequential index for saved PoC files
        for orig_idx, exploit in enumerate(entry.exploits if do_exploitdb else []):
            # Skip unverified PoCs when require_verified_poc is set
            if require_verified_poc and not exploit.verified:
                self.logger.debug("Skipping unverified PoC %d for %s", orig_idx, cve_id)
                continue

            content = exploit.source_code_content
            if not content:
                continue

            valid, reason = is_valid_poc_content(content)
            if not valid:
                continue

            poc_lang = exploit.language
            content_lang = detect_language_from_content(content)
            if poc_lang in ("unknown", "text"):
                # Extension gave nothing useful — trust content detection
                poc_lang = content_lang
            elif content_lang not in ("unknown",) and content_lang != poc_lang:
                # Content disagrees with the extension-derived label.
                # Trust content: handles files mislabeled by Exploit-DB
                # (e.g. a tcsh script saved as .php).
                self.logger.info(
                    "Language mismatch for %s: extension says %r but content says %r"
                    " — using content detection",
                    cve_id, poc_lang, content_lang,
                )
                poc_lang = content_lang

            content, _ = clean_poc_content(content)
            ext = get_file_extension_for_language(poc_lang)
            poc_filename = f"{cve_id}{ext}" if saved_idx == 0 else f"{cve_id}_poc{saved_idx}{ext}"
            poc_path = poc_dir / poc_filename

            # Check syntax results for this specific exploit
            key = f"{cve_id}:{orig_idx}"
            sr = syntax_results.get(key, {})
            needs_manual = bool(sr.get("needs_manual_review"))

            # If the LLM repair module successfully fixed this PoC, it is no
            # longer pending manual review regardless of what the syntax validator
            # originally flagged.
            if needs_manual and poc_repair_report.get(key, {}).get("repaired"):
                needs_manual = False

            # Flag PoCs saved as .txt (unrecognised language) for manual review
            if ext == ".txt":
                needs_manual = True

            # PoCs that need manual review are NOT saved to exploits/;
            # they already live in manual_supervision/ (written by SyntaxValidator).
            # The user adds them to exploits/ after review.
            poc_saved = False
            if needs_manual:
                self.logger.info(
                    "PoC %d for %s needs manual review – not saving to exploits/",
                    saved_idx, cve_id,
                )
                # Remove any stale file written by a previous run: a PoC that was
                # "repaired" before but is now flagged (e.g. the repair was
                # rejected as a hallucination, or the source is now detected as a
                # mislabeled advisory) must not leave bogus code behind for Phase 1.
                if poc_path.exists():
                    try:
                        poc_path.unlink()
                        self.logger.info(
                            "Removed stale exploit file for %s: %s",
                            cve_id, poc_path.name,
                        )
                    except OSError as exc:
                        self.logger.warning(
                            "Failed to remove stale exploit file %s: %s",
                            poc_path, exc,
                        )
            else:
                try:
                    poc_path.write_text(content, encoding="utf-8")
                    poc_saved = True
                    any_poc_saved = True
                except IOError as exc:
                    self.logger.warning("Failed to save PoC %d for %s: %s",
                                        saved_idx, cve_id, exc)

                # Multi-file PoC: the primary exploit (index 0) may ship a
                # companion archive (e.g. CVE-2014-5119's pty.c helper). Fetch and
                # extract it into exploits/<CVE>.d/ so Phase 1 can build the helper
                # the main PoC invokes (./pty). Best-effort; never fatal.
                if poc_saved and saved_idx == 0 and getattr(exploit, "companion_archive", ""):
                    self._fetch_companion_archive(
                        cve_id, exploit, poc_dir / f"{cve_id}.d", cfg,
                    )

            exploitdb_infos.append({
                "poc_index": saved_idx,
                "poc_path": str(poc_path) if poc_saved else "",
                "poc_language": poc_lang,
                "needs_manual": needs_manual,
                "poc_saved": poc_saved,
            })
            saved_idx += 1

        # ---- Option A: emit the fixing commit's regression test(s) as PoCs ----
        # poc_language "intree-test": Phase 1 overlays the test (by TEST_PATH at
        # FIX_COMMIT) + its Makefile onto the vulnerable tree and runs it in-tree;
        # baseline = the test FAILS on the vulnerable build. The test source is
        # also saved for inspection. Always offered (in addition to any ExploitDB
        # PoC) since it is typically the authoritative, deterministic reproducer.
        for rt in (reg_tests if do_intree else []):
            is_data = bool(rt.get("is_data"))
            test_src = rt.get("content") or ""
            test_b64 = rt.get("content_b64") or ""
            if is_data:
                if not test_b64:
                    continue
            elif not test_src:
                continue
            saved = False
            if is_data:
                # DATA reproducer (e.g. a crafted .pcap): keep the real extension
                # and write the RAW bytes (a UTF-8 .c write would corrupt it).
                # Phase 1 re-checks-out the authoritative copy by TEST_PATH at the
                # fix commit, so a save failure here is non-fatal for reproduction.
                repo_rel = rt.get("repo_path", "")
                ext = repo_rel.rsplit(".", 1)[-1] if "." in repo_rel else "bin"
                test_file = poc_dir / f"{cve_id}.test{saved_idx}.{ext}"
                try:
                    test_file.write_bytes(base64.b64decode(test_b64))
                    saved = True
                    any_poc_saved = True
                except (IOError, ValueError) as exc:
                    self.logger.warning("Failed to save data regression test for %s: %s",
                                        cve_id, exc)
            else:
                test_file = poc_dir / f"{cve_id}.test{saved_idx}.c"
                try:
                    test_file.write_text(test_src, encoding="utf-8")
                    saved = True
                    any_poc_saved = True
                except IOError as exc:
                    self.logger.warning("Failed to save regression test for %s: %s",
                                        cve_id, exc)
            intree_infos.append({
                "poc_index": saved_idx,
                "poc_path": str(test_file) if saved else "",
                "poc_language": "intree-test",
                "needs_manual": False,
                "poc_saved": saved,
                "test_path": rt.get("repo_path", ""),
                "test_subdir": rt.get("subdir", ""),
                "fix_commit": ps.fix_commit_hash or "",
            })
            saved_idx += 1

        # ---- Assemble in strategy priority order ----
        # The first emitted entry becomes poc_index 0 — the PRIMARY reproducer
        # Phase 1 picks (it de-dups to the first CSV row per CVE). The two
        # emitters ran in code order, so re-index here to honour the strategy
        # (e.g. [intree, exploitdb] puts the fix-commit test first).
        poc_infos: List[Dict[str, Any]] = []
        _by_source = {"exploitdb": exploitdb_infos, "intree": intree_infos}
        _idx = 0
        for _src in strategy:
            for info in _by_source.get(_src, []):
                info["poc_index"] = _idx
                poc_infos.append(info)
                _idx += 1

        # If no valid PoC could be extracted, still keep one placeholder
        # so the CVE is not silently dropped from the CSV. When the CVE qualifies
        # for manual PoC sourcing, the placeholder carries the manual-review flag
        # so Phase 0 pauses for a human to supply the real PoC (and Phase 1 skips
        # it until then).
        if not poc_infos:
            poc_infos.append({
                "poc_index": 0,
                "poc_path": "",
                "poc_language": "unknown",
                "needs_manual": manual_poc_sourcing,
                "poc_saved": False,
            })

        # ---- Version info (shared) ----
        project_name = self.config.get("project", {}).get("name", "")
        project_version = extract_project_version_from_cpe(
            meta.affected_products, project_name,
        )
        # Extract the most recent single version from the (potentially multi-value)
        # project_version string. Used by Phase 1 to resolve the OS build target.
        project_version_normalized = (
            project_version.split(",")[-1].strip() if project_version else ""
        )
        ubuntu_version = get_ubuntu_version(project_version_normalized)

        # Get vulnerable commit date/year if available
        v_commit_timestamp = ""
        v_commit_year = ""
        if ps.vulnerable_commit_metadata and "date" in ps.vulnerable_commit_metadata:
            v_commit_timestamp = ps.vulnerable_commit_metadata["date"]
            v_commit_year = v_commit_timestamp[:4]

        # ---- Collect code-unit rows (without PoC info yet) ----
        base_rows: List[Dict[str, Any]] = []
        changed_units_map = ps.changed_code_units or {}
        vuln_files = ps.vulnerable_files_content or {}

        # Process production source files before test files: fix commits
        # often ADD a regression test alongside the real fix, and a test
        # file's "changed units" (e.g. a brand-new do_test with an empty
        # vulnerable body) must not shadow the actual vulnerable function.
        # Test-file rows are emitted only when NO production file yielded
        # any unit (last-resort, so the CVE is not silently dropped).
        _ordered_files = sorted(
            changed_units_map.items(),
            key=lambda kv: _is_test_file(kv[0]),
        )
        _prod_has_units = any(
            units and not _is_test_file(fpath)
            for fpath, units in changed_units_map.items()
        )

        for fpath, units in _ordered_files:
            if _is_test_file(fpath) and _prod_has_units:
                self.logger.debug(
                    "%s: skipping test-file units from %s", cve_id, fpath
                )
                continue
            vuln_file_content = vuln_files.get(fpath, "")
            # Within a file, prefer units that actually have a vulnerable
            # body (units new in the fix commit have an empty vuln_body and
            # are useless for patch generation).
            units = sorted(units, key=lambda u: not (u.get("vuln_body") or ""))
            for unit in units:
                base_rows.append({
                    "CVE": cve_id,
                    "V_COMMIT": ps.vulnerable_commit_hash or "",
                    "V_COMMIT_TIMESTAMP": v_commit_timestamp,
                    "V_COMMIT_YEAR": v_commit_year,
                    "FilePath": fpath,
                    "F_NAME": unit["name"],
                    "UNIT_TYPE": unit["unit_type"],
                    "V_FILE": vuln_file_content,
                    "V_FUNCTION": unit["vuln_body"],
                    "CVE_Description": meta.description or "",
                    "CWE": ",".join(meta.cwe_ids or []),
                    "CWE_Description": get_cwe_descriptions(meta.cwe_ids),
                    "project_version": project_version,
                    "project_version_normalized": project_version_normalized,
                    "ubuntu_version": ubuntu_version,
                })

        # Fallback: one row per changed source file
        if not base_rows:
            for cf in (ps.changed_files or []):
                ftype = cf.get("file_type", "")
                if ftype not in ("source", "header"):
                    continue
                fpath = cf["file_path"]
                vuln_file_content = vuln_files.get(fpath, "")
                base_rows.append({
                    "CVE": cve_id,
                    "V_COMMIT": ps.vulnerable_commit_hash or "",
                    "V_COMMIT_TIMESTAMP": v_commit_timestamp,
                    "V_COMMIT_YEAR": v_commit_year,
                    "FilePath": fpath,
                    "F_NAME": "",
                    "UNIT_TYPE": "",
                    "V_FILE": vuln_file_content,
                    "V_FUNCTION": "",
                    "CVE_Description": meta.description or "",
                    "CWE": ",".join(meta.cwe_ids or []),
                    "CWE_Description": get_cwe_descriptions(meta.cwe_ids),
                    "project_version": project_version,
                    "project_version_normalized": project_version_normalized,
                    "ubuntu_version": ubuntu_version,
                })

        # Last-resort fallback: single bare row
        if not base_rows:
            first_file = ""
            if ps.changed_files:
                first_file = ps.changed_files[0]["file_path"]
            base_rows.append({
                "CVE": cve_id,
                "V_COMMIT": ps.vulnerable_commit_hash or "",
                "V_COMMIT_TIMESTAMP": v_commit_timestamp,
                "V_COMMIT_YEAR": v_commit_year,
                "FilePath": first_file,
                "F_NAME": "",
                "UNIT_TYPE": "",
                "V_FILE": "",
                "V_FUNCTION": "",
                "CVE_Description": meta.description or "",
                "CWE": ",".join(meta.cwe_ids or []),
                "CWE_Description": get_cwe_descriptions(meta.cwe_ids),
                "project_version": project_version,
                "project_version_normalized": project_version_normalized,
                "ubuntu_version": ubuntu_version,
            })

        # ---- Cross-product: base_rows × poc_infos ----
        rows: List[Dict[str, Any]] = []
        for base in base_rows:
            for pi in poc_infos:
                row = {**base}
                row["poc_index"] = pi["poc_index"]
                row["poc_path"] = pi["poc_path"]
                row["poc_language"] = pi["poc_language"]
                # Option A: in-tree regression-test PoCs carry the fix ref + the
                # test's in-repo path so Phase 1 can overlay and run it.
                row["FIX_COMMIT"] = pi.get("fix_commit", "")
                row["TEST_PATH"] = pi.get("test_path", "")
                row["TEST_SUBDIR"] = pi.get("test_subdir", "")
                row["manual_review_required"] = pi["needs_manual"]
                row["manual_verified"] = "pending" if pi["needs_manual"] else "done"
                row["_poc_saved"] = pi["poc_saved"]
                rows.append(row)

        return rows

