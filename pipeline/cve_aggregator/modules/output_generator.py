"""
Output Generation module.

Produces all final artefacts:
  1. **Global JSON** – full dataset (``cve_poc_map.json``)
  2. **Filtered JSON** – only CVEs with commits + PoC (``cve_poc_map_filtered.json``)
  3. **Complete CSV** – tabular view for pipeline consumption
  4. **PoC files** – individual exploit files saved to disk (``exploits/``)
"""

from __future__ import annotations

import csv
import json
import logging
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..models import CVEEntry, Dataset
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
        total, complete, saved = self._export_csv_and_pocs(
            filtered, csv_path, poc_dir, syntax_results, cfg,
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

    def _create_filtered(self, full: Dataset, cfg: Dict) -> Dataset:
        """Create filtered dataset according to configurable criteria."""
        project_name = self.config.get("project", {}).get("name", "custom")
        require_commit = cfg.get("filtered_require_commit", True)
        require_poc = cfg.get("filtered_require_poc", True)
        require_verified_poc = cfg.get("filtered_require_verified_poc", True)

        def include_entry(entry: CVEEntry) -> bool:
            if require_commit and not entry.has_commits:
                return False
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
        cfg: Dict,
    ) -> Tuple[int, int, int]:
        poc_dir.mkdir(parents=True, exist_ok=True)

        # Column names (customisable via config)
        default_fields = [
            "CVE", "V_COMMIT", "FilePath", "F_NAME", "UNIT_TYPE",
            "V_FILE", "V_FUNCTION",
            "CVE_Description", "CWE", "CWE_Description",
            "project_version", "ubuntu_version",
            "poc_index", "poc_path", "poc_language",
            "manual_review_required", "manual_verified",
        ]
        fieldnames = cfg.get("csv_fields", default_fields)

        rows: List[Dict[str, Any]] = []
        total = 0
        poc_saved = 0

        for cve_id, entry in dataset.cves.items():
            total += 1
            result = self._build_csv_row(cve_id, entry, poc_dir, syntax_results, cfg)
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
    # Single-row builder
    # ------------------------------------------------------------------

    def _build_csv_row(
        self,
        cve_id: str,
        entry: CVEEntry,
        poc_dir: Path,
        syntax_results: Dict,
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

        allow_without_commit = cfg.get("allow_poc_without_commit", False)

        # By default, require fix commit for pipeline-ready rows.
        # When allow_poc_without_commit is enabled, keep placeholder rows so
        # PoC inventory can still be exported and reviewed.
        if not ps.fix_commit_hash and not allow_without_commit:
            return None

        # Require at least a PoC
        if not entry.exploits:
            return None

        # ---- Save ALL PoC files and collect per-exploit info ----
        poc_infos: List[Dict[str, Any]] = []  # one dict per valid exploit
        any_poc_saved = False

        saved_idx = 0  # sequential index for saved PoC files
        for orig_idx, exploit in enumerate(entry.exploits):
            # Disregard unverified PoCs entirely
            if not exploit.verified:
                self.logger.debug("Skipping unverified PoC %d for %s", orig_idx, cve_id)
                continue

            content = exploit.source_code_content
            if not content:
                continue

            valid, reason = is_valid_poc_content(content)
            if not valid:
                continue

            poc_lang = exploit.language
            if poc_lang == "unknown":
                poc_lang = detect_language_from_content(content)

            content, _ = clean_poc_content(content)
            ext = get_file_extension_for_language(poc_lang)
            poc_filename = f"{cve_id}{ext}" if saved_idx == 0 else f"{cve_id}_poc{saved_idx}{ext}"
            poc_path = poc_dir / poc_filename

            # Check syntax results for this specific exploit
            key = f"{cve_id}:{orig_idx}"
            sr = syntax_results.get(key, {})
            needs_manual = bool(sr.get("needs_manual_review"))

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
            else:
                try:
                    poc_path.write_text(content, encoding="utf-8")
                    poc_saved = True
                    any_poc_saved = True
                except IOError as exc:
                    self.logger.warning("Failed to save PoC %d for %s: %s",
                                        saved_idx, cve_id, exc)

            poc_infos.append({
                "poc_index": saved_idx,
                "poc_path": str(poc_path) if poc_saved else "",
                "poc_language": poc_lang,
                "needs_manual": needs_manual,
                "poc_saved": poc_saved,
            })
            saved_idx += 1

        # If no valid PoC could be extracted, still keep one placeholder
        # so the CVE is not silently dropped from the CSV.
        if not poc_infos:
            poc_infos.append({
                "poc_index": 0,
                "poc_path": "",
                "poc_language": "unknown",
                "needs_manual": False,
                "poc_saved": False,
            })

        # ---- Version info (shared) ----
        project_name = self.config.get("project", {}).get("name", "")
        project_version = extract_project_version_from_cpe(
            meta.affected_products, project_name,
        )
        ubuntu_version = get_ubuntu_version(
            project_version.split(",")[-1].strip() if project_version else ""
        )

        # ---- Collect code-unit rows (without PoC info yet) ----
        base_rows: List[Dict[str, Any]] = []
        changed_units_map = ps.changed_code_units or {}
        vuln_files = ps.vulnerable_files_content or {}

        for fpath, units in changed_units_map.items():
            vuln_file_content = vuln_files.get(fpath, "")
            for unit in units:
                base_rows.append({
                    "CVE": cve_id,
                    "V_COMMIT": ps.vulnerable_commit_hash or "",
                    "FilePath": fpath,
                    "F_NAME": unit["name"],
                    "UNIT_TYPE": unit["unit_type"],
                    "V_FILE": vuln_file_content,
                    "V_FUNCTION": unit["vuln_body"],
                    "CVE_Description": meta.description or "",
                    "CWE": ",".join(meta.cwe_ids or []),
                    "CWE_Description": get_cwe_descriptions(meta.cwe_ids),
                    "project_version": project_version,
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
                    "FilePath": fpath,
                    "F_NAME": "",
                    "UNIT_TYPE": "",
                    "V_FILE": vuln_file_content,
                    "V_FUNCTION": "",
                    "CVE_Description": meta.description or "",
                    "CWE": ",".join(meta.cwe_ids or []),
                    "CWE_Description": get_cwe_descriptions(meta.cwe_ids),
                    "project_version": project_version,
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
                "FilePath": first_file,
                "F_NAME": "",
                "UNIT_TYPE": "",
                "V_FILE": "",
                "V_FUNCTION": "",
                "CVE_Description": meta.description or "",
                "CWE": ",".join(meta.cwe_ids or []),
                "CWE_Description": get_cwe_descriptions(meta.cwe_ids),
                "project_version": project_version,
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
                row["manual_review_required"] = pi["needs_manual"]
                row["manual_verified"] = "pending" if pi["needs_manual"] else "done"
                row["_poc_saved"] = pi["poc_saved"]
                rows.append(row)

        return rows
