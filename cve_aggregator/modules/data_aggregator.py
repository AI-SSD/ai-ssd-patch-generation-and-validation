"""
Data Aggregation & Structuring module.

Takes raw CVE dicts (enriched with commits and exploits by earlier stages)
and transforms them into the unified :class:`Dataset` / :class:`CVEEntry`
model.  Merges new data with any previously-persisted dataset.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List

from ..models import CVEEntry, CVEMetadata, Dataset, ExploitInfo, ProjectState
from .base import PipelineModule

logger = logging.getLogger(__name__)


class DataAggregator(PipelineModule):
    """Pipeline module: *Data Aggregation & Structuring*.

    Reads ``context["raw_cves"]`` and produces ``context["dataset"]``
    (a :class:`Dataset` instance).  If an existing JSON dataset file
    exists on disk, it is loaded and merged.
    """

    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        cfg = self.config.get("data_aggregator", {})
        output_path = Path(cfg.get("global_json_path", "cve_poc_map.json"))

        # Load existing dataset (if any)
        existing = self._load_existing(output_path, cfg)

        # Transform raw CVE dicts → CVEEntry objects & merge
        raw_cves: List[Dict] = context.get("raw_cves", [])
        new_count = updated_count = 0

        for raw in raw_cves:
            cve_id = raw.get("cve_id", "")
            if not cve_id:
                continue

            entry = self._transform(raw, cfg)

            if cve_id in existing.cves:
                existing.cves[cve_id] = self._merge(existing.cves[cve_id], entry)
                updated_count += 1
            else:
                existing.cves[cve_id] = entry
                new_count += 1

        existing.compute_statistics()
        existing.dataset_info["last_updated"] = datetime.now().isoformat()

        self.logger.info("Aggregator: %d new, %d updated → %d total CVEs",
                         new_count, updated_count, len(existing.cves))

        context["dataset"] = existing
        return context

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _load_existing(self, path: Path, cfg: Dict) -> Dataset:
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                ds = Dataset.from_dict(data)
                self.logger.info("Loaded existing dataset: %d CVEs", len(ds.cves))
                return ds
            except (json.JSONDecodeError, IOError) as exc:
                self.logger.warning("Cannot load existing dataset: %s", exc)

        project_name = self.config.get("project", {}).get("name", "custom")
        return Dataset(
            dataset_info={
                "name": f"{project_name}-cve-poc-dataset",
                "version": "1.0.0",
                "purpose": "Code-Ready dataset for AI-based Vulnerability Patching Pipeline",
                "created_at": datetime.now().isoformat(),
                "last_updated": None,
                "description": f"CVE and PoC mapping dataset for {project_name}",
                "source_apis": ["NVD"],
            },
        )

    def _transform(self, raw: Dict, cfg: Dict) -> CVEEntry:
        """Convert a raw CVE dict into a :class:`CVEEntry`."""
        meta = CVEMetadata(
            cve_id=raw.get("cve_id", ""),
            description=raw.get("description", ""),
            cvss_score=raw.get("cvss_score"),
            cvss_version=raw.get("cvss_version"),
            cvss_vector=raw.get("cvss_vector"),
            cvss_severity=raw.get("cvss_severity"),
            published_date=raw.get("published_date", ""),
            last_modified=raw.get("last_modified", ""),
            vuln_status=raw.get("vuln_status", ""),
            cwe_ids=raw.get("cwe_ids", []),
            references=raw.get("references", []),
            affected_products=raw.get("affected_products", []),
            source=raw.get("source", "NVD"),
        )

        ps_data = raw.get("project_state", {})
        ps = ProjectState.from_dict(ps_data) if ps_data else ProjectState()

        exploits = [
            ExploitInfo.from_dict(e) for e in raw.get("exploits", [])
        ]

        return CVEEntry(
            metadata=meta,
            project_state=ps,
            exploits=exploits,
            has_poc=raw.get("has_poc", len(exploits) > 0),
            has_commits=ps.fix_commit_hash is not None,
            has_vulnerable_code=bool(ps.vulnerable_files_content),
            has_vulnerable_functions=bool(ps.vulnerable_functions),
            poc_count=len(exploits),
            first_seen=raw.get("first_seen", datetime.now().isoformat()),
            last_checked=datetime.now().isoformat(),
        )

    @staticmethod
    def _merge(existing: CVEEntry, new: CVEEntry) -> CVEEntry:
        """Merge *new* data into *existing*, keeping the richer information."""
        # Keep existing metadata if not empty, else use new
        if new.metadata.description and not existing.metadata.description:
            existing.metadata.description = new.metadata.description

        if new.metadata.cvss_score is not None:
            existing.metadata.cvss_score = new.metadata.cvss_score
            existing.metadata.cvss_version = new.metadata.cvss_version
            existing.metadata.cvss_vector = new.metadata.cvss_vector
            existing.metadata.cvss_severity = new.metadata.cvss_severity

        # Merge CWE IDs
        all_cwes = set(existing.metadata.cwe_ids or []) | set(new.metadata.cwe_ids or [])
        existing.metadata.cwe_ids = sorted(all_cwes)

        # Update project_state if new has better data
        if new.project_state.fix_commit_hash and not existing.project_state.fix_commit_hash:
            existing.project_state = new.project_state
        else:
            # Selectively update fields that the new run may have improved
            if (new.project_state.vulnerable_files_content and
                    not existing.project_state.vulnerable_files_content):
                existing.project_state.vulnerable_files_content = new.project_state.vulnerable_files_content

            if (new.project_state.patched_files_content and
                    not existing.project_state.patched_files_content):
                existing.project_state.patched_files_content = new.project_state.patched_files_content

            if (new.project_state.vulnerable_functions and
                    not existing.project_state.vulnerable_functions):
                existing.project_state.vulnerable_functions = new.project_state.vulnerable_functions

            # Always prefer new changed_code_units (the improved extraction)
            if new.project_state.changed_code_units:
                existing.project_state.changed_code_units = new.project_state.changed_code_units
                # Also refresh dependent fields
                if new.project_state.vulnerable_files_content:
                    existing.project_state.vulnerable_files_content = new.project_state.vulnerable_files_content
                if new.project_state.patched_files_content:
                    existing.project_state.patched_files_content = new.project_state.patched_files_content
                if new.project_state.vulnerable_functions:
                    existing.project_state.vulnerable_functions = new.project_state.vulnerable_functions

        # Merge exploits (avoid duplicates by exploit_id)
        existing_ids = {e.exploit_id for e in existing.exploits if e.exploit_id}
        for exp in new.exploits:
            if exp.exploit_id and exp.exploit_id not in existing_ids:
                existing.exploits.append(exp)
                existing_ids.add(exp.exploit_id)

        # Refresh flags
        existing.has_poc = len(existing.exploits) > 0
        existing.has_commits = existing.project_state.fix_commit_hash is not None
        existing.has_vulnerable_code = bool(existing.project_state.vulnerable_files_content)
        existing.has_vulnerable_functions = bool(existing.project_state.vulnerable_functions)
        existing.poc_count = len(existing.exploits)
        existing.last_checked = datetime.now().isoformat()

        return existing
