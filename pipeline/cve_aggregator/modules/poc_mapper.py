"""
PoC Mapping & Extraction module.

Cross-references CVEs against the local ExploitDB repository, extracts
full source code content from matched exploit files, and optionally
performs a reverse search to discover CVEs not found via NVD keywords.
"""

from __future__ import annotations

import csv
import logging
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

import requests

from ..models import ExploitInfo
from ..utils.git_utils import clone_or_update_repo
from ..utils.file_utils import (
    detect_language_from_path,
    extract_file_content,
    is_text_file,
    is_valid_poc_content,
)
from .base import PipelineModule

logger = logging.getLogger(__name__)


class PoCMapper(PipelineModule):
    """Pipeline module: *PoC Mapping & Extraction*.

    Reads ``context["raw_cves"]`` and attaches exploit / PoC information
    to each CVE entry.  Also discovers new CVEs that weren't fetched
    from NVD but have PoCs in ExploitDB.
    """

    def validate_config(self) -> bool:
        cfg = self.config.get("poc_mapper", {})
        if not cfg.get("exploitdb_path"):
            self.logger.error("poc_mapper.exploitdb_path is required")
            return False
        return True

    # ----- main entry point -----

    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        cfg = self.config.get("poc_mapper", {})
        edb_path = Path(cfg["exploitdb_path"])
        edb_remote = cfg.get("exploitdb_remote_url", "https://gitlab.com/exploit-database/exploitdb.git")
        deep_search: bool = cfg.get("deep_search", False)
        extract_content: bool = cfg.get("extract_content", True)
        reverse_search: bool = cfg.get("reverse_search", True)
        require_verified: bool = cfg.get("require_verified", True)

        # Step 1 – Update ExploitDB
        if cfg.get("auto_update", True):
            self.logger.info("Updating ExploitDB repository …")
            clone_or_update_repo(edb_path, edb_remote)

        # Step 2 – Load CSV mapping
        self.logger.info("Loading ExploitDB CSV mappings …")
        cve_to_exploits = self._load_csv_mapping(edb_path, require_verified)
        self.logger.info("  Mapped %d CVE IDs from ExploitDB CSVs", len(cve_to_exploits))

        # Step 3 – (Optional) Reverse search for additional CVEs
        raw_cves: List[Dict[str, Any]] = context.get("raw_cves", [])
        if reverse_search:
            existing_ids = {c.get("cve_id", "") for c in raw_cves}
            extras = self._reverse_search(edb_path, cfg, existing_ids, cve_to_exploits)
            if extras:
                self.logger.info("  Reverse search found %d extra CVEs", len(extras))
                raw_cves.extend(extras)

        # Step 4 – Cross-reference each CVE with ExploitDB
        self.logger.info("Cross-referencing CVEs with ExploitDB …")
        matched = 0
        for cve in raw_cves:
            cve_id = cve.get("cve_id", "")
            exploits: List[Dict] = []

            # Direct mapping
            if cve_id in cve_to_exploits:
                exploits.extend(cve_to_exploits[cve_id])

            # Deep search (slower)
            if deep_search and not exploits:
                exploits.extend(self._search_in_content(edb_path, cve_id))

            # Extract source code
            if extract_content:
                exploits = [self._extract_content(e, edb_path) for e in exploits]

            cve["exploits"] = exploits
            cve["has_poc"] = len(exploits) > 0
            cve["poc_count"] = len(exploits)
            if exploits:
                matched += 1

        self.logger.info("PoC Mapper: %d / %d CVEs have exploits", matched, len(raw_cves))
        context["raw_cves"] = raw_cves
        return context

    # ------------------------------------------------------------------
    # CSV-based exploit mapping
    # ------------------------------------------------------------------

    def _load_csv_mapping(self, edb_path: Path, require_verified: bool = True) -> Dict[str, List[Dict]]:
        """Parse ExploitDB CSV files and build a {CVE-ID → [exploit_info]} map."""
        mapping: Dict[str, List[Dict]] = {}

        for csv_name in ("files_exploits.csv", "files_shellcodes.csv"):
            csv_path = edb_path / csv_name
            if not csv_path.exists():
                self.logger.debug("CSV not found: %s", csv_path)
                continue
            self._parse_csv(csv_path, mapping, edb_path, require_verified)

        return mapping

    def _parse_csv(self, csv_path: Path, mapping: Dict[str, List[Dict]], edb_path: Path, require_verified: bool = True) -> int:
        """Parse a single ExploitDB CSV and add entries to *mapping*."""
        count = 0
        try:
            with open(csv_path, "r", encoding="utf-8", errors="replace") as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    if require_verified and row.get("verified", "0") != "1":
                        continue
                    codes_str = row.get("codes", "")
                    for code in codes_str.split(";"):
                        code = code.strip()
                        if re.match(r"CVE-\d{4}-\d+", code):
                            info = self._row_to_info(row, edb_path)
                            mapping.setdefault(code, []).append(info)
                            count += 1
        except Exception as exc:
            self.logger.warning("Error parsing %s: %s", csv_path, exc)
        return count

    @staticmethod
    def _row_to_info(row: Dict, edb_path: Path) -> Dict:
        eid = row.get("id", "")
        file_rel = row.get("file", "")
        full_path = str(edb_path / file_rel) if file_rel else ""
        return {
            "exploit_id": f"EDB-{eid}" if eid else "",
            "file_path": file_rel,
            "full_local_path": full_path,
            "description": row.get("description", ""),
            "author": row.get("author", ""),
            "date": row.get("date_published", ""),
            "platform": row.get("platform", ""),
            "exploit_type": row.get("type", ""),
            "language": detect_language_from_path(file_rel) if file_rel else "unknown",
            "verified": row.get("verified", "0") == "1",
            "match_type": "csv_metadata",
            "exploitdb_url": f"https://www.exploit-db.com/exploits/{eid}" if eid else "",
        }

    # ------------------------------------------------------------------
    # Deep content search
    # ------------------------------------------------------------------

    def _search_in_content(self, edb_path: Path, cve_id: str) -> List[Dict]:
        """Search exploit file contents for *cve_id* mentions."""
        results: List[Dict] = []
        exploits_dir = edb_path / "exploits"
        if not exploits_dir.exists():
            return results

        try:
            proc = subprocess.run(
                ["grep", "-rl", cve_id, str(exploits_dir)],
                capture_output=True, text=True, timeout=60,
            )
            if proc.returncode == 0:
                for line in proc.stdout.strip().splitlines():
                    fpath = Path(line.strip())
                    if fpath.exists() and is_text_file(fpath):
                        rel = str(fpath.relative_to(edb_path))
                        results.append({
                            "exploit_id": "",
                            "file_path": rel,
                            "full_local_path": str(fpath),
                            "language": detect_language_from_path(rel),
                            "match_type": "content_search",
                        })
        except Exception as exc:
            self.logger.debug("Content search failed for %s: %s", cve_id, exc)

        return results

    # ------------------------------------------------------------------
    # Source code extraction
    # ------------------------------------------------------------------

    def _extract_content(self, exploit: Dict, edb_path: Path) -> Dict:
        """Attach ``source_code_content`` to an exploit dict."""
        full_path = exploit.get("full_local_path", "")
        if not full_path:
            rel = exploit.get("file_path", "")
            if rel:
                full_path = str(edb_path / rel)

        if full_path and Path(full_path).exists():
            content, status = extract_file_content(Path(full_path))
            exploit["source_code_content"] = content
            exploit["content_extraction_status"] = status
            exploit["file_size_bytes"] = Path(full_path).stat().st_size if content else None
        else:
            exploit["source_code_content"] = None
            exploit["content_extraction_status"] = "file_not_found"

        return exploit

    # ------------------------------------------------------------------
    # Reverse search (discover CVEs from ExploitDB titles / contents)
    # ------------------------------------------------------------------

    def _reverse_search(
        self,
        edb_path: Path,
        cfg: Dict,
        existing_ids: Set[str],
        cve_to_exploits: Dict[str, List[Dict]],
    ) -> List[Dict]:
        """Find CVEs in ExploitDB that weren't fetched from NVD."""
        cve_fetcher_cfg = self.config.get("cve_fetcher", {})
        strong_kws: List[str] = cfg.get("strong_keywords", cve_fetcher_cfg.get("strong_keywords", []))
        content_kws: List[str] = cfg.get("content_search_keywords", strong_kws)
        
        # Merge non_target_indicators instead of overriding
        non_target = list(set(
            cfg.get("non_target_indicators", []) + 
            cve_fetcher_cfg.get("non_target_indicators", [])
        ))
        min_published_year: Optional[int] = cve_fetcher_cfg.get("min_published_year")
        
        require_verified: bool = cfg.get("require_verified", True)
        enable_reverse_content_grep: bool = cfg.get("enable_reverse_content_grep", True)
        extras: List[Dict] = []

        def _is_allowed(cid: str, desc: str) -> bool:
            if min_published_year is not None:
                try:
                    # e.g., "CVE-2015-1234" -> 2015
                    year = int(cid.split("-")[1])
                    if year < min_published_year:
                        return False
                except (IndexError, ValueError):
                    pass
            desc_lower = desc.lower()
            if any(ind.lower() in desc_lower for ind in non_target):
                return False
            return True

        # Check CVE-to-exploit mapping for entries whose description matches keywords
        for cve_id, exploits in cve_to_exploits.items():
            if cve_id in existing_ids:
                continue
            for exp in exploits:
                desc = exp.get("description", "")
                if any(kw.lower() in desc.lower() for kw in strong_kws):
                    if require_verified and not exp.get("verified", False):
                        continue
                    if not _is_allowed(cve_id, desc):
                        continue
                    extras.append({
                        "cve_id": cve_id,
                        "description": desc,
                        "source": "ExploitDB_reverse",
                        "exploits": [exp],
                        "has_poc": True,
                        "poc_count": 1,
                    })
                    existing_ids.add(cve_id)
                    break

        # Optionally grep exploit contents for strong keywords
        if enable_reverse_content_grep and content_kws:
            exploits_dir = edb_path / "exploits"
            if exploits_dir.exists():
                for kw in content_kws:
                    try:
                        proc = subprocess.run(
                            ["grep", "-rl", kw, str(exploits_dir)],
                            capture_output=True, text=True, timeout=120,
                        )
                        if proc.returncode == 0:
                            for line in proc.stdout.strip().splitlines():
                                fpath = Path(line.strip())
                                if not fpath.exists():
                                    continue
                                # Try to extract CVE IDs from the file
                                try:
                                    text = fpath.read_text(encoding="utf-8", errors="replace")[:4096]
                                    for m in re.finditer(r"CVE-\d{4}-\d+", text):
                                        cid = m.group(0)
                                        if cid not in existing_ids and _is_allowed(cid, ""):
                                            extras.append({
                                                "cve_id": cid,
                                                "description": "",
                                                "source": "ExploitDB_content_grep",
                                            })
                                            existing_ids.add(cid)
                                except Exception:
                                    pass
                    except Exception as exc:
                        self.logger.debug("Content grep failed for '%s': %s", kw, exc)

        return extras
