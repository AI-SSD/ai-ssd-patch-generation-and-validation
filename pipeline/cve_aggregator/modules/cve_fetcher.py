"""
CVE Fetching & Enrichment module.

Fetches CVE data from external APIs (NVD and CVE.org) and enriches
entries with additional metadata.  The set of keywords, API keys,
and filtering rules are all driven by configuration.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any, Dict, List, Optional

import requests

from ..models import CVEMetadata
from .base import PipelineModule

logger = logging.getLogger(__name__)


class CVEFetcher(PipelineModule):
    """Pipeline module: *CVE Fetching & Enrichment*.

    Reads from ``config["cve_fetcher"]`` and populates
    ``context["raw_cves"]`` with a list of :class:`CVEMetadata` dicts.
    """

    NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    CVE_ORG_API_BASE = "https://cveawg.mitre.org/api/cve"

    # ----- lifecycle -----

    def validate_config(self) -> bool:
        cfg = self.config.get("cve_fetcher", {})
        if not cfg.get("keywords"):
            self.logger.error("cve_fetcher.keywords must be a non-empty list")
            return False
        return True

    # ----- main entry point -----

    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        cfg = self.config.get("cve_fetcher", {})

        # Step 1 – Fetch from NVD
        self.logger.info("Fetching CVEs from NVD API …")
        raw_cves = self._fetch_nvd(cfg)

        # Step 2 – De-duplicate & filter
        raw_cves = self._deduplicate(raw_cves, cfg)

        # Step 3 – (Optional) enrich with CVE.org
        if cfg.get("enrich_with_cve_org", False):
            self.logger.info("Enriching CVEs with CVE.org data …")
            raw_cves = self._enrich_cve_org(raw_cves, cfg)

        self.logger.info("CVE Fetcher produced %d CVEs", len(raw_cves))
        context["raw_cves"] = raw_cves
        return context

    # ------------------------------------------------------------------
    # NVD API
    # ------------------------------------------------------------------

    def _fetch_nvd(self, cfg: Dict) -> List[Dict[str, Any]]:
        keywords: List[str] = cfg.get("keywords", [])
        api_key: str = cfg.get("nvd_api_key", "")
        delay = 0.6 if api_key else 6.0
        headers = {"apiKey": api_key} if api_key else {}
        results_per_page = 100
        all_cves: List[Dict[str, Any]] = []

        for keyword in keywords:
            self.logger.info("  NVD keyword: '%s'", keyword)
            start_index = 0

            while True:
                params = {
                    "keywordSearch": keyword,
                    "startIndex": start_index,
                    "resultsPerPage": results_per_page,
                }
                try:
                    resp = requests.get(
                        self.NVD_API_BASE,
                        headers=headers,
                        params=params,
                        timeout=30,
                    )
                    if resp.status_code == 403:
                        self.logger.warning("NVD rate-limited – sleeping 30 s")
                        time.sleep(30)
                        continue

                    resp.raise_for_status()
                    data = resp.json()

                    vulns = data.get("vulnerabilities", [])
                    total = data.get("totalResults", 0)
                    self.logger.info("    Retrieved %d / %d", len(vulns), total)

                    for v in vulns:
                        parsed = self._parse_nvd_cve(v)
                        if parsed and self._is_valid_public_cve(parsed):
                            all_cves.append(parsed)

                    start_index += results_per_page
                    if start_index >= total:
                        break
                    time.sleep(delay)

                except requests.exceptions.Timeout:
                    self.logger.error("NVD timeout for '%s'", keyword)
                    break
                except requests.exceptions.RequestException as exc:
                    self.logger.error("NVD request error: %s", exc)
                    break
                except json.JSONDecodeError as exc:
                    self.logger.error("NVD JSON error: %s", exc)
                    break

        return all_cves

    # ------------------------------------------------------------------
    # Parsing helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_nvd_cve(vuln: Dict) -> Optional[Dict[str, Any]]:
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")
        if not cve_id:
            return None

        # Description (prefer English)
        descriptions = cve.get("descriptions", [])
        description = ""
        for d in descriptions:
            if d.get("lang") == "en":
                description = d.get("value", "")
                break
        if not description and descriptions:
            description = descriptions[0].get("value", "")

        # CVSS (prefer v3.1 → v3.0 → v2.0)
        cvss_score = cvss_version = cvss_vector = cvss_severity = None
        metrics = cve.get("metrics", {})
        for version_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(version_key, [])
            if metric_list:
                cvss_data = metric_list[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                cvss_version = cvss_data.get("version")
                cvss_vector = cvss_data.get("vectorString")
                cvss_severity = metric_list[0].get("baseSeverity",
                                                    cvss_data.get("baseSeverity"))
                break

        # CWE IDs
        cwe_ids: List[str] = []
        for weakness in cve.get("weaknesses", []):
            for wd in weakness.get("description", []):
                val = wd.get("value", "")
                if val.startswith("CWE-"):
                    cwe_ids.append(val)

        # References
        references = [
            ref.get("url", "") for ref in cve.get("references", []) if ref.get("url")
        ]

        # Affected products (CPE)
        affected: List[Dict[str, str]] = []
        for config_node in cve.get("configurations", []):
            for node in config_node.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe = match.get("criteria", "")
                    if cpe:
                        affected.append({
                            "cpe": cpe,
                            "vulnerable": str(match.get("vulnerable", True)),
                        })

        return {
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "cvss_version": cvss_version,
            "cvss_vector": cvss_vector,
            "cvss_severity": cvss_severity,
            "published_date": cve.get("published", ""),
            "last_modified": cve.get("lastModified", ""),
            "vuln_status": cve.get("vulnStatus", ""),
            "cwe_ids": cwe_ids,
            "references": references,
            "affected_products": affected,
            "source": "NVD",
        }

    @staticmethod
    def _is_valid_public_cve(cve: Dict) -> bool:
        cve_id = cve.get("cve_id", "")
        status = cve.get("vuln_status", "").lower()
        if status in ("rejected", "disputed"):
            return False
        if not cve_id.startswith("CVE-"):
            return False
        return True

    # ------------------------------------------------------------------
    # De-duplication & relevance filtering
    # ------------------------------------------------------------------

    def _deduplicate(self, cves: List[Dict], cfg: Dict) -> List[Dict]:
        """Remove duplicate CVE-IDs and optionally apply keyword relevance filter."""
        strong_keywords: List[str] = cfg.get("strong_keywords", [])
        non_target_indicators: List[str] = cfg.get("non_target_indicators", [])
        strict_target_matching: bool = cfg.get("strict_target_matching", False)
        require_project_cpe_match: bool = cfg.get("require_project_cpe_match", False)
        project_cpe_aliases: List[str] = cfg.get("project_cpe_aliases", [])
        min_published_year: Optional[int] = cfg.get("min_published_year")

        if not project_cpe_aliases:
            project = self.config.get("project", {})
            project_cpe_aliases = [
                project.get("name", ""),
                project.get("display_name", ""),
            ]
        project_cpe_aliases = [a for a in project_cpe_aliases if a]

        seen: set[str] = set()
        unique: List[Dict] = []
        year_filtered = 0
        for cve in cves:
            cid = cve["cve_id"]
            if cid in seen:
                continue
            seen.add(cid)

            # Filter by published year (exclude pre-git-era CVEs)
            if min_published_year:
                pub_date = cve.get("published_date", "")
                if pub_date:
                    try:
                        pub_year = int(pub_date[:4])
                        if pub_year < min_published_year:
                            self.logger.debug(
                                "Filtering %s: published %d < min_published_year %d",
                                cid, pub_year, min_published_year,
                            )
                            year_filtered += 1
                            continue
                    except (ValueError, IndexError):
                        pass  # keep CVEs with unparseable dates

            desc = cve.get("description", "")
            apply_relevance_filter = bool(
                strong_keywords or non_target_indicators or strict_target_matching or require_project_cpe_match
            )
            if apply_relevance_filter:
                if not self._is_target_related(
                    cve,
                    strong_keywords,
                    non_target_indicators,
                    strict_target_matching,
                    require_project_cpe_match,
                    project_cpe_aliases,
                ):
                    self.logger.debug("Filtering %s: not target-related", cid)
                    continue

            unique.append(cve)

        if year_filtered:
            self.logger.info("Excluded %d CVEs published before %d", year_filtered, min_published_year)
        self.logger.info("After de-dup + filter: %d CVEs", len(unique))
        return unique

    @staticmethod
    def _is_target_related(
        cve: Dict[str, Any],
        strong_keywords: List[str],
        non_target_indicators: List[str],
        strict_target_matching: bool,
        require_project_cpe_match: bool,
        project_cpe_aliases: List[str],
    ) -> bool:
        text = cve.get("description", "")
        text_lower = text.lower()

        if any(ind.lower() in text_lower for ind in non_target_indicators):
            return False

        strong_match = any(kw.lower() in text_lower for kw in strong_keywords)

        cpe_match = False
        if project_cpe_aliases:
            for product in cve.get("affected_products", []):
                cpe = (product.get("cpe") or "").lower()
                if cpe and any(alias.lower() in cpe for alias in project_cpe_aliases):
                    cpe_match = True
                    break

        if require_project_cpe_match and not cpe_match:
            return False

        if strict_target_matching:
            # In strict mode, require explicit strong keyword evidence.
            return strong_match

        if strong_match:
            return True

        return True  # permissive by default

    # ------------------------------------------------------------------
    # CVE.org enrichment (optional)
    # ------------------------------------------------------------------

    def _enrich_cve_org(self, cves: List[Dict], cfg: Dict) -> List[Dict]:
        delay = cfg.get("cve_org_delay", 1.0)
        for cve in cves:
            cid = cve.get("cve_id", "")
            try:
                resp = requests.get(f"{self.CVE_ORG_API_BASE}/{cid}", timeout=15)
                if resp.status_code == 200:
                    org_data = resp.json()
                    cve["cve_org_data"] = org_data
                time.sleep(delay)
            except Exception as exc:
                self.logger.debug("CVE.org enrichment failed for %s: %s", cid, exc)
        return cves
