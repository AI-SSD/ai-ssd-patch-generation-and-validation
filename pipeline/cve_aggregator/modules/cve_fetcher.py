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
from typing import Any, Dict, List, Optional, Tuple

import requests

from ..models import CVEMetadata
from .base import PipelineModule, FatalPipelineError

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
        if not cfg.get("keywords") and not cfg.get("cpe_match"):
            self.logger.error(
                "cve_fetcher needs a non-empty 'keywords' or 'cpe_match' list"
            )
            return False
        return True

    # ----- main entry point -----

    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        cfg = self.config.get("cve_fetcher", {})

        # Step 1 – Fetch from NVD
        self.logger.info("Fetching CVEs from NVD API …")
        self._nvd_all_failed = False
        self._nvd_unreachable = False
        raw_cves = self._fetch_nvd(cfg)

        # Fast pre-flight gate: if NVD could not be reached at all up front, stop
        # the run immediately with a clear warning rather than letting downstream
        # phases proceed on an empty dataset.
        if getattr(self, "_nvd_unreachable", False):
            raise FatalPipelineError(
                "NVD is not reachable (pre-flight probe failed: connection errors "
                "or persistent 503/timeout). Aborting the run — check network "
                "connectivity and NVD status (https://services.nvd.nist.gov), then "
                "re-run when NVD is reachable."
            )

        # Abort loudly on a total NVD outage rather than proceeding with a
        # degraded dataset (e.g. reverse-search-only CVEs with no fixing commit),
        # which would silently overwrite previously-good results and report
        # "success". A non-empty keyword/cpe config that returns NOTHING because
        # every request failed is an infrastructure error, not an empty result.
        if getattr(self, "_nvd_all_failed", False):
            raise FatalPipelineError(
                "NVD fetch failed for ALL configured queries (e.g. 503 outage / "
                "unreachable). Aborting Phase 0 to avoid overwriting good data with "
                "a degraded dataset — re-run when NVD is reachable."
            )

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
        import os
        from pathlib import Path
        api_key: str = os.environ.get("NVD_API_KEY") or str(cfg.get("nvd_api_key", ""))
        if not api_key:
            _key_file = Path("API-nvd-key")
            # Fallback file lives in the pipeline root (pipeline/API-nvd-key),
            # mirroring how poc_repair.py resolves API-openai-key.
            _pipeline_key = Path(__file__).parent.parent.parent / "API-nvd-key"
            if _key_file.exists():
                api_key = _key_file.read_text().strip()
            elif _pipeline_key.exists():
                api_key = _pipeline_key.read_text().strip()

        # CPE matching (cpe_match) selects CVEs that NVD records as genuinely
        # AFFECTING the product (cpe:2.3:a:gnu:glibc) — far more precise than a
        # keyword (which also matches CVEs that merely mention the project). It
        # is project-agnostic: the CPE lives in the per-project YAML.
        cpe_matches: List[str] = cfg.get("cpe_match", [])

        delay = 0.6 if api_key else 6.0
        headers = {"apiKey": api_key} if api_key else {}

        # Pre-flight: confirm NVD is actually reachable before issuing the full
        # set of (potentially many) keyword/CPE queries. Fail fast if it is not.
        if not self._preflight_nvd(headers):
            self._nvd_unreachable = True
            return []

        results_per_page = 100
        all_cves: List[Dict[str, Any]] = []

        queries_total = 0
        queries_failed = 0

        for keyword in keywords:
            self.logger.info("  NVD keyword: '%s'", keyword)
            cves, ok = self._fetch_nvd_query(
                {"keywordSearch": keyword}, f"keyword '{keyword}'",
                headers, delay, results_per_page,
            )
            all_cves.extend(cves)
            queries_total += 1
            queries_failed += 0 if ok else 1

        for cpe in cpe_matches:
            self.logger.info("  NVD CPE match: '%s'", cpe)
            cves, ok = self._fetch_nvd_query(
                {"virtualMatchString": cpe}, f"cpe '{cpe}'",
                headers, delay, results_per_page,
            )
            all_cves.extend(cves)
            queries_total += 1
            queries_failed += 0 if ok else 1

        # Surface a total NVD outage to the caller: when every configured query
        # failed at the transport level, the dataset is not merely "empty" — the
        # source was unreachable. run() turns this into a hard failure so a
        # transient 503 can't silently overwrite a good dataset with a degraded one.
        self._nvd_all_failed = queries_total > 0 and queries_failed >= queries_total
        return all_cves

    # Retryable HTTP statuses: 429 (rate limit), 403 (NVD's rate-limit code),
    # and 5xx (transient server outages — NVD returns 503 routinely).
    _RETRYABLE_STATUS = frozenset({403, 429, 500, 502, 503, 504})
    # NVD (behind Cloudflare) 503s/times-out intermittently — individual requests
    # fail then succeed seconds later. Retry generously so a flaky window doesn't
    # collapse the whole fetch; most requests still succeed on the first try.
    _MAX_TRIES = 6

    # Pre-flight probe: a small number of quick attempts with short backoff.
    # Kept independent of the per-query retry budget so the gate fails fast.
    _PREFLIGHT_TRIES = 3
    # Generous so a slow-but-healthy NVD (it periodically declares "increased
    # latency") still answers the probe instead of timing out and falsely
    # aborting the run. The probe fetches a single result, so it returns well
    # before this ceiling under normal conditions.
    _PREFLIGHT_TIMEOUT = 45  # seconds

    def _preflight_nvd(self, headers: Dict[str, str]) -> bool:
        """Quick reachability probe before the full fetch.

        Issues one minimal request (``resultsPerPage=1``) and returns True as
        soon as NVD answers with HTTP 200. Retries a few times with short
        backoff so a single transient 503/timeout does not abort the run, but
        gives up quickly (rather than burning every query's full retry budget)
        when NVD is genuinely unreachable or persistently degraded. Treats a
        403/404 as a definitive negative — the key/endpoint is wrong, not flaky.
        """
        params = {"resultsPerPage": 1, "startIndex": 0}
        last = "no response"
        for attempt in range(1, self._PREFLIGHT_TRIES + 1):
            wait = min(20, 5 * (2 ** (attempt - 1)))  # 5, 10, 20
            try:
                resp = requests.get(self.NVD_API_BASE, headers=headers,
                                    params=params, timeout=self._PREFLIGHT_TIMEOUT)
                if resp.status_code == 200:
                    self.logger.info("  NVD reachable — pre-flight OK (HTTP 200)")
                    return True
                last = f"HTTP {resp.status_code}"
                if resp.status_code in (403, 404):
                    self.logger.error("  NVD pre-flight rejected (%s) — check API "
                                      "key / endpoint", last)
                    return False
                self.logger.warning("  NVD pre-flight %s — attempt %d/%d",
                                    last, attempt, self._PREFLIGHT_TRIES)
            except (requests.exceptions.RequestException, json.JSONDecodeError) as exc:
                last = str(exc)
                self.logger.warning("  NVD pre-flight error — attempt %d/%d: %s",
                                    attempt, self._PREFLIGHT_TRIES, exc)
            if attempt < self._PREFLIGHT_TRIES:
                time.sleep(wait)
        self.logger.error("  NVD pre-flight FAILED after %d attempts (last: %s)",
                          self._PREFLIGHT_TRIES, last)
        return False

    def _fetch_nvd_query(self, query_params: Dict[str, Any], label: str,
                         headers: Dict[str, str], delay: float,
                         results_per_page: int) -> Tuple[List[Dict[str, Any]], bool]:
        """Paginate a single NVD 2.0 query (keyword or CPE) and parse results.

        Retries transient failures (5xx/429/403, timeouts) with exponential
        backoff before giving up. Returns ``(cves, ok)`` where ``ok`` is False
        when the query could not complete (so the caller can tell a genuine
        "0 results" apart from a transport failure / NVD outage).
        """
        out: List[Dict[str, Any]] = []
        start_index = 0
        while True:
            params = dict(query_params)
            params["startIndex"] = start_index
            params["resultsPerPage"] = results_per_page
            data = None
            for attempt in range(1, self._MAX_TRIES + 1):
                wait = min(40, 5 * (2 ** (attempt - 1)))  # 5, 10, 20, 40
                try:
                    # 90s (not 30s): full result pages are slow when NVD
                    # declares "increased latency"; give the body time to
                    # arrive instead of aborting and burning a retry.
                    resp = requests.get(self.NVD_API_BASE, headers=headers, params=params, timeout=90)
                    if resp.status_code in self._RETRYABLE_STATUS:
                        self.logger.warning("NVD %s for %s — retry %d/%d after %ds",
                                            resp.status_code, label, attempt, self._MAX_TRIES, wait)
                        if attempt < self._MAX_TRIES:
                            time.sleep(wait)
                        continue
                    resp.raise_for_status()
                    data = resp.json()
                    break
                except (requests.exceptions.RequestException, json.JSONDecodeError) as exc:
                    self.logger.warning("NVD error (%s) — retry %d/%d: %s",
                                        label, attempt, self._MAX_TRIES, exc)
                    if attempt < self._MAX_TRIES:
                        time.sleep(wait)
            if data is None:
                self.logger.error("NVD query failed after %d attempts (%s)",
                                  self._MAX_TRIES, label)
                return out, False

            vulns = data.get("vulnerabilities", [])
            total = data.get("totalResults", 0)
            self.logger.info("    Retrieved %d / %d (%s)", len(vulns), total, label)

            for v in vulns:
                parsed = self._parse_nvd_cve(v)
                if parsed and self._is_valid_public_cve(parsed):
                    out.append(parsed)

            start_index += results_per_page
            if start_index >= total:
                break
            time.sleep(delay)
        return out, True

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

        # Affected products (CPE) + version ranges. The version bounds let Phase 0
        # derive a known-vulnerable release tag when no fix commit is found.
        affected: List[Dict[str, str]] = []
        for config_node in cve.get("configurations", []):
            for node in config_node.get("nodes", []):
                for match in node.get("cpeMatch", []):
                    cpe = match.get("criteria", "")
                    if cpe:
                        affected.append({
                            "cpe": cpe,
                            "vulnerable": str(match.get("vulnerable", True)),
                            "version_start_including": match.get("versionStartIncluding", ""),
                            "version_start_excluding": match.get("versionStartExcluding", ""),
                            "version_end_including": match.get("versionEndIncluding", ""),
                            "version_end_excluding": match.get("versionEndExcluding", ""),
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
            # In strict mode, require explicit evidence — but a project CPE match
            # is authoritative (NVD records the product as affected), so accept it
            # even when the description doesn't name the project. Otherwise the
            # CPE-fetched CVEs (the whole point of cpe_match) would be discarded
            # whenever their text describes only the affected function/component.
            return strong_match or cpe_match

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
