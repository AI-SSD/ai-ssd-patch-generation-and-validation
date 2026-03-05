"""
Data models for the CVE Aggregator pipeline.

All pipeline stages communicate through these shared data structures,
keeping the modules decoupled from each other.
"""

from __future__ import annotations

import dataclasses as dc
from datetime import datetime
from typing import Any, Dict, List, Optional


# ---------------------------------------------------------------------------
# Exploit / PoC information
# ---------------------------------------------------------------------------

@dc.dataclass
class ExploitInfo:
    """A single Proof-of-Concept exploit associated with a CVE."""
    exploit_id: str = ""
    file_path: str = ""          # Relative path inside ExploitDB repo
    full_local_path: str = ""    # Absolute filesystem path
    language: str = "unknown"
    source_code_content: Optional[str] = None
    content_extraction_status: str = "not_extracted"
    file_size_bytes: Optional[int] = None
    description: str = ""
    author: str = ""
    date: str = ""
    platform: str = ""
    exploit_type: str = ""
    exploitdb_url: str = ""
    match_type: str = ""         # How this exploit was matched (csv_metadata, content_search, …)
    verified: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return dc.asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ExploitInfo":
        known = {f.name for f in dc.fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})


# ---------------------------------------------------------------------------
# Project state (source-repo context for a CVE)
# ---------------------------------------------------------------------------

@dc.dataclass
class ProjectState:
    """Git repository state surrounding a vulnerability fix."""
    repository_url: str = ""
    fix_commit_hash: Optional[str] = None
    vulnerable_commit_hash: Optional[str] = None
    fix_commit_metadata: Optional[Dict[str, str]] = None
    changed_files: Optional[List[Dict[str, str]]] = None
    vulnerable_files_content: Optional[Dict[str, str]] = None
    patched_files_content: Optional[Dict[str, str]] = None
    vulnerable_functions: Optional[Dict[str, Any]] = None
    # Per-file list of changed code units (functions/macros) with full bodies
    changed_code_units: Optional[Dict[str, List[Dict[str, str]]]] = None

    def to_dict(self) -> Dict[str, Any]:
        return dc.asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ProjectState":
        known = {f.name for f in dc.fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})


# ---------------------------------------------------------------------------
# CVE metadata
# ---------------------------------------------------------------------------

@dc.dataclass
class CVEMetadata:
    """Metadata for a single CVE entry."""
    cve_id: str = ""
    description: str = ""
    cvss_score: Optional[float] = None
    cvss_version: Optional[str] = None
    cvss_vector: Optional[str] = None
    cvss_severity: Optional[str] = None
    published_date: str = ""
    last_modified: str = ""
    vuln_status: str = ""
    cwe_ids: Optional[List[str]] = dc.field(default_factory=list)
    references: Optional[List[str]] = dc.field(default_factory=list)
    affected_products: Optional[List[Dict[str, str]]] = dc.field(default_factory=list)
    source: str = "NVD"

    def to_dict(self) -> Dict[str, Any]:
        return dc.asdict(self)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CVEMetadata":
        known = {f.name for f in dc.fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})


# ---------------------------------------------------------------------------
# Aggregated CVE entry (the main data unit flowing through the pipeline)
# ---------------------------------------------------------------------------

@dc.dataclass
class CVEEntry:
    """Fully aggregated CVE entry – the primary data unit of the pipeline."""
    metadata: CVEMetadata = dc.field(default_factory=CVEMetadata)
    project_state: ProjectState = dc.field(default_factory=ProjectState)
    exploits: List[ExploitInfo] = dc.field(default_factory=list)
    has_poc: bool = False
    has_commits: bool = False
    has_vulnerable_code: bool = False
    has_vulnerable_functions: bool = False
    poc_count: int = 0
    first_seen: str = ""
    last_checked: str = ""

    # ------ convenience helpers ------

    def to_dict(self) -> Dict[str, Any]:
        return {
            "metadata": self.metadata.to_dict(),
            "project_state": self.project_state.to_dict(),
            "exploits": [e.to_dict() for e in self.exploits],
            "has_poc": self.has_poc,
            "has_commits": self.has_commits,
            "has_vulnerable_code": self.has_vulnerable_code,
            "has_vulnerable_functions": self.has_vulnerable_functions,
            "poc_count": self.poc_count,
            "first_seen": self.first_seen,
            "last_checked": self.last_checked,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "CVEEntry":
        entry = cls()
        entry.metadata = CVEMetadata.from_dict(data.get("metadata", {}))
        entry.project_state = ProjectState.from_dict(data.get("project_state", {}))
        entry.exploits = [ExploitInfo.from_dict(e) for e in data.get("exploits", [])]
        for field in ("has_poc", "has_commits", "has_vulnerable_code",
                       "has_vulnerable_functions", "poc_count",
                       "first_seen", "last_checked"):
            if field in data:
                setattr(entry, field, data[field])
        return entry


# ---------------------------------------------------------------------------
# Syntax validation result
# ---------------------------------------------------------------------------

@dc.dataclass
class SyntaxValidationResult:
    """Result of validating a PoC file's syntax."""
    is_valid: bool = False
    language: str = "unknown"
    errors: List[str] = dc.field(default_factory=list)
    warnings: List[str] = dc.field(default_factory=list)
    needs_manual_review: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return dc.asdict(self)


# ---------------------------------------------------------------------------
# Complete dataset wrapper
# ---------------------------------------------------------------------------

@dc.dataclass
class Dataset:
    """Top-level dataset object that gets serialised to JSON."""
    dataset_info: Dict[str, Any] = dc.field(default_factory=dict)
    cves: Dict[str, CVEEntry] = dc.field(default_factory=dict)
    statistics: Dict[str, Any] = dc.field(default_factory=dict)

    # ---- serialisation helpers ----

    def to_dict(self) -> Dict[str, Any]:
        return {
            "dataset_info": self.dataset_info,
            "cves": {cve_id: entry.to_dict() for cve_id, entry in self.cves.items()},
            "statistics": self.statistics,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Dataset":
        ds = cls()
        ds.dataset_info = data.get("dataset_info", {})
        ds.cves = {
            cve_id: CVEEntry.from_dict(entry)
            for cve_id, entry in data.get("cves", {}).items()
        }
        ds.statistics = data.get("statistics", {})
        return ds

    def compute_statistics(self) -> Dict[str, Any]:
        total = len(self.cves)
        with_poc = sum(1 for e in self.cves.values() if e.has_poc)
        with_commits = sum(1 for e in self.cves.values() if e.has_commits)
        total_pocs = sum(e.poc_count for e in self.cves.values())
        pocs_with_content = sum(
            1
            for e in self.cves.values()
            for ex in e.exploits
            if ex.source_code_content
        )
        self.statistics = {
            "total_cves": total,
            "cves_with_poc": with_poc,
            "cves_with_commits": with_commits,
            "total_pocs": total_pocs,
            "pocs_with_content": pocs_with_content,
            "last_updated": datetime.now().isoformat(),
        }
        return self.statistics
