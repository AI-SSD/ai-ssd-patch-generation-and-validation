"""
CVE Aggregator - Modular Pipeline for CVE Data Collection & PoC Extraction
===========================================================================

A configurable, project-agnostic framework that:
  1. Fetches & enriches CVE data from NVD / CVE.org APIs
  2. Discovers fix/vulnerable commits from a source Git repository
  3. Maps & extracts Proof-of-Concept exploits from ExploitDB
  4. Aggregates & structures all data into a unified dataset
  5. Validates PoC syntax (GCC, Python, Shell, Ruby, Perl, PHP)
  6. Generates output files (JSON global, JSON filtered, CSV, PoC files)

Usage:
    python -m cve_aggregator                # Run full pipeline (default config)
    python -m cve_aggregator --config my.yaml  # Custom config
    python -m cve_aggregator --export-csv   # Re-export CSV only
    python -m cve_aggregator --export-poc   # Re-export PoC files only
"""

__version__ = "1.0.0"
__author__ = "AI-SSD Pipeline"
