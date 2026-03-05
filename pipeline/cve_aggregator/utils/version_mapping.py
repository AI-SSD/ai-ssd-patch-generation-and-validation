"""
Version mapping utilities.

Derives the vulnerable project version from NVD CPE data, and maps
glibc versions to the corresponding Ubuntu release.
"""

from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# glibc version → Ubuntu release mapping
# ---------------------------------------------------------------------------
# Mapping of glibc versions shipped by default in Ubuntu LTS and major
# releases.  When multiple Ubuntu versions ship the same glibc, we list
# the earliest LTS.

_GLIBC_TO_UBUNTU: Dict[str, str] = {
    # Ubuntu 6.06 (Dapper)
    "2.3.6": "6.06",
    # Ubuntu 8.04 (Hardy)
    "2.7":   "8.04",
    # Ubuntu 10.04 (Lucid)
    "2.11":  "10.04",
    "2.11.1": "10.04",
    "2.11.2": "10.04",
    "2.11.3": "10.04",
    # Ubuntu 12.04 (Precise)
    "2.15":  "12.04",
    # Ubuntu 14.04 (Trusty)
    "2.19":  "14.04",
    # Ubuntu 16.04 (Xenial)
    "2.23":  "16.04",
    # Ubuntu 18.04 (Bionic)
    "2.27":  "18.04",
    # Ubuntu 20.04 (Focal)
    "2.31":  "20.04",
    # Ubuntu 22.04 (Jammy)
    "2.35":  "22.04",
    # Ubuntu 24.04 (Noble)
    "2.39":  "24.04",
}

# Sorted (major, minor) tuples for closest-match lookup
_GLIBC_VERSIONS_SORTED = sorted(
    _GLIBC_TO_UBUNTU.keys(),
    key=lambda v: tuple(int(x) for x in v.split(".")),
)


def get_ubuntu_version(glibc_version: str) -> str:
    """Map a glibc version string to the Ubuntu release that ships it.

    If an exact match is not found, the closest *older* Ubuntu release
    whose glibc is ≤ the given version is returned (i.e. the vulnerable
    version would be present on that release).

    Parameters
    ----------
    glibc_version : str
        A glibc version string (e.g. ``"2.17"``).

    Returns
    -------
    str
        Ubuntu release identifier, or empty string if no match.
    """
    if not glibc_version:
        return ""

    # Exact match
    if glibc_version in _GLIBC_TO_UBUNTU:
        return _GLIBC_TO_UBUNTU[glibc_version]

    # Closest match: find the largest glibc version ≤ the given one
    try:
        target = tuple(int(x) for x in glibc_version.split("."))
    except ValueError:
        return ""

    best = ""
    for ver_str in _GLIBC_VERSIONS_SORTED:
        ver_tup = tuple(int(x) for x in ver_str.split("."))
        if ver_tup <= target:
            best = _GLIBC_TO_UBUNTU[ver_str]
        else:
            break
    return best


# ---------------------------------------------------------------------------
# Project version extraction from CPE data
# ---------------------------------------------------------------------------

def extract_project_version_from_cpe(
    affected_products: Optional[List[Dict[str, str]]],
    project_name: str = "",
) -> str:
    """Extract the project version from NVD CPE match data.

    Scans the ``affected_products`` list (each item has a ``"cpe"`` key)
    and returns the *first* version string that belongs to the target
    project.  If there are multiple affected versions, they are
    joined with ``", "``.

    Parameters
    ----------
    affected_products : list[dict] | None
        The ``affected_products`` field from :class:`CVEMetadata`.
    project_name : str
        Project slug (e.g. ``"glibc"``) used to filter CPE entries.

    Returns
    -------
    str
        Version string(s) or empty string.
    """
    if not affected_products:
        return ""

    versions: list[str] = []
    project_lower = project_name.lower()

    # CPE 2.3 format: cpe:2.3:part:vendor:product:version:…
    cpe_re = re.compile(
        r"cpe:2\.3:[aho\*\-]:([^:]+):([^:]+):([^:]+)",
    )

    for product in affected_products:
        cpe = product.get("cpe", "")
        m = cpe_re.match(cpe)
        if not m:
            continue

        vendor = m.group(1).lower()
        prod = m.group(2).lower()
        version = m.group(3)

        # Filter: if a project name is given, require the product or vendor
        # to match (partially).
        if project_lower:
            if project_lower not in prod and project_lower not in vendor:
                continue

        # Skip wildcard / any versions
        if version in ("*", "-", ""):
            continue

        if version not in versions:
            versions.append(version)

    return ", ".join(versions)
