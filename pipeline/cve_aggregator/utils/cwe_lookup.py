"""
CWE description lookup utility.

Provides descriptions for CWE identifiers using a comprehensive static
mapping of common CWEs found in C/system-level software CVEs, with an
optional NVD/MITRE API fallback.
"""

from __future__ import annotations

import logging
import re
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Static CWE → description mapping (covers the vast majority of glibc CVEs)
# ---------------------------------------------------------------------------

_CWE_DESCRIPTIONS: Dict[str, str] = {
    # Memory safety
    "CWE-119": "Improper Restriction of Operations within the Bounds of a Memory Buffer",
    "CWE-120": "Buffer Copy without Checking Size of Input ('Classic Buffer Overflow')",
    "CWE-121": "Stack-based Buffer Overflow",
    "CWE-122": "Heap-based Buffer Overflow",
    "CWE-123": "Write-what-where Condition",
    "CWE-124": "Buffer Underwrite ('Buffer Underflow')",
    "CWE-125": "Out-of-bounds Read",
    "CWE-126": "Buffer Over-read",
    "CWE-127": "Buffer Under-read",
    "CWE-128": "Wrap-around Error",
    "CWE-129": "Improper Validation of Array Index",
    "CWE-131": "Incorrect Calculation of Buffer Size",

    # Integer issues
    "CWE-189": "Numeric Errors",
    "CWE-190": "Integer Overflow or Wraparound",
    "CWE-191": "Integer Underflow (Wrap or Wraparound)",
    "CWE-192": "Integer Coercion Error",
    "CWE-193": "Off-by-one Error",
    "CWE-194": "Unexpected Sign Extension",
    "CWE-195": "Signed to Unsigned Conversion Error",
    "CWE-196": "Unsigned to Signed Conversion Error",
    "CWE-197": "Numeric Truncation Error",

    # Use-after-free / double-free / memory management
    "CWE-415": "Double Free",
    "CWE-416": "Use After Free",
    "CWE-401": "Missing Release of Memory after Effective Lifetime",
    "CWE-404": "Improper Resource Shutdown or Release",
    "CWE-772": "Missing Release of Resource after Effective Lifetime",
    "CWE-775": "Missing Release of File Descriptor or Handle after Effective Lifetime",
    "CWE-787": "Out-of-bounds Write",
    "CWE-788": "Access of Memory Location After End of Buffer",
    "CWE-789": "Memory Allocation with Excessive Size Value",

    # NULL pointer / uninitialised
    "CWE-457": "Use of Uninitialized Variable",
    "CWE-476": "NULL Pointer Dereference",
    "CWE-824": "Access of Uninitialized Pointer",
    "CWE-908": "Use of Uninitialized Resource",

    # Input validation
    "CWE-20": "Improper Input Validation",
    "CWE-22": "Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
    "CWE-59": "Improper Link Resolution Before File Access ('Link Following')",
    "CWE-73": "External Control of File Name or Path",
    "CWE-78": "Improper Neutralization of Special Elements used in an OS Command ('OS Command Injection')",
    "CWE-94": "Improper Control of Generation of Code ('Code Injection')",
    "CWE-134": "Use of Externally-Controlled Format String",

    # Resource management
    "CWE-399": "Resource Management Errors",
    "CWE-400": "Uncontrolled Resource Consumption",
    "CWE-770": "Allocation of Resources Without Limits or Throttling",
    "CWE-674": "Uncontrolled Recursion",

    # Permissions / access control
    "CWE-264": "Permissions, Privileges, and Access Controls",
    "CWE-269": "Improper Privilege Management",
    "CWE-276": "Incorrect Default Permissions",
    "CWE-284": "Improper Access Control",
    "CWE-362": "Concurrent Execution using Shared Resource with Improper Synchronization ('Race Condition')",

    # Information disclosure
    "CWE-200": "Exposure of Sensitive Information to an Unauthorized Actor",
    "CWE-209": "Generation of Error Message Containing Sensitive Information",

    # Type confusion / assertion
    "CWE-617": "Reachable Assertion",
    "CWE-843": "Access of Resource Using Incompatible Type ('Type Confusion')",

    # Cryptographic
    "CWE-310": "Cryptographic Issues",
    "CWE-327": "Use of a Broken or Risky Cryptographic Algorithm",
    "CWE-330": "Use of Insufficiently Random Values",
    "CWE-338": "Use of Cryptographically Weak Pseudo-Random Number Generator (PRNG)",

    # Denial of service
    "CWE-369": "Divide By Zero",
    "CWE-835": "Loop with Unreachable Exit Condition ('Infinite Loop')",

    # Other common
    "CWE-252": "Unchecked Return Value",
    "CWE-754": "Improper Check for Unusual or Exceptional Conditions",
    "CWE-763": "Release of Invalid Pointer or Reference",
    "CWE-834": "Excessive Iteration",

    # Generic / NVD catch-all
    "NVD-CWE-Other": "Other (NVD classification)",
    "NVD-CWE-noinfo": "Insufficient Information",
}


def get_cwe_description(cwe_id: str) -> str:
    """Return the human-readable description for a CWE identifier.

    Parameters
    ----------
    cwe_id : str
        A CWE identifier such as ``"CWE-119"`` or ``"NVD-CWE-Other"``.

    Returns
    -------
    str
        The CWE description, or an empty string if unknown.
    """
    return _CWE_DESCRIPTIONS.get(cwe_id, "")


def get_cwe_descriptions(cwe_ids: Optional[List[str]]) -> str:
    """Return a joined description string for a list of CWE IDs.

    Multiple descriptions are separated by ``" | "``.
    Unknown CWE IDs are included as-is (e.g. ``"CWE-9999 (unknown)"``).

    Parameters
    ----------
    cwe_ids : list[str] | None
        List of CWE identifiers.

    Returns
    -------
    str
        Combined description string.
    """
    if not cwe_ids:
        return ""

    parts: list[str] = []
    for cwe_id in cwe_ids:
        desc = get_cwe_description(cwe_id)
        if desc:
            parts.append(f"{cwe_id}: {desc}")
        else:
            parts.append(f"{cwe_id} (unknown)")
    return " | ".join(parts)
