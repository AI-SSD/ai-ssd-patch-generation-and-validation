"""
Shared SAST execution + finding classification.

Used by BOTH Phase 1 (orchestrator.py — establishes the baseline by scanning the
unpatched vulnerable file) and Phase 3 (patch_validator.py — scans the patched
file and diffs against the baseline). Keeping it here means the two phases run
the exact same tools/parsers and compare apples to apples.

Methodology: Phase 3 evaluates the *delta* a patch introduces. Findings are
classified against the Phase 1 baseline into:
  - preexisting : present in both baseline and patched (unchanged debt — documented, never gates)
  - resolved    : present in baseline, gone after patch (security improvement — documented)
  - new         : absent from baseline, introduced by the patch (THIS is what gates + feeds back)

A finding's identity for diffing is line-INSENSITIVE (line numbers shift when a
patch is applied): fingerprint = (tool, rule/CWE id, normalized message). The
diff is a multiset, so a new instance of an already-present rule still counts as
new. When no baseline exists, the baseline is treated as empty → every finding
is 'new' (strict).

A finding is a plain dict:
    {tool, severity, message, line, column, cwe_id, rule_id, file_path}
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional

from master_pipeline.sast_config import SastConfig, SastTool

# Severity classes used by the fail_on gate, in descending order.
SEVERITY_CLASSES = ("critical", "high", "medium", "low")


def severity_class(severity: str) -> str:
    """Normalise a tool's raw severity string into one gate class."""
    s = (severity or "").strip().lower()
    if s in ("critical", "error"):
        return "critical"
    if s == "high":
        return "high"
    if s in ("medium", "warning"):
        return "medium"
    return "low"


def count_by_severity(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    counts = {c: 0 for c in SEVERITY_CLASSES}
    for f in findings:
        counts[severity_class(f.get("severity", ""))] += 1
    return counts


# ---------------------------------------------------------------------------
# Output parsers — one per supported `parser` strategy. Each returns a list of
# finding dicts (including a stable `rule_id` when the tool exposes one).
# ---------------------------------------------------------------------------

def _parse_cppcheck_xml(output: str, tool_name: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    try:
        import xml.etree.ElementTree as ET
        root = ET.fromstring(output)
        for error in root.findall('.//error'):
            severity = error.get('severity', 'unknown')
            msg = error.get('msg', '')
            cwe = error.get('cwe', '')
            rule_id = error.get('id')  # e.g. "nullPointer" — stable across lines
            location = error.find('location')
            line = file_path = None
            if location is not None:
                line = int(location.get('line', 0)) or None
                file_path = location.get('file')
            findings.append({
                "tool": tool_name, "severity": severity, "message": msg,
                "line": line, "column": None,
                "cwe_id": f"CWE-{cwe}" if cwe else None,
                "rule_id": rule_id, "file_path": file_path,
            })
    except Exception:
        # Non-XML output (e.g. progress text only) — fall back to a loose scan.
        for line in output.split('\n'):
            if 'error' in line.lower() or 'warning' in line.lower():
                findings.append({
                    "tool": tool_name, "severity": "warning",
                    "message": line.strip(), "line": None, "column": None,
                    "cwe_id": None, "rule_id": None, "file_path": None,
                })
    return findings


def _parse_flawfinder(output: str, tool_name: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    # file:line:column:  [level] (category) message
    pattern = r'^(.+):(\d+):(\d+):\s*\[(\d+)\]\s*\(([^)]+)\)\s*(.+)$'
    for line in output.split('\n'):
        match = re.match(pattern, line.strip())
        if not match:
            continue
        file_path, line_num, col, level, category, msg = match.groups()
        level_int = int(level)
        severity = "high" if level_int >= 4 else "medium" if level_int >= 2 else "low"
        findings.append({
            "tool": tool_name, "severity": severity,
            "message": f"[{category}] {msg}",
            "line": int(line_num), "column": int(col),
            "cwe_id": None, "rule_id": category, "file_path": file_path,
        })
    return findings


def _parse_sarif(output: str, tool_name: str) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    level_map = {"error": "high", "warning": "medium", "note": "low", "none": "low"}
    try:
        data = json.loads(output)
    except Exception:
        # Tools interleave progress/log lines on the same stream as the SARIF
        # document — extract the outermost JSON object and retry.
        start, end = output.find("{"), output.rfind("}")
        if start == -1 or end <= start:
            return findings
        try:
            data = json.loads(output[start:end + 1])
        except Exception:
            return findings
    for run in data.get("runs", []) or []:
        rule_cwe: Dict[str, Optional[str]] = {}
        driver = (run.get("tool") or {}).get("driver") or {}
        for rule in driver.get("rules", []) or []:
            rid = rule.get("id")
            tags = ((rule.get("properties") or {}).get("tags")) or []
            cwe = next((t for t in tags if str(t).upper().startswith("CWE")), None)
            if rid:
                rule_cwe[rid] = cwe
        for res in run.get("results", []) or []:
            level = str(res.get("level", "warning")).lower()
            severity = level_map.get(level, "medium")
            msg = (res.get("message") or {}).get("text", "")
            rule_id = res.get("ruleId")
            line = file_path = None
            locs = res.get("locations") or []
            if locs:
                phys = (locs[0].get("physicalLocation") or {})
                region = phys.get("region") or {}
                line = region.get("startLine")
                file_path = ((phys.get("artifactLocation") or {}).get("uri"))
            findings.append({
                "tool": tool_name, "severity": severity,
                "message": f"[{rule_id}] {msg}" if rule_id else msg,
                "line": int(line) if line else None, "column": None,
                "cwe_id": rule_cwe.get(rule_id), "rule_id": rule_id,
                "file_path": file_path,
            })
    return findings


def _parse_regex(output: str, tool: SastTool) -> List[Dict[str, Any]]:
    findings: List[Dict[str, Any]] = []
    if not tool.regex:
        return findings
    try:
        pattern = re.compile(tool.regex)
    except re.error:
        return findings
    g = tool.groups

    def grp(match, key):
        idx = g.get(key)
        if not idx:
            return None
        try:
            return match.group(idx)
        except (IndexError, Exception):
            return None

    for raw_line in output.split("\n"):
        match = pattern.search(raw_line.strip())
        if not match:
            continue
        sev_raw = (grp(match, "severity") or "").strip().lower()
        severity = tool.severity_map.get(sev_raw, sev_raw) or "low"
        line_val = grp(match, "line")
        col_val = grp(match, "column")
        findings.append({
            "tool": tool.name, "severity": severity,
            "message": (grp(match, "message") or raw_line.strip()),
            "line": int(line_val) if line_val and str(line_val).isdigit() else None,
            "column": int(col_val) if col_val and str(col_val).isdigit() else None,
            "cwe_id": None,
            "rule_id": grp(match, "rule"),  # optional "rule" group (e.g. clang-tidy check)
            "file_path": grp(match, "file"),
        })
    return findings


def parse_output(tool: SastTool, output: str) -> List[Dict[str, Any]]:
    """Dispatch to the tool's configured parser strategy."""
    parser = (tool.parser or "").lower()
    if parser == "cppcheck-xml":
        return _parse_cppcheck_xml(output, tool.name)
    if parser == "flawfinder":
        return _parse_flawfinder(output, tool.name)
    if parser == "sarif":
        return _parse_sarif(output, tool.name)
    if parser == "regex":
        return _parse_regex(output, tool)
    return []


# ---------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------

def run_tool(file_path: Path, tool: SastTool, timeout: int,
             logger=None) -> Dict[str, Any]:
    """Run a single tool host-side on `file_path`. Returns a per-tool result:
    {tool, success, error, findings, <severity>_count, findings_count}."""
    started = time.time()
    file_str = str(file_path)
    result: Dict[str, Any] = {
        "tool": tool.name, "success": False, "error": None, "findings": [],
        "critical_count": 0, "high_count": 0, "medium_count": 0, "low_count": 0,
        "findings_count": 0,
    }

    cmd = tool.resolved_cmd(file_str) if shutil.which(tool.detect) else tool.resolved_fallback(file_str)
    if not cmd:
        result["error"] = f"{tool.name} not installed on host — skipped ({tool.install_hint()})"
        if logger:
            logger.warning(result["error"])
        return result

    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        output = (proc.stdout or "") + (proc.stderr or "")
        findings = parse_output(tool, output)
        result["findings"] = findings
        result["findings_count"] = len(findings)
        result["success"] = True
        counts = count_by_severity(findings)
        for cls in SEVERITY_CLASSES:
            result[f"{cls}_count"] = counts[cls]
        if logger:
            logger.debug(
                f"{tool.name}: {len(findings)} findings "
                f"(C:{counts['critical']} H:{counts['high']} M:{counts['medium']} L:{counts['low']}) "
                f"in {time.time() - started:.2f}s"
            )
    except subprocess.TimeoutExpired:
        result["error"] = f"{tool.name} timed out after {timeout}s"
        if logger:
            logger.warning(result["error"])
    except Exception as exc:  # noqa: BLE001
        result["error"] = str(exc)
        if logger:
            logger.warning(f"SAST tool {tool.name} failed: {exc}")
    return result


def run_sast_file(file_path: Path, sast_config: SastConfig,
                  logger=None) -> Dict[str, Any]:
    """Run every configured tool on `file_path`. Returns
    {findings: [flat finding dicts], tool_results: [per-tool summaries]}."""
    findings: List[Dict[str, Any]] = []
    tool_results: List[Dict[str, Any]] = []
    for tool in sast_config.tools:
        tr = run_tool(Path(file_path), tool, sast_config.tool_timeout, logger)
        findings.extend(tr.pop("findings"))
        tool_results.append(tr)
    return {"findings": findings, "tool_results": tool_results}


# ---------------------------------------------------------------------------
# Classification (baseline diff) + gate
# ---------------------------------------------------------------------------

def _normalise_message(message: str) -> str:
    """Drop digits (line/col/index specifics) and collapse whitespace so the
    same issue produces the same key regardless of where it sits in the file."""
    m = re.sub(r"\d+", "#", message or "")
    return re.sub(r"\s+", " ", m).strip().lower()


def fingerprint(finding: Dict[str, Any]) -> str:
    """Line-insensitive identity for a finding: (tool, rule/CWE id, normalised
    message). Two findings with the same fingerprint are 'the same issue'."""
    ident = finding.get("rule_id") or finding.get("cwe_id") or ""
    return f"{finding.get('tool', '')}|{ident}|{_normalise_message(finding.get('message', ''))}"


def classify(baseline: List[Dict[str, Any]],
             current: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    """Multiset diff of `current` (patched) against `baseline` (Phase 1):
    preexisting / resolved / new. `new` is what gates + feeds back."""
    baseline = baseline or []
    current = current or []

    base_by_fp: Dict[str, List[Dict[str, Any]]] = {}
    for f in baseline:
        base_by_fp.setdefault(fingerprint(f), []).append(f)

    preexisting: List[Dict[str, Any]] = []
    new: List[Dict[str, Any]] = []
    cur_counts: Counter = Counter()
    for f in current:
        fp = fingerprint(f)
        cur_counts[fp] += 1
        # First N instances (N = baseline count) are pre-existing; the rest new.
        if cur_counts[fp] <= len(base_by_fp.get(fp, [])):
            preexisting.append(f)
        else:
            new.append(f)

    resolved: List[Dict[str, Any]] = []
    for fp, items in base_by_fp.items():
        gone = len(items) - cur_counts.get(fp, 0)
        if gone > 0:
            resolved.extend(items[:gone])

    return {"preexisting": preexisting, "resolved": resolved, "new": new}


def gate(findings: List[Dict[str, Any]], fail_on) -> "tuple[bool, str]":
    """A patch passes when none of the `fail_on` severity classes appear in
    `findings` (which, in Phase 3, are the NEWLY introduced findings only)."""
    counts = count_by_severity(findings)
    fail_total = sum(counts[c] for c in fail_on if c in counts)
    if fail_total == 0:
        return True, ""
    parts = [f"{counts[c]} {c}" for c in sorted(fail_on) if counts.get(c)]
    return False, f"SAST introduced {', '.join(parts)} severity issue(s)"
