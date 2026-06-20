"""
Project-agnostic SAST configuration.

The list of static-analysis tools used by Phase 3 is NOT hardcoded in Python:
it lives in the ``sast:`` section of the active project's Phase 0 YAML, which is
resolved from ``config.yaml``'s ``phase0_config`` pointer. This keeps the
pipeline language- and project-agnostic — a C project lists cppcheck/flawfinder,
a Java project lists spotbugs/semgrep, etc., with no Python change.

This module is the single source of truth consumed by:
  * ``patch_validator.py``            — Phase 3: runs the tools, parses output, gates
  * ``master_pipeline/orchestrator.py`` — startup preflight: are the tools present?
  * ``setup/setup.sh`` / ``setup/verify_setup.sh`` — via the ``__main__`` CLI below,
    so the bash scripts never parse YAML themselves.

YAML schema (under the project YAML, sibling of ``phase1:``)::

    sast:
      enabled: true
      fail_on: [critical, high]      # severity classes that fail a patch
      tool_timeout: 120              # per-tool subprocess timeout (seconds)
      tools:
        - name: cppcheck
          detect: cppcheck           # binary probed on PATH (defaults to cmd[0])
          cmd: ["cppcheck", "--enable=all", "--xml", "--xml-version=2", "{file}"]
          parser: cppcheck-xml       # cppcheck-xml | flawfinder | sarif | regex
          install: { apt: cppcheck }
        - name: flawfinder
          detect: flawfinder
          cmd: ["flawfinder", "--minlevel=1", "--dataonly", "--quiet", "{file}"]
          fallback_cmd: ["{python}", "-m", "flawfinder", "--minlevel=1",
                         "--dataonly", "--quiet", "{file}"]
          parser: flawfinder
          install: { pip: flawfinder }

A ``parser: regex`` tool additionally supplies ``regex`` (a per-line pattern) and
``groups`` (a map of file/line/column/severity/message -> capture-group index),
plus an optional ``severity_map`` (raw token -> severity class). A ``parser: sarif``
tool needs only its ``cmd`` to emit SARIF JSON. Either makes a brand-new tool
config-only — no Python change.

Placeholders substituted at runtime: ``{file}`` (the patched source file) and
``{python}`` (the running interpreter, for ``python -m`` fallbacks).
"""

from __future__ import annotations

import importlib.util
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

import yaml

# Pipeline root = parent of this package directory (where config.yaml + the
# cve_aggregator/*_config.yaml project files live).
_PIPELINE_ROOT = Path(__file__).parent.parent.resolve()

# Severity classes the gate understands, mapped to the SASTResult counter the
# patch validator maintains. ``fail_on`` entries must be one of these keys.
SEVERITY_CLASSES = ("critical", "high", "medium", "low")

# Fallback tools used when a project YAML declares no ``sast:`` section — mirrors
# the historical hardcoded cppcheck + flawfinder behaviour so glibc keeps working
# unchanged during migration.
_DEFAULT_RAW_TOOLS = [
    {
        "name": "cppcheck",
        "detect": "cppcheck",
        "cmd": ["cppcheck", "--enable=all", "--xml", "--xml-version=2", "{file}"],
        "parser": "cppcheck-xml",
        "install": {"apt": "cppcheck"},
    },
    {
        "name": "flawfinder",
        "detect": "flawfinder",
        "cmd": ["flawfinder", "--minlevel=1", "--dataonly", "--quiet", "{file}"],
        "fallback_cmd": ["{python}", "-m", "flawfinder", "--minlevel=1",
                         "--dataonly", "--quiet", "{file}"],
        "parser": "flawfinder",
        "install": {"pip": "flawfinder"},
    },
]


@dataclass
class SastTool:
    """A single configured static-analysis tool."""
    name: str
    cmd: List[str]
    parser: str
    detect: str = ""
    fallback_cmd: Optional[List[str]] = None
    install: Dict[str, str] = field(default_factory=dict)
    # regex parser only:
    regex: Optional[str] = None
    groups: Dict[str, int] = field(default_factory=dict)
    severity_map: Dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.detect:
            self.detect = self.cmd[0] if self.cmd else self.name

    @staticmethod
    def _resolve(args: Optional[List[str]], file_path: str) -> Optional[List[str]]:
        if not args:
            return None
        return [a.replace("{python}", sys.executable).replace("{file}", file_path)
                for a in args]

    def resolved_cmd(self, file_path: str) -> List[str]:
        return self._resolve(self.cmd, file_path) or []

    def resolved_fallback(self, file_path: str) -> Optional[List[str]]:
        return self._resolve(self.fallback_cmd, file_path)

    def install_hint(self) -> str:
        """Human-readable remediation, e.g. 'apt install cppcheck'."""
        verbs = {"apt": "apt install", "pip": "pip install", "script": "run"}
        parts = [f"{verbs.get(m, m)} {spec}" for m, spec in self.install.items()]
        return " or ".join(parts) if parts else f"install {self.name}"


@dataclass
class SastConfig:
    """The resolved ``sast:`` policy for a project."""
    enabled: bool = True
    fail_on: Set[str] = field(default_factory=lambda: {"critical", "high"})
    tool_timeout: int = 120
    tools: List[SastTool] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Loading / resolution
# ---------------------------------------------------------------------------

def _load_yaml(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return yaml.safe_load(fh) or {}
    except Exception:
        return {}


def resolve_phase0_config_path(pipeline_config_path: Path) -> Optional[Path]:
    """Follow ``config.yaml``'s ``phase0_config`` pointer to the project YAML."""
    cfg = _load_yaml(pipeline_config_path)
    rel = cfg.get("phase0_config", "")
    if not rel:
        return None
    p = Path(rel)
    if not p.is_absolute():
        # phase0_config is relative to the pipeline root, where the YAMLs live.
        p = pipeline_config_path.parent / p
    return p if p.exists() else None


def _build_config(raw: Dict[str, Any]) -> SastConfig:
    enabled = bool(raw.get("enabled", True))

    fail_on_raw = raw.get("fail_on", ["critical", "high"])
    if isinstance(fail_on_raw, str):
        fail_on_raw = [fail_on_raw]
    fail_on = {str(s).strip().lower() for s in fail_on_raw
               if str(s).strip().lower() in SEVERITY_CLASSES}
    if not fail_on:
        fail_on = {"critical", "high"}

    tool_timeout = int(raw.get("tool_timeout", 120))

    raw_tools = raw.get("tools") or _DEFAULT_RAW_TOOLS
    tools: List[SastTool] = []
    for t in raw_tools:
        if not isinstance(t, dict) or not t.get("name") or not t.get("cmd"):
            continue
        tools.append(SastTool(
            name=str(t["name"]),
            cmd=[str(a) for a in t["cmd"]],
            parser=str(t.get("parser", "regex")),
            detect=str(t.get("detect", "")),
            fallback_cmd=[str(a) for a in t["fallback_cmd"]] if t.get("fallback_cmd") else None,
            install={str(k): str(v) for k, v in (t.get("install") or {}).items()},
            regex=t.get("regex"),
            groups={str(k): int(v) for k, v in (t.get("groups") or {}).items()},
            severity_map={str(k).lower(): str(v).lower()
                          for k, v in (t.get("severity_map") or {}).items()},
        ))
    return SastConfig(enabled=enabled, fail_on=fail_on,
                      tool_timeout=tool_timeout, tools=tools)


def load_sast_config(pipeline_config_path: Optional[Path] = None,
                     phase0_config_path: Optional[Path] = None) -> SastConfig:
    """Load the project's ``sast:`` policy.

    Resolution order: an explicit ``phase0_config_path`` wins; otherwise follow
    ``config.yaml``'s ``phase0_config`` pointer. Falls back to the default
    cppcheck + flawfinder tools when no ``sast:`` section is present.
    """
    if phase0_config_path is None:
        pc = pipeline_config_path or (_PIPELINE_ROOT / "config.yaml")
        phase0_config_path = resolve_phase0_config_path(Path(pc))
    raw: Dict[str, Any] = {}
    if phase0_config_path and Path(phase0_config_path).exists():
        section = _load_yaml(Path(phase0_config_path)).get("sast")
        if isinstance(section, dict):
            raw = section
    return _build_config(raw)


def detect_tool(tool: SastTool) -> bool:
    """True when the tool's primary binary is on PATH, or its ``python -m``
    fallback module / fallback binary is available."""
    if shutil.which(tool.detect):
        return True
    fb = tool.fallback_cmd
    if not fb:
        return False
    if len(fb) >= 3 and fb[1] == "-m":
        try:
            return importlib.util.find_spec(fb[2]) is not None
        except Exception:
            return False
    first = fb[0].replace("{python}", sys.executable)
    return bool(shutil.which(first))


# ---------------------------------------------------------------------------
# CLI — consumed by setup/setup.sh and setup/verify_setup.sh so bash never
# parses YAML. All output is TAB-separated for safe `read` in bash.
# ---------------------------------------------------------------------------

def _main(argv: Optional[List[str]] = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        description="Resolve the project's SAST tool configuration.")
    parser.add_argument("--config", default=str(_PIPELINE_ROOT / "config.yaml"),
                        help="Pipeline config.yaml (follows its phase0_config pointer).")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--enabled", action="store_true",
                       help="Print 'true'/'false' for sast.enabled.")
    group.add_argument("--list-install", action="store_true",
                       help="TAB lines: name<TAB>method<TAB>spec (install recipes).")
    group.add_argument("--check", action="store_true",
                       help="TAB lines: name<TAB>OK|MISSING<TAB>install-hint.")
    parser.add_argument("--missing-only", action="store_true",
                        help="With --list-install: only emit recipes for tools "
                             "not already present on the host (idempotent install).")
    args = parser.parse_args(argv)

    cfg = load_sast_config(pipeline_config_path=Path(args.config))

    if args.enabled:
        print("true" if cfg.enabled else "false")
        return 0

    if args.list_install:
        if not cfg.enabled:
            return 0
        for tool in cfg.tools:
            if args.missing_only and detect_tool(tool):
                continue  # already on the host — skip (idempotent install)
            for method, spec in tool.install.items():
                print(f"{tool.name}\t{method}\t{spec}")
        return 0

    if args.check:
        missing = 0
        for tool in cfg.tools:
            present = detect_tool(tool)
            if not present:
                missing += 1
            status = "OK" if present else "MISSING"
            print(f"{tool.name}\t{status}\t{tool.install_hint()}")
        return missing
    return 0


if __name__ == "__main__":
    sys.exit(_main())
