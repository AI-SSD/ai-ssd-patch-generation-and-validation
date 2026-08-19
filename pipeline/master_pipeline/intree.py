"""Container-timeout policy for in-tree (Option A) regression-test runs.

Why this module exists
----------------------
An in-tree reproduction is decided by a marker the project's own run recipe
prints on stdout (``SSD_TEST_RESULT=PASS|FAIL|NORESULT``). The recipe bounds
itself with coreutils ``timeout`` so a hanging test still reaches the final
``echo``: a hang exits 124, which the recipes map to ``FAIL`` — and for an
infinite-loop bug (CWE-835) that hang *is* the reproduction.

That only works while the recipe's OWN timeout fires before the container-level
ceiling. When the ceiling wins, Docker kills the shell mid-run, no marker is
ever printed, and Phase 1 files a genuine hang as an anonymous "build/run
error" — the CVE is routed to manual revision and silently dropped.

That is exactly what happened before this module existed: every in-tree recipe
declared budgets at or above the flat 300 s ``run_timeout`` (glibc's three-strategy
cascade declares 320+320+320+1500), so the ceiling always won. tcpdump's 120 s
budget was the only one under the ceiling, and it still lost — a bare ``timeout``
only sends SIGTERM, and a process that ignores it hangs on regardless (the
recipes now pass ``-k`` so SIGTERM escalates to SIGKILL).

The fix is to stop guessing: read the budgets the active project's recipe
actually declares and clear their sum by a margin. Nothing here knows about any
specific project — it parses whatever the YAML supplies, so a new project is
covered the moment its recipe is written.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import List, Optional, Tuple

# Defaults, overridable from config.yaml (see load_intree_timeout_policy).
DEFAULT_FLOOR = 600     # never allow less than this (matches Phase 3's historic budget)
DEFAULT_MARGIN = 60     # headroom above the recipe's own budgets
DEFAULT_CAP = 3600      # hard bound so a wedged container can't hold a slot forever

# `timeout` at a command position. Case-sensitive on purpose: it must not match
# the SHELL VARIABLES the recipes use (INTREE_TEST_TIMEOUT), and \b will not fire
# mid-identifier anyway because `_` is a word character.
_TIMEOUT_CMD_RE = re.compile(r"\btimeout\b")

# A duration argument, either a literal (`300`, `5m`) or the recipes' idiom
# `"${INTREE_TEST_TIMEOUT:-320}"` — we take the DEFAULT, which is what actually
# applies (the variable is not exported into the container).
_DURATION_RE = re.compile(
    r"""^["']?(?:
            \$\{[A-Za-z_][A-Za-z0-9_]*:-(?P<sub>\d+)\}   # ${VAR:-320}
          | (?P<lit>\d+)(?P<unit>[smhd])?                # 300 | 5m
        )["']?$""",
    re.VERBOSE,
)

_UNIT_SECONDS = {"s": 1, "m": 60, "h": 3600, "d": 86400}

# Flags that consume a following argument (`timeout -k 10 300 cmd`).
_FLAGS_WITH_VALUE = {"-k", "--kill-after", "-s", "--signal"}


def _parse_duration(token: str) -> Optional[int]:
    """Seconds for one ``timeout`` duration argument, or None if it isn't one."""
    m = _DURATION_RE.match(token)
    if not m:
        return None
    if m.group("sub"):
        return int(m.group("sub"))
    return int(m.group("lit")) * _UNIT_SECONDS.get(m.group("unit") or "s", 1)


def scan_timeout_budgets(script: str) -> List[int]:
    """Every self-imposed ``timeout`` budget (seconds) declared by a shell script.

    Walks the argument list of each ``timeout`` invocation, skipping flags (and
    the value of flags that take one), and reads the first bare token as the
    duration. Comment-only lines are ignored so prose mentioning the word does
    not inflate the result.
    """
    budgets: List[int] = []
    if not script:
        return budgets
    for m in _TIMEOUT_CMD_RE.finditer(script):
        line = script[m.end():].split("\n", 1)[0]
        # Skip a `timeout` that only appears inside a comment.
        line_start = script.rfind("\n", 0, m.start()) + 1
        if script[line_start:m.start()].lstrip().startswith("#"):
            continue
        tokens = line.split()
        i = 0
        while i < len(tokens):
            tok = tokens[i]
            if tok in _FLAGS_WITH_VALUE:
                i += 2                      # flag + its value
                continue
            if tok.startswith("-"):
                i += 1                      # valueless flag (--foreground, -k10)
                continue
            secs = _parse_duration(tok)
            if secs is not None:
                budgets.append(secs)
            break                           # first non-flag token settles it
    return budgets


def intree_container_timeout(run_script: Optional[str],
                             floor: int = DEFAULT_FLOOR,
                             margin: int = DEFAULT_MARGIN,
                             cap: int = DEFAULT_CAP) -> int:
    """Container ceiling (seconds) for one in-tree test run.

    The recipe may run several bounded strategies in sequence (glibc tries a
    native single-test target, then a standalone compile, then a subdir harness),
    so the worst-case path is their SUM — anything less can still guillotine the
    shell before it prints a marker. Clamped to [floor, cap].
    """
    total = sum(scan_timeout_budgets(run_script or "")) + margin
    return max(floor, min(cap, total))


def load_intree_timeout_policy(base_dir: Optional[Path] = None) -> Tuple[int, int, int]:
    """Read (floor, margin, cap) from config.yaml, falling back to the defaults."""
    floor, margin, cap = DEFAULT_FLOOR, DEFAULT_MARGIN, DEFAULT_CAP
    try:
        import yaml
        base = base_dir or Path(__file__).resolve().parent.parent
        with open(base / "config.yaml", "r", encoding="utf-8") as fh:
            cfg = yaml.safe_load(fh) or {}
        floor = int(cfg.get("intree_container_floor", floor) or floor)
        margin = int(cfg.get("intree_timeout_margin", margin) or margin)
        cap = int(cfg.get("intree_container_cap", cap) or cap)
    except Exception:
        pass
    floor = max(1, floor)
    margin = max(0, margin)
    cap = max(floor, cap)
    return floor, margin, cap
