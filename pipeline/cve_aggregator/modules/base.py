"""
Abstract base classes for pipeline modules.

Every stage of the CVE Aggregator pipeline inherits from
:class:`PipelineModule` and implements ``run()``.  This makes it trivial
to swap, extend, or skip individual stages.
"""

from __future__ import annotations

import abc
import logging
import os
from pathlib import Path
from typing import Any, Dict


#: Reproducer sources the pipeline understands.
_VALID_REPRODUCERS = ("exploitdb", "intree")

#: Env var set by the master pipeline executor to the pipeline root directory.
#: Used to resolve shared-INPUT paths (cloned repos) regardless of the Phase-0 CWD.
_PIPELINE_ROOT_ENV = "SSD_PIPELINE_ROOT"


def resolve_input_path(path: Any) -> Path:
    """Resolve a shared-INPUT path (a cloned repo like ExploitDB or the project
    source tree) against the pipeline root rather than the Phase-0 CWD.

    Phase 0 is launched by the master pipeline with ``cwd = base_dir`` (the
    per-project working directory ``projects/<name>/``). Config paths such as
    ``exploitdb_path: "../exploit-database"`` / ``repo_local_path: "../glibc"``
    are written to point at clones kept BESIDE the pipeline directory, so under a
    per-project CWD they would wrongly resolve to ``projects/exploit-database``
    etc. and find nothing. The executor exports ``SSD_PIPELINE_ROOT``; when set, a
    RELATIVE input path is rebased onto it so it resolves identically no matter
    the CWD. Absolute paths, and the no-env-var case (e.g. running
    ``python -m cve_aggregator`` directly from the pipeline root), are returned
    unchanged. OUTPUT paths (``results/…``) intentionally do NOT use this — they
    must stay under ``base_dir``.
    """
    p = Path(path)
    if p.is_absolute():
        return p
    root = os.environ.get(_PIPELINE_ROOT_ENV)
    return (Path(root) / p) if root else p


def parse_reproduction_strategy(config: Dict[str, Any]) -> list:
    """Return the ordered reproducer strategy from the top-level config.

    ``reproduction_strategy`` is an ORDERED list controlling which CVE
    reproducers Phase 0 emits and in what PRIORITY (the first entry becomes the
    primary reproducer Phase 1 uses). It captures all four modes with one knob:

        [exploitdb]            ExploitDB PoC only          (default; glibc today)
        [intree]               fix-commit test only        (Option A only)
        [exploitdb, intree]    both, ExploitDB preferred   (PoC, else the test)
        [intree, exploitdb]    both, Option A preferred    (test, else the PoC)

    Accepts a list or a comma/space-separated string. Unknown tokens are
    dropped; an empty/invalid result falls back to ``["exploitdb"]``. As a
    legacy bridge, ``commit_discovery.harvest_regression_tests: true`` (with no
    explicit strategy) is treated as ``[exploitdb, intree]``.
    """
    raw = config.get("reproduction_strategy")
    if raw is None:
        # Legacy bridge: the old boolean flag implies adding the intree source.
        harvest = (config.get("commit_discovery", {}) or {}).get(
            "harvest_regression_tests", False)
        return ["exploitdb", "intree"] if harvest else ["exploitdb"]
    if isinstance(raw, str):
        raw = raw.replace(",", " ").split()
    seen, out = set(), []
    for tok in raw or []:
        t = str(tok).strip().lower()
        if t in _VALID_REPRODUCERS and t not in seen:
            seen.add(t)
            out.append(t)
    return out or ["exploitdb"]


class FatalPipelineError(RuntimeError):
    """A module failure that must stop the whole pipeline.

    The orchestrator continues past ordinary module exceptions when
    ``pipeline.abort_on_error`` is false. Raising this instead signals a
    condition that invalidates the entire run (e.g. the CVE source is
    unreachable, so any downstream output would be hollow) and must halt the
    pipeline regardless of that setting.
    """


class PipelineModule(abc.ABC):
    """Base class for all pipeline stages.

    Subclasses must implement :meth:`run`.  The *config* dict is the
    resolved YAML configuration (or a relevant subset of it).
    """

    def __init__(self, config: Dict[str, Any], *, logger_name: str | None = None):
        self.config = config
        self.logger = logging.getLogger(logger_name or self.__class__.__name__)

    @abc.abstractmethod
    def run(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the module.

        Parameters
        ----------
        context : dict
            Shared pipeline context.  Each module reads what it needs
            and writes its outputs back into *context* before returning.

        Returns
        -------
        dict
            The (possibly-updated) pipeline context.
        """
        ...

    # Optional hooks that modules can override
    def validate_config(self) -> bool:
        """Return ``True`` if the module's configuration is valid."""
        return True

    def cleanup(self) -> None:
        """Release any resources held by the module."""
        pass
