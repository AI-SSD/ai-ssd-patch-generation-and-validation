"""Per-phase live-progress heartbeat that the dashboard reads for real-time stats.

Every pipeline phase calls :func:`emit` after it finishes each item (and once
more when the phase ends), atomically writing
``<results_dir>/.live_progress_p{N}.json``. The dashboard prefers this file over
the phase's final artifact (``results.json`` / ``pipeline_summary.json`` /
``validation_summary_*.json``), which is only written when a phase *finishes*, so
the by-phase cards on a cell page count up in real time (e.g. "15/30 attempted").

The file is intentionally written into the shared ``results/`` directory for ALL
phases so the dashboard has a single place to look. It is hidden (leading dot)
and tiny. This is STRICTLY best-effort: any error is swallowed so that progress
reporting can never disturb or slow down a run.
"""
from __future__ import annotations

import json
import os
import tempfile
import time
from typing import Any, Dict, Optional

FILENAME = ".live_progress_p{phase}.json"


def emit(results_dir, phase: int, total: int, done: int,
         counts: Optional[Dict[str, Any]] = None, running: bool = True) -> None:
    """Atomically write the live-progress heartbeat for ``phase``.

    Args:
        results_dir: the cell's ``results/`` directory (created if absent).
        phase:       phase number 0..3.
        total:       planned item count (the denominator, e.g. 30).
        done:        items processed so far (the numerator, e.g. 15).
        counts:      phase-specific breakdown the dashboard card renders
                     (e.g. ``{"reproduced": 12, "failed": 3}``).
        running:     False on the terminal write once the phase has ended.
    """
    try:
        rd = str(results_dir)
        os.makedirs(rd, exist_ok=True)
        payload = {
            "phase": int(phase),
            "total": int(total or 0),
            "done": int(done or 0),
            "running": bool(running),
            "ts": time.time(),
            "counts": dict(counts or {}),
        }
        dest = os.path.join(rd, FILENAME.format(phase=phase))
        fd, tmp = tempfile.mkstemp(dir=rd, prefix=".lp_", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(payload, f)
            os.replace(tmp, dest)
        finally:
            if os.path.exists(tmp):
                os.remove(tmp)
    except Exception:
        # Never let progress reporting break a run.
        pass
