"""Host-global GPU mutex for the single shared Ollama GPU.

The pipeline drives **one** shared Ollama GPU. When several pipeline processes
(cells) run concurrently — e.g. ``run_all.sh`` with ``OLLAMA_PARALLEL>1``, or a
future two-lane scheduler overlapping Phase 2 of one cell with Phase 3 of
another — their GPU-bound inference must be serialized. Otherwise two requests
for *different* model families hit the GPU at once and Ollama thrashes,
evicting and reloading multi-GiB weights per request.

The previous coordination was an **advisory** poll of ``/api/ps`` (a TOCTOU
race: two processes both observe "free" and both proceed). This module replaces
that with a real cross-process mutex: a ``flock`` on a host-global lock file that
every GPU-bound step holds for the duration of its work. ``flock`` is released
automatically by the OS when the holding process exits, so a crashed/killed cell
never leaks the lock (the per-phase watchdog that kills a hung phase therefore
also frees the GPU).

It is a **no-op** when:
  * ``provider != "ollama"`` — OpenAI and other remote APIs have no local GPU; the
    constraint there is API rate limits, not VRAM, and ``run_all.sh`` already runs
    those cells in parallel;
  * disabled via the ``SSD_GPU_LOCK=0`` env var (or ``enabled=False`` from config);
  * ``fcntl``/``flock`` is unavailable (non-POSIX host).

Uncontended acquisition (the ``OLLAMA_PARALLEL=1`` default, where only one cell
runs at a time) is a single ``open`` + ``flock`` syscall — effectively instant —
so turning this on costs nothing until cells actually overlap.

GRANULARITY: the lock is held by the *process* doing the work, for the duration
of one GPU-bound unit. Crucially, threads inside that process (e.g. Phase 0's
repair worker pool, which all use the SAME model) run freely under the single
held lock — the lock excludes *other processes* (other model families), not a
process's own same-model batching. Acquire it once around a unit; do not re-open
the lock file per call within the same process (separate ``flock`` fds in one
process would block each other).
"""
from __future__ import annotations

import contextlib
import hashlib
import logging
import os
import tempfile
import time
from pathlib import Path
from typing import Iterator, Optional

try:
    import fcntl  # POSIX only (Linux VM + macOS host both provide flock)
except ImportError:  # pragma: no cover - non-POSIX fallback
    fcntl = None  # type: ignore

_DEFAULT_POLL_LOG_SECS = 30
_LOG = logging.getLogger(__name__)


def _truthy(value: str) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes", "on")


def is_enabled(provider: str, enabled: bool = True) -> bool:
    """Whether the GPU lock should engage for *provider*.

    Precedence: the ``SSD_GPU_LOCK`` env var overrides the *enabled* arg; then the
    lock only applies to the local ``ollama`` GPU backend, and only when ``flock``
    is available.
    """
    env = os.environ.get("SSD_GPU_LOCK")
    if env is not None:
        if not _truthy(env):
            return False
    elif not enabled:
        return False
    if (provider or "ollama").strip().lower() != "ollama":
        return False
    return fcntl is not None


def _lock_dir() -> Path:
    """Resolve a HOST-GLOBAL directory shared by every cell on this host.

    Cells run with different working dirs / ``--base-dir``, so the lock must live
    at a fixed absolute path. Precedence: ``SSD_GPU_LOCK_DIR`` → ``SSD_PIPELINE_ROOT``
    /.locks (the executor exports this) → the pipeline repo root /.locks → the
    system temp dir as a last resort.
    """
    base = os.environ.get("SSD_GPU_LOCK_DIR")
    if base:
        d = Path(base)
    else:
        root = os.environ.get("SSD_PIPELINE_ROOT")
        if root:
            d = Path(root) / ".locks"
        else:
            # gpu_lock.py lives at <repo>/cve_aggregator/utils/ → repo root is 2 up.
            d = Path(__file__).resolve().parent.parent.parent / ".locks"
    try:
        d.mkdir(parents=True, exist_ok=True)
        return d
    except OSError:
        return Path(tempfile.gettempdir())


def lock_path(endpoint: str = "") -> Path:
    """Lock-file path, keyed by *endpoint* so distinct GPU servers don't share a
    mutex (and the same server always maps to the same file across cells)."""
    key = hashlib.sha1((endpoint or "default").encode("utf-8")).hexdigest()[:12]
    return _lock_dir() / f"gpu-{key}.lock"


@contextlib.contextmanager
def gpu_lock(
    provider: str = "ollama",
    *,
    enabled: bool = True,
    endpoint: str = "",
    wait_timeout: Optional[float] = None,
    poll_log_secs: float = _DEFAULT_POLL_LOG_SECS,
    logger: Optional[logging.Logger] = None,
    label: str = "",
) -> Iterator[bool]:
    """Hold the host-global GPU mutex for the duration of the ``with`` block.

    Yields ``True`` if the lock is held, ``False`` if it is a no-op (disabled /
    non-ollama) or could not be acquired within *wait_timeout*. On timeout the
    block still runs (best-effort, logged loudly) rather than deadlocking the
    pipeline — ``wait_timeout=0``/``None`` means wait indefinitely (the default;
    a hung holder is reaped by the phase watchdog, which frees the flock).

    *wait_timeout* defaults to the ``SSD_GPU_LOCK_TIMEOUT`` env var (seconds), or
    0 (infinite) when unset.
    """
    log = logger or _LOG
    if not is_enabled(provider, enabled):
        yield False
        return

    if wait_timeout is None:
        try:
            wait_timeout = float(os.environ.get("SSD_GPU_LOCK_TIMEOUT", "0") or 0)
        except ValueError:
            wait_timeout = 0.0

    path = lock_path(endpoint)
    suffix = f" [{label}]" if label else ""
    fd: Optional[int] = None
    held = False
    try:
        fd = os.open(str(path), os.O_RDWR | os.O_CREAT, 0o644)
        start = time.monotonic()
        last_log = start
        waited = False
        while True:
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                held = True
                break
            except OSError:
                waited = True
                now = time.monotonic()
                if wait_timeout and (now - start) >= wait_timeout:
                    log.warning(
                        "GPU lock%s wait exceeded its %.1fs budget (waited %.1fs) — "
                        "proceeding WITHOUT the lock (another GPU task may be running).",
                        suffix, wait_timeout, now - start,
                    )
                    break
                if now - last_log >= poll_log_secs:
                    log.info(
                        "Waiting for GPU lock%s — held by another process (%.0fs)…",
                        suffix, now - start,
                    )
                    last_log = now
                time.sleep(1.0)
        if held and waited:
            log.info(
                "Acquired GPU lock%s after %.0fs.", suffix, time.monotonic() - start
            )
        yield held
    finally:
        if fd is not None:
            if held:
                try:
                    fcntl.flock(fd, fcntl.LOCK_UN)
                except OSError:
                    pass
            try:
                os.close(fd)
            except OSError:
                pass
