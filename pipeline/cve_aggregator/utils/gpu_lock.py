"""Host-global GPU semaphore for the shared Ollama GPU(s).

The pipeline drives a shared Ollama GPU server. When several pipeline
processes (cells) run concurrently — e.g. ``run_all.sh`` with
``OLLAMA_PARALLEL>1``, or the two-lane scheduler overlapping Phase 2 of one
cell with Phase 3 of another — their GPU-bound inference must be bounded by
the number of GPUs. Otherwise two requests for *different* model families hit
one GPU at once and Ollama thrashes, evicting and reloading multi-GiB weights
per request.

Historically this was a single mutex (one shared GPU). It is now an **N-slot
counting semaphore**: ``slots`` concurrent holders are admitted, one per GPU
(the 226 proxy server has 2x L40S, so two cells may infer at once — one model
family per card). The slot count comes from the caller (see
``gpu_slots.detect_gpu_slots``: env ``SSD_GPU_SLOTS`` > config ``gpu_slots`` >
probe > 1); ``slots=1`` is byte-identical to the old mutex, including its lock
filename, so a mixed old/new deployment still mutually excludes.

The previous coordination was an **advisory** poll of ``/api/ps`` (a TOCTOU
race: two processes both observe "free" and both proceed). This module replaces
that with real cross-process ``flock`` slot files that every GPU-bound step
holds for the duration of its work. ``flock`` is released automatically by the
OS when the holding process exits, so a crashed/killed cell never leaks a slot
(the per-phase watchdog that kills a hung phase therefore also frees the GPU).

It is a **no-op** when:
  * ``provider != "ollama"`` — OpenAI and other remote APIs have no local GPU; the
    constraint there is API rate limits, not VRAM, and ``run_all.sh`` already runs
    those cells in parallel;
  * disabled via the ``SSD_GPU_LOCK=0`` env var (or ``enabled=False`` from config);
  * ``fcntl``/``flock`` is unavailable (non-POSIX host).

Uncontended acquisition (a free slot available, e.g. only one cell running) is
a single ``open`` + ``flock`` syscall — effectively instant — so turning this
on costs nothing until cells actually contend for the GPUs.

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


def _resolve_slots(slots: Optional[int]) -> int:
    """Semaphore width to use for THIS acquisition (always >= 1).

    Delegates to ``gpu_slots.current_slots``: the live poller file (fresh) wins,
    then ``SSD_GPU_SLOTS`` env, then the caller-passed *slots* (its import-time
    detected value), then 1. Reading at acquisition time is what lets the
    periodic poller grow/shrink concurrency without restarting a cell."""
    try:
        from .gpu_slots import current_slots
    except Exception:  # pragma: no cover - defensive, keep the mutex working
        raw = os.environ.get("SSD_GPU_SLOTS", "")
        try:
            n = int(float(str(raw).strip()))
        except (TypeError, ValueError):
            n = slots if (slots and slots >= 1) else 1
        return n if n >= 1 else 1
    return current_slots(default=slots if (slots and slots >= 1) else None)


def lock_path(endpoint: str = "", slot: int = 0) -> Path:
    """Slot lock-file path, keyed by *endpoint* so distinct GPU servers don't
    share a semaphore (and the same server always maps to the same files across
    cells). Slot 0 keeps the legacy single-GPU filename — old code always
    contends on it, so mixed deployments stay mutually exclusive."""
    key = hashlib.sha1((endpoint or "default").encode("utf-8")).hexdigest()[:12]
    if slot <= 0:
        return _lock_dir() / f"gpu-{key}.lock"
    return _lock_dir() / f"gpu-{key}.s{slot}.lock"


@contextlib.contextmanager
def gpu_lock(
    provider: str = "ollama",
    *,
    enabled: bool = True,
    endpoint: str = "",
    slots: Optional[int] = None,
    wait_timeout: Optional[float] = None,
    poll_log_secs: float = _DEFAULT_POLL_LOG_SECS,
    logger: Optional[logging.Logger] = None,
    label: str = "",
) -> Iterator[bool]:
    """Hold one of the host-global GPU slots for the duration of the ``with`` block.

    *slots* is the semaphore width — the number of GPUs concurrent inference may
    use (pass ``gpu_slots.detect_gpu_slots(...)``); ``None`` resolves the
    ``SSD_GPU_SLOTS`` env var, defaulting to 1 (the legacy single-GPU mutex).

    Yields ``True`` if a slot is held, ``False`` if it is a no-op (disabled /
    non-ollama) or no slot was free within *wait_timeout*. On timeout the
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

    n = _resolve_slots(slots)
    paths = [lock_path(endpoint, i) for i in range(n)]
    suffix = f" [{label}]" if label else ""
    fd: Optional[int] = None
    held = False
    held_slot = -1
    start = time.monotonic()
    last_log = start
    waited = False
    try:
        while True:
            for i, p in enumerate(paths):
                try:
                    # O_CLOEXEC so a child process can't inherit the slot fd and
                    # keep the flock held past the holder's death (slot leak).
                    cand = os.open(str(p),
                                   os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0),
                                   0o644)
                except OSError:
                    continue
                try:
                    fcntl.flock(cand, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fd = cand
                    held = True
                    held_slot = i
                    break
                except OSError:
                    try:
                        os.close(cand)
                    except OSError:
                        pass
            if held:
                break
            waited = True
            now = time.monotonic()
            if wait_timeout and (now - start) >= wait_timeout:
                log.warning(
                    "GPU lock%s wait exceeded its %.1fs budget (waited %.1fs) — "
                    "proceeding WITHOUT a slot (all %d GPU slot(s) busy).",
                    suffix, wait_timeout, now - start, n,
                )
                break
            if now - last_log >= poll_log_secs:
                log.info(
                    "Waiting for a GPU slot%s — all %d busy (%.0fs)…",
                    suffix, n, now - start,
                )
                last_log = now
            time.sleep(1.0)
        if held and waited:
            log.info(
                "Acquired GPU slot %d/%d%s after %.0fs.",
                held_slot + 1, n, suffix, time.monotonic() - start,
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
