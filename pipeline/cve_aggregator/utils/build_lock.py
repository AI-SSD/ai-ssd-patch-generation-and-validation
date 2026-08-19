"""Host-global build semaphore: cap concurrent ``docker build`` across cells.

Docker image builds — Phase 1 base/CVE images and Phase 3 patched rebuilds — are
CPU-bound (``make -j$(nproc)``). When the scheduler overlaps cells (several
project baselines building at once, or one project's Phase-3 validation running
while another project's baseline still builds), those builds compete for the
same cores and thrash: K concurrent builds each running ``make -jN`` spawn K*N
compilers on ncores. This module bounds the number of *concurrent builds
host-wide* with a flock-based counting semaphore, mirroring ``gpu_lock``'s design
— crash-safe, because the OS frees a slot when the holding (or killed) process
exits, so a watchdog-reaped build never leaks its slot.

It is a **no-op** unless a positive slot count is configured via ``SSD_BUILD_SLOTS``
(or the ``slots`` argument). So the default (unset) is byte-identical to today:
unbounded concurrent builds — which is fine when cells don't overlap. On an
8-core host running ``make -j8`` set ``SSD_BUILD_SLOTS=1`` (one full-CPU build at
a time) when enabling scheduler overlap; use 2 with a ``make -j4`` cap.

Crucially, patch GENERATION (OpenAI API / the Ollama GPU) does NOT take this
lock — only the build step does — so Phase-2 work of ready cells keeps flowing
while builds serialize. That is what makes the overlap work-conserving: the CPU
(builds), the GPU (``gpu_lock``), and the remote API each throttle independently.

Like ``gpu_lock``: acquire around ONE build unit; the slot is released on context
exit or process death. Do not nest acquisitions in one thread.
"""
from __future__ import annotations

import contextlib
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

_LOG = logging.getLogger(__name__)
_DEFAULT_POLL_LOG_SECS = 30


def _slots(default: Optional[int]) -> int:
    """Resolve the slot count. ``SSD_BUILD_SLOTS`` overrides *default*; a missing,
    zero, negative or non-integer value means 0 (semaphore disabled / no-op)."""
    env = os.environ.get("SSD_BUILD_SLOTS")
    if env is not None:
        # Tolerant parse so a common typo doesn't silently disable the cap:
        # accept "2", "2.0", " 2 ". Genuinely invalid text falls through to 0.
        try:
            return max(0, int(float(str(env).strip())))
        except ValueError:
            return 0
    try:
        return max(0, int(default or 0))
    except (TypeError, ValueError):
        return 0


def _lock_dir() -> Path:
    """HOST-GLOBAL lock directory, shared by every cell (they run with different
    ``--base-dir``, so the lock must be a fixed absolute path). Same conventions
    as ``gpu_lock`` so both live under one ``.locks`` dir."""
    base = os.environ.get("SSD_BUILD_LOCK_DIR")
    if base:
        d = Path(base)
    else:
        root = os.environ.get("SSD_PIPELINE_ROOT")
        if root:
            d = Path(root) / ".locks"
        else:
            # build_lock.py lives at <repo>/cve_aggregator/utils/ → repo root is 2 up.
            d = Path(__file__).resolve().parent.parent.parent / ".locks"
    try:
        d.mkdir(parents=True, exist_ok=True)
        return d
    except OSError:
        return Path(tempfile.gettempdir())


def is_enabled(slots: Optional[int] = None) -> bool:
    """Whether the build semaphore will engage (flock available AND slots >= 1)."""
    return fcntl is not None and _slots(slots) >= 1


@contextlib.contextmanager
def build_slot(
    slots: Optional[int] = None,
    *,
    wait_timeout: Optional[float] = None,
    poll_log_secs: float = _DEFAULT_POLL_LOG_SECS,
    logger: Optional[logging.Logger] = None,
    label: str = "",
) -> Iterator[bool]:
    """Hold one of N host-global build slots for the duration of the ``with`` block.

    Yields ``True`` if a slot is held, ``False`` if it is a no-op (disabled / no
    ``fcntl``) or could not be acquired within *wait_timeout*. On timeout the
    block still runs (best-effort, logged loudly) rather than deadlocking the
    build — ``wait_timeout=0``/``None`` waits indefinitely (a hung holder is
    reaped by the phase watchdog, which frees its flock).

    *wait_timeout* defaults to the ``SSD_BUILD_SLOT_TIMEOUT`` env var (seconds),
    or 0 (infinite) when unset.
    """
    log = logger or _LOG
    n = _slots(slots)
    if fcntl is None or n < 1:
        yield False
        return

    if wait_timeout is None:
        try:
            wait_timeout = float(os.environ.get("SSD_BUILD_SLOT_TIMEOUT", "0") or 0)
        except ValueError:
            wait_timeout = 0.0

    d = _lock_dir()
    paths = [d / f"build-slot-{i + 1}.lock" for i in range(n)]
    suffix = f" [{label}]" if label else ""
    fd: Optional[int] = None
    held = False
    start = time.monotonic()
    last_log = start
    waited = False
    try:
        while True:
            for p in paths:
                try:
                    # O_CLOEXEC so a child process can't inherit the slot fd and
                    # keep the flock held past the holder's death (slot leak).
                    cand = os.open(str(p), os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0), 0o644)
                except OSError:
                    continue
                try:
                    fcntl.flock(cand, fcntl.LOCK_EX | fcntl.LOCK_NB)
                    fd = cand
                    held = True
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
                    "Build slot%s wait exceeded its %.1fs budget (waited %.1fs) — "
                    "proceeding WITHOUT a slot (all %d builds busy).",
                    suffix, wait_timeout, now - start, n,
                )
                break
            if now - last_log >= poll_log_secs:
                log.info(
                    "Waiting for a build slot%s — all %d busy (%.0fs)…",
                    suffix, n, now - start,
                )
                last_log = now
            time.sleep(1.0)
        if held and waited:
            log.info("Acquired build slot%s after %.0fs.", suffix, time.monotonic() - start)
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
