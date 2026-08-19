"""GPU slot detection: how many GPUs may the pipeline use concurrently?

The pipeline historically assumed ONE shared Ollama GPU — ``gpu_lock``
serialized every GPU-bound inference host-globally. GPU servers with several
cards (the 226 proxy host has 2x L40S) can serve one model family per GPU, so
the pipeline now sizes its GPU concurrency at startup: this module answers
"how many GPUs are available for use?" once per process, and every GPU-aware
component consumes that number:

  * ``gpu_lock``       — semaphore width (N concurrent inferences instead of 1)
  * ``gpu_monitor``    — residency budget (N model families may stay resident)
  * ``run_all.sh``     — Ollama generation-lane width (N cells generate at once)

Detection ladder (first hit wins):
  1. ``SSD_GPU_SLOTS`` env var — explicit count. ``run_all.sh`` probes once at
     run start and exports this, so every cell of a run agrees on one number.
  2. config ``gpu_slots`` as an integer (``llm:`` section; also honored in a
     ``poc_repair:`` section dict).
  3. ``gpu_slots: "auto"`` (or unset):
       a. ``gpu_probe_command`` — a configured shell command that prints either
          a bare integer (the slot count) or nvidia-smi CSV lines
          (``nvidia-smi --query-gpu=memory.used,memory.total
          --format=csv,noheader,nounits``), typically via ssh to the GPU host,
          since the Ollama HTTP API exposes no GPU inventory.
       b. local ``nvidia-smi`` — only when the endpoint host IS this host
          (localhost / unset), so a GPU on the client machine never misreports
          a remote server's inventory.
       c. otherwise **1** — the safe single-GPU legacy behaviour.

"Available" means not hogged by a foreign workload: a GPU counts unless its
used-memory fraction is >= ``gpu_busy_memory_fraction`` (default 0.9). Our own
resident Ollama model (a 7B is ~17% of an L40S) never disqualifies a GPU; a
tenant's full-VRAM training job does. When every GPU is busy the count clamps
to 1 rather than 0, so the pipeline queues on one slot instead of deadlocking.

Client-side detection cannot change SERVER scheduling: for N slots to help,
the Ollama host must allow N resident models (``OLLAMA_MAX_LOADED_MODELS`` >=
GPU count — modern Ollama defaults to 3x GPU count, so this usually holds).
"""
from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, Optional, Tuple

_LOG = logging.getLogger(__name__)

_DEFAULT_BUSY_FRACTION = 0.9
_PROBE_TIMEOUT_SECS = 30
_DEFAULT_POLL_INTERVAL = 60
# A live slots file older than this (no poller refresh) is treated as stale and
# ignored, so a dead poller falls back to env/config instead of pinning a value
# forever. Keep comfortably above the poll interval.
_SLOTS_FILE_MAX_AGE = 900

# Memoized per (env, config inputs) so repeated calls — every phase resolves
# the count independently — run at most one probe subprocess per process.
_cache: Dict[Tuple, int] = {}

_NVIDIA_SMI_ARGS = [
    "--query-gpu=memory.used,memory.total", "--format=csv,noheader,nounits",
]


def _count_available_from_csv(text: str, busy_fraction: float) -> Optional[int]:
    """Count available GPUs from nvidia-smi CSV ``memory.used, memory.total``
    (MiB) lines. Returns None when no line parses (not CSV output)."""
    total = available = 0
    for line in text.strip().splitlines():
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 2:
            continue
        try:
            used, cap = float(parts[0]), float(parts[1])
        except ValueError:
            continue
        if cap <= 0:
            continue
        total += 1
        if used / cap < busy_fraction:
            available += 1
    if total == 0:
        return None
    if available < total:
        _LOG.info("GPU probe: %d/%d GPU(s) busy (>= %.0f%% memory used) — "
                  "not counted as available.", total - available, total,
                  busy_fraction * 100)
    return available


def _parse_probe_output(text: str, busy_fraction: float) -> Optional[int]:
    """A probe may print a bare integer (the count) or nvidia-smi CSV lines."""
    stripped = (text or "").strip()
    if re.fullmatch(r"\d+", stripped):
        return int(stripped)
    return _count_available_from_csv(stripped, busy_fraction)


def _run_probe(cmd: str, busy_fraction: float, log: logging.Logger) -> Optional[int]:
    """Run a configured availability probe (shell) and parse its output."""
    try:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True,
                              timeout=_PROBE_TIMEOUT_SECS)
    except (subprocess.SubprocessError, OSError) as exc:
        log.warning("GPU probe command failed (%s) — falling back.", exc)
        return None
    if proc.returncode != 0:
        log.warning("GPU probe command exited %d (%s) — falling back.",
                    proc.returncode, (proc.stderr or "").strip()[:200])
        return None
    return _parse_probe_output(proc.stdout, busy_fraction)


def _local_nvidia_smi(busy_fraction: float, log: logging.Logger) -> Optional[int]:
    """Count available GPUs on THIS host (covers a localhost Ollama)."""
    smi = shutil.which("nvidia-smi")
    if not smi:
        return None
    try:
        proc = subprocess.run([smi, *_NVIDIA_SMI_ARGS], capture_output=True,
                              text=True, timeout=_PROBE_TIMEOUT_SECS)
    except (subprocess.SubprocessError, OSError):
        return None
    if proc.returncode != 0:
        return None
    return _count_available_from_csv(proc.stdout, busy_fraction)


def _is_local_endpoint(endpoint: str) -> bool:
    """Whether the API endpoint's host is this machine (or unset)."""
    ep = (endpoint or "").strip()
    if not ep:
        return True
    try:
        from urllib.parse import urlparse
        host = (urlparse(ep).hostname or "").lower()
    except ValueError:
        return False
    return host in ("", "localhost", "127.0.0.1", "::1", "0.0.0.0")


def detect_gpu_slots(cfg: Optional[Dict[str, Any]] = None, *,
                     endpoint: str = "",
                     logger: Optional[logging.Logger] = None,
                     use_cache: bool = True) -> int:
    """Resolve how many GPU slots the pipeline may use (always >= 1).

    *cfg* is any config dict carrying the optional keys ``gpu_slots``,
    ``gpu_probe_command`` and ``gpu_busy_memory_fraction`` (the ``llm:``
    section for Phases 1–3, the ``poc_repair:`` section for Phase 0).
    *endpoint* is the Ollama API URL — it gates the local ``nvidia-smi`` rung
    (only meaningful when the server runs on this host). See the module
    docstring for the detection ladder.
    """
    log = logger or _LOG
    cfg = cfg or {}

    raw_cfg = cfg.get("gpu_slots")
    probe_cmd = str(cfg.get("gpu_probe_command") or "").strip()
    endpoint = endpoint or str(cfg.get("endpoint") or cfg.get("api_endpoint") or "")
    try:
        busy_fraction = float(cfg.get("gpu_busy_memory_fraction",
                                      _DEFAULT_BUSY_FRACTION))
    except (TypeError, ValueError):
        busy_fraction = _DEFAULT_BUSY_FRACTION

    key = (os.environ.get("SSD_GPU_SLOTS"), str(raw_cfg), probe_cmd,
           busy_fraction, _is_local_endpoint(endpoint))
    if use_cache and key in _cache:
        return _cache[key]

    slots: Optional[int] = None
    source = "default"

    env = os.environ.get("SSD_GPU_SLOTS")
    if env is not None and str(env).strip():
        try:
            slots = int(float(str(env).strip()))
            source = "SSD_GPU_SLOTS env"
        except ValueError:
            log.warning("Ignoring non-numeric SSD_GPU_SLOTS=%r.", env)

    if slots is None and raw_cfg is not None \
            and str(raw_cfg).strip().lower() not in ("", "auto"):
        try:
            slots = int(float(str(raw_cfg).strip()))
            source = "config gpu_slots"
        except ValueError:
            log.warning("Ignoring non-numeric gpu_slots=%r (use an int or "
                        "'auto').", raw_cfg)

    if slots is None and probe_cmd:
        probed = _run_probe(probe_cmd, busy_fraction, log)
        if probed is not None:
            slots = probed
            source = "gpu_probe_command"

    if slots is None and _is_local_endpoint(endpoint):
        probed = _local_nvidia_smi(busy_fraction, log)
        if probed is not None:
            slots = probed
            source = "local nvidia-smi"

    if slots is None:
        slots = 1
        source = "default (no probe available — single-GPU legacy)"
    elif slots < 1:
        log.warning("GPU availability probe found no free GPU — clamping to 1 "
                    "slot (requests will queue).")
        slots = 1

    log.info("GPU slots: %d  [%s]", slots, source)
    if use_cache:
        _cache[key] = slots
    return slots


# ---------------------------------------------------------------------------
# Live slot file — the "periodic timer" layer
# ---------------------------------------------------------------------------
# A background poller (run_poller / the ``--watch`` CLI) re-runs the detection
# ladder every ``interval`` seconds and writes the current count to a HOST-GLOBAL
# file that every cell reads at GPU-acquisition time (via ``current_slots`` ->
# gpu_lock / gpu_monitor). So when a GPU that was hogged by a foreign workload
# frees up, the next poll raises the count and subsequent cells start using it —
# no restart. The file lives under the same ``.locks`` dir as the gpu_lock slot
# files so one ``SSD_GPU_LOCK_DIR`` / ``SSD_PIPELINE_ROOT`` setting covers both.


def _lock_dir() -> Path:
    """HOST-GLOBAL dir shared by every cell (matches gpu_lock._lock_dir):
    ``SSD_GPU_LOCK_DIR`` -> ``SSD_PIPELINE_ROOT``/.locks -> repo-root/.locks ->
    system temp."""
    base = os.environ.get("SSD_GPU_LOCK_DIR")
    if base:
        d = Path(base)
    else:
        root = os.environ.get("SSD_PIPELINE_ROOT")
        if root:
            d = Path(root) / ".locks"
        else:
            # gpu_slots.py lives at <repo>/cve_aggregator/utils/ → repo root 2 up.
            d = Path(__file__).resolve().parent.parent.parent / ".locks"
    try:
        d.mkdir(parents=True, exist_ok=True)
        return d
    except OSError:
        return Path(tempfile.gettempdir())


def slots_file() -> Path:
    """Path to the live slot-count file written by the poller."""
    return _lock_dir() / "gpu_slots.current"


def write_current_slots(n: int, path: Optional[Path] = None) -> None:
    """Atomically publish the current slot count (temp file + rename)."""
    p = path or slots_file()
    try:
        fd, tmp = tempfile.mkstemp(dir=str(p.parent), prefix=".gpu_slots.")
        with os.fdopen(fd, "w") as fh:
            fh.write(f"{max(1, int(n))}\n")
        os.replace(tmp, str(p))
    except OSError as exc:  # pragma: no cover - best effort
        _LOG.debug("Could not write live slots file %s: %s", p, exc)


def read_current_slots(default: Optional[int] = None,
                       max_age: Optional[float] = _SLOTS_FILE_MAX_AGE,
                       path: Optional[Path] = None) -> Optional[int]:
    """Read the live slot count, or *default* when absent/stale/unparseable.

    A file older than *max_age* seconds (poller likely dead) is ignored so the
    count reverts to the env/config fallback rather than pinning forever;
    ``max_age=None`` disables the staleness check.
    """
    p = path or slots_file()
    try:
        st = p.stat()
    except OSError:
        return default
    if max_age is not None and (time.time() - st.st_mtime) > max_age:
        return default
    try:
        val = int(float(p.read_text().strip()))
    except (OSError, ValueError):
        return default
    return val if val >= 1 else default


def current_slots(cfg: Optional[Dict[str, Any]] = None, *,
                  endpoint: str = "", default: Optional[int] = None,
                  logger: Optional[logging.Logger] = None) -> int:
    """The slot count consumers should use RIGHT NOW (always >= 1).

    Precedence: the live poller file (fresh) > ``SSD_GPU_SLOTS`` env > *default*
    (a caller's import-time detected value) > a one-shot ``detect_gpu_slots``.
    The live file wins so a running poller is authoritative — the dynamic timer
    can raise/lower the effective count without restarting anything.
    """
    live = read_current_slots(default=None)
    if live is not None:
        return max(1, live)
    env = os.environ.get("SSD_GPU_SLOTS")
    if env is not None and str(env).strip():
        try:
            return max(1, int(float(str(env).strip())))
        except ValueError:
            pass
    if default is not None:
        return max(1, int(default))
    return detect_gpu_slots(cfg or {}, endpoint=endpoint, logger=logger)


def run_poller(cfg: Optional[Dict[str, Any]] = None, *,
               endpoint: str = "", interval: float = _DEFAULT_POLL_INTERVAL,
               iterations: Optional[int] = None,
               logger: Optional[logging.Logger] = None) -> None:
    """Periodically re-detect GPU availability and publish it to the live file.

    Re-runs the full detection ladder every *interval* seconds (writing the
    first value immediately, before the first sleep) so newly-freed GPUs are
    picked up by subsequent cell acquisitions. Stops after *iterations* writes
    when given (tests); otherwise loops until SIGTERM/SIGINT. Never raises on a
    transient probe failure — it logs and keeps the last published value.
    """
    log = logger or _LOG
    import signal

    stop = {"flag": False}

    def _handle(signum, _frame):  # pragma: no cover - signal path
        stop["flag"] = True

    try:
        signal.signal(signal.SIGTERM, _handle)
        signal.signal(signal.SIGINT, _handle)
    except (ValueError, OSError):  # pragma: no cover - non-main-thread
        pass

    path = slots_file()
    log.info("GPU-slot poller starting: interval=%.0fs, file=%s", interval, path)
    last: Optional[int] = None
    count = 0
    while not stop["flag"]:
        try:
            n = detect_gpu_slots(cfg or {}, endpoint=endpoint, logger=log,
                                 use_cache=False)
        except Exception as exc:  # pragma: no cover - defensive
            log.warning("GPU-slot poll failed (%s) — keeping last value.", exc)
            n = last if last is not None else 1
        write_current_slots(n, path)
        if n != last:
            log.info("GPU-slot poller: published %d slot(s).", n)
            last = n
        count += 1
        if iterations is not None and count >= iterations:
            break
        # Interruptible sleep so a signal ends the loop promptly.
        slept = 0.0
        while slept < interval and not stop["flag"]:
            time.sleep(min(1.0, interval - slept))
            slept += 1.0
    log.info("GPU-slot poller stopped after %d publish(es).", count)


def _main() -> int:  # pragma: no cover - thin CLI
    """CLI for run_all.sh.

    Default: print the detected slot count (one-shot).
    ``--watch``: run the periodic poller, publishing to the live slots file.
    ``--config <path>`` reads the ``llm:`` section of a pipeline config.yaml
    (best-effort — a missing file or PyYAML leaves the env/nvidia-smi ladder).
    Runs as a plain script (no package imports), so it works pre-venv too.
    """
    import argparse

    parser = argparse.ArgumentParser(description="Detect/watch usable GPU slots")
    parser.add_argument("--config", default="", help="pipeline config.yaml path")
    parser.add_argument("--endpoint", default="", help="Ollama API endpoint")
    parser.add_argument("--watch", action="store_true",
                        help="run the periodic poller instead of a one-shot print")
    parser.add_argument("--interval", type=float, default=_DEFAULT_POLL_INTERVAL,
                        help="poll interval in seconds (with --watch)")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO if args.watch else logging.WARNING,
                        format="%(asctime)s %(levelname)s %(message)s")
    cfg: Dict[str, Any] = {}
    if args.config:
        try:
            import yaml
            with open(args.config, "r", encoding="utf-8") as fh:
                loaded = yaml.safe_load(fh) or {}
            cfg = loaded.get("llm") or {}
        except Exception:
            cfg = {}
    endpoint = args.endpoint or str(cfg.get("endpoint") or cfg.get("api_endpoint") or "")
    if args.watch:
        run_poller(cfg, endpoint=endpoint, interval=args.interval)
        return 0
    print(detect_gpu_slots(cfg, endpoint=endpoint, use_cache=False))
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(_main())
