"""Remote Ollama GPU monitor / residency gate.

Ensures a model is only LOADED onto the shared Ollama server when a GPU is
free for it, so a new load never lands beside another resident model on the
same card and partially offloads to CPU. On a multi-GPU server (``slots`` from
``gpu_slots.detect_gpu_slots``) up to ``slots`` model families may be resident
at once — one per GPU; ``slots=1`` is the legacy fully-exclusive behaviour.
Everything works over the Ollama HTTP API through the authenticated proxy —
``/api/ps`` exposes each loaded runner's ``size``/``size_vram`` (CPU-offload
detection included), and a zero-prompt ``/api/generate`` with ``keep_alive: 0``
unloads a model remotely. No SSH access to the GPU host is needed.

Modes (config ``llm.gpu_exclusive``, env override ``SSD_GPU_EXCLUSIVE``):
  * ``evict`` (default) — actively unload every OTHER resident model, then wait
    until the GPU is empty/ours before proceeding. Correct for this pipeline's
    dedicated server: any other resident model is a leftover from a previous
    cell of OUR OWN runs (profiles are uniform, one model per run).
  * ``wait``  — passively poll until other models expire (their keep_alive) or
    are evicted by Ollama itself; never unloads anything. Polite mode for a
    server genuinely shared with other tenants.
  * ``off``   — no gate (legacy behaviour).

This complements — not replaces — ``gpu_lock`` (the host-global flock that
serializes OUR concurrent cells): the lock orders our own requests, this gate
controls WHAT is resident in VRAM when a load happens.
"""
from __future__ import annotations

import logging
import os
import time
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlunparse

import requests

logger = logging.getLogger(__name__)

VALID_MODES = ("evict", "wait", "off")


def resolve_mode(cfg_value: Optional[str] = None) -> str:
    """Effective gate mode: env ``SSD_GPU_EXCLUSIVE`` > *cfg_value* > "evict"."""
    raw = os.environ.get("SSD_GPU_EXCLUSIVE") or cfg_value or "evict"
    mode = str(raw).strip().lower()
    if mode not in VALID_MODES:
        logger.warning("Unknown gpu_exclusive mode %r — using 'evict'", raw)
        return "evict"
    return mode


def _base_urls(endpoint: str) -> Tuple[str, str]:
    """Derive (/api/ps, /api/generate) URLs from any Ollama API endpoint."""
    parsed = urlparse(endpoint)
    ps = urlunparse((parsed.scheme, parsed.netloc, "/api/ps", "", "", ""))
    gen = urlunparse((parsed.scheme, parsed.netloc, "/api/generate", "", "", ""))
    return ps, gen


def loaded_models(endpoint: str, auth: Optional[Tuple[str, str]] = None,
                  timeout: int = 10) -> Optional[List[Dict[str, Any]]]:
    """The ``/api/ps`` model list, or None when the endpoint is unreachable."""
    ps_url, _ = _base_urls(endpoint)
    try:
        resp = requests.get(ps_url, timeout=timeout, auth=auth)
        resp.raise_for_status()
        return resp.json().get("models", []) or []
    except Exception:
        return None


def _is_target(entry: Dict[str, Any], model: Optional[str]) -> bool:
    if not model:
        return False
    target = model.strip().lower()
    names = {str(entry.get(k, "")).strip().lower() for k in ("name", "model")}
    # Tolerate the implicit ":latest" tag in either direction.
    return any(n == target or n == f"{target}:latest" or f"{n}:latest" == target
               for n in names if n)


def evict_others(endpoint: str, auth: Optional[Tuple[str, str]] = None,
                 keep: Optional[str] = None,
                 log: Optional[logging.Logger] = None,
                 running: Optional[List[Dict[str, Any]]] = None) -> List[str]:
    """Unload every resident model except *keep* via ``keep_alive: 0``.

    The zero-prompt generate request is Ollama's documented remote-unload; it
    never interrupts an in-flight generation (the runtime finishes current work
    before releasing). *running* is an optional pre-fetched ``/api/ps``
    snapshot (avoids a second round-trip when the caller just polled).
    Returns the model names an unload was requested for.
    """
    log = log or logger
    if running is None:
        running = loaded_models(endpoint, auth)
    if not running:
        return []
    _, gen_url = _base_urls(endpoint)
    evicted: List[str] = []
    for entry in running:
        if _is_target(entry, keep):
            continue
        name = entry.get("name") or entry.get("model") or "?"
        try:
            requests.post(gen_url, json={"model": name, "keep_alive": 0},
                          timeout=30, auth=auth)
            evicted.append(name)
            log.info("GPU gate: requested unload of resident model '%s' "
                     "(%.1f GiB VRAM)", name, entry.get("size_vram", 0) / 1024 ** 3)
        except Exception as exc:
            log.warning("GPU gate: could not request unload of '%s': %s", name, exc)
    return evicted


def ensure_exclusive(endpoint: str, auth: Optional[Tuple[str, str]] = None,
                     model: Optional[str] = None, mode: str = "evict",
                     timeout: int = 120, poll_interval: int = 10,
                     log: Optional[logging.Logger] = None,
                     slots: int = 1) -> bool:
    """Block until a GPU is free for *model*; then return True.

    *slots* is the number of GPUs on the server (see
    ``gpu_slots.detect_gpu_slots``): up to *slots* model families may be
    resident at once — one per GPU — so the gate passes as soon as the foreign
    models leave at least one GPU for ours (i.e. fewer than *slots* foreigners
    resident; assumes one GPU per resident model, true for models that fit a
    single card). ``slots=1`` is the legacy exclusive behaviour.

    Returns True immediately for mode "off", when ``/api/ps`` is unreachable
    (assume available — matches the legacy behaviour), or when a GPU is
    already free/ours. In "evict" mode only the EXCESS foreign models are
    actively unloaded (re-requested each poll — a model mid-generation unloads
    once it finishes); the first ``slots - 1`` foreigners are left alone, since
    a concurrent cell's model legitimately occupying another GPU must not be
    thrashed. Returns False when *timeout* expires with too many foreign models
    still resident; the caller decides whether to proceed anyway.
    """
    log = log or logger
    if mode == "off":
        return True
    budget = max(1, int(slots or 1))
    start = time.time()
    while True:
        running = loaded_models(endpoint, auth)
        if running is None:
            return True  # can't reach /api/ps — assume available
        others = [e for e in running if not _is_target(e, model)]
        if len(others) < budget:
            return True
        excess = others[budget - 1:]
        if mode == "evict":
            evict_others(endpoint, auth, keep=model, log=log, running=excess)
        elapsed = time.time() - start
        if timeout and elapsed >= timeout:
            names = [e.get("name", "?") for e in excess]
            log.warning("GPU gate: foreign model(s) still resident after %ds "
                        "(%d resident, budget %d): %s",
                        int(elapsed), len(others), budget, ", ".join(names))
            return False
        vram = sum(e.get("size_vram", 0) for e in excess) / 1024 ** 3
        log.info("GPU gate (%s): waiting for %d excess foreign model(s) "
                 "(%.1f GiB VRAM, %d resident / budget %d) to unload … (%d/%d s)",
                 mode, len(excess), vram, len(others), budget,
                 int(elapsed), timeout)
        time.sleep(poll_interval)


def offload_report(endpoint: str, model: str,
                   auth: Optional[Tuple[str, str]] = None
                   ) -> Optional[Tuple[int, int]]:
    """(size, size_vram) for *model* if resident, else None.

    ``size_vram == 0`` means CPU-only; ``0 < size_vram < size`` means partial
    CPU offload — both are exactly what the exclusivity gate exists to prevent.
    """
    running = loaded_models(endpoint, auth)
    if not running:
        return None
    for entry in running:
        if _is_target(entry, model):
            return int(entry.get("size", 0)), int(entry.get("size_vram", 0))
    return None
