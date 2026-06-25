"""OpenAI model-family compatibility helpers.

The gpt-5 family and the o-series reasoning models (o1/o3/o4...) use a newer
Chat Completions parameter contract: they reject ``max_tokens`` (requiring
``max_completion_tokens``) and accept ONLY the default ``temperature`` (1) and
``top_p`` (1). Classic chat models (gpt-4.1, gpt-4o, gpt-4-*, gpt-3.5-*) take
``max_tokens`` plus a custom temperature.

Centralised here so every LLM phase applies the same rule:
  * Phase 0 PoC repair      (``cve_aggregator/modules/poc_repair.py``)
  * Phase 1 negative filter (``poc_analyzer.py``)
  * Phase 2 patch generation (``patch_generator.py``)

Kept project-agnostic — it keys only on the model id, never on a CVE or project.
"""
from typing import Any, Dict


def is_openai_reasoning_model(model: str) -> bool:
    """True for OpenAI models that only accept the default sampling params.

    Covers the gpt-5 family (gpt-5, gpt-5-mini, gpt-5.4-mini, gpt-5*-codex, ...)
    and the o-series reasoning models (o1/o3/o4). These reject a custom
    ``temperature``/``top_p`` and require ``max_completion_tokens`` over
    ``max_tokens``.
    """
    m = (model or "").lower()
    return (
        m.startswith("gpt-5")
        or m.startswith("o1")
        or m.startswith("o3")
        or m.startswith("o4")
    )


def openai_temperature_kwargs(model: str, temperature: float) -> Dict[str, Any]:
    """Sampling kwargs for ``chat.completions.create``.

    Returns ``{"temperature": <temperature>}`` for classic chat models and an
    empty dict for reasoning models (which 400 on any non-default temperature).
    Spread into the call so reasoning models simply omit the parameter.
    """
    if is_openai_reasoning_model(model):
        return {}
    return {"temperature": temperature}


def is_unsupported_temperature_error(err: object) -> bool:
    """True when an OpenAI error means the model rejected a custom temperature.

    The runtime safety net for a model the name heuristic misses (e.g. a future
    family): on this error the caller drops ``temperature`` and retries once.
    Matches the API's phrasings, e.g. "Unsupported value: 'temperature' does not
    support 0.5 with this model. Only the default (1) value is supported."
    """
    msg = str(err).lower()
    return "temperature" in msg and (
        "unsupported" in msg
        or "does not support" in msg
        or "only the default" in msg
    )
