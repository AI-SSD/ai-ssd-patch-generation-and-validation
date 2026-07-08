#!/usr/bin/env python3
"""Candidate fan-out + oracle-selection framework (Phase 2 over-generation).

This module is the generic scaffolding for "richer generation": instead of
producing a single greedy patch per (CVE, model), it produces a *set* of
candidates spanning one or more **diversity dimensions**, then lets the existing
Phase 3 oracle (PoC exit-code diff + SAST) pick the winner — the classic APR
over-generate-and-validate paradigm.

Design goals (all enforced here):

* **Default-preserving.** With the shipped defaults (``num_candidates: 1``, the
  base ``llm.temperature``, ``granularities: [minimal]``, ``chain_of_thought:
  false``) :func:`build_recipes` returns exactly ONE recipe identical to today's
  single greedy generation, so an un-configured run is byte-for-byte unchanged.

* **Project-agnostic / no per-CVE config.** Every knob is a global generation
  setting; nothing here is keyed on a specific project or CVE. The diversity
  dimensions (temperature, granularity, chain-of-thought, model, exemplar) are
  generic and live in ``config.yaml``'s ``generation:`` section.

* **Pure and injectable.** The expensive parts — actually calling the LLM and
  actually validating in Docker — are injected as callables (``generate_fn`` and
  ``oracle``). This module therefore imports no heavy dependencies, makes no
  network/Docker calls itself, and is fully unit-testable with fakes.

Every advanced technique from the thesis future-work programme is expressed as a
recipe dimension fed into this one mechanism:

    temperature       -> best-of-N sampling diversity
    granularity       -> multi-granularity patch generation
    chain_of_thought  -> reason-then-edit prompting
    model             -> (the existing per-attempt escalation ramp)
    exemplar          -> CWE-keyed repair-pattern retrieval (reserved)

The caller binds ``generate_fn`` to ``patch_generator.generate_one_candidate``
and ``oracle`` to the Phase 3 validator; this module orchestrates the rest.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Protocol, Tuple

# ---------------------------------------------------------------------------
# Diversity dimension: granularity instructions
# ---------------------------------------------------------------------------
# Extra user-prompt text appended for each generation granularity. Wording is
# language-neutral so it stays project-agnostic (C, Java, …). "minimal" is the
# empty string because the base Phase 2 prompt already asks for the smallest
# possible edit — so the default granularity changes nothing.
GRANULARITY_INSTRUCTIONS: Dict[str, str] = {
    # Today's behaviour: smallest anchored edit. No extra instruction.
    "minimal": "",
    # Bias toward a single early validation/guard before the unsafe operation.
    "guard": (
        "GRANULARITY: Prefer adding a SINGLE validation/guard as early as "
        "possible in the function — an early return or a bounds/length check "
        "before the unsafe operation — rather than restructuring existing logic."
    ),
    # Allow a fuller rewrite (still via SEARCH/REPLACE) when a minimal edit cannot
    # safely fix the defect. The signature must stay identical.
    "whole_function": (
        "GRANULARITY: A minimal edit may be insufficient here. You MAY replace a "
        "larger contiguous region of the function body with corrected logic, as "
        "long as you keep the EXACT same function signature and preserve behaviour "
        "for all legitimate inputs. Still express the change as SEARCH/REPLACE "
        "block(s)."
    ),
}

DEFAULT_GRANULARITY = "minimal"

# Chain-of-thought instruction. Appended to the USER prompt when a recipe enables
# CoT. The SEARCH/REPLACE parser scans for the edit markers and ignores any
# leading prose, so a short reasoning preamble is safe to emit and never reaches
# the patched file. This explicitly overrides the base prompt's "output only the
# blocks" rule for the candidates that opt in.
COT_INSTRUCTION = (
    "REASONING (overrides the 'output only' rule above): FIRST write a short "
    "analysis — 2-4 sentences naming the root cause and your fix plan — on lines "
    "beginning with 'ANALYSIS:'. THEN, after a blank line, output the "
    "SEARCH/REPLACE block(s) exactly as specified. Only the blocks are applied; "
    "the analysis is for your own reasoning."
)


@dataclass(frozen=True)
class Recipe:
    """One point in the diversity space — a single candidate's generation knobs.

    ``index`` 0 is always the *greedy* recipe (base temperature, minimal
    granularity, CoT off) so a "lazy" allocation can try the exact-today
    candidate first and only fan out the rest on failure.
    """
    index: int
    temperature: float
    granularity: str = DEFAULT_GRANULARITY
    chain_of_thought: bool = False
    model: Optional[str] = None          # None -> caller's provider default
    exemplar: bool = False               # reserved for CWE-keyed RAG

    @property
    def is_greedy(self) -> bool:
        """True for the attempt-1-equivalent recipe (today's single candidate)."""
        return (
            self.index == 0
            and self.granularity == DEFAULT_GRANULARITY
            and not self.chain_of_thought
            and not self.exemplar
        )

    def label(self) -> str:
        """Short human/log label, e.g. ``c0:minimal@0.2`` or ``c2:guard@0.9+cot``."""
        parts = [f"c{self.index}:{self.granularity}@{self.temperature:g}"]
        if self.chain_of_thought:
            parts.append("+cot")
        if self.exemplar:
            parts.append("+rag")
        if self.model:
            parts.append(f"[{self.model}]")
        return "".join(parts)

    def prompt_suffix(self) -> str:
        """Extra user-prompt text this recipe contributes (granularity + CoT).

        Empty for the greedy/minimal, CoT-off recipe — so today's prompt is
        unchanged. The caller appends this to the base Phase 2 user prompt.
        """
        chunks = []
        gran = GRANULARITY_INSTRUCTIONS.get(self.granularity, "")
        if gran:
            chunks.append(gran)
        if self.chain_of_thought:
            chunks.append(COT_INSTRUCTION)
        return ("\n\n" + "\n\n".join(chunks)) if chunks else ""


def build_recipes(
    gen_cfg: Optional[Dict[str, Any]],
    *,
    base_temperature: float,
    base_model: Optional[str] = None,
) -> List[Recipe]:
    """Translate the ``generation:`` config block into an ordered recipe list.

    The first recipe is always the greedy/today recipe; subsequent recipes walk
    the configured diversity dimensions deterministically. The list length is
    ``max(1, num_candidates)``.

    Parameters
    ----------
    gen_cfg:
        The ``generation`` section of ``config.yaml`` (or ``None``/empty for
        defaults). Recognised keys: ``num_candidates`` (int, default 1),
        ``candidate_temperatures`` (list[float], default ``[base_temperature]``),
        ``granularities`` (list[str], default ``["minimal"]``),
        ``chain_of_thought`` (bool, default False), ``exemplars`` (bool, reserved).
    base_temperature:
        The configured ``llm.temperature`` — used for the greedy recipe and as
        the sole temperature when ``candidate_temperatures`` is empty.
    base_model:
        Optional provider-default model id recorded on each recipe (informational;
        ``None`` means "use the caller's default").

    Returns
    -------
    list[Recipe]
        Deterministic, greedy-first ordering. With defaults this is a single
        recipe equal to today's behaviour.
    """
    cfg = gen_cfg or {}
    try:
        n = int(cfg.get("num_candidates", 1) or 1)
    except (TypeError, ValueError):
        n = 1
    n = max(1, n)

    cot = bool(cfg.get("chain_of_thought", False))
    exemplar = bool(cfg.get("exemplars", False))

    temps = [float(t) for t in (cfg.get("candidate_temperatures") or []) if _is_number(t)]
    if not temps:
        temps = [float(base_temperature)]

    grans = [str(g) for g in (cfg.get("granularities") or []) if str(g)]
    if not grans:
        grans = [DEFAULT_GRANULARITY]

    # Greedy/today recipe first: base temperature, minimal granularity, CoT off
    # (regardless of the global CoT flag, so a lazy allocation always has an
    # exact-today candidate to try before spending extra budget). The CoT flag is
    # honoured on the diversity recipes below.
    recipes: List[Recipe] = [
        Recipe(index=0, temperature=float(base_temperature),
               granularity=DEFAULT_GRANULARITY, chain_of_thought=False,
               model=base_model, exemplar=False)
    ]

    # Diversity recipes: temperature-OUTER, granularity-INNER, skipping the greedy
    # combo. Granularity (minimal vs guard vs whole_function) is the qualitatively
    # different, higher-impact axis, so a tight num_candidates budget spans every
    # granularity at the lowest temperature BEFORE spending budget on temperature
    # variants — otherwise guard/whole_function never run under a small budget.
    seen: set = {(DEFAULT_GRANULARITY, float(base_temperature), False)}
    idx = 1
    for t in temps:
        for g in grans:
            key = (g, float(t), cot)
            if key in seen:
                continue
            seen.add(key)
            recipes.append(Recipe(index=idx, temperature=float(t), granularity=g,
                                  chain_of_thought=cot, model=base_model,
                                  exemplar=exemplar))
            idx += 1
            if len(recipes) >= n:
                return recipes[:n]

    # Pad with extra stochastic samples (cycling the temperature ladder on the
    # default granularity) when num_candidates exceeds the distinct dim combos —
    # this is the pure best-of-N case (more samples at the same settings).
    ti = 0
    while len(recipes) < n:
        recipes.append(Recipe(index=idx, temperature=float(temps[ti % len(temps)]),
                              granularity=DEFAULT_GRANULARITY,
                              chain_of_thought=cot, model=base_model,
                              exemplar=exemplar))
        idx += 1
        ti += 1

    return recipes[:n]


def _is_number(x: Any) -> bool:
    try:
        float(x)
        return True
    except (TypeError, ValueError):
        return False


@dataclass
class Candidate:
    """A generated patch candidate, before/after oracle evaluation.

    ``generate_fn`` returns these; ``oracle`` annotates ``verdict``.
    """
    recipe: Recipe
    full_patched_file: str
    patched_function: str = ""
    syntax_valid: bool = False
    raw_response: str = ""
    patch_file: Optional[str] = None          # set once written to disk
    changes: int = 0                          # edit size proxy (e.g. sr_applied)
    metadata: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None               # set when generation failed
    verdict: Optional["Verdict"] = None       # set by the oracle


@dataclass
class Verdict:
    """Oracle outcome for one candidate (a thin, validator-agnostic view)."""
    success: bool                # passed validation outright (PoC blocked + SAST ok)
    poc_blocked: Optional[bool] = None
    sast_passed: Optional[bool] = None
    status: str = ""
    detail: Dict[str, Any] = field(default_factory=dict)


class Oracle(Protocol):
    """Anything that can judge a candidate. Production: the Phase 3 validator."""
    def evaluate(self, candidate: Candidate) -> Verdict: ...


@dataclass
class SelectionResult:
    """Outcome of a fan-out: the winner (if any) and the full trace."""
    winner: Optional[Candidate]
    candidates: List[Candidate]
    evaluated: List[Candidate]            # candidates actually sent to the oracle
    fanned_out: bool                      # True when >1 candidate was generated
    reason: str = ""

    @property
    def succeeded(self) -> bool:
        return self.winner is not None and bool(
            self.winner.verdict and self.winner.verdict.success
        )


# ---------------------------------------------------------------------------
# Pure helpers: dedup + cheap pre-filter (run before the expensive oracle)
# ---------------------------------------------------------------------------

def dedupe_candidates(candidates: List[Candidate]) -> List[Candidate]:
    """Drop candidates whose patched file is identical to an earlier one.

    Greedy and low-temperature samples frequently collapse to the same patch;
    validating duplicates wastes the (Docker-bound) oracle budget. Order is
    preserved and the first occurrence is kept.
    """
    out: List[Candidate] = []
    seen: set = set()
    for c in candidates:
        key = c.full_patched_file
        if key in seen:
            continue
        seen.add(key)
        out.append(c)
    return out


def prefilter_syntactic(candidates: List[Candidate]) -> List[Candidate]:
    """Keep only syntactically valid candidates — unless NONE are valid.

    A syntax-invalid candidate cannot build, so the oracle would only confirm a
    failure we already know. We still return the original list when every
    candidate is invalid, so the caller can record/feed-back the best failure
    rather than silently producing nothing.
    """
    valid = [c for c in candidates if c.syntax_valid and not c.error]
    return valid if valid else candidates


def _rank_key(c: Candidate) -> Tuple[int, int, int, int]:
    """Sort key for picking the best *failing* candidate (higher = better).

    Preference: PoC blocked > SAST passed > fewer changes (smaller, safer edit).
    Used only when no candidate validated outright, to choose what to keep / feed
    back to the serial feedback loop.
    """
    v = c.verdict
    poc = 1 if (v and v.poc_blocked) else 0
    sast = 1 if (v and v.sast_passed) else 0
    syn = 1 if c.syntax_valid else 0
    # Fewer changes is better -> negate so a larger key is still "better".
    return (poc, sast, syn, -c.changes)


def generate_and_select(
    recipes: List[Recipe],
    generate_fn: Callable[[Recipe], Candidate],
    oracle: Oracle,
    *,
    lazy: bool = True,
    dedupe: bool = True,
    prefilter: bool = True,
) -> SelectionResult:
    """Run the candidate fan-out and select a winner via the injected *oracle*.

    Control flow:

    * **lazy** (default): generate and evaluate the greedy recipe first; return
      immediately if it validates. Only if it fails do we generate the remaining
      recipes, dedupe/pre-filter them, and evaluate until one validates. This
      keeps cost at exactly today's level for the CVEs a single greedy patch
      already fixes, and spends the extra budget only where it is needed.
    * **eager**: generate all recipes up front, dedupe/pre-filter, then evaluate.

    When no candidate validates, ``winner`` is the best failing candidate (by
    :func:`_rank_key`) so the caller can hand it to the serial feedback loop.

    ``generate_fn`` and ``oracle`` are injected, so this function performs no LLM
    or Docker work itself and is fully unit-testable.
    """
    if not recipes:
        return SelectionResult(winner=None, candidates=[], evaluated=[],
                               fanned_out=False, reason="no recipes")

    generated: List[Candidate] = []
    evaluated: List[Candidate] = []
    # Dedup is GLOBAL across batches (greedy + fan-out), not per-batch: a fan-out
    # candidate whose patched file equals the already-validated greedy must not be
    # re-sent to the (Docker-bound) oracle.
    seen_files: set = set()

    def _consider(cands: List[Candidate]) -> Optional[Candidate]:
        """Evaluate a batch through the oracle; return the first that validates."""
        batch = cands
        if dedupe:
            fresh: List[Candidate] = []
            for c in batch:
                if c.full_patched_file in seen_files:
                    continue
                seen_files.add(c.full_patched_file)
                fresh.append(c)
            batch = fresh
        if prefilter:
            batch = prefilter_syntactic(batch)
        for cand in batch:
            cand.verdict = oracle.evaluate(cand)
            evaluated.append(cand)
            if cand.verdict and cand.verdict.success:
                return cand
        return None

    if lazy:
        # 1) Greedy first (today's single candidate).
        greedy = generate_fn(recipes[0])
        generated.append(greedy)
        winner = _consider([greedy])
        if winner is not None:
            return SelectionResult(winner=winner, candidates=generated,
                                   evaluated=evaluated, fanned_out=False,
                                   reason="greedy validated")
        # 2) Fan out the rest only on greedy failure.
        rest = [generate_fn(r) for r in recipes[1:]]
        generated.extend(rest)
        winner = _consider(rest)
        if winner is not None:
            return SelectionResult(winner=winner, candidates=generated,
                                   evaluated=evaluated,
                                   fanned_out=len(recipes) > 1,
                                   reason="diversity candidate validated")
    else:
        generated = [generate_fn(r) for r in recipes]
        winner = _consider(generated)
        if winner is not None:
            return SelectionResult(winner=winner, candidates=generated,
                                   evaluated=evaluated,
                                   fanned_out=len(recipes) > 1,
                                   reason="candidate validated")

    # No candidate validated — surface the best failing one for the feedback loop.
    pool = [c for c in evaluated] or generated
    best = max(pool, key=_rank_key) if pool else None
    return SelectionResult(winner=best, candidates=generated, evaluated=evaluated,
                           fanned_out=len(recipes) > 1, reason="no candidate validated")
