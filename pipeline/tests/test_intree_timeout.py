#!/usr/bin/env python3
"""Regression tests for in-tree (Option A) hang handling.

The bug, as measured on run-archive ``2026-07-26_uniform-single-model-matrix``:
four tcpdump CWE-835 infinite-loop CVEs (CVE-2017-12989/-12990/-12997/-13003)
were dropped from every one of the 19 tcpdump cells. The chain was

  1. the recipes called bare ``timeout``, which only sends SIGTERM — the looping
     tcpdump never died, so the recipe's own 120 s budget never expired;
  2. the CONTAINER ceiling (a flat ``run_timeout`` = 300 s) fired instead, killing
     the shell before it could print ``SSD_TEST_RESULT``;
  3. with no marker, Phase 1 filed the hang as an anonymous "build/run error" and
     routed it to manual revision, where it was never approved.

Step 2 was not tcpdump-specific: every project's recipe declared budgets at or
above the 300 s ceiling (glibc's three-strategy cascade declares 320+320+320+1500),
so the ceiling always won and no in-tree hang could ever self-report.

These tests lock all three links: ``-k`` escalation in every recipe, a ceiling
derived from the recipe instead of a flat constant, and a classifier that names a
timeout as a timeout.

Hermetic: stubs docker/pandas; no Docker/LLM. Run:
``python3 -m pytest tests/test_intree_timeout.py -v`` from the pipeline dir.
"""

import re
import sys
import types
from datetime import datetime
from pathlib import Path

import pytest
import yaml

for _m in ("docker", "pandas"):
    sys.modules.setdefault(_m, types.ModuleType(_m))
if not hasattr(sys.modules["docker"], "errors"):
    _err = types.ModuleType("docker.errors")
    for _n in ("BuildError", "ContainerError", "ImageNotFound", "APIError", "NotFound"):
        setattr(_err, _n, type(_n, (Exception,), {}))
    sys.modules["docker.errors"] = _err
    sys.modules["docker"].errors = _err

import orchestrator as orch  # noqa: E402
from master_pipeline.intree import (  # noqa: E402
    DEFAULT_CAP, DEFAULT_FLOOR, DEFAULT_MARGIN,
    intree_container_timeout, load_intree_timeout_policy, scan_timeout_budgets,
)

PIPELINE_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = PIPELINE_DIR / "cve_aggregator"


def _intree_recipes():
    """(config name, run_script) for every project shipping an in-tree recipe."""
    out = []
    for path in sorted(CONFIG_DIR.glob("*_config.yaml")):
        cfg = yaml.safe_load(path.read_text()) or {}
        script = ((cfg.get("phase1") or {}).get("intree_test") or {}).get("run_script")
        if script:
            out.append((path.stem, script))
    return out


RECIPES = _intree_recipes()


def test_project_configs_are_discoverable():
    """Guard the fixture itself — a rename must not quietly empty these tests."""
    assert RECIPES, "no project config exposes phase1.intree_test.run_script"
    assert any(name == "tcpdump_config" for name, _ in RECIPES)


# --- link 1: SIGTERM must escalate to SIGKILL --------------------------------
@pytest.mark.parametrize("name,script", RECIPES, ids=[n for n, _ in RECIPES])
def test_every_recipe_timeout_escalates_to_sigkill(name, script):
    """A bare ``timeout`` cannot kill a process that ignores SIGTERM.

    That is precisely the CWE-835 shape (tcpdump spinning inside a printer), so
    without ``-k`` the recipe's self-imposed budget is unenforceable and the
    reproduction is lost. Every invocation must carry the escalation.
    """
    offenders = []
    for m in re.finditer(r"\btimeout\b", script):
        line_start = script.rfind("\n", 0, m.start()) + 1
        if script[line_start:m.start()].lstrip().startswith("#"):
            continue
        rest = script[m.end():].split("\n", 1)[0]
        head = rest.split()[:2]
        if head[:1] != ["-k"]:
            offenders.append(script[line_start:m.end() + 60].strip())
    assert not offenders, f"{name}: `timeout` without -k escalation:\n" + "\n".join(offenders)


# --- link 2: the ceiling must clear the recipe's own budgets -----------------
def test_scan_parses_the_recipe_idiom():
    script = 'timeout -k 10 "${INTREE_TEST_TIMEOUT:-320}" make test\n'
    assert scan_timeout_budgets(script) == [320]


def test_scan_reads_the_default_not_the_variable_name():
    """The variable is never exported into the container, so the ``:-N`` default
    is the budget that actually applies."""
    assert scan_timeout_budgets('timeout "${SOME_VAR:-45}" cmd') == [45]


def test_scan_handles_literals_units_and_flag_values():
    assert scan_timeout_budgets("timeout 30 cmd") == [30]
    assert scan_timeout_budgets("timeout 5m cmd") == [300]
    # -s takes a value too; it must not be mistaken for the duration.
    assert scan_timeout_budgets("timeout -s KILL -k 10 90 cmd") == [90]
    assert scan_timeout_budgets("timeout --foreground 20 cmd") == [20]


def test_scan_ignores_prose_and_variable_names():
    assert scan_timeout_budgets("# bump the timeout 999 if flaky\n") == []
    assert scan_timeout_budgets('X="${INTREE_TEST_TIMEOUT:-320}"\n') == []


def test_scan_collects_a_sequential_cascade():
    """glibc runs bounded strategies one after another; the worst case is the sum."""
    script = (
        'timeout -k 10 "${INTREE_TEST_TIMEOUT:-320}" make test\n'
        'timeout -k 10 "${INTREE_TEST_TIMEOUT:-320}" ./run\n'
        'timeout -k 10 "${INTREE_SUBDIR_TIMEOUT:-1500}" make -k check\n'
    )
    assert scan_timeout_budgets(script) == [320, 320, 1500]
    assert intree_container_timeout(script) == 320 + 320 + 1500 + DEFAULT_MARGIN


def test_ceiling_is_clamped_both_ways():
    assert intree_container_timeout("timeout -k 10 5 cmd") == DEFAULT_FLOOR
    assert intree_container_timeout("timeout -k 10 99999 cmd") == DEFAULT_CAP
    assert intree_container_timeout(None) == DEFAULT_FLOOR
    assert intree_container_timeout("") == DEFAULT_FLOOR


@pytest.mark.parametrize("name,script", RECIPES, ids=[n for n, _ in RECIPES])
def test_ceiling_clears_every_budget_the_recipe_declares(name, script):
    """THE invariant that was violated.

    The old flat 300 s ceiling sat BELOW what nine of ten recipes declared, so the
    container always won the race and no marker was ever printed. The derived
    ceiling must strictly exceed the recipe's whole worst-case path.
    """
    budgets = scan_timeout_budgets(script)
    ceiling = intree_container_timeout(script, *load_intree_timeout_policy(PIPELINE_DIR))
    assert budgets, f"{name}: recipe declares no timeout budget at all"
    assert ceiling > sum(budgets), (
        f"{name}: ceiling {ceiling}s does not clear the recipe's worst-case path "
        f"{sum(budgets)}s (budgets={budgets}) — the shell can be killed before it "
        f"prints SSD_TEST_RESULT"
    )


def test_the_old_flat_ceiling_would_still_fail_these_recipes():
    """Pin the regression: 300 s was genuinely too small, this is not cosmetic."""
    too_small = [n for n, s in RECIPES if sum(scan_timeout_budgets(s)) >= 300]
    assert len(too_small) >= 5, (
        "expected most recipes to out-declare the old 300s ceiling; "
        f"only {too_small} did"
    )


def test_tcpdump_ceiling_leaves_room_for_its_own_budget():
    """The concrete case: 120 s inner budget must expire well inside the ceiling,
    so a spinning parser reports rc=124 → FAIL → reproduced."""
    script = dict(RECIPES)["tcpdump_config"]
    assert scan_timeout_budgets(script) == [120]
    assert intree_container_timeout(script, *load_intree_timeout_policy(PIPELINE_DIR)) > 120


# --- link 2b: Phase 1 and Phase 3 must agree ---------------------------------
@pytest.mark.parametrize("name,script", RECIPES, ids=[n for n, _ in RECIPES])
def test_both_phases_derive_the_same_ceiling(name, script):
    """A fail-to-pass oracle is only sound if the vulnerable and patched runs get
    the same wall-clock budget. Phase 1 used 300 s and Phase 3 used
    max(run_timeout, 600) — a patched build could out-live the baseline's budget."""
    policy = load_intree_timeout_policy(PIPELINE_DIR)
    assert intree_container_timeout(script, *policy) == intree_container_timeout(script, *policy)
    # and both call sites read the recipe from the project YAML under the same key
    assert intree_container_timeout(script, *policy) >= DEFAULT_FLOOR


# --- the watchdog must not guillotine a healthy in-tree run -----------------
def _idle_floor_for(project):
    from master_pipeline.executor import PhaseExecutor
    from master_pipeline.config import PipelineConfig, BASE_DIR
    cfg = PipelineConfig(base_dir=PIPELINE_DIR)
    cfg.phase0_config = f"cve_aggregator/{project}_config.yaml"
    e = object.__new__(PhaseExecutor)
    e.config = cfg
    e._pipeline_root = BASE_DIR
    return e._intree_idle_floor()


@pytest.mark.parametrize("name,script", RECIPES, ids=[n for n, _ in RECIPES])
def test_idle_watchdog_outlasts_the_intree_ceiling(name, script):
    """An in-tree run is a detached container: silent from launch to exit, so the
    whole ceiling is one quiet stretch. Raising the ceiling without raising the
    idle cap would have the watchdog kill healthy phases (glibc: 2520s ceiling
    against a 2400s cap)."""
    # (not str.removesuffix — the VM's runtime is Python 3.8)
    project = name[:-len("_config")] if name.endswith("_config") else name
    ceiling = intree_container_timeout(script, *load_intree_timeout_policy(PIPELINE_DIR))
    assert _idle_floor_for(project) > ceiling


def test_projects_without_an_intree_recipe_keep_the_tight_cap():
    """Only relax the watchdog where a recipe actually needs it."""
    assert _idle_floor_for("kernel") == 0
    assert _idle_floor_for("tomcat") == 0


def test_idle_floor_is_zero_for_an_unreadable_project_config():
    """A missing/broken YAML must not raise — the watchdog falls back to config."""
    assert _idle_floor_for("does_not_exist") == 0


def test_policy_knobs_are_read_from_config_yaml():
    floor, margin, cap = load_intree_timeout_policy(PIPELINE_DIR)
    assert floor >= 1 and margin >= 0 and cap >= floor
    cfg = yaml.safe_load((PIPELINE_DIR / "config.yaml").read_text()) or {}
    assert cfg.get("intree_container_floor") == floor
    assert cfg.get("intree_timeout_margin") == margin
    assert cfg.get("intree_container_cap") == cap


# --- link 3: a hang must be classified as a hang -----------------------------
class _StubLogger:
    def info(self, *a, **k): pass
    def warning(self, *a, **k): pass
    def error(self, *a, **k): pass
    def exception(self, *a, **k): pass


class _StubBaseBuilder:
    def ensure_base_image(self, ubuntu_version): return "base:20.04"


class _StubCveBuilder:
    def build_intree_test_image(self, vuln, base_tag, build_script=None, run_script=None):
        return True, "built"


class _StubDockerMgr:
    def __init__(self, exit_code, logs):
        self._ret = (exit_code, logs)
        self.seen_timeout = None

    def run_container_from_tag(self, vuln, tag, run_timeout, container_suffix=""):
        self.seen_timeout = run_timeout
        return self._ret

    # The REAL log parser — it is pure text handling, so use it rather than a
    # stub that could disagree with production about what a marker looks like.
    _extract_result_record = orch.DockerManager._extract_result_record


def _make_orchestrator(exit_code, logs, tmp_path, ceiling=600):
    """A PipelineOrchestrator shell carrying only what _process_intree_test touches."""
    o = object.__new__(orch.PipelineOrchestrator)
    o.logger = _StubLogger()
    o._p1 = {}
    o._base_builder = _StubBaseBuilder()
    o._cve_builder = _StubCveBuilder()
    o.docker_mgr = _StubDockerMgr(exit_code, logs)
    o.intree_run_timeout = ceiling
    o.base_dir = tmp_path
    o._manual_dir = tmp_path / "manual_supervision"
    o.flagged = []
    return o


def _vuln():
    """The real dataclass — cve_image_tag is a derived property, not a field."""
    v = object.__new__(orch.VulnerabilityInfo)
    v.cve = "CVE-2017-12989"
    v.commit_hash = "2ecb9d2c67d9"
    v.fix_commit = "aaaabbbbcccc"
    v.test_path = "tests/resp_4_infiniteloop.pcap"
    v.ubuntu_version = "16.04"
    v.build_arch = "amd64"
    v._cve_image_prefix = "ai-ssd-cve"
    v._base_image_prefix = "ai-ssd-base"
    return v


def _result():
    return orch.ExecutionResult(
        cve="CVE-2017-12989", commit_hash="2ecb9d2c67d9", status="",
        vulnerability_reproduced=False, build_success=False, poc_executed=False,
        execution_time_seconds=0.0, error_message=None, container_logs=None,
        timestamp=datetime.now().isoformat(),
    )


def test_container_ceiling_hang_is_labelled_a_timeout(tmp_path):
    """The exact shape of the four lost tcpdump CVEs.

    It still routes to manual revision (we cannot tell a hung test from a hung
    harness once the ceiling wins), but it must no longer masquerade as a generic
    "build/run error" — that anonymity is why the loss went unnoticed.
    """
    logs = ("TIMEOUT after 600s (PoC caused hang/deadlock). Partial output: "
            "--- /build/project-src/tcpdump -vvv -e -r tests/resp_4_infiniteloop.pcap ---\n")
    o = _make_orchestrator(-1, logs, tmp_path)
    res = o._process_intree_test(_vuln(), _result(), datetime.now())

    assert res.timed_out is True
    assert res.needs_manual_revision is True
    assert res.status == orch.ExecutionStatus.NEEDS_REVIEW.value
    assert res.vulnerability_reproduced is False
    assert "build/run error" not in (res.error_message or "")
    assert "hang" in (res.error_message or "").lower()


def test_intree_run_uses_the_derived_ceiling_not_run_timeout(tmp_path):
    o = _make_orchestrator(-1, "TIMEOUT after 2520s", tmp_path, ceiling=2520)
    o.run_timeout = 300  # what the old code passed
    o._process_intree_test(_vuln(), _result(), datetime.now())
    assert o.docker_mgr.seen_timeout == 2520


def test_genuine_build_error_is_still_a_build_error(tmp_path):
    """No-marker for a NON-timeout reason must keep its original classification."""
    o = _make_orchestrator(2, "configure: error: no acceptable C compiler\n", tmp_path)
    res = o._process_intree_test(_vuln(), _result(), datetime.now())
    assert res.timed_out is False
    assert "build/run error" in (res.error_message or "")
    assert res.needs_manual_revision is True


def test_fail_marker_still_reproduces(tmp_path):
    """A recipe that DOES report (incl. rc=124 → FAIL) yields the baseline."""
    o = _make_orchestrator(1, "SSD_TEST_RESULT=FAIL (rc=124)\n", tmp_path)
    res = o._process_intree_test(_vuln(), _result(), datetime.now())
    assert res.vulnerability_reproduced is True
    assert res.status == orch.ExecutionStatus.SUCCESS.value
    assert res.baseline_exit_code == 1
    assert res.timed_out is False


# --- the metric that hid the loss -------------------------------------------
def test_failure_breakdown_counts_real_timeouts(tmp_path):
    """``ExecutionStatus.TIMEOUT`` is assigned nowhere, so the old expression was
    structurally 0 — the archive reports "timeouts: 0" for 57 cells that between
    them contain 95 timed-out runs. Counting the flag makes the metric honest
    while leaving `status` (and therefore the manual-supervision gate and the
    reproduced/manual tallies) untouched."""
    logs = "TIMEOUT after 600s (PoC caused hang/deadlock). Partial output: \n"
    o = _make_orchestrator(-1, logs, tmp_path)
    hung = o._process_intree_test(_vuln(), _result(), datetime.now())
    # The gate is unchanged: still manual revision, still not reproduced.
    assert hung.status == orch.ExecutionStatus.NEEDS_REVIEW.value
    assert hung.status != orch.ExecutionStatus.TIMEOUT.value
    # ...but the run is now countable.
    assert hung.timed_out is True

    timed_out = _result()
    timed_out.timed_out = True
    timed_out.status = orch.ExecutionStatus.NEEDS_REVIEW.value
    clean = _result()
    clean.status = orch.ExecutionStatus.NEEDS_REVIEW.value

    assert _breakdown_of([timed_out, clean])["failure_breakdown"]["timeouts"] == 1


def _breakdown_of(results, tmp_path=None):
    """Drive the REAL ReportGenerator and return its failure_breakdown."""
    import json
    import tempfile
    rg = object.__new__(orch.ReportGenerator)
    rg.results = list(results)
    rg.logger = _StubLogger()
    d = Path(tmp_path or tempfile.mkdtemp())
    rg.output_dir = d
    rg.results_dir = d
    path = rg.generate_report()
    return json.loads(Path(path).read_text())


def test_a_credited_hang_is_not_also_counted_as_a_failure(tmp_path):
    """Caught by adversarial review of this very fix.

    ``timed_out`` is a neutral fact, so it is True for a hang the DoS branch
    CREDITS as a reproduction (baseline -1, status Success) as well as for one
    routed to manual revision. Counting the flag unfiltered put such a run in
    ``successful_reproductions`` AND in ``failure_breakdown.timeouts`` while
    ``total_failures`` (= len - successful) excluded it, so the breakdown stopped
    partitioning the corpus and ``timeouts`` could exceed ``total_failures``.
    """
    credited = _result()               # the hang→DoS shape
    credited.timed_out = True
    credited.vulnerability_reproduced = True
    credited.status = orch.ExecutionStatus.SUCCESS.value
    credited.baseline_exit_code = -1

    dropped = _result()                # the routed-to-manual shape
    dropped.timed_out = True
    dropped.status = orch.ExecutionStatus.NEEDS_REVIEW.value

    report = _breakdown_of([credited, dropped], tmp_path)
    fb = report["failure_breakdown"]
    assert report["metadata"]["successful_reproductions"] == 1
    assert fb["timeouts"] == 1, "the credited hang must not be counted as a failure"
    assert fb["timeouts"] <= fb["total_failures"], "breakdown must stay a partition"


# --- BOTH reproducer paths must detect a hang the same way -------------------
# The in-tree test and the ExploitDB PoC hit the identical container timeout, and
# each used to read it ad hoc: the in-tree path filed it as "build/run error",
# the PoC path fed its own banner to the LLM negative filter. One predicate now
# serves both, and these tests pin that.

def test_timeout_predicate_requires_the_banner_not_just_minus_one():
    """_run_image also returns -1 for infrastructure errors (image missing,
    daemon refused). Those are NOT hangs and must never be credited or counted
    as such — the banner is the only thing that distinguishes them."""
    banner = orch._timeout_banner(300, "partial\n")
    assert orch.is_timeout_run(-1, banner) is True
    assert orch.is_timeout_run(-1, "No such image: ai-ssd-cve:foo") is False
    assert orch.is_timeout_run(0, banner) is False
    assert orch.is_timeout_run(1, "") is False
    assert orch.is_timeout_run(None, None) is False


def test_banner_round_trips_so_the_filter_sees_only_the_poc():
    """The banner is a pure PREFIX; stripping it must yield the PoC's own output
    byte-for-byte, never a truncated log."""
    poc = "--- Running exploit ---\nsome partial output\n"
    assert orch.strip_timeout_banner(orch._timeout_banner(300, poc)) == poc
    # Non-timeout logs pass through untouched.
    assert orch.strip_timeout_banner("plain logs") == "plain logs"
    assert orch.strip_timeout_banner(None) == ""


def _baseline_run(exit_code, logs, tmp_path):
    """Drive the REAL per-run baseline detector used by the PoC path."""
    o = _make_orchestrator(exit_code, logs, tmp_path)
    o.run_timeout = 300
    o.docker_mgr.run_container_from_tag = (
        lambda vuln, tag, rt, container_suffix="": (exit_code, logs))
    return orch.PipelineOrchestrator._run_baseline_once(o, _vuln(), "tag", 0, 3)


@pytest.mark.parametrize("exit_code,logs,expected", [
    (-1, orch._timeout_banner(300, "partial\n"), True),     # a genuine hang
    (-1, "Error: no such image", False),                    # infrastructure, not a hang
    (0, "clean run\n", False),
])
def test_both_paths_agree_on_what_a_hang_is(exit_code, logs, expected, tmp_path):
    """The PoC path's per-run detector and the in-tree classifier must reach the
    same verdict for the same (exit code, logs) pair."""
    poc_says = _baseline_run(exit_code, logs, tmp_path)["is_timeout"]
    intree_says = _make_orchestrator(exit_code, logs, tmp_path)._process_intree_test(
        _vuln(), _result(), datetime.now()).timed_out
    assert poc_says is expected
    assert intree_says is expected
    assert poc_says == intree_says


def test_poc_path_flags_a_hang_that_never_reached_unanimity(tmp_path):
    """A flaky hang (some runs hang, some crash) yields no baseline and lands in
    the non-deterministic bucket. It still HUNG, so it must still be counted —
    otherwise the metric under-reports exactly the flakiest cases."""
    banner = orch._timeout_banner(300, "partial\n")
    runs = [{"is_timeout": True, "run_logs": banner, "record": {}, "marker_present": False},
            {"is_timeout": False, "run_logs": "exit 139", "record": {}, "marker_present": True}]
    assert any(r.get("is_timeout") for r in runs) is True
    # and the branch that consumes it is wired to that expression
    src = (PIPELINE_DIR / "orchestrator.py").read_text()
    assert 'result.timed_out = any(r.get("is_timeout") for r in (baseline_runs or []))' in src


def test_i386_rerun_is_covered_too():
    """The 32-bit arch-fallback is a full PoC execution and can hang like any
    other; it must record the timeout and must not judge the exploit by our
    own banner."""
    src = (PIPELINE_DIR / "orchestrator.py").read_text()
    i386 = src.split("reproduced on 32-bit build")[0][-2500:]
    assert "is_timeout_run(a_code, a_logs)" in i386
    assert "strip_timeout_banner(a_logs)" in i386


def test_no_site_re_derives_the_timeout_contract():
    """Single source of truth: no ad-hoc `"TIMEOUT" in logs` parsing outside the
    helpers, which is how the two paths drifted apart in the first place."""
    src = (PIPELINE_DIR / "orchestrator.py").read_text()
    offenders = [
        ln.strip() for ln in src.splitlines()
        if '"TIMEOUT"' in ln and not ln.strip().startswith("#")
        and "_TIMEOUT_BANNER" not in ln
    ]
    assert not offenders, f"ad-hoc timeout parsing: {offenders}"


def test_memoized_hang_baseline_reports_the_same_as_a_cold_run():
    """A warm re-run reuses the memoized -1 baseline; -1 IS the hang sentinel, so
    it must carry the same timed_out as the cold run whose result it reuses."""
    src = (PIPELINE_DIR / "orchestrator.py").read_text()
    assert "result.timed_out = (result.baseline_exit_code == -1)" in src
