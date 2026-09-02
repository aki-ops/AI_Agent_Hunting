"""Unit and integration tests for Phase 3 (M3 Constraints and M4 Controller)."""
import pytest

from hunting.contracts.capabilities import CapabilityDescriptor, CapabilityMatcher
from hunting.contracts.cells import Cell, CellState, ProviderScope
from hunting.contracts.conflicts import Conflict
from hunting.contracts.coverage import CoverageBound, RequirementCoverage
from hunting.contracts.entities import ANY, Host
from hunting.contracts.expectations import EvidenceRequirement, Expectation, TestStatus
from hunting.contracts.explanations import Attribution, Explanation, ExplanationClass, ExplanationStatus
from hunting.contracts.observations import EpistemicType, Observation
from hunting.contracts.queries import CapabilityBinding, Diagnostic, ProviderOperation, QueryIntent
from hunting.contracts.state import DarkSource, Disposition, InvestigationState, TerminalState
from hunting.m1_ledger import ObservationLedger
from hunting.m3_constraints import (
    evaluate_cell_retry,
    is_diagnostic_retryable,
    update_explanation_contradictions,
    validate_citation_integrity,
)
from hunting.m4_controller import (
    BudgetLedger,
    FrontierManager,
    compile_query_plan,
    emit_final_account,
    evaluate_stopping,
    sample_wildcard_cells,
    select_next_action,
    split_partial_cell,
)

# ---------------------------------------------------------------------------
# Tests for Planning, Frontier, and Sampling
# ---------------------------------------------------------------------------

def test_compile_query_plan_and_unsupported_requirement():
    scope = ProviderScope("winsec", {"table": "events"}, "scope-winsec")
    op_proc = ProviderOperation("cdb_proc_scan", "winsec", ("scope-winsec",))
    binding_proc = CapabilityBinding(EvidenceRequirement.PROCESS_ANCESTRY, "winsec", "cdb_proc_scan")

    desc = CapabilityDescriptor("winsec", (scope,), (op_proc,), (binding_proc,))
    matcher = CapabilityMatcher([desc])

    # Supported requirement compiles without provider-specific branch
    query, diag = compile_query_plan(
        EvidenceRequirement.PROCESS_ANCESTRY,
        matcher,
        Host(name="HOST1"),
        "2026-09-01T10:00:00Z/2026-09-01T11:00:00Z",
    )
    assert query is not None
    assert diag is None
    assert query.intent == QueryIntent.PROCESS_LINEAGE
    assert query.operation_id == "cdb_proc_scan"

    # Unsupported requirement returns Diagnostic.UNSUPPORTED_REQUIREMENT without fabricating a query
    query_unsupported, diag_unsupported = compile_query_plan(
        EvidenceRequirement.DNS_ACTIVITY,
        matcher,
        Host(name="HOST1"),
        "2026-09-01T10:00:00Z/2026-09-01T11:00:00Z",
    )
    assert query_unsupported is None
    assert diag_unsupported == Diagnostic.UNSUPPORTED_REQUIREMENT


def test_frontier_manager_wildcard_sample_vs_instance_expand():
    scope1 = ProviderScope("cdb", {"table": "events"}, "scope1")
    scope2 = ProviderScope("ids", {"stream": "eve.json"}, "scope2")

    frontier = FrontierManager([scope1, scope2])

    # Build wildcards for known scopes
    w_cells = frontier.build_wildcards("window-01")
    assert len(w_cells) == 2
    assert all(c.is_wildcard for c in w_cells)

    # Restrict wildcard selection to SAMPLE
    sample_candidates = frontier.select_sample_candidates()
    assert len(sample_candidates) == 2

    # Add discovered instance entity (e.g. from ledger observations)
    host1 = Host(name="HOST-01")
    i_cells = frontier.add_instance_entity(host1, "window-01")
    assert len(i_cells) == 2
    assert all(not c.is_wildcard for c in i_cells)

    # Restrict entity expansion to EXPAND
    expand_candidates = frontier.select_expand_candidates()
    assert len(expand_candidates) == 2

    # ANY cannot be added as an instance entity
    with pytest.raises(ValueError):
        frontier.add_instance_entity(ANY, "window-01")


def test_provider_scope_stratified_deterministic_sampling():
    scope1 = ProviderScope("cdb", {"table": "events"}, "scope1")
    scope2 = ProviderScope("ids", {"stream": "eve.json"}, "scope2")

    c1 = Cell(scope1, ANY, "2026-09-01T10:00:00Z/2026-09-01T11:00:00Z")
    c2 = Cell(scope1, ANY, "2026-09-01T11:00:00Z/2026-09-01T12:00:00Z")
    c3 = Cell(scope2, ANY, "2026-09-01T10:00:00Z/2026-09-01T11:00:00Z")
    c4 = Cell(scope2, ANY, "2026-09-01T11:00:00Z/2026-09-01T12:00:00Z")

    candidates = [c1, c2, c3, c4]

    # Equal allocation across strata with seed reproducibility
    sampled_run1 = sample_wildcard_cells(candidates, budget=2, seed=42)
    sampled_run2 = sample_wildcard_cells(candidates, budget=2, seed=42)
    assert sampled_run1 == sampled_run2

    # Must sample across both scopes (stratified)
    sampled_scopes = {c.provider_scope.scope_id for c in sampled_run1}
    assert "scope1" in sampled_scopes
    assert "scope2" in sampled_scopes


def test_split_partial_cell_and_min_bucket_bound():
    scope = ProviderScope("cdb", {"table": "events"}, "scope1")

    # 1. Splittable cell (1 hour duration)
    cell_1h = Cell(scope, ANY, "2026-09-01T10:00:00Z/2026-09-01T11:00:00Z")
    children = split_partial_cell(cell_1h, min_bucket_seconds=300)
    assert children is not None
    left, right = children
    assert left.time_bucket == "2026-09-01T10:00:00Z/2026-09-01T10:30:00Z"
    assert right.time_bucket == "2026-09-01T10:30:00Z/2026-09-01T11:00:00Z"

    # 2. Irreducibly truncated cell (duration = 5 min = 300s <= min_bucket_seconds)
    cell_5m = Cell(scope, ANY, "2026-09-01T10:00:00Z/2026-09-01T10:05:00Z")
    no_children = split_partial_cell(cell_5m, min_bucket_seconds=300)
    assert no_children is None
    # Marked UNREACHABLE to prevent re-issuing truncated query forever
    assert cell_5m.state is CellState.UNREACHABLE


# ---------------------------------------------------------------------------
# Tests for Constraints, Budgets, and Stopping
# ---------------------------------------------------------------------------

def test_citation_integrity_and_m2_mutation_guard():
    ledger = ObservationLedger()
    scope = ProviderScope("cdb", {"table": "events"}, "scope1")
    obs = Observation(
        id="obs-real-1",
        provider_scope=scope,
        cell_id="c1",
        timestamp="2026-09-01T10:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
    )
    ledger.add_observation(obs)

    # Valid citation
    valid_expl = Explanation(
        id="exp-1",
        label="lateral-movement",
        class_=ExplanationClass.MALICIOUS,
        attributions=[Attribution(observation_id="obs-real-1", cause="wmi exec")],
    )
    validate_citation_integrity(valid_expl, ledger, actor="controller")

    # Invalid citation (cites non-existent observation)
    bad_expl = Explanation(
        id="exp-2",
        label="test",
        class_=ExplanationClass.BENIGN,
        attributions=[Attribution(observation_id="obs-ghost-999", cause="none")],
    )
    with pytest.raises(KeyError, match="non-existent observation"):
        validate_citation_integrity(bad_expl, ledger, actor="controller")

    # M2 / LLM cannot write attribution directly
    with pytest.raises(PermissionError, match="M2"):
        validate_citation_integrity(valid_expl, ledger, actor="M2")


def test_contradiction_handling_weakened_and_rejected():
    expl1 = Explanation(id="e1", label="malicious-flow", class_=ExplanationClass.MALICIOUS)
    expl2 = Explanation(id="e2", label="benign-backup", class_=ExplanationClass.BENIGN)

    exp1 = Expectation(
        id="exp-1",
        owner_explanation_id="e1",
        evidence_requirement=EvidenceRequirement.PROCESS_ANCESTRY,
        predicted_observation="cmd.exe spawned by powershell",
        entity_ref=Host(name="H1"),
        field_predicate=None,
        provider_scope_id="s1",
        time_window="w1",
        falsification_condition="none",
        test_status=TestStatus.CONFIRMED,
    )
    exp2_1 = Expectation(
        id="exp-2-1",
        owner_explanation_id="e2",
        evidence_requirement=EvidenceRequirement.AUTHENTICATION_ACTIVITY,
        predicted_observation="backup service user logon",
        entity_ref=Host(name="H1"),
        field_predicate=None,
        provider_scope_id="s1",
        time_window="w1",
        falsification_condition="none",
        test_status=TestStatus.REFUTED,
    )

    update_explanation_contradictions([expl1, expl2], [exp1, exp2_1])

    # Confirmed expectation keeps explanation LIVE
    assert expl1.status is ExplanationStatus.LIVE
    assert expl1.supported_count == 1

    # All expectations refuted -> REJECTED with preserved rejection_reason
    assert expl2.status is ExplanationStatus.REJECTED
    assert expl2.refuted_count == 1
    assert "refuted" in expl2.rejection_reason.lower()


def test_diagnostic_partition_and_retry_bound():
    scope = ProviderScope("cdb", {"table": "events"}, "scope1")
    cell = Cell(scope, ANY, "window")

    # Permanent diagnostic -> immediately UNREACHABLE
    assert is_diagnostic_retryable(Diagnostic.UNQUERYABLE) is False
    st1 = evaluate_cell_retry(cell, Diagnostic.UNQUERYABLE, retry_count=0)
    assert st1 is CellState.UNREACHABLE

    # Retryable diagnostic (QUERY_FAILED) under limit -> UNEXPLORED
    assert is_diagnostic_retryable(Diagnostic.QUERY_FAILED) is True
    st2 = evaluate_cell_retry(cell, Diagnostic.QUERY_FAILED, retry_count=1, max_retries=2)
    assert st2 is CellState.UNEXPLORED

    # Retryable diagnostic exceeding max_retries -> UNREACHABLE
    st3 = evaluate_cell_retry(cell, Diagnostic.QUERY_FAILED, retry_count=2, max_retries=2)
    assert st3 is CellState.UNREACHABLE


def test_fixed_action_order_and_budget_tracking():
    # Priority: TEST -> EXPAND -> SAMPLE
    assert select_next_action(True, True, True) == "TEST"
    assert select_next_action(False, True, True) == "EXPAND"
    assert select_next_action(False, False, True) == "SAMPLE"
    assert select_next_action(False, False, False) is None

    # Budget tracking and tainted entity rate-limiting
    budgets = BudgetLedger(t_max=15, q_max=60, n_taint=2)
    assert not budgets.is_budget_exhausted

    # Tainted entities beyond n_taint (2) are deferred, and deferred count is tracked
    tainted = [Host(name="H1"), Host(name="H2"), Host(name="H3"), Host(name="H4")]
    allowed = budgets.filter_tainted_entities(tainted)
    assert len(allowed) == 2
    assert budgets.deferred_taint_entities == 2


def test_stopping_rules_stop_resolved_vs_stop_bounded():
    state = InvestigationState(registry=None)
    budgets = BudgetLedger(t_max=15, q_max=60)

    # 1. STOP_RESOLVED: Surviving malicious explanation, zero blockers
    expl_mal = Explanation(
        id="e-mal",
        label="attack",
        class_=ExplanationClass.MALICIOUS,
        status=ExplanationStatus.LIVE,
        supported_count=3,
    )
    state.explanations = [expl_mal]

    term_state, disp, blockers = evaluate_stopping(state, budgets)
    assert term_state is TerminalState.STOP_RESOLVED
    assert disp is Disposition.MALICIOUS
    assert len(blockers) == 0

    # 2. STOP_BOUNDED: Critical dark source introduces blocking uncertainty
    state.dark_sources.append(DarkSource(source="firewall", window="w", demanded_by=["exp-1"]))
    term_bounded, disp_bounded, blockers_bounded = evaluate_stopping(state, budgets)
    assert term_bounded is TerminalState.STOP_BOUNDED
    assert disp_bounded is Disposition.INSUFFICIENT_EVIDENCE
    assert len(blockers_bounded) > 0

    # 3. STOP_BOUNDED: Unresolved evidence conflict yields CONFLICTED disposition
    state.conflicts.append(Conflict(id="conf-1", resolved=False))
    _, disp_conflict, _ = evaluate_stopping(state, budgets)
    assert disp_conflict is Disposition.CONFLICTED


def test_final_account_emission_separate_coverage():
    cb = CoverageBound(
        known_cells_wildcard=5,
        explored_cells_wildcard=5,
        requirement_coverage=RequirementCoverage(
            attempted_requirements=["process_ancestry"],
            satisfied_requirements=["process_ancestry"],
        ),
    )

    account = emit_final_account(
        disposition=Disposition.MALICIOUS,
        terminal_state=TerminalState.STOP_RESOLVED,
        coverage_bound=cb,
        residuals=[],
        human_confirmed=True,
    )
    assert account.disposition == Disposition.MALICIOUS
    assert account.terminal_state == TerminalState.STOP_RESOLVED
    assert account.human_confirmed is True
    assert account.coverage_bound.requirement_coverage.total_satisfied == 1
    assert account.coverage_bound.explored_cells_wildcard == 5


def test_mandatory_human_confirmation_enforced():
    """Regression 1: emit_final_account MUST raise PermissionError if confirmation is omitted for sensitive states."""
    cb = CoverageBound()

    # MALICIOUS requires confirmation
    with pytest.raises(PermissionError, match="Mandatory analyst confirmation required"):
        emit_final_account(
            disposition=Disposition.MALICIOUS,
            terminal_state=TerminalState.STOP_RESOLVED,
            coverage_bound=cb,
            residuals=[],
            human_confirmed=False,
        )

    # CONFLICTED requires confirmation
    with pytest.raises(PermissionError, match="Mandatory analyst confirmation required"):
        emit_final_account(
            disposition=Disposition.CONFLICTED,
            terminal_state=TerminalState.STOP_BOUNDED,
            coverage_bound=cb,
            residuals=["tie"],
            human_confirmed=False,
        )

    # All STOP_BOUNDED requires confirmation
    with pytest.raises(PermissionError, match="Mandatory analyst confirmation required"):
        emit_final_account(
            disposition=Disposition.INSUFFICIENT_EVIDENCE,
            terminal_state=TerminalState.STOP_BOUNDED,
            coverage_bound=cb,
            residuals=["budget"],
            human_confirmed=False,
        )

    # BENIGN + STOP_RESOLVED does not strictly require confirmation
    benign_acc = emit_final_account(
        disposition=Disposition.BENIGN,
        terminal_state=TerminalState.STOP_RESOLVED,
        coverage_bound=cb,
        residuals=[],
        human_confirmed=False,
    )
    assert benign_acc.human_confirmed is False

    # Providing human_confirmed=True succeeds for MALICIOUS
    confirmed_acc = emit_final_account(
        disposition=Disposition.MALICIOUS,
        terminal_state=TerminalState.STOP_RESOLVED,
        coverage_bound=cb,
        residuals=[],
        human_confirmed=True,
    )
    assert confirmed_acc.human_confirmed is True


def test_frontier_manager_instance_entity_in_multiple_windows():
    """Regression 2: FrontierManager must register cells per (entity, window), not entity alone."""
    scope1 = ProviderScope("cdb", {"table": "events"}, "scope1")
    frontier = FrontierManager([scope1])

    host = Host(name="HOST-01")

    # Window 1: creates 1 cell
    cells_w1 = frontier.add_instance_entity(host, "window_1")
    assert len(cells_w1) == 1
    assert cells_w1[0].time_bucket == "window_1"

    # Window 1 again: deduplicated, creates 0 cells
    cells_w1_dup = frontier.add_instance_entity(host, "window_1")
    assert len(cells_w1_dup) == 0

    # Window 2: same host in a NEW window MUST create 1 new cell!
    cells_w2 = frontier.add_instance_entity(host, "window_2")
    assert len(cells_w2) == 1
    assert cells_w2[0].time_bucket == "window_2"

    # Total instance cells in frontier must be 2
    assert len(frontier.instance_cells) == 2
    buckets = [c.time_bucket for c in frontier.instance_cells]
    assert buckets == ["window_1", "window_2"]

