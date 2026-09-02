"""MVP Integration Scenarios verifying the complete end-to-end hunting lifecycle.

Scenarios tested:
  1. Entity-bearing alert -> instance frontier -> operation -> observation -> stub explanation -> stop.
  2. Entity-free alert -> wildcard scope cells -> BroadSweep -> entities -> instance frontier.
  3. Unknown native event -> ledger -> UNMAPPED -> abduction candidate, without false family.
  4. Partial scope scan -> PARTIAL -> cursor/split -> complete children; no parent re-issue.
  5. Empty target -> three controls -> VALID_NEGATIVE or typed uncertainty.
  6. No-adapter known scope -> UNQUERYABLE -> INSUFFICIENT_EVIDENCE contribution.
"""
from datetime import datetime, timezone

import pytest

from hunting.contracts.capabilities import CapabilityMatcher
from hunting.contracts.cells import Cell, CellState, ProviderScope
from hunting.contracts.coverage import RequirementCoverage
from hunting.contracts.entities import ANY, Account, Host
from hunting.contracts.expectations import EvidenceRequirement, FieldOp, FieldPredicate, TestStatus
from hunting.contracts.explanations import Attribution, ExplanationClass
from hunting.contracts.queries import (
    QueryIntent,
)
from hunting.contracts.state import DarkSource, Disposition, InvestigationState, TerminalState
from hunting.m1_ledger import ObservationLedger
from hunting.m1_ledger.extraction import build_observation
from hunting.m1_ledger.raw_storage import ProtectedRawStore
from hunting.m2_abduction import StubAbductionProvider, build_llm_prompt_context, validate_m2_response
from hunting.m3_constraints import update_explanation_contradictions, validate_citation_integrity
from hunting.m4_controller import (
    BudgetLedger,
    FrontierManager,
    compile_query_plan,
    emit_final_account,
    evaluate_stopping,
    split_partial_cell,
)
from hunting.m5_adapter import CdbAdapter, license_valid_negative
from hunting.m5_reporter import render_investigation_report


@pytest.fixture
def cdb_suite() -> tuple[CdbAdapter, CapabilityMatcher]:
    adapter = CdbAdapter(":memory:")
    adapter.insert_events([
        {
            "timestamp": "2026-09-01T10:14:00Z",
            "event_id": "4688",
            "native_type": "process_creation",
            "host": "HOST-01",
            "user": "alice",
            "pid": 1001,
            "ppid": 500,
            "cmdline": "powershell.exe -enc JABhID0A...",
            "image": "C:\\Windows\\System32\\powershell.exe",
        },
        {
            "timestamp": "2026-09-01T10:15:00Z",
            "event_id": "3",
            "native_type": "net_connect",
            "host": "HOST-01",
            "ip": "10.0.0.99",
            "port": 443,
        },
    ])
    desc = adapter.get_capability_descriptor()
    matcher = CapabilityMatcher([desc])
    return adapter, matcher


# ---------------------------------------------------------------------------
# Scenario 1: Entity-bearing alert -> instance frontier -> observation -> stop
# ---------------------------------------------------------------------------

def test_scenario_1_entity_bearing_alert_to_resolved_stop(cdb_suite):
    adapter, matcher = cdb_suite
    ledger = ObservationLedger()
    window = "2026-09-01T10:00:00Z/2026-09-01T11:00:00Z"

    # 1. Alert arrives bearing Host("HOST-01")
    alert_host = Host(name="HOST-01")
    frontier = FrontierManager([adapter.scope])
    frontier.add_instance_entity(alert_host, window)

    # 2. Frontier selects instance cell for EXPAND
    expand_candidates = frontier.select_expand_candidates()
    assert len(expand_candidates) == 1
    target_cell = expand_candidates[0]

    # 3. Planner compiles EvidenceRequirement.PROCESS_ANCESTRY
    query, diag = compile_query_plan(EvidenceRequirement.PROCESS_ANCESTRY, matcher, alert_host, window)
    assert query is not None and diag is None

    # 4. Adapter executes operation -> observation added to ledger
    res = adapter.execute_query(query.operation_id, alert_host, window)
    ledger.record_query_outcome(query.intent, target_cell, res)
    assert target_cell.state is CellState.EXPLORED

    raw_store = ProtectedRawStore()
    raw_ref = raw_store.store('{"host": "HOST-01", "pid": 1001, "cmdline": "powershell"}').ref_id
    obs = build_observation(

        record={"host": "HOST-01", "pid": 1001, "cmdline": "powershell"},
        provider_scope=adapter.scope,
        cell_id=target_cell.time_bucket,
        raw_ref=raw_ref,
        query_id=query.id,
        collector="cdb",
        ingest_time="2026-09-01T10:14:00Z",
    )
    ledger.add_observation(obs)


    # 5. M2 Abduction generates diverse explanations and expectations
    stub = StubAbductionProvider()
    prompt_ctx = build_llm_prompt_context(InvestigationState(registry=None), ledger, window)
    explanations, expectations = validate_m2_response(stub.generate(prompt_ctx))

    # 6. M3 Constraints validate citations and confirmed expectation
    mal_expl = next(e for e in explanations if e.class_ == ExplanationClass.MALICIOUS)
    mal_expl.attributions = [Attribution(observation_id=obs.id, cause="powershell spawned")]
    validate_citation_integrity(mal_expl, ledger)

    # Expectation tested and confirmed
    exp = expectations[0]
    exp.test_status = TestStatus.CONFIRMED
    update_explanation_contradictions(explanations, [exp])

    # 7. M4 Controller terminates as STOP_RESOLVED with confirmed disposition
    state = InvestigationState(registry=None)
    state.explanations = [mal_expl]
    budgets = BudgetLedger()
    term_state, disp, blockers = evaluate_stopping(state, budgets)

    assert term_state is TerminalState.STOP_RESOLVED
    assert disp is Disposition.MALICIOUS
    assert len(blockers) == 0

    cb = ledger.build_coverage_bound()
    cb.requirement_coverage = RequirementCoverage(
        attempted_requirements=["process_ancestry"],
        satisfied_requirements=["process_ancestry"],
    )

    account = emit_final_account(disp, term_state, cb, blockers, human_confirmed=True)
    report = render_investigation_report(account, state, ledger)
    assert "STOP_RESOLVED" in report or "stop_resolved" in report
    assert "`obs-" in report


# ---------------------------------------------------------------------------
# Scenario 2: Entity-free alert -> wildcard scope cells -> BroadSweep -> entities
# ---------------------------------------------------------------------------

def test_scenario_2_entity_free_alert_broad_sweep_to_instance_frontier(cdb_suite):
    adapter, matcher = cdb_suite
    ledger = ObservationLedger()
    window = "2026-09-01T10:00:00Z/2026-09-01T11:00:00Z"

    # 1. Entity-free alert creates finite wildcard frame alone
    frontier = FrontierManager([adapter.scope])
    wildcard_cells = frontier.build_wildcards(window)
    assert len(wildcard_cells) == 1
    w_cell = wildcard_cells[0]
    ledger.register_cell(w_cell)

    # 2. BroadSweep executes on wildcard cell
    query, _ = compile_query_plan(EvidenceRequirement.SCOPE_RECORDS, matcher, ANY, window)
    res = adapter.execute_query(query.operation_id, ANY, window)
    ledger.record_query_outcome(query.intent, w_cell, res)

    # Broad sweep complete -> scope coverage marked EXPLORED
    assert w_cell.state is CellState.EXPLORED

    # 3. Extract discovered entities from rows and feed into instance frontier
    discovered_host = Host(name=res.rows[0]["host"])
    discovered_user = Account(username=res.rows[0]["user"])

    new_instance_cells_1 = frontier.add_instance_entity(discovered_host, window)
    new_instance_cells_2 = frontier.add_instance_entity(discovered_user, window)

    assert len(new_instance_cells_1) == 1
    assert len(new_instance_cells_2) == 1
    assert len(frontier.select_expand_candidates()) == 2


# ---------------------------------------------------------------------------
# Scenario 3: Unknown native event -> ledger -> UNMAPPED -> abduction candidate
# ---------------------------------------------------------------------------

def test_scenario_3_unknown_native_event_unmapped_abduction(cdb_suite):
    adapter, _ = cdb_suite
    ledger = ObservationLedger()

    # Proprietary event with no semantic mapping
    raw_store = ProtectedRawStore()
    raw_ref = raw_store.store('{"custom_hex_id": "0x99", "host": "HOST-UNK"}').ref_id
    unknown_obs = build_observation(

        record={"custom_hex_id": "0x99", "host": "HOST-UNK"},
        provider_scope=adapter.scope,
        cell_id="c-unk",
        raw_ref=raw_ref,
        query_id="q-unk",
        collector="cdb",
        ingest_time="2026-09-01T10:00:00Z",
    )
    ledger.add_observation(unknown_obs)


    # Remains in ledger as UNMAPPED
    assert unknown_obs.is_unmapped is True
    assert unknown_obs.semantic_type is None
    assert unknown_obs in ledger.unmapped_observations

    # Prompt context includes unmapped ID for abduction
    prompt_ctx = build_llm_prompt_context(InvestigationState(registry=None), ledger)
    assert unknown_obs.id in prompt_ctx["unmapped_observation_ids"]


# ---------------------------------------------------------------------------
# Scenario 4: Partial scope scan -> PARTIAL -> split -> complete children
# ---------------------------------------------------------------------------

def test_scenario_4_partial_scope_scan_and_split(cdb_suite):
    adapter, _ = cdb_suite
    ledger = ObservationLedger()
    window = "2026-09-01T10:00:00Z/2026-09-01T11:00:00Z"

    parent_cell = Cell(adapter.scope, ANY, window)
    ledger.register_cell(parent_cell)

    # 1. Truncated query executed (limit=1)
    partial_res = adapter.execute_query("cdb_scope_scan", ANY, window, limit=1)
    ledger.record_query_outcome(QueryIntent.BROAD_SWEEP, parent_cell, partial_res)
    assert parent_cell.state is CellState.PARTIAL

    # 2. Time-split fallback
    children = split_partial_cell(parent_cell, min_bucket_seconds=300)
    assert children is not None
    left_child, right_child = children

    # 3. Store partial parent as audit split record; excluded from active coverage
    ledger.record_split_parent(parent_cell, left_child, right_child)
    cb = ledger.build_coverage_bound()
    assert cb.known_cells_wildcard == 2  # left and right children
    assert cb.partial_cells_wildcard == 1  # audit count


# ---------------------------------------------------------------------------
# Scenario 5: Empty target -> three controls -> VALID_NEGATIVE or uncertainty
# ---------------------------------------------------------------------------

def test_scenario_5_empty_target_and_negative_controls(cdb_suite):
    adapter, matcher = cdb_suite
    window = "2026-09-01T10:00:00Z/2026-09-01T11:00:00Z"
    ghost_host = Host(name="HOST-NON-EXISTENT")
    as_of = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)

    # 1. Target query for ghost host returns empty
    target_res = adapter.execute_query("cdb_process_search", ghost_host, window)
    assert len(target_res.rows) == 0
    assert target_res.complete is True

    # 2. Controls pass -> licenses VALID_NEGATIVE
    c_health = adapter.control_health(window, as_of=as_of)
    c_any = adapter.control_any_record(window)
    c_obs = adapter.control_observability(
        EvidenceRequirement.PROCESS_ANCESTRY,
        FieldPredicate("cmdline", FieldOp.EQUALS, "netcat"),
    )
    assert license_valid_negative(target_res, c_health, c_any, c_obs) is True

    # 3. Stale ingestion lag fails control -> cannot license negative
    stale_as_of = datetime(2026, 9, 1, 10, 5, 0, tzinfo=timezone.utc)
    c_stale_health = adapter.control_health(window, as_of=stale_as_of)
    assert license_valid_negative(target_res, c_stale_health, c_any, c_obs) is False


# ---------------------------------------------------------------------------
# Scenario 6: No-adapter known scope -> UNQUERYABLE -> INSUFFICIENT_EVIDENCE
# ---------------------------------------------------------------------------

def test_scenario_6_no_adapter_scope_unqueryable_insufficient_evidence():
    ledger = ObservationLedger()
    unsupported_scope = ProviderScope("legacy_siem", {"index": "legacy"}, "legacy_scope_01")
    unqueryable_cell = Cell(unsupported_scope, ANY, "window-1", state=CellState.UNQUERYABLE)

    ledger.register_cell(unqueryable_cell)

    state = InvestigationState(registry=None)
    # Critical dark source because legacy_scope_01 has no adapter
    state.dark_sources.append(DarkSource(source="legacy_scope_01", window="window-1", demanded_by=["exp-01"]))

    budgets = BudgetLedger()

    term_state, disp, blockers = evaluate_stopping(state, budgets)

    assert term_state is TerminalState.STOP_BOUNDED
    assert disp is Disposition.INSUFFICIENT_EVIDENCE
    assert any("legacy_scope_01" in b for b in blockers)

    cb = ledger.build_coverage_bound()
    assert cb.unqueryable_cells_wildcard == 1

    account = emit_final_account(disp, term_state, cb, blockers, human_confirmed=True)
    report = render_investigation_report(account, state, ledger)
    assert "Unqueryable (no adapter): 1" in report
    assert "legacy_scope_01" in report
