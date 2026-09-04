"""Unit tests for Phase 5 — reporting and coverage.

Verifies:
1. Scope coverage is separate from requirement coverage.
2. Targeted query never implies full scope coverage.
3. NO_EVIDENCE_FOUND is never rendered as BENIGN.
4. Final account cites request, hypothesis, cards, observations, queries, diagnostics, residuals, and coverage.
5. Report distinguishes not found, not observable, unqueryable, and unknown source.
"""
from __future__ import annotations

from hunting.contracts.cells import Cell, CellState, ProviderScope
from hunting.contracts.coverage import CoverageBound
from hunting.contracts.entities import AnyEntity, Host
from hunting.contracts.hunt import (
    EvidenceCard,
    EvidenceRequirementV4,
    HuntObjective,
    HuntRequestKind,
    HuntState,
    Hypothesis,
    HypothesisOrigin,
    HypothesisStatus,
    QueryPlan,
    RequirementStatus,
    StoppingDecision,
    TimePolicy,
)
from hunting.contracts.observations import EpistemicType, Observation
from hunting.m1_ledger.ledger import ObservationLedger
from hunting.reporter import build_final_hunt_account, render_final_hunt_account


def test_scope_coverage_separate_from_requirement_coverage():
    """Item 1: Scope coverage is accounted strictly separately from requirement coverage."""
    scope = ProviderScope(provider_id="sqlite-cdb", native_partition={"table": "events"})

    # 2 wildcard cells, 2 instance cells
    cell_wc1 = Cell(provider_scope=scope, entity=AnyEntity(), time_bucket="2026-02-01T00:00:00Z/P1D", state=CellState.EXPLORED)
    cell_wc2 = Cell(provider_scope=scope, entity=AnyEntity(), time_bucket="2026-02-02T00:00:00Z/P1D", state=CellState.UNEXPLORED)
    cell_inst1 = Cell(provider_scope=scope, entity=Host(name="SRV-01"), time_bucket="2026-02-01T00:00:00Z/P1D", state=CellState.EXPLORED)
    cell_inst2 = Cell(provider_scope=scope, entity=Host(name="SRV-02"), time_bucket="2026-02-01T00:00:00Z/P1D", state=CellState.UNQUERYABLE)

    # 3 requirements
    req1 = EvidenceRequirementV4(id="req-proc", description="Process execution", evidence_type="process", status=RequirementStatus.VALIDATED)
    req2 = EvidenceRequirementV4(id="req-net", description="Network connection", evidence_type="network", status=RequirementStatus.VALIDATED)
    req3 = EvidenceRequirementV4(id="req-dns", description="DNS lookup", evidence_type="dns", status=RequirementStatus.UNSUPPORTED)

    card = EvidenceCard(id="card-1", fingerprint="fp-1", fact_type="process", count=1)

    state = HuntState(
        objective=HuntObjective(request_id="req-hunt-1", statement="Hunt for TTPs"),
        cells=[cell_wc1, cell_wc2, cell_inst1, cell_inst2],
        requirements=[req1, req2, req3],
        evidence_cards=[card],
    )

    account = build_final_hunt_account(state)

    # Scope coverage checks
    assert account.coverage_bound.known_cells_wildcard == 2
    assert account.coverage_bound.explored_cells_wildcard == 1
    assert account.coverage_bound.unexplored_cells_wildcard == 1

    assert account.coverage_bound.known_cells_instance == 2
    assert account.coverage_bound.explored_cells_instance == 1
    assert account.coverage_bound.unqueryable_cells_instance == 1

    # Requirement coverage checks
    assert account.coverage_bound.requirement_coverage is not None
    assert set(account.coverage_bound.requirement_coverage.attempted_requirements) == {"req-proc", "req-net", "req-dns"}
    assert set(account.coverage_bound.requirement_coverage.satisfied_requirements) == {"req-proc", "req-net"}
    assert set(account.coverage_bound.requirement_coverage.unsupported_requirements) == {"req-dns"}

    # Rendered report check
    report = render_final_hunt_account(account)
    assert "### Scope Coverage (Spatial-Temporal Partition Cells)" in report
    assert "#### Wildcard Cells (BroadSweep / Population):" in report
    assert "#### Instance Cells (Discovered Concrete Entities):" in report
    assert "### Requirement Coverage (Behavioral TTPs)" in report
    assert "Active Scope Coverage Ratio:" in report
    assert "Requirement Satisfaction Ratio:" in report


def test_targeted_query_never_implies_full_scope_coverage():
    """Item 2: Targeted query on a concrete entity never marks wildcard cells explored."""
    scope = ProviderScope(provider_id="sqlite-cdb", native_partition={"table": "events"})

    # Wildcard cell remains UNEXPLORED
    cell_wc = Cell(provider_scope=scope, entity=AnyEntity(), time_bucket="2026-02-01T00:00:00Z/P1D", state=CellState.UNEXPLORED)
    # Targeted instance cell explored
    cell_inst = Cell(provider_scope=scope, entity=Host(name="DB-01"), time_bucket="2026-02-01T00:00:00Z/P1D", state=CellState.EXPLORED)

    targeted_query = QueryPlan(
        id="q-targeted-1",
        requirement_id="req-auth",
        provider_id="sqlite-cdb",
        scope_id="scope-1",
        operation_id="find_logins",
        is_targeted=True,
    )

    state = HuntState(
        objective=HuntObjective(request_id="req-hunt-2"),
        cells=[cell_wc, cell_inst],
        queries=[targeted_query],
    )

    account = build_final_hunt_account(state)

    # Invariant: Wildcard explored count must remain 0
    assert account.coverage_bound.explored_cells_wildcard == 0
    assert account.coverage_bound.explored_cells_instance == 1

    report = render_final_hunt_account(account)
    # Verify the note is present and active scope ratio does not claim 100%
    assert "Targeted queries on specific entities do NOT" in report
    assert account.coverage_bound.scope_coverage_denominator == 2
    assert "1 / 2 active cells (50.0%)" in report


def test_no_evidence_found_is_never_rendered_as_benign():
    """Item 3: When zero attack evidence is found, report emits NO_EVIDENCE_FOUND and NEVER BENIGN."""
    scope = ProviderScope(provider_id="sqlite-cdb", native_partition={"table": "events"})
    cell = Cell(provider_scope=scope, entity=AnyEntity(), time_bucket="2026-02-01T00:00:00Z/P1D", state=CellState.EXPLORED)

    hyp = Hypothesis(
        id="hyp-cve-2024-21887",
        statement="Ivanti Connect Secure command injection",
        origin=HypothesisOrigin.RULE,
        status=HypothesisStatus.LIVE,
    )

    state = HuntState(
        objective=HuntObjective(
            request_id="req-hunt-clean",
            statement="Proactive sweep for Ivanti exploitation",
            time_policy=TimePolicy(start="2026-02-01T00:00:00Z", end="2026-02-02T00:00:00Z"),
        ),
        cells=[cell],
        hypotheses=[hyp],
        evidence_cards=[],  # Zero cards found
        stopping_decision=StoppingDecision.STOP_BOUNDED,
    )

    account = build_final_hunt_account(state)
    report = render_final_hunt_account(account)

    # Outcome check
    assert "NO_EVIDENCE_FOUND" in report
    assert "**Investigation Outcome:** `NO_EVIDENCE_FOUND`" in report

    # Invariant: The word "BENIGN" must NEVER appear as disposition or verdict in the report
    assert "Disposition: BENIGN" not in report
    assert "Outcome: BENIGN" not in report
    # Even more strictly: the only place "BENIGN" is mentioned is in the warning forbidding it
    assert "This result is strictly **NOT** a finding of `BENIGN`" in report
    assert "BENIGN" not in [h.status.value for h in account.hypotheses]


def test_final_account_full_citations():
    """Item 4: Final account cites request, hypothesis, cards, observations, queries, diagnostics, residuals, and coverage."""
    ledger = ObservationLedger()
    scope = ProviderScope(provider_id="sqlite-cdb", native_partition={"table": "events"})
    obs1 = Observation(
        id="obs-101",
        provider_scope=scope,
        cell_id="cell-1",
        timestamp="2026-02-01T12:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        fields={"image": "cmd.exe", "command_line": "cmd.exe /c whoami"},
        entities=[Host(name="DMZ-01")],
    )
    obs2 = Observation(
        id="obs-102",
        provider_scope=scope,
        cell_id="cell-1",
        timestamp="2026-02-01T12:01:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        fields={"dest_ip": "198.51.100.4", "dest_port": 443},
        entities=[Host(name="DMZ-01")],
    )
    ledger.add_observation(obs1)
    ledger.add_observation(obs2)

    hyp1 = Hypothesis(
        id="hyp-webshell",
        statement="Adversary dropped webshell",
        origin=HypothesisOrigin.RULE,
        status=HypothesisStatus.SUPPORTED,
        requirements=["req-shell"],
        source_refs=["CVE-2024-21887"],
    )
    hyp2 = Hypothesis(
        id="hyp-admin-maint",
        statement="Legitimate admin maintenance",
        origin=HypothesisOrigin.RULE,
        status=HypothesisStatus.REFUTED,
    )

    card = EvidenceCard(
        id="card-exec-01",
        fingerprint="fp-exec-cmd",
        fact_type="process",
        count=1,
        completeness="complete",
        entity_summary={"host": "DMZ-01"},
        field_summary={"observation_ids": ["obs-101"]},
    )

    query = QueryPlan(
        id="q-exec-01",
        requirement_id="req-shell",
        provider_id="sqlite-cdb",
        scope_id="scope-main",
        operation_id="find_cmd_execution",
        completeness_contract="complete",
    )

    scope = ProviderScope(provider_id="sqlite-cdb", native_partition={"table": "events"})
    cell = Cell(provider_scope=scope, entity=AnyEntity(), time_bucket="2026-02-01T00:00:00Z/P1D", state=CellState.EXPLORED)

    state = HuntState(
        objective=HuntObjective(
            request_id="req-hunt-cite",
            kind=HuntRequestKind.CVE,
            statement="Investigate CVE-2024-21887",
            entities=[Host(name="DMZ-01")],
            time_policy=TimePolicy(start="2026-02-01T00:00:00Z", end="2026-02-02T00:00:00Z"),
        ),
        cells=[cell],
        hypotheses=[hyp1, hyp2],
        evidence_cards=[card],
        queries=[query],
        stopping_decision=StoppingDecision.STOP_RESOLVED,
    )

    account = build_final_hunt_account(
        state,
        ledger=ledger,
        residuals=["Uncertainty in parent process ancestry."],
        diagnostics=[{"name": "PARTIAL_TRUNCATION", "diagnostic_class": "Warning", "details": "Capped at 100 rows"}],
    )

    # Verify structured citations
    assert account.request_id == "req-hunt-cite"
    assert "hyp-webshell" in account.supporting
    assert "hyp-admin-maint" in account.contradicting
    assert "obs-101" in account.observation_citations
    assert "obs-102" in account.observation_citations
    assert any(q["query_id"] == "q-exec-01" for q in account.queries)
    assert any(d["name"] == "PARTIAL_TRUNCATION" for d in account.diagnostics)
    assert "Uncertainty in parent process ancestry." in account.residuals

    # Verify rendered markdown citations
    report = render_final_hunt_account(account)
    assert "req-hunt-cite" in report
    assert "`hyp-webshell`" in report
    assert "`hyp-admin-maint`" in report
    assert "`card-exec-01`" in report
    assert "`obs-101`" in report
    assert "`obs-102`" in report
    assert "`q-exec-01`" in report
    assert "PARTIAL_TRUNCATION" in report
    assert "Uncertainty in parent process ancestry." in report


def test_gap_breakdown_distinguishes_four_categories():
    """Item 5: Report distinguishes not found, not observable, unqueryable, and unknown source."""
    scope = ProviderScope(provider_id="sqlite-cdb", native_partition={"table": "events"})

    # 1. Unqueryable cell
    cell_unq = Cell(provider_scope=scope, entity=AnyEntity(), time_bucket="2026-02-01T00:00:00Z/P1D", state=CellState.UNQUERYABLE)
    # Explored cell
    cell_exp = Cell(provider_scope=scope, entity=AnyEntity(), time_bucket="2026-02-02T00:00:00Z/P1D", state=CellState.EXPLORED)

    # 2. Not observable requirement
    req_unobs = EvidenceRequirementV4(
        id="req-tls-payload",
        description="TLS unencrypted payload inspection",
        evidence_type="tls",
        status=RequirementStatus.UNSUPPORTED,
    )
    # 3. Not found requirement (attempted and valid scope, but 0 hits)
    req_not_found = EvidenceRequirementV4(
        id="req-c2-beacon",
        description="Outbound periodic beaconing",
        evidence_type="network",
        status=RequirementStatus.PROPOSED,
    )

    cov = CoverageBound(
        unknown_sources=["external_syslog_firewall_192.168.1.254"],  # 4. Unknown source
    )

    state = HuntState(
        objective=HuntObjective(request_id="req-hunt-gaps"),
        cells=[cell_unq, cell_exp],
        requirements=[req_unobs, req_not_found],
        coverage=cov,
    )

    account = build_final_hunt_account(state)
    gaps = account.gap_breakdown

    # Category 1: Not observable
    assert any("req-tls-payload" in item for item in gaps["not_observable"])

    # Category 2: Unqueryable
    assert any("unqueryable" in item.lower() or "adapter unsupported" in item.lower() for item in gaps["unqueryable"])

    # Category 3: Not found
    assert any("req-c2-beacon" in item for item in gaps["not_found"])

    # Category 4: Unknown source
    assert "external_syslog_firewall_192.168.1.254" in gaps["unknown_source"]

    # Invariant: Unknown source is strictly outside scope coverage denominator
    assert "external_syslog_firewall_192.168.1.254" not in str(account.coverage_bound.scope_coverage_denominator)
    assert account.coverage_bound.scope_coverage_denominator == 2  # 1 unqueryable + 1 explored

    # Rendered report breakdown
    report = render_final_hunt_account(account)
    assert "## 5. Visibility & Gap Breakdown" in report
    assert "### 1. Not Found (Queried with Complete Coverage, Zero Findings)" in report
    assert "### 2. Not Observable (Telemetry Lacks Required Behavioral Fields)" in report
    assert "### 3. Unqueryable (Adapter Unsupported, Permission Denied, or Syntax Error)" in report
    assert "### 4. Unknown Source (Unmapped / Unregistered Telemetry, Excluded from Denominator)" in report

    assert "external_syslog_firewall_192.168.1.254" in report
    assert "req-tls-payload" in report
    assert "req-c2-beacon" in report
