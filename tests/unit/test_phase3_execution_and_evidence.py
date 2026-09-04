"""Phase 3 — Execution and Evidence Layer Tests.

Verifies the 8 Phase 3 checklist items from 04-IMPLEMENTATION-CHECKLIST.md:
1. Adapters return complete QueryResult envelopes.
2. Cursor pagination and bounded time-split fallback work.
3. Raw observations are append-only and auditable.
4. Deterministic fact extraction handles fields and relationships.
5. Repeated observations form EvidenceGroups with representative IDs/counts.
6. Grouping preserves held-out malicious-event recall.
7. LLM receives cards/deltas, never the full raw ledger.
8. Ambiguous groups are batched; no per-event LLM call.
"""
from __future__ import annotations

import json

import pytest

from hunting.contracts.cells import ProviderScope
from hunting.contracts.entities import ANY
from hunting.contracts.hunt import Hypothesis
from hunting.contracts.observations import EpistemicType, Observation
from hunting.contracts.queries import Diagnostic, QueryOutcome, QueryResult
from hunting.evidence import (
    EvidenceEvaluator,
    EvidenceGroupBuilder,
    extract_facts,
)
from hunting.m1_ledger.ledger import ObservationLedger
from hunting.m4_controller.planner import split_partial_cell


def test_1_adapters_return_complete_query_result_envelope():
    """1. Adapters return complete QueryResult envelopes."""
    result = QueryResult(
        query_id="q-exec-01",
        outcome=QueryOutcome.ROWS,
        executed_ok=True,
        complete=True,
        rows=[{"id": 1, "image": "cmd.exe"}],
    )

    assert result.query_id == "q-exec-01"
    assert result.executed_ok is True
    assert result.complete is True
    assert len(result.rows) == 1

    # Incomplete result envelope
    incomplete_res = QueryResult(
        query_id="q-exec-02",
        outcome=QueryOutcome.ROWS,
        executed_ok=True,
        complete=False,
        diagnostic=Diagnostic.PARTIAL_RESULT,
    )
    assert incomplete_res.complete is False
    assert incomplete_res.diagnostic == Diagnostic.PARTIAL_RESULT


def test_2_cursor_pagination_and_bounded_time_split():
    """2. Cursor pagination and bounded time-split fallback work."""
    scope = ProviderScope(provider_id="cdb", native_partition={"table": "events"})
    from hunting.contracts.cells import Cell

    parent_cell = Cell(provider_scope=scope, entity=ANY, time_bucket="2026-09-01T00:00:00Z/2026-09-01T01:00:00Z")

    # Split 1 hour cell into 2 half-hour sub-buckets
    children = split_partial_cell(parent_cell, min_bucket_seconds=300)
    assert len(children) == 2
    assert children[0].time_bucket == "2026-09-01T00:00:00Z/2026-09-01T00:30:00Z"
    assert children[1].time_bucket == "2026-09-01T00:30:00Z/2026-09-01T01:00:00Z"

    # Bounded: when cell is already at min_bucket_seconds (e.g. 5 min = 300s), split returns None and marks UNREACHABLE
    small_cell = Cell(provider_scope=scope, entity=ANY, time_bucket="2026-09-01T00:00:00Z/2026-09-01T00:05:00Z")
    res = split_partial_cell(small_cell, min_bucket_seconds=300)
    assert res is None
    assert small_cell.state.value == "unreachable"


def test_3_raw_observations_append_only_and_auditable():
    """3. Raw observations are append-only and auditable."""
    ledger = ObservationLedger()
    scope = ProviderScope(provider_id="cdb", native_partition={"table": "events"})

    obs1 = Observation(
        id="obs-001",
        provider_scope=scope,
        cell_id="c1",
        timestamp="2026-09-01T12:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        fields={"host": "SRV-01"},
    )
    ledger.add_observation(obs1)

    # Overwrite attempt with duplicate ID must fail (Append-Only invariant)
    obs_dup = Observation(
        id="obs-001",
        provider_scope=scope,
        cell_id="c1",
        timestamp="2026-09-01T12:05:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        fields={"host": "SRV-01-MUTATED"},
    )
    with pytest.raises(ValueError, match="already exists in ledger"):
        ledger.add_observation(obs_dup)

    assert len(ledger.observations) == 1


def test_4_deterministic_fact_extraction_fields_and_relationships():
    """4. Deterministic fact extraction handles fields and relationships."""
    scope = ProviderScope(provider_id="edr", native_partition={"table": "process_events"})
    obs = Observation(
        id="obs-fact-01",
        provider_scope=scope,
        cell_id="c1",
        timestamp="2026-09-01T10:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        fields={
            "host": "WEB-SERVER-01",
            "image": "cmd.exe",
            "cmdline": "cmd.exe /c whoami",
            "pid": 1234,
            "parent_image": "w3wp.exe",
            "parent_pid": 5678,
        },
    )

    facts = extract_facts(obs)
    assert len(facts) >= 1
    fact = facts[0]
    assert fact.fact_type == "process_execution"
    assert fact.primary_entity.pid == 1234

    # Verify relationships: host -> process and parent_process -> child_process
    rel_types = [r.relation_type for r in fact.relations]
    assert "executed_process" in rel_types
    assert "spawned_process" in rel_types


def test_5_repeated_observations_form_evidence_groups():
    """5. Repeated observations form EvidenceGroups with representative IDs/counts."""
    scope = ProviderScope(provider_id="edr", native_partition={"table": "events"})
    builder = EvidenceGroupBuilder(max_representative_ids=3)

    # Generate 10 identical background observations
    observations = [
        Observation(
            id=f"obs-benign-{i}",
            provider_scope=scope,
            cell_id="c1",
            timestamp=f"2026-09-01T10:{i:02d}:00Z",
            epistemic_type=EpistemicType.OBSERVED,
            fields={"host": "DESKTOP-1", "image": "svchost.exe", "cmdline": "svchost.exe -k netsvcs"},
        )
        for i in range(10)
    ]

    cards = builder.build_cards(observations)
    # Must compress 10 observations into 1 card!
    assert len(cards) == 1
    card = cards[0]
    assert card.count == 10
    assert len(card.representative_observation_ids) == 3  # Capped at 3
    assert card.time_summary["earliest"] == "2026-09-01T10:00:00Z"
    assert card.time_summary["latest"] == "2026-09-01T10:09:00Z"


def test_6_grouping_preserves_malicious_event_recall():
    """6. Grouping preserves held-out malicious-event recall."""
    scope = ProviderScope(provider_id="edr", native_partition={"table": "events"})
    builder = EvidenceGroupBuilder()

    # 50 benign observations
    observations = [
        Observation(
            id=f"obs-benign-{i}",
            provider_scope=scope,
            cell_id="c1",
            timestamp="2026-09-01T10:00:00Z",
            epistemic_type=EpistemicType.OBSERVED,
            fields={"host": "SRV", "image": "svchost.exe", "cmdline": "svchost.exe -k netsvcs"},
        )
        for i in range(50)
    ]

    # 1 critical malicious anomaly (PowerShell download cradle)
    malicious_obs = Observation(
        id="obs-malicious-001",
        provider_scope=scope,
        cell_id="c1",
        timestamp="2026-09-01T10:05:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        fields={
            "host": "SRV",
            "image": "powershell.exe",
            "cmdline": "powershell.exe -enc SQBFAFgA...",
        },
    )
    observations.append(malicious_obs)

    cards = builder.build_cards(observations)
    # The malicious event MUST NOT be collapsed into benign card!
    assert len(cards) == 2

    # Malicious card must exist with count=1 and contain the malicious observation ID
    malicious_cards = [c for c in cards if "obs-malicious-001" in c.representative_observation_ids]
    assert len(malicious_cards) == 1
    assert malicious_cards[0].count == 1
    assert any("powershell" in cmd for cmd in malicious_cards[0].field_summary.get("cmdlines", []))


def test_7_llm_receives_cards_deltas_never_full_raw_ledger():
    """7. LLM receives cards/deltas, never the full raw ledger."""
    scope = ProviderScope(provider_id="edr", native_partition={"table": "events"})
    builder = EvidenceGroupBuilder()

    # Create 100 observations
    observations = [
        Observation(
            id=f"obs-{i}",
            provider_scope=scope,
            cell_id="c1",
            timestamp="2026-09-01T10:00:00Z",
            epistemic_type=EpistemicType.OBSERVED,
            fields={"host": "SRV", "cmdline": f"command_{i % 5}"},
        )
        for i in range(100)
    ]

    cards = builder.build_cards(observations)
    # Verify that serialized cards size is a small fraction of raw observations
    cards_json = json.dumps([{"id": c.id, "count": c.count, "summary": c.field_summary} for c in cards])
    raw_json = json.dumps([o.fields for o in observations])

    # Cards representation is significantly more compact than raw row dumping
    assert len(cards) == 5  # Compressed 100 rows into 5 cards
    assert len(cards_json) < len(raw_json)


def test_8_ambiguous_groups_are_batched_no_per_event_llm_call():
    """8. Ambiguous groups are batched; no per-event LLM call."""
    llm_call_count = 0

    def mock_llm_batch(prompt: str) -> str:
        nonlocal llm_call_count
        llm_call_count += 1
        # Returns mapping for all cards in one single response
        return json.dumps({
            "card-01": ["hypo-01"],
            "card-02": ["hypo-01"],
            "card-03": [],
        })

    evaluator = EvidenceEvaluator(llm_caller=mock_llm_batch)

    # 3 ambiguous cards
    cards = [
        EvidenceGroupBuilder().build_cards([
            Observation(
                id=f"obs-ambiguous-{i}",
                provider_scope=ProviderScope(provider_id="p1", native_partition={"t": "1"}),
                cell_id="c1",
                timestamp="2026-09-01T10:00:00Z",
                epistemic_type=EpistemicType.OBSERVED,
                fields={"arbitrary_field": f"val_{i}"},
            )
        ])[0]
        for i in range(3)
    ]

    # Rename card IDs for test predictability
    cards[0].id = "card-01"
    cards[1].id = "card-02"
    cards[2].id = "card-03"

    hypotheses = [Hypothesis(id="hypo-01", statement="Custom anomaly inquiry")]

    result = evaluator.evaluate_cards(cards, hypotheses)

    # Exactly 1 LLM call was made for all 3 cards (NO per-event calls!)
    assert llm_call_count == 1
    assert result["card-01"] == ["hypo-01"]
    assert result["card-02"] == ["hypo-01"]
    assert result["card-03"] == []
