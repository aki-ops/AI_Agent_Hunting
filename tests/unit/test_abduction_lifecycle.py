"""Tests for M2 State-Gated Micro-Batch Abduction Lifecycle & Resilience.

Validates the 10 production invariants:
1. 30 observations with partial attribution does not trigger hot-loop on every turn.
2. No new observations prevents duplicate M2 call.
3. 5 new observations triggers exactly one abduction epoch (Trigger B).
4. Deterministic context hash prevents duplicate calls for identical state.
5. API timeout retries within bound and degrades gracefully to STOP_BOUNDED without crash.
6. Entity-free BroadSweep prompt context contains only curated delta (capped at max_observations).
7. Partial attribution keeps remaining observations unexplained in ledger without hot-looping.
8. Concluded expectations with remaining unexplained evidence triggers new epoch (Trigger D).
9. Malformed M2 response records diagnostic without mutating state.
10. max_calls hard limit strictly enforced.
"""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from hunting import InvestigationOrchestrator, InvestigationResult
from hunting.contracts.abduction import AbductionRuntime
from hunting.contracts.expectations import EvidenceRequirement, Expectation, TestStatus
from hunting.contracts.state import Alert, InvestigationState, TerminalState
from hunting.m1_ledger import ObservationLedger
from hunting.m2_abduction.policy import AbductionPolicy, AbductionPolicyConfig
from hunting.m2_abduction.prompting import build_llm_prompt_context
from hunting.m2_abduction.provider import LLMProvider
from hunting.m4_controller import BudgetLedger
from hunting.m5_adapter import CdbAdapter
from hunting.registry.loader import load_registry


@pytest.fixture
def test_registry():
    fixture_path = Path(__file__).parent.parent / "fixtures" / "registry_cdb.yaml"
    return load_registry(fixture_path)


class PartialAttributionProvider(LLMProvider):
    """Mocks an LLM that only attributes 2 observations out of any batch."""

    def __init__(self) -> None:
        self.call_count = 0

    def generate(self, prompt_context: dict[str, Any]) -> str:
        self.call_count += 1
        observations = prompt_context.get("observations", [])
        attr_ids = [o["id"] for o in observations[:2]]
        attributions_json = ", ".join(
            f'{{"observation_id": "{oid}", "cause": "suspicious activity"}}'
            for oid in attr_ids
        )
        return f"""
        {{
            "explanations": [
                {{
                    "id": "expl-{self.call_count:02d}",
                    "label": "Hypothesis from batch {self.call_count}",
                    "class_": "malicious",
                    "attributions": [{attributions_json}]
                }}
            ],
            "expectations": []
        }}
        """


class TimeoutProvider(LLMProvider):
    """Mocks an LLM that always times out."""

    def __init__(self) -> None:
        self.call_count = 0

    def generate(self, prompt_context: dict[str, Any]) -> str:
        self.call_count += 1
        raise TimeoutError("The read operation timed out after 60 seconds")


class MalformedResponseProvider(LLMProvider):
    """Mocks an LLM that returns invalid schema."""

    def __init__(self) -> None:
        self.call_count = 0

    def generate(self, prompt_context: dict[str, Any]) -> str:
        self.call_count += 1
        return "<html><body>502 Bad Gateway</body></html>"



def test_30_observations_partial_attribution_no_hot_loop(test_registry):
    """1. 30 observations, M2 attributes 2 -> not called on every subsequent turn."""
    adapter = CdbAdapter(":memory:")
    # Seed 30 events into SQLite CDB
    events = [
        {
            "timestamp": f"2026-09-01T10:{i:02d}:00Z",
            "event_id": "4688",
            "native_type": "process_creation",
            "host": f"HOST-{i:02d}",
            "user": "alice",
            "pid": 1000 + i,
            "ppid": 500,
            "cmdline": f"cmd.exe /c job_{i}",
            "image": "C:\\Windows\\System32\\cmd.exe",
        }
        for i in range(30)
    ]
    adapter.insert_events(events)

    llm = PartialAttributionProvider()
    orchestrator = InvestigationOrchestrator(
        registry=test_registry,
        adapters={"cdb_security": adapter},
        llm_provider=llm,
        budgets=BudgetLedger(t_max=8, q_max=20),
        auto_confirm_analyst=True,
    )

    alert = Alert(
        id="alt-entity-free-30",
        raw="Broad anomaly detected",
        source="cdb_security",
        received_at="2026-09-01T10:15:00Z",
        fields={},
    )
    as_of = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
    res = orchestrator.investigate(alert, as_of=as_of)

    assert isinstance(res, InvestigationResult)
    # LLM was NOT called 8 times!
    assert llm.call_count <= 2
    assert res.state.abduction_runtime.calls == llm.call_count


def test_no_new_observations_no_duplicate_call():
    """2. No new observations -> no M2 call."""
    policy = AbductionPolicy()
    state = InvestigationState(registry=None)
    runtime = AbductionRuntime(calls=1)  # Initial call already done

    should_call, reason = policy.should_call(state, runtime)
    assert should_call is False
    assert "no pending observations" in reason


def test_5_new_observations_triggers_single_epoch():
    """3. 5 new observations triggers exactly one abduction epoch."""
    policy = AbductionPolicy(AbductionPolicyConfig(min_new_observations=5))
    state = InvestigationState(registry=None)
    runtime = AbductionRuntime(calls=1)  # Past initial call

    runtime.pending_observation_ids = {"obs-1", "obs-2", "obs-3", "obs-4"}
    should_call, _ = policy.should_call(state, runtime)
    assert should_call is False  # 4 < 5

    runtime.pending_observation_ids.add("obs-5")
    should_call, reason = policy.should_call(state, runtime)
    assert should_call is True
    assert "Trigger B" in reason


def test_context_hash_deduplication():
    """4. Same pending IDs + state hash -> deduplicated, call suppressed."""
    policy = AbductionPolicy()
    state = InvestigationState(registry=None)
    runtime = AbductionRuntime(calls=1)
    runtime.pending_observation_ids = {"obs-1", "obs-2", "obs-3", "obs-4", "obs-5"}

    ctx_hash = policy.compute_context_hash(["obs-1", "obs-2", "obs-3", "obs-4", "obs-5"], state)
    runtime.last_context_hash = ctx_hash

    should_call, reason = policy.should_call(state, runtime)
    assert should_call is False
    assert "context hash unchanged" in reason


def test_api_timeout_retry_bounded_and_graceful_stop_bounded(test_registry):
    """5. API timeout -> 2 retries bounded, does not crash, degrades to STOP_BOUNDED."""
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
            "cmdline": "powershell.exe -enc abc",
            "image": "C:\\Windows\\System32\\powershell.exe",
        }
    ])

    timeout_llm = TimeoutProvider()
    orchestrator = InvestigationOrchestrator(
        registry=test_registry,
        adapters={"cdb_security": adapter},
        llm_provider=timeout_llm,
        budgets=BudgetLedger(t_max=3, q_max=5),
        auto_confirm_analyst=True,
        abduction_policy=AbductionPolicy(AbductionPolicyConfig(max_retries=2, backoff_seconds=(0.01, 0.01))),
    )

    alert = Alert(
        id="alt-timeout-test",
        raw="Suspicious execution",
        source="cdb_security",
        received_at="2026-09-01T10:14:00Z",
        fields={"host": "HOST-01"},
    )
    as_of = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)

    # Must NOT raise unhandled exception!
    res = orchestrator.investigate(alert, as_of=as_of)
    assert isinstance(res, InvestigationResult)
    # Retried 1 initial + 2 retries = 3 attempts total
    assert timeout_llm.call_count == 3
    assert res.state.abduction_runtime.failures == 1
    assert res.account.terminal_state in {TerminalState.STOP_BOUNDED, TerminalState.STOP_RESOLVED}
    assert any("m2_abduction" in g[0] for g in res.state.scope_gaps)


def test_entity_free_broadsweep_prompt_is_delta_only():
    """6. BroadSweep with 30 rows -> prompt context has at most 20 observations."""
    state = InvestigationState(registry=None)
    ledger = ObservationLedger()
    pending_ids = set()

    from hunting.contracts.cells import ProviderScope
    from hunting.contracts.observations import EpistemicType, Observation


    scope = ProviderScope(provider_id="cdb", native_partition={"table": "events"}, scope_id="cdb_security")

    for i in range(30):
        obs = Observation(
            id=f"obs-{i:03d}",
            provider_scope=scope,
            cell_id="2026-09-01T10:00:00Z/2026-09-01T11:00:00Z",
            timestamp="2026-09-01T10:14:00Z",
            epistemic_type=EpistemicType.OBSERVED,
            fields={"cmd": f"test_{i}", "host": f"HOST-{i}"},
        )
        ledger.add_observation(obs)
        pending_ids.add(obs.id)


    prompt_ctx = build_llm_prompt_context(
        state=state,
        ledger=ledger,
        pending_observation_ids=pending_ids,
        epoch=1,
        max_observations=20,
    )

    assert len(prompt_ctx["observations"]) == 20
    assert prompt_ctx["total_ledger_observations"] == 30


def test_partial_attribution_remainder_kept_unexplained_no_hot_loop(test_registry):
    """7. Partial attribution keeps remaining unexplained in ledger without hot loop."""
    adapter = CdbAdapter(":memory:")
    adapter.insert_events([
        {
            "timestamp": f"2026-09-01T10:{i:02d}:00Z",
            "event_id": "4688",
            "native_type": "process_creation",
            "host": f"HOST-{i:02d}",
            "cmdline": f"job_{i}",
        }
        for i in range(25)
    ] + [
        {
            "timestamp": "2026-09-01T10:30:00Z",
            "event_id": "3",
            "native_type": "net_connect",
            "host": "HOST-00",
            "ip": "10.0.0.1",
            "port": 443,
        }
    ])

    llm = PartialAttributionProvider()
    orchestrator = InvestigationOrchestrator(
        registry=test_registry,
        adapters={"cdb_security": adapter},
        llm_provider=llm,
        budgets=BudgetLedger(t_max=5, q_max=10),
        auto_confirm_analyst=True,
    )

    alert = Alert(
        id="alt-partial-test",
        raw="Sweep",
        source="cdb_security",
        received_at="2026-09-01T10:15:00Z",
        fields={},
    )
    as_of = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
    res = orchestrator.investigate(alert, as_of=as_of)

    # Observations in ledger > 0, unattributed observations > 0
    assert len(res.ledger.observations) > 0
    assert len(res.ledger.unattributed_observations) > 0
    # Processed observations tracked so they don't hot-loop
    assert len(res.state.abduction_runtime.processed_observation_ids) > 0


def test_all_expectations_concluded_triggers_new_epoch():
    """8. All current expectations concluded & pending evidence remains -> Trigger D."""
    policy = AbductionPolicy()
    state = InvestigationState(registry=None)
    runtime = AbductionRuntime(calls=1)
    runtime.pending_observation_ids = {"obs-new-1", "obs-new-2"}

    # Add an expectation that is still UNTESTED
    exp = Expectation(
        id="exp-01",
        owner_explanation_id="expl-01",
        evidence_requirement=EvidenceRequirement.PROCESS_ANCESTRY,
        predicted_observation="cmdline",
        entity_ref=None,
        field_predicate=None,
        provider_scope_id="default",
        time_window="2026-09-01T10:00:00Z/2026-09-01T11:00:00Z",
        falsification_condition="none",
        test_status=TestStatus.UNTESTED,
    )
    state.expectations.append(exp)

    # Suppressed while expectation is untested
    should_call, _ = policy.should_call(state, runtime)
    assert should_call is False

    # Once expectation is concluded (REFUTED/CONFIRMED):
    exp.test_status = TestStatus.REFUTED
    should_call, reason = policy.should_call(state, runtime)
    assert should_call is True
    assert "Trigger D" in reason


def test_invalid_m2_response_does_not_mutate_state(test_registry):
    """9. Malformed M2 response records diagnostic without mutating explanations."""
    adapter = CdbAdapter(":memory:")
    adapter.insert_events([
        {
            "timestamp": "2026-09-01T10:14:00Z",
            "event_id": "4688",
            "native_type": "process_creation",
            "host": "HOST-01",
            "cmdline": "test",
        }
    ])

    malformed_llm = MalformedResponseProvider()
    orchestrator = InvestigationOrchestrator(
        registry=test_registry,
        adapters={"cdb_security": adapter},
        llm_provider=malformed_llm,
        budgets=BudgetLedger(t_max=3, q_max=5),
        auto_confirm_analyst=True,
    )

    alert = Alert(
        id="alt-malformed",
        raw="test",
        source="cdb_security",
        received_at="2026-09-01T10:14:00Z",
        fields={"host": "HOST-01"},
    )
    as_of = datetime(2026, 9, 1, 12, 0, 0, tzinfo=timezone.utc)
    res = orchestrator.investigate(alert, as_of=as_of)

    assert isinstance(res, InvestigationResult)
    assert len(res.state.explanations) == 0
    assert res.state.abduction_runtime.failures >= 1
    assert any("Invalid M2 response" in g[1] for g in res.state.scope_gaps)


def test_max_calls_hard_limit_enforced():
    """10. max_calls hard limit strictly enforced."""
    policy = AbductionPolicy(AbductionPolicyConfig(max_calls_per_investigation=3))
    state = InvestigationState(registry=None)
    runtime = AbductionRuntime(calls=3)
    runtime.pending_observation_ids = {"obs-1", "obs-2", "obs-3", "obs-4", "obs-5", "obs-6"}

    should_call, reason = policy.should_call(state, runtime)
    assert should_call is False
    assert "max_calls_per_investigation reached" in reason
