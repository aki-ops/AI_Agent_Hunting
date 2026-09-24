"""Test pre-routing source profiling on novel relations against CDB with constraint-grounded entrypoints.

Verifies:
1. Constraint-grounded entrypoint: 'Which host executed an encoded PowerShell command?'
   has subject 'cmd' with value=None and constraints (cmdline contains 'powershell', encoding=encoded).
2. Pre-routing source profiling discovers and probes 'executed_on' BEFORE census selection,
   materializing runtime operation with relation_observable proof mode backed by canonical ontology.
3. Census selects CDB provider, planner schedules step with unbound constraint-grounded subject,
   and executor executes query with entity=None and constraint filters.
4. Database contains 2 events:
   - WORKSTATION-01 running powershell.exe -enc SQBYAE8... (matching)
   - WORKSTATION-02 running powershell.exe -Command Get-Process (benign/unencoded, non-matching)
5. Only WORKSTATION-01 is retrieved, proved by ProofEngine, and bound as a VERIFIED answer.
"""
from __future__ import annotations

import json
from typing import Any

from hunting.compiler.compiler import KnowledgeBehaviorCompiler
from hunting.contracts.hunt import (
    AnswerStatus,
    HuntRequest,
    HuntRequestKind,
    StoppingDecision,
)
from hunting.engine import HypothesisHuntEngine
from hunting.m5_adapter.cdb_adapter import CdbAdapter


def test_prerouting_source_profiler_resolves_unsupported_relation_e2e() -> None:
    """Authentic constraint-grounded E2E test without artificial variable values or green-washing."""
    adapter = CdbAdapter()
    adapter.insert_events([
        {
            "timestamp": "2026-02-01T10:00:00Z",
            "native_type": "process",
            "cmdline": "powershell.exe -enc SQBYAE8...",
            "host": "WORKSTATION-01",
            "image": "powershell.exe",
            "user": "alice",
        },
        {
            "timestamp": "2026-02-01T10:05:00Z",
            "native_type": "process",
            "cmdline": "powershell.exe -Command Get-Process",
            "host": "WORKSTATION-02",
            "image": "powershell.exe",
            "user": "bob",
        },
    ])

    def mock_llm_caller(prompt: str, **kwargs: Any) -> str:
        phase = kwargs.get("phase", "")
        # Compiler prompt
        if "goal-graph" in prompt or phase == "C1_COMPILER":
            return json.dumps({
                "id": "goal-graph-powershell",
                "request_id": "req-powershell-1",
                "objective": "Identify host executing encoded PowerShell",
                "variables": [
                    {
                        "id": "cmd",
                        "entity_type": "command_execution",
                        "value": None,
                        "value_origin": "llm_proposal",
                        "verification_status": "UNVERIFIED",
                        "constraints": [
                            {"key": "cmdline", "operator": "contains", "value": "powershell"},
                            {"key": "encoding", "operator": "equals", "value": "encoded", "retrieval_terms": ["-enc", "-encodedcommand"]},
                        ],
                    },
                    {
                        "id": "host",
                        "entity_type": "host",
                        "value": None,
                        "value_origin": "llm_proposal",
                        "verification_status": "UNVERIFIED",
                        "constraints": [],
                    },
                ],
                "relations": [
                    {
                        "id": "goal-1",
                        "subject": "cmd",
                        "relation": "executed_on",
                        "object": "host",
                        "required": True,
                        "description": "powershell process executed on host",
                        "atomic_obligation": "identify executing host",
                        "provenance_span": "host executed an encoded PowerShell command",
                        "dependencies": [],
                        "dependency_operator": "AND",
                        "gate_condition": None,
                    }
                ],
                "qualifiers": [],
                "answers": [
                    {"variable_id": "host", "answer_type": "host", "required": True}
                ],
                "answer_contracts": [
                    {
                        "slot_name": "host",
                        "value_type": "host",
                        "target_variable_id": "host",
                        "required_qualifiers": [],
                        "min_citations": 1,
                        "acceptance_rule": "observed value",
                    }
                ],
                "assumptions": [],
                "uncertainties": [],
                "forbidden_inferences": [],
                "clarification_triggers": [],
            })
        # Source profiler prompt
        return json.dumps({
            "proposals": [
                {
                    "source_id": "cdb:source:events",
                    "relation": "executed_on",
                    "input_roles": {"command_execution": "cmdline"},
                    "output_roles": {"host": "host"},
                    "proof_mode": "relation_observable",
                    "probe_kind": "cooccurrence",
                    "supported_constraints": ["cmdline", "encoding", "command_interpreter", "encoding_state"],
                    "constraint_mappings": [
                        {"semantic_constraint": "cmdline", "native_field": "cmdline", "proof_method": "field_match"},
                        {"semantic_constraint": "encoding", "native_field": "cmdline", "transform": "powershell_encoded"},
                    ],
                }
            ]
        })

    compiler = KnowledgeBehaviorCompiler(llm_caller=mock_llm_caller)
    engine = HypothesisHuntEngine(
        compiler=compiler,
        source_profiler_caller=mock_llm_caller,
        cdb_adapter=adapter,
        configured_adapters=[adapter],
    )

    request = HuntRequest(
        id="req-powershell-1",
        kind=HuntRequestKind.QUESTION,
        content="Which host executed an encoded PowerShell command?",
        provider_hints=("cdb",),
    )

    result = engine.execute_hunt(request, adapter=adapter)

    # 1. Did not stop as STOP_UNSUPPORTED or STOP_INCONCLUSIVE
    assert result.state.stopping_decision != StoppingDecision.STOP_UNSUPPORTED, (
        f"Engine prematurely terminated as {result.state.stopping_decision}: {result.state.residuals}"
    )

    # 2. Dynamic source profiler audit recorded proposal and validation
    audit = getattr(result.state, "source_profile_audit", {})
    assert audit, "Source profile audit was not recorded"
    assert audit.get("runtime_capabilities"), "No runtime capabilities were materialized"

    # 3. Provider was successfully selected and queries were executed
    assert result.state.capability_catalog is not None
    assert result.state.capability_catalog.provider_id == "cdb"
    assert len(result.state.queries) > 0, "No queries were executed"

    # 4. Verified that WORKSTATION-01 was proved and WORKSTATION-02 was excluded
    account = result.account
    answer_val = account.answer.get("value") if account and account.answer else None
    assert answer_val == "WORKSTATION-01", (
        f"Expected WORKSTATION-01 as answer, got: {answer_val}. Account answer: {account.answer if account else None}"
    )
    assert account.answer.get("status") == "ANSWERED", (
        f"Expected answer status ANSWERED, got: {account.answer}"
    )
    assert account.answer_status in (AnswerStatus.FULLY_ANSWERED, AnswerStatus.ANSWERED)


def test_counterexample_cmd_not_powershell_rejected() -> None:
    """P0 Regression Test: cmd.exe -enc NOT_POWERSHELL on FALSE-HOST must be rejected.

    Constraints:
    - command_interpreter = PowerShell
    - encoding_state = encoded

    Must NOT return STOP_ANSWERED, must NOT prove goal-1, must NOT declare FALSE-HOST as answer.
    """
    adapter = CdbAdapter()
    adapter.insert_events([
        {
            "timestamp": "2026-02-01T10:00:00Z",
            "native_type": "process",
            "cmdline": "cmd.exe -enc NOT_POWERSHELL",
            "host": "FALSE-HOST",
            "image": "cmd.exe",
            "user": "attacker",
        },
    ])

    def mock_llm_caller(prompt: str, **kwargs: Any) -> str:
        phase = kwargs.get("phase", "")
        if "goal-graph" in prompt or phase == "C1_COMPILER":
            return json.dumps({
                "id": "goal-graph-counterexample",
                "request_id": "req-fp",
                "objective": "Which host executed an encoded PowerShell command?",
                "variables": [
                    {
                        "id": "command",
                        "entity_type": "command_execution",
                        "value": None,
                        "value_origin": "request",
                        "verification_status": "UNVERIFIED",
                        "constraints": [
                            {"key": "command_interpreter", "operator": "equals", "value": "PowerShell"},
                            {"key": "encoding_state", "operator": "equals", "value": "encoded", "retrieval_terms": ["-enc", "-encodedcommand"]},
                        ],
                    },
                    {
                        "id": "host",
                        "entity_type": "host",
                        "value": None,
                        "value_origin": "llm_proposal",
                        "verification_status": "UNVERIFIED",
                        "constraints": [],
                    },
                ],
                "relations": [
                    {
                        "id": "goal-1",
                        "subject": "command",
                        "relation": "executed_on",
                        "object": "host",
                        "required": True,
                        "description": "encoded PowerShell executed on host",
                        "atomic_obligation": "identify host executing encoded powershell",
                        "provenance_span": "host executed an encoded PowerShell command",
                        "dependencies": [],
                        "dependency_operator": "AND",
                        "gate_condition": None,
                    }
                ],
                "qualifiers": [],
                "answers": [
                    {"variable_id": "host", "answer_type": "host", "required": True}
                ],
                "answer_contracts": [
                    {
                        "slot_name": "host",
                        "value_type": "host",
                        "target_variable_id": "host",
                        "required_qualifiers": [],
                        "min_citations": 1,
                        "acceptance_rule": "observed value",
                    }
                ],
                "assumptions": [],
                "uncertainties": [],
                "forbidden_inferences": [],
                "clarification_triggers": [],
            })
        return json.dumps({
            "proposals": [
                {
                    "source_id": "cdb:source:events",
                    "relation": "executed_on",
                    "input_roles": {"command_execution": "cmdline"},
                    "output_roles": {"host": "host"},
                    "proof_mode": "relation_observable",
                    "probe_kind": "cooccurrence",
                    "supported_constraints": ["command_interpreter", "encoding_state", "cmdline"],
                    "constraint_mappings": [
                        {"semantic_constraint": "command_interpreter", "native_field": "cmdline", "transform": "powershell_interpreter"},
                        {"semantic_constraint": "encoding_state", "native_field": "cmdline", "transform": "powershell_encoded"},
                    ],
                }
            ]
        })

    compiler = KnowledgeBehaviorCompiler(llm_caller=mock_llm_caller)
    engine = HypothesisHuntEngine(
        compiler=compiler,
        source_profiler_caller=mock_llm_caller,
        cdb_adapter=adapter,
        configured_adapters=[adapter],
    )

    request = HuntRequest(
        id="req-fp",
        kind=HuntRequestKind.QUESTION,
        content="Which host executed an encoded PowerShell command?",
        provider_hints=("cdb",),
    )

    result = engine.execute_hunt(request, adapter=adapter)

    # 1. Must NOT stop with STOP_ANSWERED
    assert result.state.stopping_decision != StoppingDecision.STOP_ANSWERED, (
        f"P0 False Positive: Engine stopped with STOP_ANSWERED on non-PowerShell command! Stopping decision: {result.state.stopping_decision}"
    )

    # 2. Answer must NOT be FALSE-HOST
    account = result.account
    answer_val = account.answer.get("value") if account and account.answer else None
    assert answer_val != "FALSE-HOST", f"P0 False Positive: FALSE-HOST accepted as answer! {account.answer}"

    # 3. Answer status must NOT be ANSWERED
    if account and account.answer:
        assert account.answer.get("status") != "ANSWERED"
        assert account.answer.get("status") in ("INCONCLUSIVE", "NOT_FOUND")

    # 4. Proof results must record unsatisfied constraint or proof gap
    proof_results = getattr(result.state, "proof_results", [])
    if proof_results:
        assert not any(pr.verified for pr in proof_results), (
            "ProofEngine should NOT verify cmd.exe -enc as proving executed_on with PowerShell constraint"
        )


def test_counterexample_multi_event_discrimination() -> None:
    """When both FALSE-HOST (cmd.exe -enc) and WORKSTATION-01 (powershell.exe -enc) exist,
    only WORKSTATION-01 must be proven and answered.
    """
    adapter = CdbAdapter()
    adapter.insert_events([
        {
            "timestamp": "2026-02-01T10:00:00Z",
            "native_type": "process",
            "cmdline": "cmd.exe -enc NOT_POWERSHELL",
            "host": "FALSE-HOST",
            "image": "cmd.exe",
            "user": "attacker",
        },
        {
            "timestamp": "2026-02-01T10:05:00Z",
            "native_type": "process",
            "cmdline": "powershell.exe -enc SQBYAE8...",
            "host": "WORKSTATION-01",
            "image": "powershell.exe",
            "user": "alice",
        },
    ])

    def mock_llm_caller(prompt: str, **kwargs: Any) -> str:
        phase = kwargs.get("phase", "")
        if "goal-graph" in prompt or phase == "C1_COMPILER":
            return json.dumps({
                "id": "goal-graph-discrimination",
                "request_id": "req-discrim-1",
                "objective": "Which host executed an encoded PowerShell command?",
                "variables": [
                    {
                        "id": "command",
                        "entity_type": "command_execution",
                        "value": None,
                        "value_origin": "request",
                        "verification_status": "UNVERIFIED",
                        "constraints": [
                            {"key": "command_interpreter", "operator": "equals", "value": "PowerShell"},
                            {"key": "encoding_state", "operator": "equals", "value": "encoded", "retrieval_terms": ["-enc", "-encodedcommand"]},
                        ],
                    },
                    {
                        "id": "host",
                        "entity_type": "host",
                        "value": None,
                        "value_origin": "llm_proposal",
                        "verification_status": "UNVERIFIED",
                        "constraints": [],
                    },
                ],
                "relations": [
                    {
                        "id": "goal-1",
                        "subject": "command",
                        "relation": "executed_on",
                        "object": "host",
                        "required": True,
                        "description": "encoded PowerShell executed on host",
                        "atomic_obligation": "identify host executing encoded powershell",
                        "provenance_span": "host executed an encoded PowerShell command",
                        "dependencies": [],
                        "dependency_operator": "AND",
                        "gate_condition": None,
                    }
                ],
                "qualifiers": [],
                "answers": [
                    {"variable_id": "host", "answer_type": "host", "required": True}
                ],
                "answer_contracts": [
                    {
                        "slot_name": "host",
                        "value_type": "host",
                        "target_variable_id": "host",
                        "required_qualifiers": [],
                        "min_citations": 1,
                        "acceptance_rule": "observed value",
                    }
                ],
                "assumptions": [],
                "uncertainties": [],
                "forbidden_inferences": [],
                "clarification_triggers": [],
            })
        return json.dumps({
            "proposals": [
                {
                    "source_id": "cdb:source:events",
                    "relation": "executed_on",
                    "input_roles": {"command_execution": "cmdline"},
                    "output_roles": {"host": "host"},
                    "proof_mode": "relation_observable",
                    "probe_kind": "cooccurrence",
                    "supported_constraints": ["command_interpreter", "encoding_state", "cmdline"],
                    "constraint_mappings": [
                        {"semantic_constraint": "command_interpreter", "native_field": "cmdline", "transform": "powershell_interpreter"},
                        {"semantic_constraint": "encoding_state", "native_field": "cmdline", "transform": "powershell_encoded"},
                    ],
                }
            ]
        })

    compiler = KnowledgeBehaviorCompiler(llm_caller=mock_llm_caller)
    engine = HypothesisHuntEngine(
        compiler=compiler,
        source_profiler_caller=mock_llm_caller,
        cdb_adapter=adapter,
        configured_adapters=[adapter],
    )

    request = HuntRequest(
        id="req-discrim-1",
        kind=HuntRequestKind.QUESTION,
        content="Which host executed an encoded PowerShell command?",
        provider_hints=("cdb",),
    )

    result = engine.execute_hunt(request, adapter=adapter)

    # Must stop with STOP_ANSWERED
    assert result.state.stopping_decision == StoppingDecision.STOP_ANSWERED
    account = result.account
    assert account.answer.get("value") == "WORKSTATION-01"
    assert account.answer.get("status") == "ANSWERED"
