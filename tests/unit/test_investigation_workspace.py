import pytest

from hunting.contracts.lifecycle import AnalystDecision, WorkspaceRole
from hunting.workspace import InvestigationWorkspace, WorkspaceEvent


def test_workspace_keeps_graphs_separate_and_decisions_cited():
    workspace = InvestigationWorkspace("run-1", roles={"analyst": WorkspaceRole.ANALYST})
    workspace.append_annotation(WorkspaceEvent(
        event_id="annotation-1", run_id="run-1", kind="comment", actor="analyst",
        payload={"text": "inspect this row"}, citations=("obs-1",),
    ))
    workspace.append_decision(AnalystDecision(
        id="decision-1", run_id="run-1", actor="analyst", decision="select",
        citations=("obs-1",), rationale="native field match",
    ))

    snapshot = workspace.snapshot(
        observation_ids=("obs-1",),
        goal_graph={"relations": ["goal-1"]},
        evidence_graph={"edges": [], "proof": False},
        unexamined_routes=("source-2",),
    )

    assert snapshot.goal_graph != snapshot.evidence_graph
    assert snapshot.analyst_decisions[0].citations == ("obs-1",)
    assert snapshot.unexamined_routes == ("source-2",)


def test_workspace_rejects_runtime_mutation_and_cross_run_event():
    workspace = InvestigationWorkspace("run-1", roles={"analyst": WorkspaceRole.ANALYST})
    with pytest.raises(ValueError, match="cannot mutate"):
        workspace.append_annotation(WorkspaceEvent(
            event_id="bad", run_id="run-1", kind="proof", actor="model", payload={},
        ))
    with pytest.raises(ValueError, match="another run"):
        workspace.append_annotation(WorkspaceEvent(
            event_id="bad-2", run_id="run-2", kind="comment", actor="analyst", payload={},
        ))
