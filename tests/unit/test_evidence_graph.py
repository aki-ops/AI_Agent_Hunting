from hunting.contracts.cells import ProviderScope
from hunting.contracts.observations import EpistemicType, Observation
from hunting.evidence.evidence_graph import EvidenceGraph


def _observation(obs_id: str, host: str, cmdline: str) -> Observation:
    return Observation(
        id=obs_id,
        provider_scope=ProviderScope("cdb", {"dataset": "test"}, "scope"),
        cell_id="cell-1",
        timestamp="2026-02-01T10:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        native_type="process_creation",
        fields={"host": host, "image": "powershell.exe", "cmdline": cmdline, "pid": 7},
        query_id="q-1",
    )


def test_evidence_graph_preserves_native_observation_and_provenance() -> None:
    graph = EvidenceGraph.from_observations([_observation("o-1", "HOST-1", "powershell -enc x")])
    obs = graph.nodes["observation:o-1"]
    assert obs.payload["native_fields"]["host"] == "HOST-1"
    assert obs.payload["query_id"] == "q-1"
    assert any(edge.edge_type == "observed_transition" for edge in graph.edges.values())
    assert all(edge.proof_status == "NOT_PROOF" for edge in graph.edges.values())
    assert graph.to_dict()["proof_note"]


def test_evidence_graph_does_not_overwrite_conflicting_facts() -> None:
    graph = EvidenceGraph()
    graph.append_observation(_observation("o-1", "HOST-1", "powershell -enc x"))
    graph.append_observation(_observation("o-2", "HOST-2", "powershell -enc x"))
    assert set(graph.observation_ids) == {"o-1", "o-2"}
    assert len([node for node in graph.nodes.values() if node.node_type == "observation"]) == 2


def test_evidence_graph_merges_provenance_for_same_entity() -> None:
    graph = EvidenceGraph.from_observations([
        _observation("o-1", "HOST-1", "powershell -enc x"),
        _observation("o-2", "HOST-1", "powershell -enc y"),
    ])
    entity_nodes = [node for node in graph.nodes.values() if node.node_type == "entity"]
    assert entity_nodes
    assert {"o-1", "o-2"}.issubset(set(entity_nodes[0].provenance_ids))
