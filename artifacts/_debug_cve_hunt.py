from hunting.contracts.entities import Host
from hunting.contracts.hunt import HuntRequest, HuntRequestKind
from hunting.engine import HypothesisHuntEngine
from hunting.m5_adapter.cdb_adapter import CdbAdapter

cdb = CdbAdapter()
cdb.insert_events([
    {
        "timestamp": "2026-02-01T10:00:00Z",
        "native_type": "process_creation",
        "host": "WEB-IVANTI-01",
        "user": "root",
        "pid": 4123,
        "cmdline": "python -c import socket",
        "image": "/usr/bin/python3",
        "status": "SUCCESS",
    },
    {
        "timestamp": "2026-02-01T10:01:00Z",
        "native_type": "file_modification",
        "host": "WEB-IVANTI-01",
        "user": "root",
        "file_path": "/home/etc/manifest/webshell.py",
        "action": "CREATE",
        "pid": 4123,
        "status": "SUCCESS",
    },
])
engine = HypothesisHuntEngine(cdb_adapter=cdb)
result = engine.execute_hunt(
    HuntRequest(
        id="hunt-req-cve-21887",
        kind=HuntRequestKind.CVE,
        content="CVE-2024-21887",
        entities=[Host(name="WEB-IVANTI-01")],
    ),
    adapter=cdb,
    time_window="2026-02-01T00:00:00Z/P1D",
)
print("hypos", [(h.id, str(h.status)) for h in result.account.hypotheses])
print("cards", len(result.account.evidence_cards))
print("queries", len(result.state.queries))
print("stop", result.state.stopping_decision)
sa = result.state.semantic_analysis or {}
print("unresolved", sa.get("unresolved_reasons"))
print("executed", sa.get("executed_steps"))
print("variables", sa.get("variables") or result.state.semantic_analysis)
from dataclasses import asdict, is_dataclass
# executions live on semantic analysis
print("analysis keys", sorted(sa.keys()))
print("bindings", sa.get("binding_provenance"))
print("step_actions", sa.get("step_actions"))
for q in result.state.queries:
    params = getattr(q, "parameters", {}) or {}
    print("Q", getattr(q, "operation_id", None), "intent", (params.get("query_intent") or {}) if isinstance(params, dict) else None)
    print("  native", params.get("native_query") if isinstance(params, dict) else None)
    print("  last?", getattr(q, "native_query", None))
