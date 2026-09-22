"""Freeze a SUPPORTED semantic goal graph into a reusable template.

Reads the ledger of a SUPPORTED run, strips run-specific IDs/timestamps,
and writes a template JSON that replays deterministically without LLM.
"""
import json
import sys
from pathlib import Path

src_dir = Path(sys.argv[1]) if len(sys.argv) > 1 else Path(
    "artifacts/hunt-req-20260922-022524")
out_path = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(
    "templates/joomla-web-compromise.graph.json")

graph = json.loads((src_dir / "semantic_goal_graph.json").read_text(encoding="utf-8"))
request = json.loads((src_dir / "request.json").read_text(encoding="utf-8"))

template = {
    "template_id": "tpl-joomla-web-compromise",
    "frozen_from": src_dir.name,
    "frozen_outcome": "SUPPORTED",
    "match": {
        "hypothesis_contains": ["joomla", "imreallynotbatman.com"],
    },
    "graph": {
        "objective": graph["objective"],
        "variables": graph["variables"],
        "relations": graph["relations"],
        "qualifiers": graph["qualifiers"],
        "answers": graph.get("answers", []),
        "assumptions": graph.get("assumptions", []),
        "uncertainties": graph.get("uncertainties", []),
    },
    "recommended_window": request.get("time_window"),
    "recommended_query_limit": 10000,
}
out_path.parent.mkdir(parents=True, exist_ok=True)
out_path.write_text(json.dumps(template, indent=2), encoding="utf-8")
print(f"frozen {template['template_id']} -> {out_path}", flush=True)
print(f"  relations: {[(r['subject'], r['relation'], r['object']) for r in template['graph']['relations']]}", flush=True)
