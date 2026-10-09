"""Write a plan (and the files the executing team needs) to a directory."""
from __future__ import annotations

import json
from pathlib import Path

from hunting.plan.render import render_plan_md
from hunting.plan.schema import HuntPlan, QueryResult, ResultBundle


def result_template(plan: HuntPlan) -> ResultBundle:
    """A results file with every planned query listed as 'skipped', for the executing team to fill in."""
    return ResultBundle(
        plan_id=plan.plan_id, iteration=plan.iteration, executor="",
        results=[QueryResult(query_id=q.query_id, status="skipped") for q in plan.all_queries()],
    )


def queries_spl(plan: HuntPlan) -> str:
    lines = [
        f"// {plan.plan_id} (round {plan.iteration}) - READ-ONLY searches with placeholders.",
        "// Bind {{INDEX_*}} to your indexes; {{EARLIEST}}/{{LATEST}}/{{MAX_ROWS}} come from the plan limits.",
        "// Run coverage probes (C-*) first: an empty result is only meaningful where the source has data.",
        "",
    ]
    for q in plan.all_queries():
        lines += [f"// [{q.query_id}] ({q.role}, {q.data_source}) {q.purpose}", q.spl, ""]
    return "\n".join(lines)


def write_plan(plan: HuntPlan, directory: str | Path) -> Path:
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    (out / "plan.json").write_text(plan.model_dump_json(indent=2), encoding="utf-8")
    (out / "plan.md").write_text(render_plan_md(plan), encoding="utf-8")
    (out / "queries.spl").write_text(queries_spl(plan), encoding="utf-8")
    (out / "result.template.json").write_text(result_template(plan).model_dump_json(indent=2), encoding="utf-8")
    if plan.peak:
        (out / "peak_able.md").write_text(plan.peak.able_markdown + "\n", encoding="utf-8")
        (out / "peak_hunt_plan.md").write_text(plan.peak.hunt_plan_markdown + "\n", encoding="utf-8")
    return out


def write_schemas(directory: str | Path) -> None:
    out = Path(directory)
    out.mkdir(parents=True, exist_ok=True)
    (out / "plan.schema.json").write_text(json.dumps(HuntPlan.model_json_schema(), indent=2), encoding="utf-8")
    (out / "result.schema.json").write_text(json.dumps(ResultBundle.model_json_schema(), indent=2), encoding="utf-8")
