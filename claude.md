# Repository Working Rules (v7)

Read `context.md` first, then `docs/ARCHITECTURE.md`. The v6 engine (ClaimGraph / CapabilityGraph) was
removed; its documents live in `docs/archive/` and its code at git tag `v6-engine-final`.

---

## Invariants

- PEAK Assistant (Cisco Talos) does PEAK **Prepare**: ABLE table and hunt plan. Its output is advisory.
- **Execute** is deterministic: literal `(field, op, value)` predicates through an adapter. No LLM in matching.
- The LLM never creates or edits evidence. Judge and advisor outputs are advisory and cannot change the
  rule-computed disposition by more than one step; the advisor cannot change it at all.
- Absence of rows is never "clean" by itself: a missing telemetry source gives `COLLECT_DATA_THEN_RERUN`.
- Every recommendation has `decision_required = True`; the hunter decides, the system never acts.
- Strict field role isolation (`client_ip` ≠ `server_ip`, account ≠ person); do not bind web servers as clients.

## Documentation Integrity

- Any change to the disposition rules in `recommend.py` must update `docs/ARCHITECTURE.md` and `tests/unit/test_pipeline.py`.
- `artifacts/` is run output (git-ignored). Verified sample results are copied to `results/`.
- Never commit `.env` or secrets. `llm.py` writes only `${ENV}` placeholders into PEAK's `model_config.json`.

## Agent Autonomy & Execution Directive

- **Autonomous Proactivity**: Do not ask the user for permission, clarification, or confirmation. Always decide the optimal implementation and execute directly to completion.
