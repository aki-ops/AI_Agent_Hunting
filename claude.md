# Repository Working Rules (v7)

Read `context.md` first, then `docs/ARCHITECTURE.md`. The v6 engine (ClaimGraph / CapabilityGraph) was
removed; code and documents are in git history (`git checkout v6-engine-final`, commit `9d49fe1`).
The current direction is Prepare-only from public PoCs (`main.py plan | verify | schema`): see `docs/PREPARE-WORKFLOW.md`.
The PoC -> Execute -> Act pipeline below is kept as a local lab harness on public BOTS v1 data.

---

## Invariants

- PEAK Assistant (Cisco Talos) does PEAK **Prepare**: ABLE table and hunt plan. Its output is advisory.
- **Execute** is deterministic: literal `(field, op, value)` predicates through an adapter. No LLM in matching.
- The LLM never creates or edits evidence. Judge and advisor outputs are advisory and cannot change the
  rule-computed disposition by more than one step; the advisor cannot change it at all.
- Absence of rows is never "clean" by itself: a missing telemetry source gives `COLLECT_DATA_THEN_RERUN`.
- Every recommendation has `decision_required = True`; the hunter decides, the system never acts.
- Prepare-only workflow: never read internal systems, never run a PoC; every search an LLM writes must pass `plan/safety.py::check_spl`; results from the Execute team are verified without any LLM (`plan/verify.py`).
- Strict field role isolation (`client_ip` ≠ `server_ip`, account ≠ person); do not bind web servers as clients.

## Documentation Integrity

- Any change to the disposition rules in `recommend.py` must update `docs/ARCHITECTURE.md` and `tests/unit/test_pipeline.py`.
- `artifacts/` is run output (git-ignored). Verified sample results are copied to `results/`.
- Never commit `.env` or secrets. `llm.py` writes only `${ENV}` placeholders into PEAK's `model_config.json`.

## Agent Autonomy & Execution Directive

- **Autonomous Proactivity**: Do not ask the user for permission, clarification, or confirmation. Always decide the optimal implementation and execute directly to completion.
