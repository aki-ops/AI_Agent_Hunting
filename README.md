# AI Agent Hunting

Research prototype for an **Evidence-Grounded Progressive Hunt Graph** agent.

## Status

The v9 architecture is accepted as the target design but is not fully integrated or empirically validated. The current unit suite includes legacy behavior and isolated component tests; live and end-to-end claims must be checked against `04-IMPLEMENTATION-CHECKLIST.md`.

## Target flow

```text
Question / hypothesis / alert / PoC / CTI / TTP / IOC / CVE / scheduled hunt
  -> RequestContract + SearchEnvelope
  -> SemanticGoalGraph + OutcomeContract proposal
  -> Semantic Acceptance Gate
  -> explicit AND/OR/GATE obligation planning
  -> progressive capability discovery
  -> controlled CandidateSet binding or user clarification
  -> typed EvidenceAction / QueryIntent
  -> bounded provider execution
  -> Observation -> FieldFact -> CandidateRelation
  -> executable ProofContract
  -> deterministic recovery and stopping
  -> grounded report and machine run account
```

The LLM proposes interpretation and actions. It cannot verify evidence, select ambiguous entities, broaden scope or stop the hunt.

## Documentation

Read in this order:

1. `01_FINAL-ARCHITECTURE.md` — sole normative architecture;
2. `02_METHOD-AND-IMPLEMENTATION-PLAN.md` — runtime method;
3. `03_LITERATURE-AND-TRACEABILITY.md` — research basis and claim limits;
4. `04-IMPLEMENTATION-CHECKLIST.md` — honest implementation status;
5. `08-EVIDENCE-BASED-REARCHITECTURE-PLAN.md` — detailed migration plan;
6. `06-REFERENCE-ARCHITECTURE-DECISION.md` — v9 decision record;
7. `05-SCIENTIFIC-ARCHITECTURE-REVIEW.md` and `07-STRATEGIC-RESEARCH-REVIEW.md` — reviews;
8. `docs/01-REAL-PROVIDER-SPECIFICATIONS.md` — provider boundary.

Generated `report.md`, `artifacts/` and `baseline_reports/` are not architecture sources.

## Current verification

```powershell
python -m pytest -q
python -m compileall -q src main.py
ruff check src tests
```

Do not interpret a green test suite as v9 completion unless the P0 integration and executable evaluation gates in `04` pass.

## CLI

```powershell
python main.py --llm api --hypothesis "<question or hunt hypothesis>"
```

Provider configuration and secrets belong in `.env` or deployment-specific configuration. Never commit API keys or credentials.

