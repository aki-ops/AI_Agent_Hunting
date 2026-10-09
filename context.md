# AI Agent Hunting — Project Context (v7)

Read `docs/ARCHITECTURE.md` for the pipeline, the recommendation rules and known limits.

## Two workflows

1. **Prepare-only (current direction)**: `main.py plan --cve ...` -> `src/hunting/intel/` (NVD, GitHub) -> `src/hunting/plan/` (`build.py` LLM + `safety.py` checks -> `HuntPlan`) -> another team executes -> `main.py verify` (`plan/verify.py`) decides accept / pivot round. See `docs/PREPARE-WORKFLOW.md`.
2. **Lab harness** on public BOTS v1 data (below).

## Flow (lab harness)

`PoC JSON → PEAK Assistant (ABLE + hunt plan) → deterministic Execute → rules + judge + advisor → recommendation`

## Where things are

1. `src/hunting/llm.py` — `.env` → PEAK `model_config.json`; one LLM path for PEAK agents and our judge/advisor.
2. `src/hunting/prepare.py` — PEAK bridge with offline fallback.
3. `src/hunting/poc/` + `src/hunting/adapters/` — PoC model/loader, executor and the CDB adapter (the live Splunk adapter was removed after commit `4dace56`; see git history).
4. `src/hunting/recommend.py` — dispositions and confidence rules.
5. `pocs/` — BOTS v1 PoCs; `data/botsv1_eval.sqlite` (git-ignored, rebuild via `scripts/`).

## Core invariants

1. The LLM never creates evidence; observations come only from adapters.
2. Matching is literal and reproducible: same PoC + same data = same rows.
3. Missing telemetry or an unproven outcome lowers confidence; it never turns into "benign".
4. The hunter decides; every recommendation is `decision_required`.
5. Every LLM call, including PEAK's agents, is metered by `llm.UsageMeter` (SDK hook); `--token-budget` caps it.
