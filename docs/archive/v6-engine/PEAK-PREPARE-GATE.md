# PEAK Prepare — mandatory gate on every hunt entrypoint

Splunk SURGe's PEAK process starts with **Prepare**: before any hunt runs it
must declare a topic, an ABLE model (Actor, Behavior, Location, Evidence), a
scope, a max duration and a plan. This tool now enforces that Prepare step on
**every** hunt entrypoint, not just the PoC path.

## What is gated

| Entrypoint | Flags | Prepare enforced |
|---|---|---|
| PoC-driven hunt | `--poc`, `--poc-file`, `--poc-chain` | Yes (pre-existing) |
| Hypothesis engine | `--hypothesis`, `--cve`, `--ttp`, `--ioc`, `--query`, `--threat-actor`, `--campaign` | Yes (new) |
| Baseline (EDA) | `--baseline` | Yes (new) |
| M-ATH (API-assisted) | `--math` | Yes (new) |
| Alert (legacy) | `--alert`, `--host`, ... | No — alert triage has no hypothesis to prepare |

The gate runs **before** the environment audit / provider setup, so a hunt
without a valid Prepare never contacts a telemetry provider.

## How the gate resolves a Prepare plan

Resolution order (first match wins):

1. `--skip-prepare` — bypass the gate. The run proceeds with no recorded
   Prepare plan. Use only for tests or a deliberate ad-hoc run.
2. `--hunt-plan <file>` — load an explicit YAML/JSON plan. An **incomplete**
   explicit plan is a hard error (exit 2): if you ask for a plan it must be a
   valid PEAK plan.
3. Otherwise the gate **derives** a minimal, complete Prepare plan from the
   hunt inputs (the objective, entities, scope and time window you already
   passed). Every derived field is explicit and printed, so an analyst can see
   exactly what was assumed. If there is no objective to derive from, the gate
   blocks (exit 2).

On success the resolved Prepare is printed:

```text
[+] [PREPARE] PEAK Prepare ready: topic='...' scope='...' max_duration='14d' (source=derived from hunt inputs)
```

The `max_duration` doubles as the PEAK hunt deadline and is derived from the
time-window span when one is supplied.

## Examples

```bash
# Derived Prepare (normal hunt, no plan file needed):
python main.py --provider cdb --db data/botsv1_eval.sqlite \
  --ttp T1190 --time-window "2016-08-10T00:00:00Z/2016-08-11T00:00:00Z"

# Explicit Prepare plan:
python main.py --provider cdb --db data/cdb_sample.sqlite \
  --hypothesis "..." --hunt-plan configs/hunt_plan.example.yaml

# Bypass (tests / ad-hoc only):
python main.py --provider cdb --db data/cdb_sample.sqlite \
  --baseline cdb:events --skip-prepare
```

## Where it lives in code

- `src/hunting/peak.py` — `derive_prepare_plan()` builds the plan;
  `missing_prepare_fields_from_plan()` validates it against the PEAK checklist
  (`_REQUIRED` + `research_refs`).
- `src/hunting/cli.py` — `resolve_prepare_gate()` is the shared resolver; it is
  called at the top of the baseline, M-ATH and hypothesis-engine dispatches.
- The PoC path keeps its existing gate (`enforce_prepare=True` →
  `missing_prepare_fields()` → `PrepareError`).
