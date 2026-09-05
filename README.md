# AI Agent Hunting

This repository implements a bounded, evidence-grounded, hypothesis-driven
threat-hunting engine. The core hunt starts from a hypothesis/TTP/IOC/CVE/CTI
question or natural-language request; it does not require an alert or a PoC.

## Current status

The verified runtime supports:

- deterministic CDB/SQLite replay;
- live Splunk REST/oneshot queries, including BOTSv1;
- semantic compilation through an explicitly configured LLM API;
- typed requirements/expectations, safe native query compilation, evidence
  cards, bounded action control, coverage-aware stopping and cost accounting.

EDR and IDS are provider extension contracts. Live EDR/IDS adapters are not
implemented in the current repository.

The canonical documents are:

- [01_FINAL-ARCHITECTURE.md](01_FINAL-ARCHITECTURE.md) — architecture;
- [02_METHOD-AND-IMPLEMENTATION-PLAN.md](02_METHOD-AND-IMPLEMENTATION-PLAN.md) — executable method;
- [03_LITERATURE-AND-TRACEABILITY.md](03_LITERATURE-AND-TRACEABILITY.md) — sources and provenance;
- [04-IMPLEMENTATION-CHECKLIST.md](04-IMPLEMENTATION-CHECKLIST.md) — tests and remaining gates;
- [docs/01-REAL-PROVIDER-SPECIFICATIONS.md](docs/01-REAL-PROVIDER-SPECIFICATIONS.md) — provider contracts.

## Installation

```bash
python -m venv .venv
# Windows PowerShell
.venv\Scripts\Activate.ps1
# Linux/macOS
source .venv/bin/activate
pip install -e ".[dev]"
```

## Local CDB replay

```bash
python scripts/seed_cdb.py
python main.py --provider cdb --cve CVE-2024-21887 --host WEB-IVANTI-01
```

Known CVE/TTP/IOC/template requests use deterministic compilation and do not
need an LLM.

## Free-text hypothesis

Free text must use the semantic compiler API. The API returns structured
hypotheses and evidence requirements; it does not execute queries.

```env
LLM_ENDPOINT=https://your-llm-service/v1/chat/completions
LLM_MODEL=your-model
LLM_API_KEY=your-api-key
LLM_TIMEOUT=30
```

```bash
python main.py --provider cdb --llm api \
  --hypothesis "Attacker compromised web www.imreallynotbatman.com"
```

The shared usage tracker enforces three calls and 12,000 total tokens by
default. It records calls, tokens, latency, model and estimated USD cost.

`--llm stub` is offline deterministic mode for structured/deterministic
requests. It does not interpret arbitrary free text; such input stops safely
as `STOP_INSUFFICIENT`. Test-only semantic fixtures are selected explicitly by
scenario in the test suite.

## Live Splunk BOTSv1

Default credentials and URL can be overridden with `SPLUNK_URL`,
`SPLUNK_USER`, `SPLUNK_PASSWORD` and `SPLUNK_INDEX`.

```bash
python main.py --provider splunk --splunk-index botsv1 --llm api \
  --hypothesis "Attacker compromised web www.imreallynotbatman.com"
```

The adapter discovers capabilities, applies the configured manifest when
available, compiles bounded SPL, preserves native fields, applies the L+1
completeness rule and reports incomplete/unreachable scopes explicitly.

## Tests

```bash
python -m pytest tests/ -q
ruff check .
python -m compileall -q src scripts main.py
```

The live Splunk tests require `https://localhost:8089` with accessible
credentials. A real LLM API run is intentionally a separate gate because it
can incur cost and must produce captured usage metadata.

## Non-negotiable invariants

- `Cell = (ProviderScope, entity | ANY, time_bucket)`; no `event_family` axis.
- Native event types and unknown records are preserved.
- Natural-language words cannot classify evidence or hypotheses.
- `search_hints` are query constraints, never evidence or confirmed Cells.
- Incomplete, unobservable, unsupported or unreachable data cannot license a
  benign conclusion.
- The LLM cannot execute queries, mutate state, select actions or determine
  final disposition.
