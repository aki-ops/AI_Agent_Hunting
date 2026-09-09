# AI Agent Hunting (v6)

This repository implements an evidence-grounded investigation agent. It uses
three provider-neutral contracts:

```text
Request -> ClaimGraph -> CapabilityGraph -> safe query
        -> EvidenceGraph -> verified answer / explicit uncertainty
```

The runtime does not use `if email`, `if Tor`, `if CVE`, event-family or
keyword routes. Relations are created only when required by validated claims
and supported by observations.

## Canonical documents

1. [01_FINAL-ARCHITECTURE.md](01_FINAL-ARCHITECTURE.md) — architecture and boundaries.
2. [02_METHOD-AND-IMPLEMENTATION-PLAN.md](02_METHOD-AND-IMPLEMENTATION-PLAN.md) — execution and migration.
3. [03_LITERATURE-AND-TRACEABILITY.md](03_LITERATURE-AND-TRACEABILITY.md) — sources and traceability.
4. [04-IMPLEMENTATION-CHECKLIST.md](04-IMPLEMENTATION-CHECKLIST.md) — evidence-gated checklist.
5. [06-REFERENCE-ARCHITECTURE-DECISION.md](06-REFERENCE-ARCHITECTURE-DECISION.md) — detailed decision record.
6. [docs/01-REAL-PROVIDER-SPECIFICATIONS.md](docs/01-REAL-PROVIDER-SPECIFICATIONS.md) — provider contracts.

## Installation

```bash
python -m venv .venv
# Windows PowerShell
.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
```

## Running

```bash
python main.py --hypothesis "Amber Turing visited a competitor website. What domain was it?"
```

## Tests

```bash
python -m pytest tests/unit -q
python -m compileall -q src main.py
ruff check .
```
