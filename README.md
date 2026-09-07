# AI Agent Hunting (v5.0)

This repository implements an evidence-grounded, relation-first threat-hunting engine.
The hunting agent operates over an **Investigation Case Graph**, enforcing causal
provenance chains before querying telemetry or asserting conclusions.

---

## Core v5.0 Epistemic Paradigm

- **v4 Legacy Model**: `requirement → broad query → host/IP discovered → pivot`
- **v5.0 Relation-First Model**: `known entity → unresolved relation → valid operation → verified relation → pivot`

### The Identity-First Invariant (e.g. Amber Turing)
$$\text{Amber (Person)} \xrightarrow{\text{owns}} \text{Account} \xrightarrow{\text{logged\_on\_to}} \text{Endpoint} \xrightarrow{\text{assigned}} \text{Client IP} \xrightarrow{\text{requested}} \text{Web Activity} \xrightarrow{\text{targets}} \text{Domain}$$

**Strict Rule**: Global web traffic sweeps (`sourcetype="stream:http"`) are strictly barred
before the causal relation path $\text{Person} \rightarrow \text{Client IP}$ is proven.
Web servers (such as `jabbah` or IIS) are permanently barred from being bound as user endpoints.

---

## Canonical Documents

1. [01_FINAL-ARCHITECTURE.md](01_FINAL-ARCHITECTURE.md) — Canonical source of truth: Case Graph, Verifier, Planner.
2. [02_METHOD-AND-IMPLEMENTATION-PLAN.md](02_METHOD-AND-IMPLEMENTATION-PLAN.md) — Executable method and lifecycle.
3. [03_LITERATURE-AND-TRACEABILITY.md](03_LITERATURE-AND-TRACEABILITY.md) — External literature grounding (26 sources) and decision traceability.
4. [04-IMPLEMENTATION-CHECKLIST.md](04-IMPLEMENTATION-CHECKLIST.md) — Implementation gates and verified test checklist.
5. [docs/01-REAL-PROVIDER-SPECIFICATIONS.md](docs/01-REAL-PROVIDER-SPECIFICATIONS.md) — Provider contracts, field roles, and operations.

---

## Installation

```bash
python -m venv .venv
# Windows PowerShell
.venv\Scripts\Activate.ps1
# Linux/macOS
source .venv/bin/activate
pip install -e ".[dev]"
```

---

## Running a Threat Hunt

### Natural Language Free-Text Hypothesis
```bash
python main.py \
  --hypothesis "Amber Turing visited the website of a potential competitor to find executive contact info. What domain was it?"
```

### Deterministic Known Knowledge (CVE / TTP)
```bash
python main.py --provider cdb --cve CVE-2024-21887 --host WEB-IVANTI-01
```

---

## Running Tests

```bash
# Run unit test suite
python -m pytest tests/unit -q

# Code quality and compilation check
python -m compileall -q src main.py
ruff check .
```
