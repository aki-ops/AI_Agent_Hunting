# AI Agent Hunting

[![Tests](https://img.shields.io/badge/tests-100%20passed-brightgreen.svg)]()
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)]()
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)]()

**AI Agent Hunting** is a deterministic, evidence-grounded, human-in-the-loop threat investigation agent architecture. It provides mathematically bounded, auditable, and replayable cyber threat investigations without trusting generative models to execute actions or compute outcomes.

---

## 📖 Key Architectural Principles

1. **M4 Controller in Strict Control**: The LLM (M2 Abduction Engine) is treated as an untrusted hypothesis generator. The LLM never makes queries, mutates investigation state, controls actions, evaluates stopping conditions, or determines the final disposition.
2. **The Universal Cell Model**: A unit of telemetry addressability is strictly:
   $$\text{Cell} = (\text{ProviderScope}, \text{entity} \mid \text{ANY}, \text{time\_bucket})$$
   There is **no** artificial `event_family` axis. Known scopes without an adapter are explicitly tracked as `UNQUERYABLE` coverage gaps.
3. **Negative Evidence Licensing**: Absence of evidence only refutes a hypothesis if three independent control queries pass:
   - **`ScopeHealthControl`**: Telemetry ingestion lag is bounded and provider is operational.
   - **`AnyRecordInScope`**: Telemetry exists in the target partition (sensor is active).
   - **`PredicateObservabilityControl`**: The queried fields are actively extracted and observable.
4. **Non-Erasure & Taint Propagation**: Unknown native event types are preserved as valid observations (`semantic_type = None`). Attacker-influenced alert fields are deterministically tainted and cannot exhaust investigation budgets.
5. **Separate Coverage Accounting**: Investigation accounts explicitly partition:
   - **Wildcard Coverage** (known partition cells explored via `BroadSweep` / `SAMPLE`).
   - **Instance Coverage** (cells discovered via entity pivot `EXPAND`).
   - **Requirement Coverage** (evidence requirement satisfaction & attempted query audit).
6. **Mandatory Analyst Confirmation**: High-impact states (`MALICIOUS`, `CONFLICTED`, `STOP_BOUNDED`) enforce analyst confirmation before a final disposition is emitted.

---

## 🚀 Quickstart Guide

### 1. Installation

```bash
git clone https://github.com/aki-ops/AI_Agent_Hunting.git
cd AI_Agent_Hunting

python -m venv .venv
# On Windows PowerShell:
.venv\Scripts\Activate.ps1
# On Linux / macOS:
source .venv/bin/activate

pip install -e ".[dev]"
```

### 2. Seed Sample Telemetry

Generate a sample SQLite database (`data/cdb_sample.sqlite`) preloaded with realistic Windows & Sysmon attack telemetry (phishing PowerShell invocation, C2 network beaconing, registry persistence):

```bash
python scripts/seed_cdb.py
```

### 3. Run Investigation via CLI

The CLI provides four distinct modes of operation:

#### A. Ingest Alert from File
```bash
python main.py --alert tests/fixtures/alert_entity_bearing.json --output report.md
```

#### B. Ingest Ad-hoc Alert from CLI Flags
```bash
python main.py --host DESKTOP-VICTIM1 --user "CORP\alice" --source EDR --output report.md
```

#### C. Ingest Alert via Stdin Pipe
```bash
cat tests/fixtures/alert_entity_bearing.json | python main.py --output report.md
```

#### D. Interactive Mode
```bash
python main.py -i
```

---

## 🤖 LLM Abduction Engine Configuration

The M2 Abduction Engine proposes explanations and testable expectations from unexplained observations:

- **Offline Deterministic Stub (Default)**:
  ```bash
  python main.py --alert tests/fixtures/alert_entity_bearing.json --llm stub
  ```
  Runs 100% offline without network calls, suitable for CI/CD, benchmarks, and regression testing.

- **External OpenAI-Compatible API**:
  Create or edit `.env`:
  ```env
  LLM_ENDPOINT=https://your-llm-service/v1/chat/completions
  LLM_MODEL=hermes-3-llama-3.1-8b
  LLM_API_KEY=your_api_key_here
  LLM_TIMEOUT=30
  ```
  Run with:
  ```bash
  python main.py --alert tests/fixtures/alert_entity_bearing.json --llm api
  ```

---

## 🏢 Enterprise Real-Provider Specifications

The architecture connects to production enterprise telemetry backends via provider adapters. Detailed integration contracts, native partition boundaries, pagination mechanics, and negative controls are documented in:

- **[Real-Provider Gate Specifications](docs/01-REAL-PROVIDER-SPECIFICATIONS.md)**:
  - **Splunk SIEM**: Native `(index, sourcetype, source)` partition scopes, search-time field extraction, parameterized SPL allowlist, and $L+1$ completeness.
  - **EDR (CrowdStrike / Defender)**: Dataset/tenant/endpoint scopes isolated from operational workflows, cursor pagination, and rate limit backoff.
  - **IDS (Suricata / Zeek)**: Sensor/interface/stream scopes, non-destructive evolving JSON schema retention, and packet drop monitoring.

---

## 🧪 Verification & Test Suite

Run the full test suite (100 tests covering contracts, invariants, scenarios, orchestrator, CLI, and real-provider specifications):

```bash
python -m pytest tests/ -v
```

Check code style and linting with Ruff:

```bash
ruff check .
```

---

## 📚 Technical Documentation

- [`01_FINAL-ARCHITECTURE.md`](01_FINAL-ARCHITECTURE.md) — Frozen architectural boundaries and module interfaces.
- [`02_METHOD-AND-IMPLEMENTATION-PLAN.md`](02_METHOD-AND-IMPLEMENTATION-PLAN.md) — Algorithms, data contracts, and formal proofs.
- [`03_LITERATURE-AND-TRACEABILITY.md`](03_LITERATURE-AND-TRACEABILITY.md) — Provenance mapping and citations.
- [`04-IMPLEMENTATION-CHECKLIST.md`](04-IMPLEMENTATION-CHECKLIST.md) — Executable milestone checklist and definition of done.
- [`docs/01-REAL-PROVIDER-SPECIFICATIONS.md`](docs/01-REAL-PROVIDER-SPECIFICATIONS.md) — Splunk, EDR, and IDS provider adapter architecture.
