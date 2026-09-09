# 02 — METHOD AND IMPLEMENTATION PLAN (v6)

`01_FINAL-ARCHITECTURE.md` defines the contracts. This file defines the
executable method and migration sequence. No step may claim more than its
evidence supports.

## 1. End-to-end method

### Step 0 — Accept and freeze the request

Preserve the exact `HuntRequest`, time policy, entities and provider hints.
Do not parse a keyword into an attack scenario. Assign a run ID and budget
ledger.

Output: immutable request record.

Basis: hypothesis-driven hunting starts from an unverified objective. The
request contract is a thesis engineering decision grounded by TaHiTI,
Evidential Cyber Threat Hunting and MITRE hunting practice.

### Step 1 — Provider Census

Inspect all configured providers without assuming a provider, index, event
family or field. Record reachability, native partitions, schemas, aliases,
retention, permissions, pagination and completeness.

Output: versioned `CapabilityGraph` and source-selection audit.

If no source can satisfy any required claim, return an explicit unsupported or
unreachable result. A reachable but irrelevant provider is not a valid fallback.

Basis: OCSF, MITRE Data Components and Microsoft's schema-aware hunting
assistant. The exact census implementation is local.

### Step 2 — Semantic Claim-Plan Proposal

Send the request plus a compact capability summary to the LLM. Require a
schema-strict `ClaimGraph` containing objective, answer contract, atomic
claims, dependencies, evidence requirements, acceptance/refutation rules,
allowed expansion reasons and provenance.

The LLM must not emit SPL/KQL/SQL, invent evidence, add an unrequested attack
story, or silently change scope.

Output: candidate `ClaimGraph`.

Basis: ThreatRaptor demonstrates structured behaviour extraction before query
synthesis; AIQL demonstrates typed logical investigation queries. The exact
LLM schema, prompt and reliability are thesis work and require metrics.

### Step 3 — Deterministic Plan Validation

Validate schema, objective preservation, claim provenance, dependency
acyclicity, acceptable output fields and forbidden unsupported expansion.
Reject or reduce invalid plans. Never repair an invalid plan by adding a
hard-coded scenario.

Required invariants:

- every non-prerequisite claim traces to request/source/verified observation;
- every required claim has an acceptance rule;
- technical prerequisites are explicitly labelled;
- no claim has raw provider syntax;
- no claim is accepted merely because a schema field exists.

Basis: typed query and safe tool-use research; the validator is local.

### Step 4 — Claim-to-Capability Binding

For each unresolved claim, find operations whose required inputs are known or
can be obtained and whose outputs can satisfy the claim. Preserve candidate
bindings and their reasons.

No operation is selected only because its name contains a keyword. No provider
fallback is valid unless its output contract matches the claim.

Basis: AIQL, ATT&CK analytics separation and Microsoft schema-aware query
selection. Binding implementation is local.

### Step 5 — Deterministic Action Selection

Score candidates with transparent factors: expected unresolved-claim
reduction, source relevance, completeness confidence, cost and risk. If two
valid candidates remain equivalent, an LLM may rank candidate IDs only; the
controller can abstain.

Output: one bounded action or a truthful stop. The score is an engineering
hypothesis to compare experimentally, not a hidden prompt policy.

### Step 6 — Native Query Compilation and Execution

The adapter receives a logical operation, validated parameters and provider
capabilities. It compiles native SPL/KQL/SQL/API calls, allowlists syntax,
executes pagination/time splits, and returns:

```text
QueryResult {
  query_id, provider, native_query,
  rows, raw_count, cursor_state,
  complete, coverage, diagnostics, error_state
}
```

`complete` is explicit; row count is never interpreted as EOF. Basis: AIQL and
provider query systems. The exact adapter contract is local and must be tested.

### Step 7 — Observation and Fact Construction

Append raw rows unchanged. Extract normalized facts and strict field roles as
an additional view. Preserve unknown native fields/types. Group repeated rows
into evidence cards only if representative IDs and held-out recall are retained.

Output: observations, facts, cards and candidate evidence edges.

Basis: SLEUTH, HOLMES, OmegaLog and OCSF. Grouping thresholds and aliases are
local and require malicious-event recall tests.

### Step 8 — Claim Verification

Verify cited observation IDs, field role and identity, temporal constraints,
requested values, source/query completeness and the claim acceptance rule.

Output: `SUPPORTED`, `REFUTED`, `PARTIAL`, `UNKNOWN` or `INCONCLUSIVE` claim
status. This verifier is the epistemic gate; LLM text never promotes a claim.

### Step 9 — Bounded Replanning

Re-invoke the LLM only at a material boundary: unresolved ambiguity, new
evidence changing dependencies, or a capability/coverage gap with a valid
alternative. Pass compact deltas and claim state, not the raw ledger. Every
new claim returns through Step 3.

Stop replanning when no claim-reducing action remains, no progress occurs, or a
budget is reached. Basis: adaptive threat hunting and plan/retrieve/generate
research; call/card limits are local experimental parameters.

### Step 10 — Final account

Render request → claim analysis → evidence/explanation → queries → answer and
limitations → cost. Include observation IDs and coverage diagnostics. If the
explainer fails, render deterministic verified facts and the parse failure.

## 2. Code migration plan

### Phase A — Contracts

Add/reconcile `Claim`, `ClaimGraph`, `EvidenceRequirement`, `AcceptanceRule`,
`RefutationRule`, `CapabilityGraph`, `ProviderOperation` and `QueryResult`.
Keep `Cell` only for execution coverage. Existing graph types become evidence
projections, not a prewritten planner story.

### Phase B — Compiler

Replace scenario/template routing with schema-strict ClaimGraph output. Remove
unconditional branches such as `is_email` that create message, recipient, role,
IP or web edges. A relation is created only when the plan or verified evidence
requires it. The active free-text compiler makes one proposal call, rejects
invalid output without an LLM repair call, and projects the validated claims
mechanically into the compatibility case graph. Legacy runtime hypotheses and
evidence requirements are compatibility projections only; they add no claims.

### Phase C — Provider census and binding

Make auto-provider selection produce a source audit. Add operation input/output
contracts, native partitions, completeness and permissions. Reject irrelevant
fallbacks. Do not expand provider count until Splunk and CDB contracts pass.

### Phase D — Execution and evidence

Unify adapters behind `QueryResult`; preserve raw observations; implement fact
roles, evidence cards and claim citations. Test unknown native events and
partial queries.

### Phase E — Controller

Drive actions from unresolved claims and valid capabilities. Remove hard-coded
entity prefix/suffix paths as mandatory rules. Technical prerequisites may be
derived from operation contracts only.

### Phase F — Verification and reporting

Make claim verification the only promotion gate. Reduce the report to the
required evidence narrative and expose raw artifacts by ID. Keep LLM as a
bounded explainer, never as a source of facts.

### Phase G — Evaluation

Build labelled lookup, artifact, causal and hypothesis datasets. Measure claim
F1, evidence precision/recall, edge F1, answer exact-match/F1, citation
grounding, coverage, latency, query volume and LLM cost. Do not claim global F1
on unlabeled production telemetry.

## 3. Definition of done

The migration is complete only when unrelated requests create request-derived
ClaimGraphs without scenario branches; every final value has an observation or
fact citation; irrelevant fallback is rejected; incomplete telemetry cannot
produce a negative verdict; graph edges derive from claims/evidence; F1 and
cost are measured on labelled data; and `01–04`, code and tests describe the
same contracts.
