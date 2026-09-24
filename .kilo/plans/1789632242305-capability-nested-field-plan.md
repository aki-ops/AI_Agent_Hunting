# Plan: Open-vocabulary mapping + nested payload census

## Goal

Unblock hunts whose C1 relation string does not match catalog labels and whose answer lives in nested `_raw` keys, without aliases, SMTP/email/zip/Taedonggang branches, or treating `proposals: []` as permission to invent a query.

Live defect (`hunt-req-20260918-010114`): C1 and C2 HTTP 200; C2 `proposals: []`; F1 ranked `stream:smtp`; flat census has no attachment key; `attach_filename` exists only in `_raw`; 0 Splunk queries; `STOP_INCONCLUSIVE` is the honest stop, not the desired capability.

## Locked decisions

1. Do **not** set `guaranteed_relations=("sent_message",)` on `find_outbound_message_metadata`.
2. Do **not** add a MIME/email parser. Nested discovery is generic payload-key census + allowlisted `extract_nested_key`.
3. Collapsed C1 graphs remain valid for EXPLORE if C2 receives the full `CapabilityQuery` (constraints, qualifiers, answer role). Richer C1 graphs are a later structural check, not a scenario template.
4. LLM still only proposes. Admission requires census-backed field IDs (flat or nested-origin). Proof still requires ProofContract.

## Complete flow (one unresolved goal)

```text
accepted graph
  -> CapabilityQuery (types, answer_role, constraint_keys, qualifier hints)
  -> F0 exact contract if labels coincide
  -> F1 retrieve top-k sources/ops (already exists)
  -> if answer_role not in flat fields of a hit:
       bounded payload-key census on sample _raw
       (JSON flatten + generic "key":value / key:["v"] patterns)
       keys enter census with origin=nested_payload
  -> F2 one C2 call with FULL query + nested keys + transform catalog
  -> admission (fields in census, transform allowlisted)
  -> QueryIntent EXPLORE
  -> execute with extract_nested_key when mapping origin is nested
  -> ProofEngine (still not proven by metadata)
  -> stop: INCONCLUSIVE if nested census/C2 deferred;
           UNSUPPORTED only after F1+nested+F2 completed and 0 admitted
```

## Tasks

### 1. C2 context must carry CapabilityQuery, not a stripped relation

Files: `src/hunting/capabilities/source_profiler.py`, engine requirement dict passed into `profiler.propose`, tests in `tests/unit/test_source_profiler.py` (or new `test_v9_c2_capability_context.py`).

Pass through, no vendor names:

- `answer_role`
- `constraint_keys` and qualifier `{key, value}` as **searchable hints**, not proof
- `subject_type` / `object_type` / `relation_text`
- nested census fields (id, name, `origin`)

Keep instruction: return `{"proposals":[]}` when no census field can fill `answer_role`.

Test: requirement with `answer_role=file_name`, constraints `file_format=zip`, qualifier `recipient=OrgX`, plus a nested field `attach_filename` in the source card → stub LLM sees those keys in the prompt JSON. Same test without nested/flat field covering `file_name` → empty proposals still valid.

### 2. Bounded payload-key census (generic nested discovery)

Files: new `src/hunting/capabilities/payload_key_census.py`; Splunk adapter sample-rows helper (reuse existing `head` + `_raw`, **not** `fieldsummary` as the only schema); engine F1-shortlist hook.

Algorithm (provider-neutral):

- For each F1 hit whose flat fields do not cover `answer_role`, fetch ≤N sample rows (N small, same bound as current fieldsummary head).
- From each `_raw`/payload string: parse JSON if possible (flatten nested dict/list); else regex-extract identifier keys of the form `"key":` / `key:` with conservative identifier charset.
- Cap keys per source. Record `TelemetryFieldProfile` with `origin="nested_payload"` and `evidence_query_id`.
- Never treat key presence as proof that the semantic attribute holds.

Test with a **synthetic** payload containing `"widget_label":["alpha.dat"]` (not `attach_filename` / smtp). Census must list `widget_label`. `fieldsummary`-only path must not invent it.

### 3. Allowlisted `extract_nested_key` transform

Files: `src/hunting/contracts/transforms.py`, mapping validator, adapter compile path that already applies transforms to SPL/SQL.

Transform: given native field (usually payload/raw) and proposed nested key, extract values. SPL/SQL generation must be generic (e.g. `spath` / `json path` / quoted-key rex) parameterized by the **census key**, never a hardcoded filename key.

Admission: nested `native_field` must exist in census; `transform` must be `extract_nested_key` (or empty for flat fields).

Test: proposal citing `widget_label` + transform admitted; proposal citing `attach_filename` when not in census rejected.

### 4. Do not admit static ops that cannot fill answer_role

F1 may rank a message-metadata op. Admission must reject it for `answer_role=file_name` unless a census field (flat or nested) can fill that role. This prevents “run SMTP metadata query and hope”.

Test: op with only `sender`,`subject` + query `answer_role=file_name` → not admitted; after nested census adds `widget_label` → may be admitted as EXPLORE.

### 5. C1 anti-collapse (structural, optional repair)

Files: `SemanticGoalGraphValidator` / acceptance gate.

Deterministic flags (no email ontology):

- named request entities that are neither subject nor object should not be **only** an untyped qualifier if the OutcomeContract needs them as scope;
- `answer_type` must be consistent with the answer variable (attribute of that variable, not a missing slot).

If uncertain: `NEEDS_CLARIFICATION` or C1V/C5 graph revision through the acceptance gate. Do not inject a message-attachment template.

Test: graph `A--rel-->B` with extra named entity only as qualifier still compiles; validator records uncertainty. Do **not** require a four-node email graph.

### 6. Stop / coverage accounting

If nested census is skipped (budget/adapter), mark those F1 hits unexamined; forbid `STOP_UNSUPPORTED` / `COVERAGE_EXHAUSTED`.

Test: F1 hit + nested census deferred + `proposals:[]` → `STOP_INCONCLUSIVE` with unexamined payload sources.

## Forbidden in the PR

- `sent_message` / SMTP / zip / Frothly / `attach_filename` strings in kernel matcher, profiler instructions, or transforms
- MIME parser as the nested strategy
- Running `find_outbound_message_metadata` solely because F1 ranked it

## Validation

- Unit tests above, plus existing Workstream L tests still green
- Mock e2e: org/file graph, synthetic source `src:payload`, `_raw` JSON with nested key, C2 stub returns mapping to that key + `extract_nested_key` → ≥1 EXPLORE query, proof not auto-VERIFIED
- Live BOTS hunt is **not** the merge gate; it is a later acceptance check after mock e2e

## Risks

- Nested key regex over-extracts noise: cap keys, require identifier-like names, admission still needs C2 to pick `answer_role`
- `head 20` may miss rare nested keys: record incompleteness; do not claim schema complete
- Adapter-specific extract (spath vs rex) stays behind provider compiler, not the kernel
