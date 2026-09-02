# 03 — LITERATURE AND TRACEABILITY (v3)

This document records what informed the architecture and what remains an
engineering decision. A source supporting a design principle is not evidence
that this project is production-complete.

## Verification levels

| Level | Meaning |
|---|---|
| `FULL-TEXT` | paper body or released repository read directly |
| `ABSTRACT/HTML-VERIFIED` | official abstract or publisher HTML inspected; not a claim of full-paper review |
| `OFFICIAL-DOC-VERIFIED` | vendor/standards documentation inspected directly |
| `INDEX-VERIFIED` | bibliographic identity confirmed; body not read |
| `UNVERIFIED` | retained for history only; must not support a thesis claim |

## 1. Current contract traceability

| Contract/decision | Evidence | Relationship | What we adopt | What remains ours |
|---|---|---|---|---|
| `ProviderScope` uses native provider partitions | OCSF; OpenTelemetry Events; Splunk field/data-source docs; Suricata EVE docs | adapted/composed | provider-owned addressability and observed fields | scope identity, bounded coverage states |
| `ProviderOperation` is separate from partition | Splunk search model; EDR API model in provider docs; SynRAG | adapted | backend-specific operation and executable query boundary | capability binding contract and allowlist |
| native records are preserved; semantic mapping is optional | OCSF extension/normalization model; OpenTelemetry event model; Matryoshka | adapted | normalize without erasing source shape | nullable `semantic_type`, `UNMAPPED` handling |
| parser/schema cannot be assumed closed | Sieve; Matryoshka; Suricata evolving EVE schema | adapted | retrieve/represent unknown records | no `OTHER` fallback and native-type retention |
| `EvidenceRequirement` is question-side vocabulary | MITRE Data Components; SynRAG | adapted | describe required evidence independently of vendor fields | versioning and explicit `UNSUPPORTED_REQUIREMENT` |
| `Cell` is coverage address | incomplete-information databases; discovery sampling | composed | countable known frame and explicit unknown boundary | `(ProviderScope, entity/ANY, time)` contract |
| partial result cannot license absence | incomplete-information semantics; provider pagination contracts | adapted | distinguish incomplete from empty | `PARTIAL` split state and negative-evidence controls |
| sampling is bounded exploration | discovery sampling literature | adapted | stratum/sample/frame accounting | strata are provider scopes, not event families |
| competing explanations and constraints | abduction, diagnosis and argumentation literature | adapted | M2/M3 split and typed explanations | no hypothesis-completeness claim |
| LLM boundary and log injection defence | Poisoning the Watchtower; DiagChain | adapted | raw-log isolation, provenance and deterministic state | concrete enforcement and regression tests |
| coverage bound instead of completeness alarm | E3/E4/E5/E6 project experiments | experimentally derived | report reachability/coverage limits | exact counters and terminal output |

## 2. Why the old EventFamily axis was rejected

The old design used one closed enum for provider addressability, event meaning,
field availability and question requirements. The reviewed sources contradict
that coupling in practical ways:

- Splunk addresses data through native partitions and performs much field
  extraction at search time; a family-to-field table cannot be authoritative.
- EDR interfaces expose functions and relationships such as process trees,
  rather than one universal event-code axis.
- Suricata EVE has an evolving and nested event schema; unknown native types must
  remain queryable/preservable.
- OCSF and OpenTelemetry normalize semantic information but do not make every
  producer emit the same native shape.

Therefore `EventFamily` is not used to enumerate Cells, choose sampling strata,
or restrict queries. It may be assigned after retrieval as an optional semantic
label.

## 3. Sources used for the v3 reset

| Tag | Source | Verification | Architectural implication |
|---|---|---|---|
| `REF-OCSF-01` | [OCSF documentation](https://ocsf.io/) | `OFFICIAL-DOC-VERIFIED` | common semantic schema must coexist with producer-native records |
| `REF-OTEL-01` | [OpenTelemetry Events semantic conventions](https://opentelemetry.io/docs/specs/semconv/general/events/) | `OFFICIAL-DOC-VERIFIED` | event semantics are conventions, not an addressability universe |
| `REF-ATTACK-DC-01` | [MITRE ATT&CK Data Components](https://attack.mitre.org/datacomponents/) | `OFFICIAL-DOC-VERIFIED` | question/evidence vocabulary is distinct from vendor telemetry partitions |
| `REF-SPLUNK-01` | [Splunk fields](https://docs.splunk.com/Documentation/SplunkCloud/latest/Knowledge/Aboutfields) and [data-source validation](https://docs.splunk.com/Documentation/InfoSec/latest/Admin/ValidateDataSources) | `OFFICIAL-DOC-VERIFIED` | fields and data sources require deployment/runtime validation |
| `REF-SURICATA-01` | [Suricata EVE JSON format](https://docs.suricata.io/en/suricata-8.0.0/output/eve/eve-json-format.html) | `OFFICIAL-DOC-VERIFIED` | evolving/nested native event types and optional fields |
| `REF-MATRYOSHKA-01` | [Matryoshka: Semantic-Aware Parsing for Security Logs](https://arxiv.org/abs/2506.17512) | `ABSTRACT/HTML-VERIFIED` | semantic parsing can enrich heterogeneous logs; it does not define source coverage |
| `REF-SIEVE-01` | [Sieve: Parser-Free Querying of Security Logs](https://arxiv.org/abs/2605.22027) | `ABSTRACT/HTML-VERIFIED` | query-time interpretation reduces dependence on a closed parser taxonomy |
| `REF-SYNRAG-01` | [SynRAG: executable query generation in heterogeneous SIEM](https://arxiv.org/abs/2512.24571) | `ABSTRACT/HTML-VERIFIED` | executable query generation needs backend-aware grounding/validation |
| `REF-CDB-01` | [Cyber Defense Benchmark](https://arxiv.org/abs/2604.19533) | `ABSTRACT/HTML-VERIFIED` | CDB is a testbed, not evidence of cross-backend production coverage |
| `REF-INCOMP-01` | Lipski, *On Semantic Issues Connected with Incomplete Information Databases* | `INDEX-VERIFIED` | empty answers and incomplete information must be separated |
| `REF-SAMP-01` | discovery-sampling references retained in prior bibliography | `INDEX-VERIFIED` | sampling bounds apply only to a defined frame/stratum |
| `REF-EVID-01` | DiagChain benchmark/repository | `FULL-TEXT` | evidence-grounded, auditable observation links |
| `REF-INJECT-01` | Pandey et al., *Poisoning the Watchtower* | `ABSTRACT/HTML-VERIFIED` | log content is an injection surface; isolate it from LLM control |

The four recent research papers above were inspected at abstract/HTML level in
the design review. They are used for architectural direction, not quoted for
unverified numerical claims.

## 4. Architecture-to-source map

| Architecture item | Primary references | Status |
|---|---|---|
| native scope discovery and observed field presence | `REF-SPLUNK-01`, `REF-SURICATA-01`, `REF-OCSF-01` | engineering + adapted |
| provider operation/capability binding | `REF-SYNRAG-01`, provider docs | adapted; implementation must test adapters |
| optional semantic enrichment | `REF-OCSF-01`, `REF-OTEL-01`, `REF-MATRYOSHKA-01` | adapted; not a retrieval gate |
| unknown/unmapped observation path | `REF-SIEVE-01`, `REF-SURICATA-01` | adapted; project contract |
| evidence requirements | `REF-ATTACK-DC-01`, `REF-SYNRAG-01` | adapted; versioned project vocabulary |
| Cell/coverage and incomplete answers | `REF-INCOMP-01`, `REF-SAMP-01` | composed; project contract |
| explanation generation and constraints | prior abduction/diagnosis/argumentation bibliography | adapted; no completeness claim |
| LLM-safe ledger boundary | `REF-INJECT-01`, `REF-EVID-01` | adapted; project enforcement |

## 5. Claims we explicitly do not make

- OCSF, OpenTelemetry or ATT&CK provides a complete query universe.
- A semantic schema guarantees that an unknown source/event is visible.
- Sampling proves absence outside its defined frame.
- A research prototype or CDB execution proves Splunk/EDR/IDS production readiness.
- `3/n` is a universal confidence guarantee for adversarial or unqueryable telemetry.

## 6. Evidence status for implementation

The literature supports the separation of addressability, execution and
semantics. The following remain empirical project gates: provider completeness,
partition discovery accuracy, field observability, pagination/truncation,
negative-evidence validity, unknown-record retention and cross-provider
capability binding. These are tracked as EXP-01 through EXP-13 in `02` and in
the checklist.
