"""PoC models — concretized threat hypotheses with testable signatures.

A PoC (Proof-of-Concept) is a structured threat hypothesis with concrete,
observable signals. The point of a PoC is to remove the ambiguity that
free-text hypotheses create: every claim in a PoC is anchored to at least
one testable predicate (regex/field/key) that a CDB or SIEM can run.

We include four PoC kinds:

- ``ttp`` — anchored on a MITRE ATT&CK technique id.
- ``cve`` — anchored on a CVE identifier.
- ``ioc`` — anchored on an observable indicator (hash, IP, domain, file).
- ``behavior`` — anchored on a process or network behavior signature
  (cmdline tokens, syscalls, DNS patterns).

Each PoC declares:

- A list of ``TestStep`` objects, each with a target field, an operator and
  a value.
- Optional fallbacks to try if the primary step returns empty.
- A list of MITRE references for traceability.
- An optional LLM escalation hint that is only consulted if local CDB
  queries do not produce sufficient evidence.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class PocKind(str, Enum):
    TTP = "ttp"
    CVE = "cve"
    IOC = "ioc"
    BEHAVIOR = "behavior"


class FieldOp(str, Enum):
    CONTAINS = "CONTAINS"
    EQUALS = "EQUALS"
    STARTS_WITH = "STARTS_WITH"
    ENDS_WITH = "ENDS_WITH"
    MATCHES = "MATCHES"
    EXISTS = "EXISTS"


@dataclass(frozen=True)
class TestStep:
    """A single observable predicate. CDB/Splunk adapters compile this
    into a native query at runtime."""

    step_id: str
    description: str
    target_field: str          # e.g. "cmdline", "parent_image", "domain"
    op: FieldOp
    value: str
    time_window_hint: str | None = None
    source_kind: str = "process"   # informs adapter routing

    def render(self) -> dict[str, Any]:
        return {
            "step_id": self.step_id,
            "description": self.description,
            "target_field": self.target_field,
            "op": self.op.value,
            "value": self.value,
            "time_window_hint": self.time_window_hint,
            "source_kind": self.source_kind,
        }


@dataclass(frozen=True)
class EscalationHint:
    """Used only when local adapter steps return empty and the agent decides
    to ask the LLM. The hint is short, scoped, and bounded: a one-sentence
    question with an explicit evidence requirement."""

    question: str
    evidence_requirement: str = ""
    max_tokens: int = 4000


@dataclass(frozen=True)
class PoC:
    """Proof-of-Concept hypothesis.

    PoCs are not run sequentially; the agent selects one PoC at a time and
    may chain several PoCs into a single hunt. PoCs are deterministic when
    LLM escalation is disabled (``escalation_hint=None``).
    """

    poc_id: str
    name: str
    kind: PocKind
    summary: str
    steps: list[TestStep] = field(default_factory=list)
    fallbacks: list[TestStep] = field(default_factory=list)
    references: list[str] = field(default_factory=list)
    escalation_hint: EscalationHint | None = None
    expected_chain: list[str] = field(default_factory=list)

    def render(self) -> dict[str, Any]:
        return {
            "poc_id": self.poc_id,
            "name": self.name,
            "kind": self.kind.value,
            "summary": self.summary,
            "steps": [s.render() for s in self.steps],
            "fallbacks": [s.render() for s in self.fallbacks],
            "references": list(self.references),
            "escalation_hint": (
                {
                    "question": self.escalation_hint.question,
                    "evidence_requirement": self.escalation_hint.evidence_requirement,
                    "max_tokens": self.escalation_hint.max_tokens,
                }
                if self.escalation_hint
                else None
            ),
            "expected_chain": list(self.expected_chain),
        }
