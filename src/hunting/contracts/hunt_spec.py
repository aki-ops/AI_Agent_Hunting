"""Provider-neutral hunt specification and discovery contracts.

The hunt specification is deliberately smaller than an investigation graph.
It describes what must be answered and how evidence may be found, without
prescribing a person/account/endpoint path or a vendor event taxonomy.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

_ANSWER_FIELD_ALIASES: dict[str, tuple[str, ...]] = {
    "software_version": ("ProductVersion", "FileVersion", "Version", "version"),
    "domain": ("domains", "sites", "site", "domain"),
    "uri": ("uri", "url", "urls"),
    "url": ("uri", "url", "urls"),
    "ip_address": ("destination_ips", "dest_ips", "ips", "src_ip", "client_ip"),
    "email_address": ("sender_email", "recipient_email", "email"),
}


@dataclass(frozen=True)
class AnswerContract:
    """Machine-checkable shape of the requested answer."""

    answer_type: str
    required_fields: tuple[str, ...] = ()
    requires_binding: bool = True
    allowed_values: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "answer_type": self.answer_type,
            "required_fields": list(self.required_fields),
            "requires_binding": self.requires_binding,
            "allowed_values": list(self.allowed_values),
        }


@dataclass(frozen=True)
class Anchor:
    """Entity or value that can be used to discover telemetry."""

    value: str
    kind: str = "unknown"
    origin: str = "input"
    confidence: float = 1.0


@dataclass(frozen=True)
class QueryTermGroup:
    """Group of semantic query terms combined with a boolean operator."""
    terms: tuple[str, ...]
    mode: str = "OR"  # "OR" | "AND"
    required: bool = True

    def __post_init__(self) -> None:
        if isinstance(self.terms, (list, set)):
            object.__setattr__(self, "terms", tuple(self.terms))

    def to_dict(self) -> dict[str, Any]:
        return {
            "terms": list(self.terms),
            "mode": self.mode,
            "required": self.required,
        }


@dataclass(frozen=True)
class SearchTerm:
    """Provider-neutral lexical search term.

    The term is never native query syntax.  Terms derived by the LLM are
    useful for candidate discovery but cannot alone support a final verdict.
    """

    value: str
    origin: str = "llm_derived"
    confidence: float = 0.0


@dataclass(frozen=True)
class EvidencePredicate:
    semantic_intent: str
    description: str = ""
    necessity: str = "CRITICAL"
    required_fields: tuple[str, ...] = ()


@dataclass(frozen=True)
class EvidencePath:
    name: str
    predicate_types: tuple[str, ...] = ()


@dataclass
class HuntSpec:
    """Provider-neutral intermediate representation for a hunt request."""

    question: str
    answer_contract: AnswerContract
    anchors: list[Anchor] = field(default_factory=list)
    search_terms: list[SearchTerm] = field(default_factory=list)
    evidence_predicates: list[EvidencePredicate] = field(default_factory=list)
    alternative_paths: list[EvidencePath] = field(default_factory=list)
    time_window: str = ""
    uncertainties: list[str] = field(default_factory=list)

    @classmethod
    def from_semantic(
        cls,
        intent: Any,
        requirements: list[Any],
        time_window: str = "",
        answer_spec: dict[str, Any] | None = None,
    ) -> "HuntSpec":
        """Build a HuntSpec from validated compiler output.

        This consumes only provider-neutral compiler fields.  It intentionally
        does not infer event codes, sourcetypes, or an identity traversal.
        """
        subject = getattr(intent, "subject", None)
        requested = getattr(intent, "requested_object", None)
        answer_type = str(getattr(requested, "type", "unknown") or "unknown").strip().lower()
        required_fields = tuple(
            str(value).strip()
            for value in (answer_spec or {}).get("required_fields", [])
            if str(value).strip()
        )
        canonical_fields = _ANSWER_FIELD_ALIASES.get(answer_type, ())
        if canonical_fields:
            requested_lower = {field.casefold() for field in required_fields}
            matched = tuple(field for field in canonical_fields if field.casefold() in requested_lower)
            required_fields = matched or canonical_fields
        anchors: list[Anchor] = []
        if subject and str(getattr(subject, "value", "")).strip():
            anchors.append(Anchor(
                value=str(subject.value).strip(),
                kind=str(getattr(subject, "type", "unknown") or "unknown").lower(),
                origin="input",
                confidence=1.0,
            ))

        terms: list[SearchTerm] = []
        seen: set[str] = set()

        def add_term(value: Any, origin: str, confidence: float) -> None:
            text = str(value or "").strip()
            key = text.casefold()
            if text and len(text) >= 2 and key not in seen and not any(ch in text for ch in ("\n", "\r")):
                seen.add(key)
                terms.append(SearchTerm(text, origin=origin, confidence=confidence))

        if subject:
            add_term(getattr(subject, "value", ""), "input", 1.0)
        for req in requirements:
            for hint in getattr(req, "search_hints", []) or []:
                add_term(hint, "llm_derived", 0.65)
        # The requested object is a useful discovery seed only when it is
        # concrete (e.g. "Tor Browser"), not a generic type such as version.
        requested_value = str(getattr(intent, "behavior", "") or "")
        if requested_value and requested_value.casefold() not in {"unknown", ""}:
            # Keep the full behavior out of the query.  Requirement hints are
            # the validated lexical seeds; this value is retained as context.
            pass

        predicates = [
            EvidencePredicate(
                semantic_intent=str(getattr(req, "semantic_intent", "") or getattr(req, "evidence_type", "")),
                description=str(getattr(req, "description", "")),
                necessity=str(getattr(req, "necessity", "CRITICAL")).upper(),
                required_fields=tuple(getattr(req, "required_fields", []) or []),
            )
            for req in requirements
        ]
        paths = [
            EvidencePath(name="raw_text_search", predicate_types=("discovery",)),
            EvidencePath(name="process_telemetry", predicate_types=("process",)),
            EvidencePath(name="file_telemetry", predicate_types=("file",)),
            EvidencePath(name="registry_or_inventory", predicate_types=("metadata",)),
        ]
        return cls(
            question=str(getattr(intent, "question", "") or getattr(intent, "original_request", "")),
            answer_contract=AnswerContract(answer_type=answer_type, required_fields=required_fields),
            anchors=anchors,
            search_terms=terms,
            evidence_predicates=predicates,
            alternative_paths=paths,
            time_window=time_window,
            uncertainties=list(getattr(intent, "uncertainties", []) or []),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "question": self.question,
            "answer_contract": {
                **self.answer_contract.to_dict(),
            },
            "anchors": [a.__dict__ for a in self.anchors],
            "search_terms": [t.__dict__ for t in self.search_terms],
            "evidence_predicates": [p.__dict__ for p in self.evidence_predicates],
            "alternative_paths": [p.__dict__ for p in self.alternative_paths],
            "time_window": self.time_window,
            "uncertainties": list(self.uncertainties),
        }

    def discovery_groups(self, relaxation_level: int = 1) -> list[list[str]]:
        """Return high-recall lexical groups for provider discovery with progressive relaxation.

        Aliases in one semantic role are alternatives (OR); roles are
        combined (AND). This prevents an LLM emitting many aliases from
        accidentally requiring every alias in one event.

        Relaxation levels:
        - Level 1: Subject (Group 1) AND Evidence/Software (Group 2)
        - Level 2: Only Evidence/Software (Group 2) (e.g. if subject identity is uncertain)
        - Level 3: Relaxed Evidence aliases (pruning narrow/path terms, retaining core names)
        """
        groups: list[list[str]] = []
        anchor_values = [a.value for a in self.anchors if a.value.strip()]
        if anchor_values and relaxation_level == 1:
            subject_aliases: list[str] = []
            for value in anchor_values:
                subject_aliases.append(value)
                parts = [p for p in value.split() if len(p) >= 3]
                if len(parts) > 1:
                    subject_aliases.append(parts[0])
            groups.append(list(dict.fromkeys(subject_aliases)))

        evidence_aliases: list[str] = []
        anchor_keys = {v.casefold() for v in anchor_values}
        for term in self.search_terms:
            if term.value.casefold() in anchor_keys:
                continue
            chunks = [term.value]
            if "\\" in term.value or "/" in term.value:
                chunks.extend(p for p in term.value.replace("/", "\\").split("\\") if p)
            for chunk in chunks:
                text = chunk.strip().strip('"')
                if text and len(text) >= 3 and text.casefold() not in {v.casefold() for v in evidence_aliases}:
                    if relaxation_level >= 3 and ("\\" in text or "/" in text or len(text) > 30):
                        continue
                    evidence_aliases.append(text)
        if evidence_aliases:
            groups.append(evidence_aliases[:24])
        return groups

    def structured_query_groups(self, relaxation_level: int = 1) -> list[QueryTermGroup]:
        """Return structured QueryTermGroup instances for boolean query assembly."""
        raw_groups = self.discovery_groups(relaxation_level=relaxation_level)
        return [
            QueryTermGroup(terms=tuple(grp), mode="OR", required=True)
            for grp in raw_groups
            if grp
        ]


__all__ = [
    "AnswerContract",
    "Anchor",
    "SearchTerm",
    "EvidencePredicate",
    "EvidencePath",
    "HuntSpec",
]
