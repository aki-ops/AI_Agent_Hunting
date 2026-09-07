"""Semantic Hunt Intent Contracts.

Defines provider-neutral, strictly validated semantic intent emitted by LLM compiler.
The LLM describes what needs to be verified without raw SPL, index, host, or sourcetype.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class SubjectEntity:
    """The entity being investigated (actor, victim, asset)."""
    type: str  # e.g., 'person', 'host', 'service', 'domain', 'ip', 'account'
    value: str

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "value": self.value}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SubjectEntity:
        return cls(
            type=str(data.get("type", "unknown")).strip().lower(),
            value=str(data.get("value", "")).strip(),
        )


@dataclass
class RequestedObject:
    """The target object or answer sought by the investigation."""
    type: str  # e.g., 'website_domain', 'ip_address', 'file_artifact', 'process_name'
    role: str = "answer"

    def to_dict(self) -> dict[str, Any]:
        return {"type": self.type, "role": self.role}

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RequestedObject:
        return cls(
            type=str(data.get("type", "unknown")).strip().lower(),
            role=str(data.get("role", "answer")).strip().lower(),
        )


@dataclass
class SemanticEvidenceRequirement:
    """High-level evidence requirement specified by semantic intent."""
    semantic_intent: str  # e.g., 'identity_binding', 'web_navigation', 'dns_resolution'
    required_fields: list[str] = field(default_factory=list)
    necessity: str = "CRITICAL"  # 'CRITICAL' | 'SUPPORTING'
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "semantic_intent": self.semantic_intent,
            "required_fields": list(self.required_fields),
            "necessity": self.necessity,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SemanticEvidenceRequirement:
        return cls(
            semantic_intent=str(data.get("semantic_intent", "")).strip().lower(),
            required_fields=[str(f).strip().lower() for f in data.get("required_fields", []) if str(f).strip()],
            necessity=str(data.get("necessity", "CRITICAL")).strip().upper(),
            description=str(data.get("description", "")).strip(),
        )


@dataclass
class SemanticHuntIntent:
    """Canonical semantic analysis emitted by the LLM for unstructured hunt requests."""
    original_request: str
    question: str
    subject: SubjectEntity
    requested_object: RequestedObject
    behavior: str
    evidence_requirements: list[SemanticEvidenceRequirement] = field(default_factory=list)
    required_correlations: list[str] = field(default_factory=list)
    assumptions: list[str] = field(default_factory=list)
    uncertainties: list[str] = field(default_factory=list)

    def validate_provider_isolation(self) -> list[str]:
        """Check that LLM did not leak provider-specific keywords (SPL, indexes, etc.)."""
        leaks: list[str] = []
        forbidden_tokens = ["index=", "sourcetype=", "| table", "| stats", "| eval", "select *", "from events"]
        full_text = (
            f"{self.question} {self.behavior} "
            + " ".join(r.semantic_intent for r in self.evidence_requirements)
            + " ".join(self.required_correlations)
        ).lower()

        for token in forbidden_tokens:
            if token in full_text:
                leaks.append(f"Forbidden provider syntax found in semantic intent: '{token}'")
        return leaks

    def to_dict(self) -> dict[str, Any]:
        return {
            "original_request": self.original_request,
            "question": self.question,
            "subject": self.subject.to_dict(),
            "requested_object": self.requested_object.to_dict(),
            "behavior": self.behavior,
            "evidence_requirements": [r.to_dict() for r in self.evidence_requirements],
            "required_correlations": list(self.required_correlations),
            "assumptions": list(self.assumptions),
            "uncertainties": list(self.uncertainties),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SemanticHuntIntent:
        subj_raw = data.get("subject", {})
        if isinstance(subj_raw, str):
            subj = SubjectEntity(type="unknown", value=subj_raw)
        elif isinstance(subj_raw, dict):
            subj = SubjectEntity.from_dict(subj_raw)
        else:
            subj = SubjectEntity(type="unknown", value=str(subj_raw))

        obj_raw = data.get("requested_object", {})
        if isinstance(obj_raw, str):
            req_obj = RequestedObject(type=obj_raw, role="answer")
        elif isinstance(obj_raw, dict):
            req_obj = RequestedObject.from_dict(obj_raw)
        else:
            req_obj = RequestedObject(type="unknown", role="answer")

        reqs = [
            SemanticEvidenceRequirement.from_dict(r)
            for r in data.get("evidence_requirements", [])
            if isinstance(r, dict)
        ]

        return cls(
            original_request=str(data.get("original_request", "")).strip(),
            question=str(data.get("question", "")).strip(),
            subject=subj,
            requested_object=req_obj,
            behavior=str(data.get("behavior", "")).strip(),
            evidence_requirements=reqs,
            required_correlations=[str(c).strip() for c in data.get("required_correlations", []) if str(c).strip()],
            assumptions=[str(a).strip() for a in data.get("assumptions", []) if str(a).strip()],
            uncertainties=[str(u).strip() for u in data.get("uncertainties", []) if str(u).strip()],
        )


__all__ = [
    "SubjectEntity",
    "RequestedObject",
    "SemanticEvidenceRequirement",
    "SemanticHuntIntent",
]
