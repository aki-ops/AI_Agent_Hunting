"""Capability descriptor and provider-neutral capability matcher.

Allows the core planner to select executable operations without provider-specific
branches in the planner.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from hunting.contracts.cells import ProviderScope
from hunting.contracts.entities import EntityRef
from hunting.contracts.expectations import EvidenceRequirement
from hunting.contracts.queries import CapabilityBinding, Diagnostic, ProviderOperation


@dataclass(frozen=True)
class CapabilityDescriptor:
    """Published capabilities of one telemetry provider adapter."""
    provider_id: str
    scopes: tuple[ProviderScope, ...]
    operations: tuple[ProviderOperation, ...]
    bindings: tuple[CapabilityBinding, ...]


@dataclass
class ProviderCapabilityCatalog:
    """Discovered runtime telemetry capability catalog from provider."""
    provider_id: str
    status: str = "ONLINE"  # "ONLINE", "UNREACHABLE", "UNSUPPORTED"
    indices: list[str] = field(default_factory=list)
    sourcetypes: dict[str, int] = field(default_factory=dict)
    supported_evidence_types: list[str] = field(default_factory=list)
    observable_fields: list[str] = field(default_factory=list)
    retention_days: int = 4000
    details: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class MatchResult:
    """Result of matching an evidence requirement to an executable operation."""
    binding: CapabilityBinding | None
    operation: ProviderOperation | None
    diagnostic: Diagnostic | None = None

    @property
    def is_supported(self) -> bool:
        return self.binding is not None and self.diagnostic is None


class CapabilityMatcher:
    """Selects an EXACT or PARTIAL binding for an EvidenceRequirement.

    Returns Diagnostic.UNSUPPORTED_REQUIREMENT when no safe binding exists.
    The planner consumes descriptors and does not contain Splunk, EDR, IDS,
    or cloud-specific branches.
    """

    def __init__(self, descriptors: list[CapabilityDescriptor] | tuple[CapabilityDescriptor, ...]) -> None:
        self.descriptors = {desc.provider_id: desc for desc in descriptors}

    def match(
        self,
        requirement: EvidenceRequirement,
        preferred_provider: str | None = None,
        entity: EntityRef | None = None,
        parameters: dict[str, Any] | None = None,
    ) -> MatchResult:
        """Find the best binding and operation for an evidence requirement."""
        candidate_descriptors = (
            [self.descriptors[preferred_provider]]
            if preferred_provider and preferred_provider in self.descriptors
            else list(self.descriptors.values())
        )

        exact_matches: list[tuple[CapabilityDescriptor, CapabilityBinding]] = []
        partial_matches: list[tuple[CapabilityDescriptor, CapabilityBinding]] = []

        for desc in candidate_descriptors:
            for binding in desc.bindings:
                if binding.evidence_requirement == requirement:
                    if binding.confidence.upper() == "EXACT":
                        exact_matches.append((desc, binding))
                    else:
                        partial_matches.append((desc, binding))

        selected = exact_matches[0] if exact_matches else (partial_matches[0] if partial_matches else None)

        if not selected:
            return MatchResult(
                binding=None,
                operation=None,
                diagnostic=Diagnostic.UNSUPPORTED_REQUIREMENT,
            )

        desc, binding = selected
        operation = next((op for op in desc.operations if op.id == binding.operation_id), None)
        if not operation:
            return MatchResult(
                binding=binding,
                operation=None,
                diagnostic=Diagnostic.UNQUERYABLE,
            )

        return MatchResult(binding=binding, operation=operation, diagnostic=None)


__all__ = ["CapabilityDescriptor", "ProviderCapabilityCatalog", "CapabilityMatcher", "MatchResult"]
