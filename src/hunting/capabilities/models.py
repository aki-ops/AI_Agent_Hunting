"""Versioned capability contracts.

Fulfills Phase 2 requirements:
- Version deployment-specific capability descriptors.
- Declare supported entity kinds, permissions, observable fields, and completeness contract.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from hunting.contracts.cells import ProviderScope
from hunting.contracts.queries import CapabilityBinding, ProviderOperation


@dataclass(frozen=True)
class VersionedCapabilityDescriptor:
    """Published capabilities of one telemetry provider adapter in a specific deployment."""
    provider_id: str
    version: str
    deployment_env: str  # e.g. "enterprise-prod", "dmz", "cloud-sandbox"
    scopes: tuple[ProviderScope, ...]
    operations: tuple[ProviderOperation, ...]
    bindings: tuple[CapabilityBinding, ...]
    supported_entity_kinds: tuple[str, ...] = field(default_factory=tuple)
    permissions: tuple[str, ...] = field(default_factory=tuple)
    observable_fields: tuple[str, ...] = field(default_factory=tuple)
    completeness_contract: str = "complete"

    def __post_init__(self) -> None:
        if not self.provider_id.strip():
            raise ValueError("VersionedCapabilityDescriptor.provider_id must not be empty")
        if not self.version.strip():
            raise ValueError("VersionedCapabilityDescriptor.version must not be empty")
        if not self.scopes:
            raise ValueError("VersionedCapabilityDescriptor.scopes must not be empty")
        if not self.operations:
            raise ValueError("VersionedCapabilityDescriptor.operations must not be empty")
        if not self.supported_entity_kinds:
            raise ValueError("VersionedCapabilityDescriptor.supported_entity_kinds must not be empty")
        if not self.observable_fields:
            raise ValueError("VersionedCapabilityDescriptor.observable_fields must not be empty")


__all__ = ["VersionedCapabilityDescriptor"]
