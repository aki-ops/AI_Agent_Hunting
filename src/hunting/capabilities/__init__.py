"""Capability Layer module."""
from hunting.capabilities.models import VersionedCapabilityDescriptor
from hunting.capabilities.registry import build_default_capability_registry

__all__ = [
    "VersionedCapabilityDescriptor",
    "build_default_capability_registry",
]
