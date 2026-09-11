"""Small deterministic cache for validated source profiles/capabilities."""
from __future__ import annotations

from dataclasses import dataclass, field

from hunting.contracts.source_profile import RuntimeCapability


@dataclass
class RuntimeCapabilityCache:
    _items: dict[str, tuple[RuntimeCapability, ...]] = field(default_factory=dict)

    @staticmethod
    def key(
        provider_id: str,
        scope_id: str,
        schema_fingerprint: str,
        requirement_signature: str,
        *,
        tenant_id: str = "default",
        principal_digest: str = "default",
        proof_contract_id: str = "none",
        parser_version: str = "v1",
    ) -> str:
        return "|".join((
            provider_id,
            scope_id,
            schema_fingerprint,
            requirement_signature,
            tenant_id,
            principal_digest,
            proof_contract_id,
            parser_version,
        ))

    def get(self, key: str) -> tuple[RuntimeCapability, ...] | None:
        return self._items.get(key)

    def put(self, key: str, capabilities: list[RuntimeCapability] | tuple[RuntimeCapability, ...]) -> None:
        self._items[key] = tuple(capabilities)

    def invalidate_schema(self, schema_fingerprint: str) -> None:
        for key in list(self._items):
            if schema_fingerprint not in key:
                del self._items[key]

    def invalidate_contract(self, contract_id: str) -> None:
        for key in list(self._items):
            if contract_id in key:
                del self._items[key]

    def invalidate_permission(self, principal_digest: str) -> None:
        for key in list(self._items):
            if principal_digest in key:
                del self._items[key]


    def clear(self) -> None:
        self._items.clear()


__all__ = ["RuntimeCapabilityCache"]
