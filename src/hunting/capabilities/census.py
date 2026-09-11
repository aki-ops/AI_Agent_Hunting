"""Versioned Provider Census and claim-specific source selection."""
from __future__ import annotations

from typing import Any, Iterable

from hunting.capabilities.models import VersionedCapabilityDescriptor
from hunting.contracts.capabilities import (
    CapabilityDescriptor,
    CapabilityGraph,
    ProviderCapabilityCatalog,
    ProviderSelectionAudit,
)
from hunting.contracts.cells import ProviderScope
from hunting.contracts.claim import Claim, ClaimEvidenceRequirement, ClaimGraph
from hunting.contracts.queries import ProviderOperation
from hunting.contracts.source_profile import TelemetryFieldProfile, TelemetrySourceProfile


class ProviderCensusService:
    """Normalize configured adapters into one auditable CapabilityGraph."""

    CENSUS_VERSION = "2026.1.0"

    def census(
        self,
        adapters: Iterable[Any],
        claim_graph: ClaimGraph | None = None,
        provider_hints: Iterable[str] = (),
    ) -> CapabilityGraph:
        catalogs = [self._discover(adapter) for adapter in adapters]
        hints = {str(value).strip() for value in provider_hints if str(value).strip()}
        audits: list[ProviderSelectionAudit] = []

        claims = claim_graph.claims if claim_graph is not None else []
        for catalog in catalogs:
            if not claims:
                audits.append(self._audit_without_claim(catalog, hints))
                continue
            for claim in claims:
                audits.append(self._audit_claim(catalog, claim, hints))

        operations = self._deduplicate_operations(catalogs)
        graph_id = f"capability-graph:{claim_graph.request_id if claim_graph else 'runtime'}"
        return CapabilityGraph(
            id=graph_id,
            census_version=self.CENSUS_VERSION,
            providers=catalogs,
            operations=operations,
            audit=audits,
        )

    def select_claim_graph(
        self,
        capability_graph: CapabilityGraph,
        claim_graph: ClaimGraph | None,
        provider_hints: Iterable[str] = (),
    ) -> CapabilityGraph:
        """Apply claim-specific selection to an already captured census.

        Provider discovery is a side-effecting operation (network/API/schema
        calls).  The engine therefore performs it once before semantic
        compilation, then reuses the immutable catalog for claim selection.
        This keeps the LLM context and the execution audit tied to the same
        observed provider state.
        """
        hints = {str(value).strip() for value in provider_hints if str(value).strip()}
        audits: list[ProviderSelectionAudit] = []
        claims = claim_graph.claims if claim_graph is not None else []
        for catalog in capability_graph.providers:
            if not claims:
                audits.append(self._audit_without_claim(catalog, hints))
                continue
            for claim in claims:
                audits.append(self._audit_claim(catalog, claim, hints))
        graph_id = f"capability-graph:{claim_graph.request_id if claim_graph else 'runtime'}"
        return CapabilityGraph(
            id=graph_id,
            census_version=capability_graph.census_version,
            providers=list(capability_graph.providers),
            operations=list(capability_graph.operations),
            audit=audits,
        )

    def _discover(self, adapter: Any) -> ProviderCapabilityCatalog:
        provider_id = self._provider_id(adapter)
        try:
            if self._method_is_declared(adapter, "discover_full_capabilities"):
                catalog = adapter.discover_full_capabilities()
                if not isinstance(catalog, ProviderCapabilityCatalog):
                    raise TypeError("discover_full_capabilities returned an invalid catalog")
            else:
                catalog = self._catalog_from_descriptor(adapter)
        except Exception as error:
            return ProviderCapabilityCatalog(
                provider_id=provider_id,
                status="UNREACHABLE",
                details={"error": str(error)},
                completeness_semantics="unknown",
            )

        if not catalog.provider_id:
            catalog.provider_id = provider_id
        try:
            catalog = self._merge_descriptor(adapter, catalog)
            if not catalog.source_profiles and not catalog.details.get("suppress_schema_profile_fallback"):
                catalog.source_profiles = self._build_source_profiles(catalog)
            return catalog
        except Exception as error:
            catalog.details.setdefault("descriptor_error", str(error))
            if catalog.status == "ONLINE":
                catalog.status = "UNSUPPORTED"
            return catalog

    @staticmethod
    def _provider_id(adapter: Any) -> str:
        provider_id = getattr(adapter, "provider_id", None)
        if isinstance(provider_id, str) and provider_id.strip():
            return provider_id.strip()
        scope = getattr(adapter, "scope", None)
        scope_provider = getattr(scope, "provider_id", None)
        if isinstance(scope_provider, str) and scope_provider.strip():
            return scope_provider.strip()
        return type(adapter).__name__

    @staticmethod
    def _method_is_declared(adapter: Any, name: str) -> bool:
        return any(name in cls.__dict__ for cls in type(adapter).__mro__)

    def _catalog_from_descriptor(self, adapter: Any) -> ProviderCapabilityCatalog:
        descriptor: CapabilityDescriptor | None = None
        if self._method_is_declared(adapter, "get_capability_descriptor"):
            candidate = adapter.get_capability_descriptor()
            if isinstance(candidate, CapabilityDescriptor):
                descriptor = candidate
        versioned: VersionedCapabilityDescriptor | None = None
        if self._method_is_declared(adapter, "get_versioned_descriptor"):
            candidate = adapter.get_versioned_descriptor()
            if isinstance(candidate, VersionedCapabilityDescriptor):
                versioned = candidate

        if descriptor is not None:
            return ProviderCapabilityCatalog(
                provider_id=descriptor.provider_id,
                status="ONLINE",
                operations=list(descriptor.operations),
                partitions=self._partitions(descriptor.scopes),
            )
        if versioned is not None:
            return ProviderCapabilityCatalog(
                provider_id=versioned.provider_id,
                status="ONLINE",
                observable_fields=list(versioned.observable_fields),
                operations=list(versioned.operations),
                permissions=list(versioned.permissions),
                completeness_semantics=versioned.completeness_contract,
                partitions=self._partitions(versioned.scopes),
            )

        # Compatibility for legacy/custom adapters. They remain in the census,
        # but are claim-filtered only when they publish typed operation metadata.
        scope = getattr(adapter, "scope", None)
        scopes = (scope,) if isinstance(scope, ProviderScope) else ()
        return ProviderCapabilityCatalog(
            provider_id=self._provider_id(adapter),
            status="ONLINE",
            details={"descriptor_status": "LEGACY_UNTYPED"},
            partitions=self._partitions(scopes),
        )

    def _merge_descriptor(
        self,
        adapter: Any,
        catalog: ProviderCapabilityCatalog,
    ) -> ProviderCapabilityCatalog:
        descriptor: CapabilityDescriptor | None = None
        versioned: VersionedCapabilityDescriptor | None = None
        if self._method_is_declared(adapter, "get_capability_descriptor"):
            candidate = adapter.get_capability_descriptor()
            if isinstance(candidate, CapabilityDescriptor):
                descriptor = candidate
        if self._method_is_declared(adapter, "get_versioned_descriptor"):
            candidate = adapter.get_versioned_descriptor()
            if isinstance(candidate, VersionedCapabilityDescriptor):
                versioned = candidate

        if descriptor:
            if not catalog.operations:
                catalog.operations = list(descriptor.operations)
            for scope_id, partition in self._partitions(descriptor.scopes).items():
                catalog.partitions.setdefault(scope_id, partition)

        if versioned:
            if not catalog.operations:
                catalog.operations = list(versioned.operations)
            if not catalog.permissions:
                catalog.permissions = list(versioned.permissions)
            if not catalog.observable_fields:
                catalog.observable_fields = list(versioned.observable_fields)
            if catalog.completeness_semantics == "provider-defined":
                catalog.completeness_semantics = versioned.completeness_contract
            catalog.details.setdefault("descriptor_version", versioned.version)
            catalog.details.setdefault("deployment_env", versioned.deployment_env)
            for scope_id, partition in self._partitions(versioned.scopes).items():
                catalog.partitions.setdefault(scope_id, partition)

        if (
            not catalog.supported_evidence_types
            and descriptor
            and catalog.details.get("semantic_bindings_from_descriptor", True)
        ):
            catalog.supported_evidence_types = sorted(
                {
                    binding.evidence_requirement.value
                    for binding in descriptor.bindings
                }
            )
        return catalog

    @staticmethod
    def _partitions(scopes: Iterable[Any]) -> dict[str, dict[str, Any]]:
        partitions: dict[str, dict[str, Any]] = {}
        for index, scope in enumerate(scopes):
            scope_id = scope.scope_id or f"scope-{index + 1}"
            partitions[scope_id] = {
                "native_partition": dict(scope.native_partition),
                "coverage_start": scope.coverage_start,
                "coverage_end": scope.coverage_end,
                "retention_days": scope.retention_days,
                "known_gaps": [dict(value) for value in scope.known_gaps],
            }
        return partitions

    @staticmethod
    def _build_source_profiles(
        catalog: ProviderCapabilityCatalog,
    ) -> list[TelemetrySourceProfile]:
        """Build semantic-neutral profiles from provider census metadata.

        Providers with richer introspection may populate ``source_profiles``
        themselves. This fallback only records native schema identifiers and
        fields; it deliberately does not classify sourcetypes by name.
        """
        profiles: list[TelemetrySourceProfile] = []
        partitions = list(catalog.partitions) or ["default"]
        schemas = catalog.schemas or {}
        if schemas:
            for native_type, schema in schemas.items():
                if not isinstance(schema, dict):
                    continue
                names = schema.get("fields", [])
                fields = tuple(
                    TelemetryFieldProfile(
                        field_id=f"{catalog.provider_id}:{native_type}:field:{name}",
                        name=str(name),
                        primitive_type="unknown",
                    )
                    for name in names
                    if str(name).strip()
                )
                profiles.append(TelemetrySourceProfile(
                    source_id=f"{catalog.provider_id}:source:{native_type}",
                    provider_id=catalog.provider_id,
                    partition_id=partitions[0],
                    native_type=str(native_type),
                    event_count=schema.get("event_count"),
                    fields=fields,
                    retention_days=catalog.retention_days,
                    permissions=tuple(catalog.permissions),
                    query_primitives=("search", "table", "head"),
                ))
        elif catalog.observable_fields:
            fields = tuple(
                TelemetryFieldProfile(
                    field_id=f"{catalog.provider_id}:default:field:{name}",
                    name=str(name),
                    primitive_type="unknown",
                )
                for name in catalog.observable_fields
                if str(name).strip()
            )
            profiles.append(TelemetrySourceProfile(
                source_id=f"{catalog.provider_id}:source:default",
                provider_id=catalog.provider_id,
                partition_id=partitions[0],
                native_type="unknown",
                fields=fields,
                retention_days=catalog.retention_days,
                permissions=tuple(catalog.permissions),
                query_primitives=("search", "table", "head"),
            ))
        return profiles

    @staticmethod
    def _deduplicate_operations(
        catalogs: Iterable[ProviderCapabilityCatalog],
    ) -> list[ProviderOperation]:
        operations: list[ProviderOperation] = []
        seen: set[tuple[str, str]] = set()
        for catalog in catalogs:
            for operation in catalog.operations:
                key = (operation.provider_id, operation.id)
                if key in seen:
                    continue
                seen.add(key)
                operations.append(operation)
        return operations

    def _audit_without_claim(
        self,
        catalog: ProviderCapabilityCatalog,
        hints: set[str],
    ) -> ProviderSelectionAudit:
        if catalog.status != "ONLINE":
            return ProviderSelectionAudit(
                provider_id=catalog.provider_id,
                selected=False,
                reason="provider is unreachable",
                status=catalog.status,
            )
        if hints and catalog.provider_id not in hints:
            return ProviderSelectionAudit(
                provider_id=catalog.provider_id,
                selected=False,
                reason="provider excluded by request provider hints",
                status="UNSUPPORTED",
            )
        return ProviderSelectionAudit(
            provider_id=catalog.provider_id,
            selected=True,
            reason="provider is online; no ClaimGraph was available for relevance filtering",
            status=catalog.status,
        )

    def _audit_claim(
        self,
        catalog: ProviderCapabilityCatalog,
        claim: Claim,
        hints: set[str],
    ) -> ProviderSelectionAudit:
        if catalog.status != "ONLINE":
            return ProviderSelectionAudit(
                provider_id=catalog.provider_id,
                selected=False,
                reason="provider is unreachable",
                status=catalog.status,
                claim_id=claim.id,
            )
        if hints and catalog.provider_id not in hints:
            return ProviderSelectionAudit(
                provider_id=catalog.provider_id,
                selected=False,
                reason="provider excluded by request provider hints",
                status="UNSUPPORTED",
                claim_id=claim.id,
            )

        matches = [
            requirement
            for requirement in claim.observation_requirements
            if self._supports(catalog, requirement, target_entity_type=claim.value_type)
        ]
        if matches:
            kinds = ", ".join(sorted({requirement.fact_kind for requirement in matches}))
            partial = any(
                (requirement.required_roles or requirement.field_roles)
                and not any(
                    set(requirement.required_roles or requirement.field_roles).issubset(
                        set(operation.output_roles)
                    )
                    for operation in catalog.operations
                    if requirement.fact_kind in operation.output_fact_kinds
                )
                for requirement in matches
            )
            return ProviderSelectionAudit(
                provider_id=catalog.provider_id,
                selected=True,
                reason=(
                    f"provider can observe required fact kinds: {kinds}"
                    + (" (partial role coverage; residuals remain)" if partial else "")
                ),
                status=catalog.status,
                claim_id=claim.id,
            )
        return ProviderSelectionAudit(
            provider_id=catalog.provider_id,
            selected=False,
            reason="provider cannot satisfy this claim's observation requirements",
            status="UNSUPPORTED",
            claim_id=claim.id,
        )

    @staticmethod
    def _supports(
        catalog: ProviderCapabilityCatalog,
        requirement: ClaimEvidenceRequirement,
        *,
        target_entity_type: str | None = None,
    ) -> bool:
        if catalog.status != "ONLINE":
            return False

        required_roles = {
            str(role).casefold()
            for role in (requirement.required_roles or requirement.field_roles)
            if str(role).strip()
        }
        required_fields = {field.casefold() for field in requirement.required_fields}
        candidate_operations = [
            operation
            for operation in catalog.operations
            if requirement.fact_kind in operation.output_fact_kinds
        ]
        if not candidate_operations:
            return False
        # A provider may satisfy only part of a compound claim (for example,
        # it can bind a person to an email but cannot prove the qualifier
        # "personal").  That is still executable evidence and must not be
        # rejected before the query runs; the verifier will retain the
        # uncovered role as UNOBSERVABLE/INCONCLUSIVE.
        if required_roles:
            if any(
                required_roles.intersection({role.casefold() for role in operation.output_roles})
                or (
                    target_entity_type
                    and str(target_entity_type).casefold()
                    in {kind.casefold() for kind in operation.output_entity_kinds}
                )
                for operation in candidate_operations
            ):
                return True
        if required_fields and not any(
            required_fields.issubset(
                {field.casefold() for field in operation.output_fields}
            )
            for operation in candidate_operations
        ):
            return False

        observable = {field.casefold() for field in catalog.observable_fields}
        if required_fields and not required_fields.issubset(observable):
            return False
        if requirement.completeness_required and not any(
            operation.completeness.strip() or operation.limit_semantics.strip()
            for operation in candidate_operations
        ):
            return False
        return True


__all__ = ["ProviderCensusService"]
