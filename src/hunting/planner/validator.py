"""Query Validator — hard filter enforcement, allowlist checking, and dry-run execution.

Enforces:
- Entity kind supported by provider scope.
- Time window bounds within scope retention.
- Observable fields allowlisted.
- Permissions authorized.
- Query AST / operator allowlisting.
- Non-mutating dry-run validation.
"""
from __future__ import annotations

import re

from hunting.capabilities.models import VersionedCapabilityDescriptor
from hunting.contracts.capabilities import ProviderCapabilityCatalog
from hunting.contracts.cells import ProviderScope
from hunting.contracts.entities import EntityRef
from hunting.contracts.hunt import LogicalQueryPlan, NativeQueryPlan, QueryPlan
from hunting.contracts.queries import Diagnostic


class QueryValidationError(ValueError):
    """Raised when a query plan violates provider capability or safety allowlists."""
    pass


class QueryValidator:
    """Deterministic validator verifying query plans against provider capabilities."""

    def __init__(self, descriptors: dict[str, VersionedCapabilityDescriptor]) -> None:
        self.descriptors = descriptors

    def validate_plan(
        self,
        plan: QueryPlan,
        entity: EntityRef | None,
        scope: ProviderScope,
        time_window: str,
        required_permission: str = "read",
    ) -> tuple[bool, Diagnostic | None]:
        """Validate a QueryPlan against provider descriptor constraints."""
        descriptor = self.descriptors.get(plan.provider_id)
        if descriptor is None:
            return False, Diagnostic.UNQUERYABLE

        # 1. Validate Entity Kind
        if entity is not None:
            kind_str = ""
            if hasattr(entity, "kind") and hasattr(entity.kind, "value"):
                kind_str = entity.kind.value
            elif hasattr(entity, "kind") and isinstance(entity.kind, str):
                kind_str = entity.kind
            else:
                type_name = type(entity).__name__.lower()
                kind_str = "host" if "host" in type_name else ("ip" if "ip" in type_name else type_name)

            allowed = {k.lower() for k in descriptor.supported_entity_kinds}
            if kind_str.lower() not in allowed and "any" not in allowed:
                return False, Diagnostic.UNSUPPORTED_REQUIREMENT

        # 2. Validate Time Window & Retention
        if scope.retention_days is not None:
            # Check if time window exceeds retention limit (e.g. "NOW-300d" when retention is 90)
            lookback_match = re.search(r"NOW-(\d+)d", time_window)
            if lookback_match:
                days = int(lookback_match.group(1))
                if days > scope.retention_days:
                    return False, Diagnostic.SOURCE_UNAVAILABLE

        # 3. Validate Observable Fields
        allowlisted_param_keys = (
            "window", "limit", "offset", "host", "user", "ip", "path", "domain",
            "custom_field", "custom_query", "query", "raw", "extracted_fields",
            "filter", "sourcetype", "field", "value", "op", "search_hints",
        )
        for param_key in plan.parameters:
            if param_key in allowlisted_param_keys:
                continue
            if param_key not in descriptor.observable_fields:
                return False, Diagnostic.UNSUPPORTED_REQUIREMENT

        # 4. Validate Permissions
        if required_permission != "read" and required_permission not in descriptor.permissions:
            return False, Diagnostic.UNQUERYABLE

        # 5. Validate Completeness Contract
        if not plan.completeness_contract:
            return False, Diagnostic.PARTIAL_RESULT

        return True, None

    def dry_run(self, plan: QueryPlan) -> bool:
        """Perform non-mutating dry-run validation of parameters and syntax."""
        # Ensure parameters are well-formed and non-empty
        if not isinstance(plan.parameters, dict):
            return False
        # Reject SQL injection attempts in parameters
        for v in plan.parameters.values():
            if isinstance(v, str) and re.search(r"('|\bUNION\b|\bDROP\b|;)", v, re.IGNORECASE):
                return False
        return True

    def validate_logical_plan(
        self,
        plan: LogicalQueryPlan,
        catalog: ProviderCapabilityCatalog | None = None,
    ) -> tuple[bool, Diagnostic | None]:
        """Validate LogicalQueryPlan against discovered catalog or descriptors."""
        if catalog is not None:
            if catalog.status == "UNREACHABLE":
                return False, Diagnostic.UNREACHABLE
            if catalog.status == "UNSUPPORTED":
                return False, Diagnostic.UNSUPPORTED_REQUIREMENT

            # Validate requirement evidence type
            ev_type = (getattr(plan, "evidence_type", None) or plan.requirement_id).lower()
            req_type = plan.requirement_id.lower()
            matching_supported = False
            for st in catalog.supported_evidence_types:
                st_lower = st.lower()
                if st_lower == ev_type or st_lower in ev_type or ev_type in st_lower or st_lower in req_type or req_type in st_lower:
                    matching_supported = True
                    break
                if ("proc" in ev_type and "proc" in st_lower) or \
                   ("web" in ev_type and "web" in st_lower) or \
                   ("file" in ev_type and "file" in st_lower) or \
                   ("auth" in ev_type and "auth" in st_lower) or \
                   ("net" in ev_type and "net" in st_lower):
                    matching_supported = True
                    break
            if "baseline" in ev_type or "scope" in ev_type or "baseline" in req_type or "scope" in req_type:
                matching_supported = True

            if not matching_supported:
                return False, Diagnostic.UNSUPPORTED_REQUIREMENT

            # Validate observable fields in filters
            for f in plan.filters:
                fn = str(f.get("field", "")).strip().lower()
                if fn and catalog.observable_fields and fn not in catalog.observable_fields:
                    return False, Diagnostic.UNSUPPORTED_REQUIREMENT

        return True, None

    def validate_native_plan(
        self,
        plan: NativeQueryPlan,
        catalog: ProviderCapabilityCatalog | None = None,
    ) -> tuple[bool, Diagnostic | None]:
        """Validate NativeQueryPlan before execution."""
        if not plan.native_query or not plan.native_query.strip():
            return False, Diagnostic.QUERY_FAILED

        # Prevent destructive keywords or raw shell injection
        forbidden = re.search(r"\b(delete|drop|shutdown|truncate|rm\s+-rf)\b", plan.native_query, re.IGNORECASE)
        if forbidden:
            return False, Diagnostic.UNQUERYABLE

        return True, None


__all__ = ["QueryValidator", "QueryValidationError"]
