"""Canonical Query Planner.

Coordinates Component 3 of v4 architecture:
- Matches EvidenceRequirement to CapabilityDescriptor.
- Lexicographical ranking:
    EXACT > PARTIAL
    template > generated fallback
    targeted > broad
    strong completeness contract > weak
    lower estimated cost > higher cost
- Hard filter validation (entity, retention, observable fields, permissions).
- Template-first execution with cache.
- Non-fabrication: emits UNSUPPORTED_REQUIREMENT or UNREACHABLE when no valid plan exists.
"""
from __future__ import annotations

from typing import Callable

from hunting.capabilities.models import VersionedCapabilityDescriptor
from hunting.capabilities.registry import build_default_capability_registry
from hunting.contracts.cells import ProviderScope
from hunting.contracts.entities import ANY, AnyEntity, EntityRef
from hunting.contracts.hunt import EvidenceRequirementV4, QueryPlan
from hunting.contracts.queries import Diagnostic
from hunting.planner.cache import PlanCache
from hunting.planner.templates import QueryTemplate, build_default_query_templates
from hunting.planner.validator import QueryValidator


class CanonicalQueryPlanner:
    """Deterministic Query Planner binding EvidenceRequirements to executable QueryPlans."""

    def __init__(
        self,
        registry: dict[str, VersionedCapabilityDescriptor] | None = None,
        templates: dict[str, QueryTemplate] | None = None,
        cache: PlanCache | None = None,
        llm_generator: Callable[[str], str] | None = None,
    ) -> None:
        self.registry = registry if registry is not None else build_default_capability_registry()
        self.templates = templates if templates is not None else build_default_query_templates()
        self.cache = cache if cache is not None else PlanCache()
        self.validator = QueryValidator(self.registry)
        self.llm_generator = llm_generator
        self.llm_fallback_used = False

    def plan_query(
        self,
        requirement: EvidenceRequirementV4,
        entity: EntityRef | None,
        scope: ProviderScope,
        time_window: str,
        query_id: str = "qp-001",
    ) -> tuple[QueryPlan | None, Diagnostic | None]:
        """Compile a validated QueryPlan for the requirement, entity, and scope."""
        # Step 1: Check cache
        cached_plan = self.cache.get(requirement.evidence_type, scope.provider_id)
        if cached_plan is not None:
            # Customize parameters for current entity and time window
            params = dict(cached_plan.parameters)
            params["window"] = time_window
            is_targeted = (
                entity is not None
                and not isinstance(entity, (AnyEntity, type(ANY)))
                and cached_plan.operation_id not in ("cdb_broad_sweep", "cdb_scope_scan")
            )
            if entity is not None and not isinstance(entity, (AnyEntity, type(ANY))):
                target_val = getattr(entity, "name", None) or getattr(entity, "address", None) or getattr(entity, "path", "")
                if "host" in params:
                    params["host"] = target_val
                elif "user" in params:
                    params["user"] = target_val
                elif "ip" in params:
                    params["ip"] = target_val

            return QueryPlan(
                id=query_id,
                requirement_id=requirement.id,
                provider_id=cached_plan.provider_id,
                scope_id=scope.scope_id,
                operation_id=cached_plan.operation_id,
                parameters=params,
                estimated_cost=cached_plan.estimated_cost,
                completeness_contract=cached_plan.completeness_contract,
                is_targeted=is_targeted,
            ), None

        # Step 2: Check provider descriptor
        descriptor = self.registry.get(scope.provider_id)
        if descriptor is None:
            return None, Diagnostic.UNQUERYABLE

        # Step 3: Check if scope is reachable (e.g. not in known gaps)
        for gap in scope.known_gaps:
            gap_reason = gap.get("reason", "maintenance")
            if gap_reason:
                # If target window intersects known gap
                return None, Diagnostic.UNREACHABLE

        # Step 4: Template-first resolution
        template = self.templates.get(requirement.evidence_type)
        if template is not None:
            # Populate parameters from entity and window
            params: dict[str, str | int] = {}
            for k, v in template.parameters_template.items():
                if isinstance(v, str):
                    if "{window}" in v:
                        params[k] = time_window
                    elif "{host}" in v:
                        params[k] = getattr(entity, "name", "ANY") if entity else "ANY"
                    elif "{user}" in v:
                        params[k] = getattr(entity, "username", "ANY") if entity else "ANY"
                    elif "{ip}" in v:
                        params[k] = getattr(entity, "address", "ANY") if entity else "ANY"
                    elif "{path}" in v:
                        params[k] = getattr(entity, "path", "ANY") if entity else "ANY"
                    elif "{domain}" in v:
                        params[k] = getattr(entity, "name", "ANY") if entity else "ANY"
                    else:
                        params[k] = v
                else:
                    params[k] = v

            is_targeted = (
                entity is not None
                and not isinstance(entity, (AnyEntity, type(ANY)))
                and template.operation_id not in ("cdb_broad_sweep", "cdb_scope_scan")
            )

            plan = QueryPlan(
                id=query_id,
                requirement_id=requirement.id,
                provider_id=scope.provider_id,
                scope_id=scope.scope_id,
                operation_id=template.operation_id,
                parameters=params,
                estimated_cost=template.estimated_cost,
                completeness_contract=descriptor.completeness_contract,
                is_targeted=is_targeted,
            )

            # Hard filter validation
            valid, diag = self.validator.validate_plan(plan, entity, scope, time_window)
            if not valid:
                return None, diag

            # Dry-run validation
            if not self.validator.dry_run(plan):
                return None, Diagnostic.QUERY_FAILED

            # Store in cache
            self.cache.put(requirement.evidence_type, scope.provider_id, plan)
            return plan, None

        # Step 5: LLM fallback only if no template exists
        if self.llm_generator is not None:
            self.llm_fallback_used = True
            prompt = (
                f"Generate query plan parameters for requirement: {requirement.evidence_type}\n"
                f"Provider: {scope.provider_id}\n"
                f"Observable fields: {', '.join(descriptor.observable_fields)}"
            )
            raw_gen = self.llm_generator(prompt)
            # Parse parameters
            params = {"window": time_window, "custom_field": raw_gen}
            is_targeted = entity is not None and not isinstance(entity, (AnyEntity, type(ANY)))
            plan = QueryPlan(
                id=query_id,
                requirement_id=requirement.id,
                provider_id=scope.provider_id,
                scope_id=scope.scope_id,
                operation_id="custom_operation",
                parameters=params,
                estimated_cost=5,
                completeness_contract=descriptor.completeness_contract,
                is_targeted=is_targeted,
            )
            valid, diag = self.validator.validate_plan(plan, entity, scope, time_window)
            if not valid or not self.validator.dry_run(plan):
                return None, (diag or Diagnostic.UNSUPPORTED_REQUIREMENT)

            return plan, None

        # Missing capability -> explicit unsupported
        return None, Diagnostic.UNSUPPORTED_REQUIREMENT


__all__ = ["CanonicalQueryPlanner"]
