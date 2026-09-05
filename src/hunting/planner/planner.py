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

import json
import re
from typing import Any, Callable

from hunting.capabilities.models import VersionedCapabilityDescriptor
from hunting.capabilities.registry import build_default_capability_registry
from hunting.contracts.capabilities import ProviderCapabilityCatalog
from hunting.contracts.cells import ProviderScope
from hunting.contracts.entities import ANY, AnyEntity, EntityRef
from hunting.contracts.hunt import (
    EvidenceRequirementV4,
    LogicalQueryPlan,
    NativeQueryPlan,
    QueryPlan,
    RequirementStatus,
)
from hunting.contracts.queries import Diagnostic
from hunting.planner.cache import PlanCache
from hunting.planner.compiler import (
    CdbQueryCompiler,
    NativeQueryCompiler,
    SplunkQueryCompiler,
)
from hunting.planner.templates import QueryTemplate, build_default_query_templates
from hunting.planner.validator import QueryValidator


def parse_llm_query_output(raw: str) -> dict[str, Any]:
    """Parse raw LLM output into structured query parameters, filters, and predicates."""
    if not raw:
        return {}
    clean = raw.strip()
    if clean.startswith("```"):
        lines = clean.splitlines()
        if lines and lines[0].startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip() == "```":
            lines = lines[:-1]
        clean = "\n".join(lines).strip()

    parsed_params: dict[str, Any] = {
        "raw": clean,
        "query": clean,
        "custom_field": clean,
    }

    if clean.startswith("{") and clean.endswith("}"):
        try:
            data = json.loads(clean)
            if isinstance(data, dict):
                for k, v in data.items():
                    parsed_params[k] = v
                if "query" in data:
                    parsed_params["query"] = data["query"]
                    parsed_params["custom_field"] = data["query"]
                if "filter" in data:
                    parsed_params["filter"] = data["filter"]
                if "field" in data and "value" in data:
                    parsed_params["field"] = data["field"]
                    parsed_params["value"] = data["value"]
                    parsed_params["op"] = data.get("op", "EQUALS")
                return parsed_params
        except Exception:
            pass

    kv_pattern = re.compile(r'(\b[A-Za-z_][A-Za-z0-9_]*)\s*=\s*(?:"([^"]*)"|\'([^\']*)\'|([^\s\(\)]+))')
    matches = kv_pattern.findall(clean)
    if matches:
        extracted_kv = {}
        for m in matches:
            k = m[0]
            v = m[1] or m[2] or m[3]
            extracted_kv[k] = v
        if extracted_kv:
            parsed_params["extracted_fields"] = extracted_kv

    return parsed_params


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
        effective_ev_type = requirement.evidence_type
        if effective_ev_type not in self.templates and requirement.semantic_intent:
            SEMANTIC_TO_TYPE = {
                "web_request_activity": "web_request",
                "server_side_execution": "process_ancestry",
                "process_execution": "process_ancestry",
                "file_artifact": "file_modification",
                "remote_authentication": "authentication_activity",
                "network_c2_communication": "network_connection",
                "dns_resolution": "dns_activity",
                "operational_baseline": "scope_records",
            }
            effective_ev_type = SEMANTIC_TO_TYPE.get(requirement.semantic_intent, effective_ev_type)

        template = self.templates.get(effective_ev_type)
        if template is not None:
            # Populate parameters from entity and window
            params: dict[str, str | int] = {}
            if requirement.search_hints:
                params["search_hints"] = list(requirement.search_hints)
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
            requirement.status = RequirementStatus.PLANNED
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
            # Parse parameters using structured parser
            parsed_llm = parse_llm_query_output(raw_gen)
            params = {"window": time_window}
            params.update(parsed_llm)
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

            requirement.status = RequirementStatus.PLANNED
            return plan, None

        # Missing capability -> explicit unsupported
        return None, Diagnostic.UNSUPPORTED_REQUIREMENT

    def plan_logical_query(
        self,
        requirement: EvidenceRequirementV4,
        entity: EntityRef | None,
        scope: ProviderScope,
        time_window: str,
        catalog: ProviderCapabilityCatalog | None = None,
        query_id: str = "lqp-001",
        custom_constraints: dict[str, Any] | None = None,
    ) -> tuple[LogicalQueryPlan | None, Diagnostic | None]:
        """Generate provider-neutral LogicalQueryPlan."""
        ev_type = requirement.evidence_type.lower()
        data_sources: list[dict[str, Any]] = []
        if scope.provider_id == "splunk":
            st = None
            if "web" in ev_type:
                st = '(sourcetype="stream:http" OR sourcetype="iis")'
            elif "process" in ev_type:
                st = "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
            elif "file" in ev_type:
                st = "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
            elif "net" in ev_type:
                st = "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
            elif "auth" in ev_type:
                st = "WinEventLog:Security"
            elif "dns" in ev_type:
                st = "stream:dns"
            index = getattr(scope, "native_partition", {}).get("index", "botsv1") if hasattr(scope, "native_partition") else "botsv1"
            data_sources.append({"index": index, "sourcetype": st})
        else:
            data_sources.append({"table": ev_type})

        filters: list[dict[str, Any]] = []
        constraints: dict[str, Any] = {}
        if custom_constraints:
            constraints.update(custom_constraints)
            if "field" in custom_constraints and "value" in custom_constraints:
                filters.append({
                    "field": custom_constraints["field"],
                    "op": custom_constraints.get("op", "EQUALS"),
                    "value": custom_constraints["value"],
                })
            if "extracted_fields" in custom_constraints and isinstance(custom_constraints["extracted_fields"], dict):
                for fk, fv in custom_constraints["extracted_fields"].items():
                    filters.append({
                        "field": fk,
                        "op": "CONTAINS" if "*" in str(fv) else "EQUALS",
                        "value": str(fv).strip("*"),
                    })
        if requirement.predicate is not None:
            p = requirement.predicate
            op_str = p.op.name if hasattr(p.op, "name") else str(p.op)
            filters.append({
                "field": p.field,
                "op": op_str,
                "value": p.value,
            })
            if p.field.lower() in ("site", "domain") and p.value:
                constraints["domain"] = p.value

        if getattr(requirement, "entity_scope", None) and hasattr(requirement.entity_scope, "name"):
            constraints.setdefault("domain", getattr(requirement.entity_scope, "name"))

        if getattr(requirement, "search_hints", None):
            constraints["search_hints"] = list(requirement.search_hints)
            if "domain" not in constraints:
                for h in requirement.search_hints:
                    if "." in str(h) and not str(h).startswith("*"):
                        constraints["domain"] = str(h)
                        break

        is_targeted = entity is not None and not isinstance(entity, (AnyEntity, type(ANY)))
        fields = list(getattr(requirement, "required_fields", [])) or ["timestamp", "host", "user"]

        logical_plan = LogicalQueryPlan(
            id=query_id,
            requirement_id=requirement.id,
            provider=scope.provider_id,
            scope=scope.scope_id,
            data_sources=data_sources,
            filters=filters,
            fields=fields,
            entity=entity,
            time_window=time_window,
            constraints=constraints,
            limit=100,
            is_targeted=is_targeted,
            evidence_type=requirement.evidence_type,
        )

        valid, diag = self.validator.validate_logical_plan(logical_plan, catalog)
        if not valid:
            return None, diag

        return logical_plan, None

    def compile_native_query(
        self,
        logical_plan: LogicalQueryPlan,
        compiler: NativeQueryCompiler | None = None,
        catalog: ProviderCapabilityCatalog | None = None,
    ) -> tuple[NativeQueryPlan | None, Diagnostic | None]:
        """Compile LogicalQueryPlan to provider NativeQueryPlan."""
        if compiler is None:
            if logical_plan.provider == "splunk":
                compiler = SplunkQueryCompiler()
            else:
                compiler = CdbQueryCompiler()

        try:
            native_plan = compiler.compile(logical_plan)
        except Exception:
            return None, Diagnostic.QUERY_FAILED

        valid, diag = self.validator.validate_native_plan(native_plan, catalog)
        if not valid:
            return None, diag

        return native_plan, None


__all__ = ["CanonicalQueryPlanner"]
