"""Materialize probed source mappings as executable provider operations."""
from __future__ import annotations

from typing import Any

from hunting.contracts.queries import ProviderOperation, RetrievalPolicy, RetrievalStage
from hunting.contracts.source_profile import (
    RuntimeCapability,
    SourceCapabilityProposal,
    TelemetrySourceProfile,
)


def _native_names(profile: TelemetrySourceProfile, field_ids: Any) -> tuple[str, ...]:
    names: list[str] = []
    for field_id in field_ids or ():
        field = profile.field(str(field_id))
        if field is not None:
            native_name = field.parent_field if field.origin == "nested_payload" and field.parent_field else field.name
            if native_name not in names:
                names.append(native_name)
    return tuple(names)


def _role_names(profile: TelemetrySourceProfile, mapping: dict[str, str]) -> dict[str, tuple[str, ...]]:
    return {
        role: _native_names(profile, (field_id,))
        for role, field_id in mapping.items()
    }


def materialize_runtime_operation(
    proposal: SourceCapabilityProposal,
    profile: TelemetrySourceProfile,
    requirement: dict[str, Any],
    capability: RuntimeCapability,
) -> ProviderOperation | None:
    """Create one planner operation from a successfully probed mapping."""
    if capability.status != "VALIDATED":
        return None
    if capability.provider_id != profile.provider_id or proposal.source_id != profile.source_id:
        return None

    input_bindings = _role_names(profile, proposal.input_roles)
    output_bindings = _role_names(profile, proposal.output_roles)
    output_fields = tuple(dict.fromkeys(
        field
        for values in (*input_bindings.values(), *output_bindings.values())
        for field in values
    ))
    object_fields = tuple(dict.fromkeys(
        field
        for role, values in output_bindings.items()
        if not proposal.projection_roles or role in proposal.projection_roles
        for field in values
    ))
    if not object_fields:
        object_fields = tuple(dict.fromkeys(
            field for values in output_bindings.values() for field in values
        ))
    allow_scope_explore = bool(requirement.get("allow_scope_explore"))
    if (not input_bindings and not allow_scope_explore) or not output_bindings or not object_fields:
        return None

    nested_field_bindings: dict[str, dict[str, str]] = {}
    for role, field_id in {**proposal.input_roles, **proposal.output_roles}.items():
        field = profile.field(field_id)
        if field is not None and field.origin == "nested_payload":
            nested_field_bindings[role] = {
                "field_id": field_id,
                "field": field.parent_field or "_raw",
                "key": field.nested_key or field.name,
                "transform": proposal.field_transforms.get(field_id, "extract_nested_key"),
            }

    retrieval_policy = None
    if capability.relaxable_constraint_keys:
        retrieval_policy = RetrievalPolicy(
            stages=(
                RetrievalStage("narrow", (), "retrieval_only", "apply validated retrieval predicates"),
                RetrievalStage(
                    "base_relation",
                    capability.relaxable_constraint_keys,
                    "retrieval_only",
                    "remove validated retrieval-only predicates after complete-empty",
                ),
            ),
            max_attempts=2,
        )

    subject_type = str(requirement.get("subject_type", "entity")).strip().lower() or "entity"
    object_type = str(requirement.get("object_type", "entity")).strip().lower() or "entity"
    return ProviderOperation(
        id=capability.capability_id,
        provider_id=profile.provider_id,
        scope_ids=(profile.partition_id,),
        params_schema={
            "window": "interval",
            "input_bindings": "object",
            "output_bindings": "object",
            "runtime_capability": "object",
        },
        pagination="offset",
        limit_semantics="complete only on EOF",
        input_entity_kinds=("ANY",) if allow_scope_explore and not input_bindings else (subject_type,),
        output_entity_kinds=(object_type,),
        output_fields=output_fields,
        guaranteed_relations=(),
        input_roles=tuple(input_bindings),
        output_roles=tuple(output_bindings),
        native_field_bindings=input_bindings,
        output_value_bindings={"object": object_fields},
        output_binding_entity_kinds={"object": object_type},
        supported_constraints=capability.supported_constraints,
        searchable_constraints=capability.searchable_constraints,
        constraint_mappings=tuple(mapping.to_dict() for mapping in capability.constraint_mappings),
        retrieval_policy=retrieval_policy,
        allow_constraint_relaxation=False,
        proof_mode=capability.proof_mode,
        schema_fingerprint=capability.schema_fingerprint,
        temporal_roles=_role_names(profile, capability.temporal_roles),
        action_roles=_role_names(profile, capability.action_roles),
        state_roles=_role_names(profile, capability.state_roles),
        artifact_identity_roles=_role_names(profile, capability.artifact_identity_roles),
        correlation_roles=_role_names(profile, capability.correlation_roles),
        query_builder="runtime.source_profile.v1",
        completeness="limit+1 EOF proof",
        expected_cost=1,
        runtime_source_id=profile.source_id,
        nested_field_bindings=nested_field_bindings,
        route_goal_ids=(str(requirement.get("goal_id", "")).strip(),)
        if str(requirement.get("goal_id", "")).strip() else (),
        route_class="EXECUTABLE",
        # Only the deterministic admission result can grant PROVE.  A
        # proposal's requested proof mode, provider relation name, or LLM
        # narrative is not sufficient authority.
        route_mode=(
            "PROVE"
            if (
                str(getattr(capability, "capability_level", "")).upper() == "PROOF_CAPABLE"
                and bool(getattr(capability, "proof_contract_id", None))
            )
            else "EXPLORE"
        ),
        proof_contract_id=(
            capability.proof_contract_id
            if (
                str(getattr(capability, "capability_level", "")).upper() == "PROOF_CAPABLE"
                and bool(getattr(capability, "proof_contract_id", None))
            )
            else None
        ),
        discovery_provenance=("F2_C2_PROBED_CAPABILITY",),
    )


__all__ = ["materialize_runtime_operation"]
