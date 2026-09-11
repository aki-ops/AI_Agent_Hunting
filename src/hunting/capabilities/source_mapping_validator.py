"""Deterministic validation of LLM source-capability proposals."""
from __future__ import annotations

from hunting.contracts.source_profile import (
    ProbeSpec,
    RuntimeCapability,
    SourceCapabilityProposal,
    TelemetrySourceProfile,
)


class SourceMappingValidator:
    """Validate references and policy; never infer semantics from names."""

    def validate(
        self,
        proposal: SourceCapabilityProposal,
        profiles: list[TelemetrySourceProfile] | tuple[TelemetrySourceProfile, ...],
    ) -> tuple[bool, tuple[str, ...], ProbeSpec | None]:
        profile = next((item for item in profiles if item.source_id == proposal.source_id), None)
        if profile is None:
            return False, ("source_id_not_in_census",), None

        fields = {item.field_id for item in profile.fields}
        if any(not str(role).strip() or not str(field_id).strip()
               for mapping in (proposal.input_roles, proposal.output_roles)
               for role, field_id in mapping.items()):
            return False, ("role_or_field_binding_is_empty",), None
        referenced = set(proposal.input_roles.values()) | set(proposal.output_roles.values()) | {
            field_id for mapping in (
                proposal.temporal_roles,
                proposal.action_roles,
                proposal.state_roles,
                proposal.artifact_identity_roles,
                proposal.correlation_roles,
            ) for field_id in mapping.values()
        }
        missing = sorted(field for field in referenced if field not in fields)
        if missing:
            return False, (f"field_id_not_in_census:{','.join(missing)}",), None
        if not proposal.input_roles and not proposal.output_roles:
            return False, ("proposal_has_no_field_bindings",), None
        if proposal.probe_kind not in {"cooccurrence", "schema", "value_presence", "temporal"}:
            return False, ("unsupported_probe_kind",), None
        if proposal.proof_mode == "relation_observable" and not proposal.output_roles:
            return False, ("relation_probe_requires_output_role",), None
        if set(proposal.relaxable_constraint_keys) - set(proposal.searchable_constraints):
            return False, ("relaxable_constraint_not_searchable",), None
        all_roles = {
            field_id for mapping in (
                proposal.temporal_roles,
                proposal.action_roles,
                proposal.state_roles,
                proposal.artifact_identity_roles,
                proposal.correlation_roles,
            ) for field_id in mapping.values()
        }
        missing_roles = sorted(field_id for field_id in all_roles if field_id not in fields)
        if missing_roles:
            return False, (f"role_field_id_not_in_census:{','.join(missing_roles)}",), None

        probe = ProbeSpec(
            source_id=proposal.source_id,
            kind=proposal.probe_kind,
            field_ids=tuple(sorted(referenced)),
            max_rows=20,
            timeout_seconds=10,
        )
        return True, (), probe

    def materialize(
        self,
        proposal: SourceCapabilityProposal,
        profile: TelemetrySourceProfile,
        *,
        probe_query_id: str | None = None,
        probe_succeeded: bool = False,
        diagnostics: tuple[str, ...] = (),
    ) -> RuntimeCapability:
        status = "VALIDATED" if probe_succeeded else "CANDIDATE"
        capability_id = (
            f"runtime:{profile.provider_id}:{profile.schema_fingerprint}:"
            f"{proposal.source_id}:{proposal.relation}"
        )
        return RuntimeCapability(
            capability_id=capability_id,
            source_id=proposal.source_id,
            provider_id=profile.provider_id,
            relation=proposal.relation,
            input_roles=proposal.input_roles,
            output_roles=proposal.output_roles,
            status=status,
            proof_mode=proposal.proof_mode,
            schema_fingerprint=profile.schema_fingerprint,
            supported_constraints=proposal.supported_constraints,
            searchable_constraints=proposal.searchable_constraints,
            temporal_roles=proposal.temporal_roles,
            action_roles=proposal.action_roles,
            state_roles=proposal.state_roles,
            artifact_identity_roles=proposal.artifact_identity_roles,
            correlation_roles=proposal.correlation_roles,
            relaxable_constraint_keys=proposal.relaxable_constraint_keys,
            probe_query_id=probe_query_id,
            diagnostics=diagnostics,
        )


__all__ = ["SourceMappingValidator"]
