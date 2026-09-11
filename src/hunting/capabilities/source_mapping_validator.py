"""Deterministic validation of LLM source-capability proposals."""
from __future__ import annotations

from hunting.contracts.source_profile import (
    ProbeSpec,
    RuntimeCapability,
    SourceCapabilityProposal,
    TelemetrySourceProfile,
)
from hunting.registry.proof_contract_registry import (
    ProofContractRegistry,
    get_default_proof_contract_registry,
)


class SourceMappingValidator:
    """Validate references and policy; never infer semantics from names."""

    def __init__(self, registry: ProofContractRegistry | None = None) -> None:
        self.registry = registry or get_default_proof_contract_registry()

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
        if proposal.proof_mode in {"relation_observable", "proof_capable"} and not proposal.output_roles:
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

        # Resolve field IDs to native names using profile fields
        field_id_to_native = {f.field_id: f.name for f in profile.fields}
        resolved_input_roles = {
            r: field_id_to_native.get(fid, fid) for r, fid in proposal.input_roles.items()
        }
        resolved_output_roles = {
            r: field_id_to_native.get(fid, fid) for r, fid in proposal.output_roles.items()
        }
        resolved_action_roles = {
            r: field_id_to_native.get(fid, fid) for r, fid in proposal.action_roles.items()
        }
        resolved_state_roles = {
            r: field_id_to_native.get(fid, fid) for r, fid in proposal.state_roles.items()
        }
        resolved_artifact_roles = {
            r: field_id_to_native.get(fid, fid) for r, fid in proposal.artifact_identity_roles.items()
        }

        # Gated by human-approved ProofContractRegistry:
        contract, rejection_reasons = self.registry.find_matching_contract(
            relation=proposal.relation,
            input_roles=resolved_input_roles,
            output_roles=resolved_output_roles,
            action_roles=resolved_action_roles,
            state_roles=resolved_state_roles,
            artifact_identity_roles=resolved_artifact_roles,
        )

        diag_list = list(diagnostics)
        if contract is not None and probe_succeeded:
            effective_proof_mode = "relation_observable"
            effective_contract_id = contract.contract_id
            effective_capability_level = "PROOF_CAPABLE"
        else:
            effective_proof_mode = "retrieval_only"
            effective_contract_id = None
            effective_capability_level = "RETRIEVAL_CAPABLE"
            if proposal.probe_kind == "cooccurrence":
                diag_list.append("cooccurrence_probe_cannot_grant_proof")
            if proposal.proof_mode in {"relation_observable", "proof_capable"}:
                if not probe_succeeded:
                    diag_list.append("probe_pending_or_unsuccessful")
                else:
                    diag_list.extend(rejection_reasons or ["no_approved_proof_contract_satisfied"])

        return RuntimeCapability(
            capability_id=capability_id,
            source_id=proposal.source_id,
            provider_id=profile.provider_id,
            relation=proposal.relation,
            input_roles=proposal.input_roles,
            output_roles=proposal.output_roles,
            status=status,
            proof_mode=effective_proof_mode,
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
            diagnostics=tuple(diag_list),
            proof_contract_id=effective_contract_id,
            capability_level=effective_capability_level,
        )


__all__ = ["SourceMappingValidator"]

