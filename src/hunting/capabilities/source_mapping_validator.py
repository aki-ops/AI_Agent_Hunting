"""Deterministic validation of LLM source-capability proposals."""
from __future__ import annotations

from hunting.contracts.source_profile import (
    ProbeSpec,
    RuntimeCapability,
    SourceCapabilityProposal,
    TelemetrySourceProfile,
)
from hunting.contracts.transforms import canonical_transform_name, get_transform_by_name
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

        field_by_id = {field.field_id: field for field in profile.fields}
        field_transform_errors: list[str] = []
        for field_id, transform_name in getattr(proposal, "field_transforms", {}).items():
            field = field_by_id.get(str(field_id))
            if field is None:
                field_transform_errors.append(f"field_transform_field_id_not_in_census:{field_id}")
                continue
            normalized = str(transform_name).strip().casefold()
            if normalized != "extract_nested_key":
                field_transform_errors.append(f"field_transform_not_registered:{transform_name}")
            elif field.origin != "nested_payload":
                field_transform_errors.append(f"extract_nested_key_requires_nested_field:{field_id}")
        nested_referenced = {
            field_id for field_id in referenced
            if field_by_id.get(field_id) is not None
            and field_by_id[field_id].origin == "nested_payload"
        }
        nested_referenced.update(
            mapping.native_field
            for mapping in getattr(proposal, "constraint_mappings", ())
            if field_by_id.get(mapping.native_field) is not None
            and field_by_id[mapping.native_field].origin == "nested_payload"
        )
        for field_id in sorted(nested_referenced):
            if str(getattr(proposal, "field_transforms", {}).get(field_id, "")).casefold() != "extract_nested_key":
                field_transform_errors.append(f"nested_field_transform_required:{field_id}")
        if field_transform_errors:
            return False, tuple(dict.fromkeys(field_transform_errors)), None

        # Constraint mappings are executable semantic claims, not descriptive
        # metadata.  Validate their field and transform independently from
        # entity-role bindings so a malformed LLM proposal cannot silently
        # become a proof-capable runtime operation.
        allowed_operators = {
            "equals", "eq", "contains", "like", "exists", "absent",
            "startswith", "endswith",
        }
        mapping_errors: list[str] = []
        seen_constraints: set[str] = set()
        for mapping in getattr(proposal, "constraint_mappings", ()):
            semantic_key = str(mapping.semantic_constraint).strip().casefold()
            native_field = str(mapping.native_field).strip()
            operator = str(mapping.operator).strip().casefold()
            if not semantic_key or not native_field:
                mapping_errors.append("constraint_mapping_missing_key_or_field")
                continue
            if native_field not in fields:
                mapping_errors.append(f"constraint_mapping_field_id_not_in_census:{native_field}")
            if operator not in allowed_operators:
                mapping_errors.append(f"constraint_mapping_operator_not_allowed:{operator}")
            if semantic_key in seen_constraints:
                mapping_errors.append(f"duplicate_constraint_mapping:{semantic_key}")
            seen_constraints.add(semantic_key)

            # An empty transform is valid for a direct native-field match.
            # A non-empty transform, however, must be an allowlisted semantic
            # evaluator compatible with the declared constraint.
            if str(mapping.transform).strip():
                transform_id = canonical_transform_name(mapping.transform, semantic_key, None)
                transform = get_transform_by_name(transform_id or "")
                if transform is None:
                    mapping_errors.append(
                        f"constraint_mapping_transform_not_registered:{mapping.transform or '<empty>'}"
                    )
                elif not transform.supports_constraint_key(semantic_key):
                    mapping_errors.append(
                        f"constraint_mapping_transform_incompatible:{transform.name}:{semantic_key}"
                    )

        if mapping_errors:
            return False, tuple(dict.fromkeys(mapping_errors)), None

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
        resolved_constraint_mappings = tuple(
            type(mapping)(
                semantic_constraint=mapping.semantic_constraint,
                native_field=(
                    next(
                        (
                            field.parent_field or "_raw"
                            for field in profile.fields
                            if field.field_id == mapping.native_field
                            and field.origin == "nested_payload"
                        ),
                        field_id_to_native.get(mapping.native_field, mapping.native_field),
                    )
                ),
                operator=mapping.operator,
                transform=canonical_transform_name(
                    mapping.transform,
                    mapping.semantic_constraint,
                    None,
                ) or mapping.transform,
                proof_method=mapping.proof_method,
                nested_path=(
                    next(
                        (
                            field.nested_key or field.name
                            for field in profile.fields
                            if field.field_id == mapping.native_field
                            and field.origin == "nested_payload"
                        ),
                        getattr(mapping, "nested_path", ""),
                    )
                ),
            )
            for mapping in getattr(proposal, "constraint_mappings", ())
        )
        nested_field_bindings: dict[str, dict[str, str]] = {}
        for role, field_id in {**proposal.input_roles, **proposal.output_roles}.items():
            field = next((item for item in profile.fields if item.field_id == field_id), None)
            if field is not None and field.origin == "nested_payload":
                nested_field_bindings[role] = {
                    "field_id": field_id,
                    "field": field.parent_field or "_raw",
                    "key": field.nested_key or field.name,
                    "transform": proposal.field_transforms.get(field_id, "extract_nested_key"),
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
            goal_id=proposal.goal_id,
            input_roles=proposal.input_roles,
            output_roles=proposal.output_roles,
            status=status,
            proof_mode=effective_proof_mode,
            schema_fingerprint=profile.schema_fingerprint,
            supported_constraints=tuple(
                dict.fromkeys(
                    [str(x).strip().casefold() for x in proposal.supported_constraints if str(x).strip()]
                    + [str(cm.semantic_constraint).strip().casefold() for cm in resolved_constraint_mappings if str(cm.semantic_constraint).strip()]
                )
            ),
            searchable_constraints=tuple(
                dict.fromkeys(
                    [str(x).strip().casefold() for x in proposal.searchable_constraints if str(x).strip()]
                    + [str(x).strip().casefold() for x in proposal.supported_constraints if str(x).strip()]
                    + [str(cm.semantic_constraint).strip().casefold() for cm in resolved_constraint_mappings if str(cm.semantic_constraint).strip()]
                )
            ),
            constraint_mappings=resolved_constraint_mappings,
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
            nested_field_bindings=nested_field_bindings,
        )


__all__ = ["SourceMappingValidator"]
