"""Deterministic admission gate for untrusted capability proposals."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from hunting.contracts.ontology import types_are_compatible
from hunting.contracts.source_profile import SourceCapabilityProposal, TelemetrySourceProfile


@dataclass(frozen=True)
class AdmissionResult:
    admitted: bool
    reasons: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {"admitted": self.admitted, "reasons": list(self.reasons)}


def _slot_labels(operation: Any) -> tuple[str, ...]:
    labels = [
        *[str(item) for item in tuple(getattr(operation, "output_roles", ()) or ())],
        *[str(item) for item in tuple(getattr(operation, "output_fields", ()) or ())],
    ]
    for binding in dict(getattr(operation, "nested_field_bindings", {}) or {}).values():
        if isinstance(binding, dict):
            labels.append(str(binding.get("key", "")))
    return tuple(item for item in labels if str(item).strip())


class CapabilityAdmissionGate:
    """Checks census reachability before a proposal can become an operation.

    This gate is intentionally independent from LLM confidence.  The existing
    SourceMappingValidator remains the deeper schema/transform validator; this
    gate makes the admission boundary explicit and auditable.
    """

    @staticmethod
    def evaluate(
        proposal: SourceCapabilityProposal,
        profile: TelemetrySourceProfile,
        requirement: dict[str, Any] | None = None,
    ) -> AdmissionResult:
        reasons: list[str] = []
        if proposal.source_id != profile.source_id:
            reasons.append("source_not_reachable_in_census")
        field_ids = {field.field_id for field in profile.fields}
        cited = {
            str(field_id)
            for mapping in (
                proposal.input_roles,
                proposal.output_roles,
                proposal.temporal_roles,
                proposal.action_roles,
                proposal.state_roles,
                proposal.artifact_identity_roles,
                proposal.correlation_roles,
            )
            for field_id in mapping.values()
        }
        cited.update(mapping.native_field for mapping in proposal.constraint_mappings)
        reasons.extend(
            f"native_field_not_in_census:{field_id}"
            for field_id in sorted(cited - field_ids)
        )
        allow_scope_explore = bool(requirement and requirement.get("allow_scope_explore"))
        if not proposal.input_roles and not allow_scope_explore:
            reasons.append("missing_input_mapping")
        if not proposal.output_roles:
            reasons.append("missing_output_mapping")
        if requirement is not None:
            if not str(requirement.get("subject_type", "")).strip():
                reasons.append("missing_subject_type")
            if not str(requirement.get("object_type", "")).strip():
                reasons.append("missing_object_type")
        return AdmissionResult(not reasons, tuple(dict.fromkeys(reasons)))

    @classmethod
    def evaluate_operation(
        cls,
        operation: Any,
        requirement: dict[str, Any] | None = None,
        profile: TelemetrySourceProfile | None = None,
    ) -> AdmissionResult:
        """Admit a typed provider operation without treating relation text as proof."""
        reasons: list[str] = []
        requirement = requirement or {}
        subject_type = str(requirement.get("subject_type", "")).strip()
        object_type = str(requirement.get("object_type", "")).strip()
        answer_role = str(requirement.get("answer_role", "")).strip()
        input_kinds = tuple(getattr(operation, "input_entity_kinds", ()) or ())
        output_kinds = tuple(getattr(operation, "output_entity_kinds", ()) or ())
        if not input_kinds:
            reasons.append("input_type_not_reachable")
        elif subject_type and not any(types_are_compatible(subject_type, kind) for kind in input_kinds):
            reasons.append("input_type_not_reachable")
        if not output_kinds:
            reasons.append("output_type_not_reachable")
        elif object_type and not any(types_are_compatible(object_type, kind) for kind in output_kinds):
            reasons.append("output_type_not_reachable")
        if answer_role and not (
            (object_type and types_are_compatible(answer_role, object_type))
            or any(types_are_compatible(answer_role, kind) for kind in output_kinds)
            or any(types_are_compatible(answer_role, label) for label in _slot_labels(operation))
        ):
            reasons.append(f"answer_role_not_reachable:{answer_role.casefold()}")
        has_mapping = bool(
            getattr(operation, "native_field_bindings", None)
            or getattr(operation, "output_value_bindings", None)
            or getattr(operation, "output_fields", None)
            or getattr(operation, "output_roles", None)
        )
        if not has_mapping and requirement.get("allow_scope_explore"):
            has_mapping = True
        if not has_mapping:
            reasons.append("missing_native_mapping")
        if profile is not None:
            field_names = {str(item.name).casefold() for item in profile.fields}
            field_ids = {str(item.field_id) for item in profile.fields}
            cited = {
                str(field_name).casefold()
                for values in (
                    *dict(getattr(operation, "native_field_bindings", {}) or {}).values(),
                    *dict(getattr(operation, "output_value_bindings", {}) or {}).values(),
                )
                for field_name in (values if isinstance(values, (tuple, list)) else (values,))
                if str(field_name).strip()
            }
            cited.update(str(item).casefold() for item in getattr(operation, "output_fields", ()) or ())
            if cited and not any(name in field_names or name in field_ids for name in cited):
                reasons.append("native_field_not_in_census")
        return AdmissionResult(not reasons, tuple(dict.fromkeys(reasons)))


__all__ = ["AdmissionResult", "CapabilityAdmissionGate"]
