"""LLM-assisted source profiling with strict deterministic admission."""
from __future__ import annotations

import json
from typing import Any

from hunting.capabilities.source_mapping_validator import SourceMappingValidator
from hunting.contracts.ontology import FILE_IDENTITY_ANSWER_TYPES, types_are_compatible
from hunting.contracts.source_profile import (
    ConstraintMapping,
    SourceCapabilityProposal,
    TelemetrySourceProfile,
)
from hunting.contracts.transforms import canonical_transform_name, list_transform_specs

_FIELD_CAP = 12
_SKIP_OBLIGATIONS = frozenset({"", "entity", "value", "any"})


def _field_labels(field: Any) -> tuple[str, ...]:
    labels = [str(getattr(field, "name", "") or "")]
    nested = str(getattr(field, "nested_key", "") or "")
    if nested:
        labels.append(nested)
    return tuple(label for label in labels if label.strip())


def _port_token(value: Any) -> str:
    text = str(value or "").strip().casefold()
    return "" if text in _SKIP_OBLIGATIONS else text


def mapping_ports(requirement: dict[str, Any]) -> dict[str, tuple[str, ...]]:
    """Subject, object, and answer are C2 ports. Context names are not."""
    mapping: list[str] = []
    for key in (
        requirement.get("subject_type"),
        requirement.get("object_type"),
        requirement.get("answer_role"),
    ):
        token = _port_token(key)
        if token and token not in mapping:
            mapping.append(token)
    mapped = set(mapping)
    unmapped: list[str] = []
    for key in requirement.get("constraint_keys") or ():
        token = _port_token(key)
        if token and token not in mapped and token not in unmapped:
            unmapped.append(token)
    for hint in list(requirement.get("qualifier_hints") or ()) + list(requirement.get("constraint_hints") or ()):
        raw = hint.get("key") or hint.get("qualifier") if isinstance(hint, dict) else hint
        token = _port_token(raw)
        if token and token not in mapped and token not in unmapped:
            unmapped.append(token)
    return {"mapping_keys": tuple(mapping), "unmapped_keys": tuple(unmapped)}


def split_mapping_obligations(
    requirement: dict[str, Any],
    profiles: list[TelemetrySourceProfile] | tuple[TelemetrySourceProfile, ...] = (),
) -> dict[str, tuple[str, ...]]:
    del profiles
    return mapping_ports(requirement)


def compact_fields_for_c2(
    fields: tuple[Any, ...] | list[Any],
    ports: tuple[str, ...] | list[str],
    *,
    limit: int = _FIELD_CAP,
) -> tuple[Any, ...]:
    """Keep relation ports in the compact C2 window. Context tokens do not rank fields."""
    cleaned = []
    for port in ports:
        token = _port_token(port)
        if not token:
            continue
        if token not in cleaned:
            cleaned.append(token)
        if token in FILE_IDENTITY_ANSWER_TYPES and "file" not in cleaned:
            cleaned.append("file")
    cleaned = tuple(cleaned)
    preferred = []
    rest = []
    for field in fields:
        backed = any(
            types_are_compatible(label, port)
            for label in _field_labels(field)
            for port in cleaned
        )
        if backed:
            preferred.append(field)
        else:
            rest.append(field)
    return tuple((preferred + rest)[: max(1, int(limit))])


def _prompt_fields(
    profile: TelemetrySourceProfile,
    mapping_keys: tuple[str, ...],
) -> tuple[Any, ...]:
    return compact_fields_for_c2(profile.fields, mapping_keys, limit=_FIELD_CAP)


class SourceProfiler:
    """Turn bounded census metadata into validated proposal candidates.

    This class does not execute queries. It also does not trust LLM confidence;
    every source and field reference is checked against the census.
    """

    def __init__(self, llm_caller: Any | None = None, *, validator: SourceMappingValidator | None = None) -> None:
        self.llm_caller = llm_caller
        self.validator = validator or SourceMappingValidator()

    def _context(
        self,
        profiles: list[TelemetrySourceProfile] | tuple[TelemetrySourceProfile, ...],
        requirements: list[dict[str, Any]] | tuple[dict[str, Any], ...],
    ) -> dict[str, Any]:
        splits = [mapping_ports(item) for item in requirements]
        mapping_keys = tuple(dict.fromkeys(key for split in splits for key in split["mapping_keys"]))
        return {
            "component": "source_profiler",
            "instructions": (
                "Map available telemetry sources to the requested relations. "
                "Each role in input_roles and output_roles MUST map to the exact 'field_id' from the source's fields list. "
                "Output MUST be valid JSON conforming to: "
                "{\"proposals\": [{\"goal_id\": \"<goal_id>\", \"source_id\": \"<source_id>\", \"relation\": \"<relation>\", "
                "\"input_roles\": {\"<role>\": \"<field_id>\"}, \"output_roles\": {\"<role>\": \"<field_id>\"}, "
                "\"field_transforms\": {\"<field_id>\": \"extract_nested_key\"}, "
                "\"proof_mode\": \"retrieval_only\" | \"relation_observable\", \"probe_kind\": \"cooccurrence\", "
                "\"constraint_mappings\": [{\"semantic_constraint\": \"<key>\", \"native_field\": \"<field_id>\", \"operator\": \"equals\"|\"contains\", \"transform\": \"<transform>\"}]}]}. "
                "The transform value MUST be empty for direct field matching or one of the registered transform IDs in transform_catalog. "
                "Nested census fields require field_transforms[<field_id>]=extract_nested_key and must retain their parent/key metadata. "
                "mapping_keys are relation ports (subject, object, answer). Map each to a field_id when a census field supports it. "
                "unmapped_keys are request context, not columns: emit them on the proposal as unaligned with reason no_census_field. "
                "Do not withhold the source because of unmapped_keys. Emit a proposal when the shortlist is non-empty. "
                "A mapping is a retrieval/proof capability claim, not a guess: use only a field whose native name and census provenance support the restriction. "
                "Never invent a transform name. Output ONLY the JSON object. Do not include explanatory text."
            ),
            "transform_catalog": list_transform_specs(),
            "requirements": [
                {
                    "goal_id": item.get("goal_id"),
                    "relation": item.get("relation"),
                    "relation_text": item.get("relation_text", item.get("relation")),
                    "subject_type": item.get("subject_type"),
                    "object_type": item.get("object_type"),
                    "answer_role": item.get("answer_role"),
                    "constraint_keys": list(item.get("constraint_keys") or ()),
                    "mapping_keys": list(split["mapping_keys"]),
                    "unmapped_keys": list(split["unmapped_keys"]),
                    "constraint_hints": list(item.get("constraint_hints") or ()),
                    "qualifier_hints": list(item.get("qualifier_hints") or ()),
                    "capability_query": dict(item.get("capability_query") or {}),
                    "roles": list(item.get("roles") or ())[:4],
                }
                for item, split in zip(requirements, splits)
            ],
            "sources": [
                {
                    "source_id": profile.source_id,
                    "native_type": profile.native_type,
                    "fields": [
                        {
                            "field_id": field.field_id,
                            "name": field.name,
                            "primitive_type": field.primitive_type,
                            "origin": field.origin,
                            "parent_field": field.parent_field,
                            "nested_key": field.nested_key,
                            "evidence_query_id": field.evidence_query_id,
                        }
                        for field in _prompt_fields(profile, mapping_keys)
                    ],
                }
                for profile in profiles
            ],
        }

    def propose(
        self,
        profiles: list[TelemetrySourceProfile] | tuple[TelemetrySourceProfile, ...],
        requirements: list[dict[str, Any]] | tuple[dict[str, Any], ...],
        *,
        validation_profiles: list[TelemetrySourceProfile] | tuple[TelemetrySourceProfile, ...] | None = None,
    ) -> tuple[list[SourceCapabilityProposal], dict[str, Any]]:
        if self.llm_caller is None:
            return [], {"status": "NO_LLM_CALLER", "proposals": []}

        def _clean_and_parse(text: Any) -> Any:
            if isinstance(text, dict):
                return text
            if not isinstance(text, str):
                return None
            s = text.strip()
            if s.startswith("```"):
                lines = s.splitlines()
                if lines and lines[0].startswith("```"):
                    lines = lines[1:]
                if lines and lines[-1].startswith("```"):
                    lines = lines[:-1]
                s = "\n".join(lines).strip()
            return json.loads(s)

        # The shared tracked LLM caller accepts a serialized prompt. Keeping
        # the boundary textual also makes the prompt hash/cost auditable.
        prompt = json.dumps(
            self._context(profiles, requirements),
            ensure_ascii=False,
            sort_keys=True,
        )
        shortlist_present = bool(profiles)

        def _invoke() -> tuple[dict[str, Any] | None, str]:
            try:
                payload = _clean_and_parse(self.llm_caller(prompt))
            except Exception as exc:
                return None, f"JSONDecodeError: {exc}"
            if not isinstance(payload, dict) or not isinstance(payload.get("proposals"), list):
                return None, "source profiler output must contain proposals[]"
            return payload, ""

        repair_status = "REPAIR_NOT_ATTEMPTED"
        payload, error = _invoke()
        if error:
            return [], {
                "status": "MALFORMED_OUTPUT",
                "repair_status": repair_status,
                "error": error,
                "proposals": [],
                "rejected": [],
            }
        if payload is not None and not payload["proposals"] and shortlist_present:
            repair_status = "REPAIR_ATTEMPTED"
            payload, error = _invoke()
            if error or payload is None or not payload["proposals"]:
                return [], {
                    "status": "MALFORMED_OUTPUT",
                    "repair_status": repair_status,
                    "error": error or "proposals empty while an F1 shortlist remains",
                    "proposals": [],
                    "rejected": [],
                }

        accepted: list[SourceCapabilityProposal] = []
        rejected: list[dict[str, Any]] = []
        # Prompt profiles may be compact/truncated. Validation must always use
        # the complete census profiles so context reduction cannot authorize a
        # field that was not actually observed by the provider.
        authoritative_profiles = tuple(validation_profiles or profiles)
        for index, item in enumerate(payload["proposals"]):
            try:
                if not isinstance(item, dict):
                    raise ValueError("proposal must be an object")
                source_id_str = str(item["source_id"])
                prof = next((p for p in authoritative_profiles if p.source_id == source_id_str), None)
                name_to_fid = {f.name.lower(): f.field_id for f in prof.fields} if prof else {}

                def _norm_role_map(raw_map: Any) -> dict[str, str]:
                    res = {}
                    for k, v in dict(raw_map or {}).items():
                        v_str = str(v)
                        res[str(k)] = name_to_fid.get(v_str.lower(), v_str)
                    return res

                raw_probe_kind = str(
                    item.get("probe_kind")
                    or (item.get("probe", {}).get("kind") if isinstance(item.get("probe"), dict) else None)
                    or "cooccurrence"
                )
                if raw_probe_kind == "filter":
                    raw_probe_kind = "cooccurrence"

                raw_cms = []
                for cm in item.get("constraint_mappings", []):
                    if isinstance(cm, dict):
                        f_id = str(cm.get("native_field", cm.get("field", "")))
                        semantic_key = str(cm.get("semantic_constraint", cm.get("key", "")))
                        transform_name = canonical_transform_name(
                            str(cm.get("transform", "")),
                            semantic_key,
                            cm.get("value"),
                        )
                        raw_cms.append(ConstraintMapping(
                            semantic_constraint=semantic_key,
                            native_field=name_to_fid.get(f_id.lower(), f_id),
                            operator=str(cm.get("operator", "equals")),
                            transform=transform_name or str(cm.get("transform", "")),
                            proof_method=str(cm.get("proof_method", "field_match")),
                        ))

                proposal = SourceCapabilityProposal(
                    source_id=source_id_str,
                    relation=str(item["relation"]),
                    goal_id=str(item.get("goal_id", "")).strip(),
                    input_roles=_norm_role_map(item.get("input_roles")),
                    output_roles=_norm_role_map(item.get("output_roles")),
                    proof_mode=str(item.get("proof_mode", "retrieval_only")),
                    probe_kind=raw_probe_kind,
                    projection_roles=tuple(
                        str(v) for v in (
                            item.get("projection_roles")
                            or (item.get("probe", {}).get("projection_roles", [])
                                if isinstance(item.get("probe"), dict) else [])
                        )
                    ),
                    supported_constraints=tuple(str(v) for v in item.get("supported_constraints", [])),
                    searchable_constraints=tuple(str(v) for v in item.get("searchable_constraints", [])),
                    constraint_mappings=tuple(raw_cms),
                    temporal_roles=_norm_role_map(item.get("temporal_roles")),
                    action_roles=_norm_role_map(item.get("action_roles")),
                    state_roles=_norm_role_map(item.get("state_roles")),
                    artifact_identity_roles=_norm_role_map(item.get("artifact_identity_roles")),
                    correlation_roles=_norm_role_map(item.get("correlation_roles")),
                    relaxable_constraint_keys=tuple(str(v) for v in item.get("relaxable_constraint_keys", [])),
                    rationale_refs=tuple(str(v) for v in item.get("rationale_refs", [])),
                    confidence=float(item["confidence"]) if item.get("confidence") is not None else None,
                    field_transforms={
                        name_to_fid.get(str(key).lower(), str(key)): str(value)
                        for key, value in dict(item.get("field_transforms") or {}).items()
                    },
                )
                valid, reasons, _ = self.validator.validate(proposal, authoritative_profiles)
                if not valid:
                    raise ValueError(";".join(reasons))
                accepted.append(proposal)
            except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
                rejected.append({"index": index, "reason": str(exc)})
        audit = {
            "status": "VALIDATED_CANDIDATES",
            "proposals": [item.to_dict() for item in accepted],
            "rejected": rejected,
        }
        if repair_status == "REPAIR_ATTEMPTED":
            audit["repair_status"] = repair_status
        return accepted, audit


__all__ = [
    "SourceProfiler",
    "compact_fields_for_c2",
    "mapping_ports",
    "split_mapping_obligations",
]
