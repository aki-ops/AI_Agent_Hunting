"""LLM-assisted source profiling with strict deterministic admission."""
from __future__ import annotations

import json
from typing import Any

from hunting.capabilities.source_mapping_validator import SourceMappingValidator
from hunting.contracts.source_profile import (
    ConstraintMapping,
    SourceCapabilityProposal,
    TelemetrySourceProfile,
)
from hunting.contracts.transforms import canonical_transform_name, list_transform_specs


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
                "For every required constraint and required qualifier in capability_query, either emit a validated constraint_mappings entry using the exact field_id (including nested fields) or return no proposal; never silently omit a required semantic restriction. "
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
                    "constraint_hints": list(item.get("constraint_hints") or ()),
                    "qualifier_hints": list(item.get("qualifier_hints") or ()),
                    "capability_query": dict(item.get("capability_query") or {}),
                    "roles": list(item.get("roles") or ())[:4],
                }
                for item in requirements
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
                        for field in profile.fields[:12]
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
        raw = self.llm_caller(json.dumps(
            self._context(profiles, requirements),
            ensure_ascii=False,
            sort_keys=True,
        ))

        payload = None
        try:
            payload = _clean_and_parse(raw)
        except Exception as exc:
            return [], {
                "status": "MALFORMED_OUTPUT",
                "repair_status": "REPAIR_NOT_ATTEMPTED",
                "error": f"JSONDecodeError: {exc}",
                "proposals": [],
                "rejected": [],
            }

        if not isinstance(payload, dict) or not isinstance(payload.get("proposals"), list):
            return [], {
                "status": "MALFORMED_OUTPUT",
                "repair_status": "REPAIR_NOT_ATTEMPTED",
                "error": "source profiler output must contain proposals[]",
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
        return accepted, {
            "status": "VALIDATED_CANDIDATES",
            "proposals": [item.to_dict() for item in accepted],
            "rejected": rejected,
        }


__all__ = ["SourceProfiler"]
