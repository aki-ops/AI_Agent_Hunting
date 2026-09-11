"""LLM-assisted source profiling with strict deterministic admission."""
from __future__ import annotations

import json
from typing import Any

from hunting.capabilities.source_mapping_validator import SourceMappingValidator
from hunting.contracts.source_profile import (
    SourceCapabilityProposal,
    TelemetrySourceProfile,
)


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
            "requirements": [dict(item) for item in requirements],
            # The profiler needs schema metadata, not representative values.
            # Values are intentionally omitted to keep the call bounded and
            # prevent sensitive telemetry from entering the LLM context.
            "sources": [
                {
                    "source_id": profile.source_id,
                    "provider_id": profile.provider_id,
                    "partition_id": profile.partition_id,
                    "native_type": profile.native_type,
                    "event_count": profile.event_count,
                    "schema_fingerprint": profile.schema_fingerprint,
                    "fields": [
                        {
                            "field_id": field.field_id,
                            "name": field.name,
                            "primitive_type": field.primitive_type,
                            "coverage": field.coverage,
                        }
                        for field in profile.fields
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
        # The shared tracked LLM caller accepts a serialized prompt. Keeping
        # the boundary textual also makes the prompt hash/cost auditable.
        raw = self.llm_caller(json.dumps(
            self._context(profiles, requirements),
            ensure_ascii=False,
            sort_keys=True,
        ))
        payload = json.loads(raw) if isinstance(raw, str) else raw
        if not isinstance(payload, dict) or not isinstance(payload.get("proposals"), list):
            raise ValueError("source profiler output must contain proposals[]")

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
                proposal = SourceCapabilityProposal(
                    source_id=str(item["source_id"]),
                    relation=str(item["relation"]),
                    input_roles={str(k): str(v) for k, v in dict(item.get("input_roles", {})).items()},
                    output_roles={str(k): str(v) for k, v in dict(item.get("output_roles", {})).items()},
                    proof_mode=str(item.get("proof_mode", "retrieval_only")),
                    probe_kind=str(
                        item.get("probe_kind")
                        or (item.get("probe", {}).get("kind") if isinstance(item.get("probe"), dict) else None)
                        or "cooccurrence"
                    ),
                    projection_roles=tuple(
                        str(v) for v in (
                            item.get("projection_roles")
                            or (item.get("probe", {}).get("projection_roles", [])
                                if isinstance(item.get("probe"), dict) else [])
                        )
                    ),
                    supported_constraints=tuple(str(v) for v in item.get("supported_constraints", [])),
                    searchable_constraints=tuple(str(v) for v in item.get("searchable_constraints", [])),
                    temporal_roles={str(k): str(v) for k, v in dict(item.get("temporal_roles", {})).items()},
                    action_roles={str(k): str(v) for k, v in dict(item.get("action_roles", {})).items()},
                    state_roles={str(k): str(v) for k, v in dict(item.get("state_roles", {})).items()},
                    artifact_identity_roles={str(k): str(v) for k, v in dict(item.get("artifact_identity_roles", {})).items()},
                    correlation_roles={str(k): str(v) for k, v in dict(item.get("correlation_roles", {})).items()},
                    relaxable_constraint_keys=tuple(str(v) for v in item.get("relaxable_constraint_keys", [])),
                    rationale_refs=tuple(str(v) for v in item.get("rationale_refs", [])),
                    confidence=float(item["confidence"]) if item.get("confidence") is not None else None,
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
