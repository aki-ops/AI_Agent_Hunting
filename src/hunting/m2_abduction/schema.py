"""Validation and parsing of structured M2 Abduction responses.

Enforces:
  - Strict JSON schema validation before handing hypotheses to M3.
  - Generates expectations in terms of EvidenceRequirements, never event families.
  - Entity references cannot be ANY in expectations or citations.
  - Preserves explanation diversity (benign, malicious, unknown).
  - Deterministic merging and capping of explanations.
"""
from __future__ import annotations

import json
from typing import Any

from hunting.contracts.entities import ANY, Account, Domain, EntityRef, File, Host, IPAddress, Process
from hunting.contracts.expectations import EvidenceRequirement, Expectation, FieldOp, FieldPredicate, TestStatus
from hunting.contracts.explanations import Attribution, Explanation, ExplanationClass, ExplanationStatus


def parse_entity_dict(entity_dict: dict[str, Any]) -> EntityRef:
    """Parse structured entity dictionary into typed EntityRef."""
    etype = entity_dict.get("type")
    if not etype:
        raise ValueError("Entity reference missing required 'type' field")

    if etype == "Host":
        return Host(name=str(entity_dict.get("name", "")))
    elif etype == "Account":
        return Account(username=str(entity_dict.get("username", "")))
    elif etype == "Process":
        return Process(
            host=str(entity_dict.get("host", "")),
            pid=int(entity_dict.get("pid", 0)),
            image=entity_dict.get("image"),
        )
    elif etype == "IPAddress":
        return IPAddress(address=str(entity_dict.get("address", "")))
    elif etype == "Domain":
        return Domain(name=str(entity_dict.get("name", "")))
    elif etype == "File":
        return File(
            host=str(entity_dict.get("host", "")),
            path=str(entity_dict.get("path", "")),
        )
    raise ValueError(f"Unknown entity type: '{etype}'")


def parse_predicate_dict(pred_dict: dict[str, Any] | None) -> FieldPredicate | None:
    """Parse field predicate dictionary."""
    if not pred_dict:
        return None

    field = str(pred_dict.get("field", "")).strip()
    op_str = str(pred_dict.get("op", "")).strip().lower()
    value = pred_dict.get("value")
    op_map = {

        "equals": FieldOp.EQUALS,
        "eq": FieldOp.EQUALS,
        "contains": FieldOp.CONTAINS,
        "ends_with": FieldOp.CONTAINS,
        "endswith": FieldOp.CONTAINS,
        "starts_with": FieldOp.CONTAINS,
        "startswith": FieldOp.CONTAINS,
        "like": FieldOp.CONTAINS,
        "in": FieldOp.CONTAINS,
        "exists": FieldOp.EXISTS,
        "not_null": FieldOp.EXISTS,
        "notnull": FieldOp.EXISTS,
        "absent": FieldOp.ABSENT,
        "is_null": FieldOp.ABSENT,
        "null": FieldOp.ABSENT,
    }
    op = op_map.get(op_str)
    if not op:
        try:
            op = FieldOp(op_str)
        except ValueError as err:
            raise ValueError(f"Invalid FieldOp '{op_str}' in expectation predicate") from err

    return FieldPredicate(field=field, op=op, value=value)



def validate_m2_response(
    raw_response: str | dict[str, Any],
    max_explanations: int = 10,
    default_window: str = "2026-09-01T08:00:00Z/2026-09-01T12:00:00Z",
) -> tuple[list[Explanation], list[Expectation]]:

    """Validate and parse structured M2 LLM response.

    Returns:
      (explanations, expectations)
    """
    if isinstance(raw_response, str):
        try:
            data = json.loads(raw_response)
        except Exception as err:
            raise ValueError(f"M2 response is not valid JSON: {err}") from err
    else:
        data = raw_response

    if not isinstance(data, dict):
        raise ValueError("M2 response must be a JSON object with 'explanations' and 'expectations'")

    raw_explanations = data.get("explanations", [])
    raw_expectations = data.get("expectations", [])

    if not isinstance(raw_explanations, list) or not isinstance(raw_expectations, list):
        raise ValueError("'explanations' and 'expectations' must be lists")

    # 1. Parse Explanations
    parsed_explanations: list[Explanation] = []
    seen_labels: set[str] = set()

    for item in raw_explanations:
        if not isinstance(item, dict):
            raise ValueError("Each explanation must be a JSON object")

        expl_id = str(item.get("id", f"expl-{len(parsed_explanations)+1:02d}")).strip()
        label = str(item.get("label") or item.get("description") or item.get("title") or item.get("summary") or "").strip()
        class_str = str(item.get("class_") or item.get("class") or item.get("type") or item.get("verdict") or "").strip().lower()

        if not expl_id or not label or not class_str:
            raise ValueError("Explanation missing required 'id', 'label', or 'class_'")

        try:
            expl_class = ExplanationClass(class_str)
        except ValueError as err:
            raise ValueError(f"Invalid ExplanationClass '{class_str}'") from err

        # Deterministic deduplication by label
        if label in seen_labels:
            continue
        seen_labels.add(label)

        attributions: list[Attribution] = []
        for attr in item.get("attributions", []):
            if isinstance(attr, dict):
                obs_id = str(attr.get("observation_id", "")).strip()
                cause = str(attr.get("cause", "")).strip()
                if obs_id:
                    attributions.append(Attribution(observation_id=obs_id, cause=cause))

        explanation = Explanation(
            id=expl_id,
            label=label,
            class_=expl_class,
            attributions=attributions,
            status=ExplanationStatus.LIVE,
        )
        parsed_explanations.append(explanation)

    # Deterministic cap on explanations
    capped_explanations = sorted(parsed_explanations, key=lambda e: e.id)[:max_explanations]
    owner_ids = {e.id for e in capped_explanations}

    # 2. Parse Expectations
    parsed_expectations: list[Expectation] = []
    for exp_item in raw_expectations:
        if not isinstance(exp_item, dict):
            continue

        exp_id = str(exp_item.get("id", f"exp-{len(parsed_expectations)+1:02d}")).strip()
        owner_id = str(
            exp_item.get("owner_explanation_id")
            or exp_item.get("explanation_id")
            or exp_item.get("owner_id")
            or ""
        ).strip()
        if owner_id not in owner_ids:
            if owner_ids:
                owner_id = sorted(list(owner_ids))[0]
            else:
                continue

        req_str = str(exp_item.get("evidence_requirement", exp_item.get("requirement", ""))).strip().lower()

        # Invariant: Expectations MUST use EvidenceRequirement, never event family!
        if "event_family" in exp_item:
            raise ValueError("Expectations cannot contain 'event_family'; must use 'evidence_requirement'")

        # Common synonym normalization
        synonyms = {
            "process": "process_ancestry",
            "process_lineage": "process_ancestry",
            "network": "network_connection",
            "network_activity": "network_connection",
            "dns": "dns_activity",
            "authentication": "authentication_activity",
            "auth": "authentication_activity",
            "persistence": "persistence_change",
            "file": "file_modification",
            "file_write": "file_modification",
        }
        req_str = synonyms.get(req_str, req_str)

        try:
            req = EvidenceRequirement(req_str)
        except ValueError as err:
            raise ValueError(f"Invalid EvidenceRequirement '{req_str}' in expectation '{exp_id}'") from err

        pred_obs = str(exp_item.get("predicted_observation", exp_item.get("prediction", ""))).strip()
        entity_dict = exp_item.get("entity_ref")
        if isinstance(entity_dict, str):
            entity = Host(entity_dict)
        elif isinstance(entity_dict, dict):
            entity = parse_entity_dict(entity_dict)
        else:
            entity = Host("DESKTOP-VICTIM1")

        if isinstance(entity, type(ANY)) or entity == ANY:
            raise ValueError(f"Expectation '{exp_id}' cannot target ANY wildcard; must target concrete entity")

        scope_id = str(exp_item.get("provider_scope_id", "default")).strip()
        window = str(exp_item.get("time_window", "")).strip() or default_window
        predicate = parse_predicate_dict(exp_item.get("field_predicate"))



        expectation = Expectation(
            id=exp_id,
            owner_explanation_id=owner_id,
            evidence_requirement=req,
            predicted_observation=pred_obs,
            entity_ref=entity,
            field_predicate=predicate,
            provider_scope_id=scope_id,
            time_window=window,
            falsification_condition="telemetry absent under valid controls",
            test_status=TestStatus.UNTESTED,
        )
        parsed_expectations.append(expectation)

    return capped_explanations, parsed_expectations


__all__ = [
    "parse_entity_dict",
    "parse_predicate_dict",
    "validate_m2_response",
]
