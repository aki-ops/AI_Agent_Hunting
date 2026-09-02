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

    try:
        op = FieldOp(op_str)
    except ValueError as err:
        raise ValueError(f"Invalid FieldOp '{op_str}' in expectation predicate") from err

    return FieldPredicate(field=field, op=op, value=value)


def validate_m2_response(
    raw_response: str | dict[str, Any],
    max_explanations: int = 10,
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

        expl_id = str(item.get("id", "")).strip()
        label = str(item.get("label", "")).strip()
        class_str = str(item.get("class_", item.get("class", ""))).strip().lower()

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
            obs_id = str(attr.get("observation_id", "")).strip()
            cause = str(attr.get("cause", "")).strip()
            if not obs_id:
                raise ValueError("Attribution missing 'observation_id'")
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
            raise ValueError("Each expectation must be a JSON object")

        exp_id = str(exp_item.get("id", "")).strip()
        owner_id = str(exp_item.get("owner_explanation_id", "")).strip()
        if owner_id not in owner_ids:
            continue

        req_str = str(exp_item.get("evidence_requirement", "")).strip().lower()

        # Invariant: Expectations MUST use EvidenceRequirement, never event family!
        if "event_family" in exp_item:
            raise ValueError("Expectations cannot contain 'event_family'; must use 'evidence_requirement'")

        try:
            req = EvidenceRequirement(req_str)
        except ValueError as err:
            raise ValueError(f"Invalid EvidenceRequirement '{req_str}' in expectation '{exp_id}'") from err

        pred_obs = str(exp_item.get("predicted_observation", "")).strip()
        entity_dict = exp_item.get("entity_ref")
        if not entity_dict or not isinstance(entity_dict, dict):
            raise ValueError(f"Expectation '{exp_id}' missing 'entity_ref' object")

        entity = parse_entity_dict(entity_dict)
        if isinstance(entity, type(ANY)) or entity == ANY:
            raise ValueError(f"Expectation '{exp_id}' cannot target ANY wildcard; must target concrete entity")

        scope_id = str(exp_item.get("provider_scope_id", "default")).strip()
        window = str(exp_item.get("time_window", "")).strip()
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
