"""Provider-neutral adaptive operation selection.

This layer chooses a semantic operation from the runtime capability descriptor.
It does not generate native SPL/SQL/KQL; adapters remain responsible for that.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from dataclasses import dataclass
from typing import Any, Callable

from hunting.capabilities.models import VersionedCapabilityDescriptor
from hunting.contracts.hunt import QueryPlan
from hunting.contracts.hunt_spec import HuntSpec

logger = logging.getLogger("hunting.observability")

DISALLOWED_NATIVE_PATTERNS = [
    re.compile(r"\bindex\s*=", re.IGNORECASE),
    re.compile(r"\bsourcetype\s*=", re.IGNORECASE),
    re.compile(r"\|\s*(table|stats|eval|rex|where|rename|dedup|head|fields|search)\b", re.IGNORECASE),
    re.compile(r"\b(SELECT|FROM|WHERE|JOIN|UNION|INSERT|UPDATE|DELETE)\b", re.IGNORECASE),
]


def _contains_native_query(text: str) -> bool:
    if not text or not isinstance(text, str):
        return False
    return any(pat.search(text) for pat in DISALLOWED_NATIVE_PATTERNS)


def _extract_fallback_terms(question: str, spec_terms: tuple[str, ...]) -> tuple[str, ...]:
    """Derive search terms from NL question if explicit search terms are missing."""
    if spec_terms:
        return spec_terms
    stopwords = {
        "what", "which", "where", "who", "when", "why", "how",
        "is", "are", "was", "were", "be", "been", "being",
        "the", "a", "an", "and", "or", "in", "on", "at", "to", "for",
        "of", "with", "by", "from", "installed", "used", "run", "did",
        "does", "do", "find", "show", "tell", "me", "any", "please",
    }
    words = re.findall(r"[A-Za-z0-9_.-]+", question or "")
    meaningful = [w for w in words if w.lower() not in stopwords and len(w) > 1]
    return tuple(meaningful[:5]) if meaningful else ((question.strip(),) if question.strip() else ())


@dataclass(frozen=True)
class AdaptiveDecision:
    operation_id: str | None
    reason: str
    required_fields: tuple[str, ...] = ()
    ready_for_answer: bool = False
    search_terms: tuple[str, ...] = ()
    prompt_hash: str = ""
    validation_result: str = ""

    @property
    def operation(self) -> str | None:
        """Alias for operation_id for contract consistency."""
        return self.operation_id

    def to_dict(self) -> dict[str, Any]:
        return {
            "operation": self.operation_id,
            "operation_id": self.operation_id,
            "reason": self.reason,
            "required_fields": list(self.required_fields),
            "ready_for_answer": self.ready_for_answer,
            "search_terms": list(self.search_terms),
            "prompt_hash": self.prompt_hash,
            "validation_result": self.validation_result,
        }


def _fields_satisfied(required: tuple[str, ...], observed: set[str], answer_type: str = "") -> bool:
    """Check if required fields are present in observed fields.

    If required fields are all aliases of a single canonical answer type
    (e.g. ProductVersion, FileVersion), observing ANY of them satisfies the requirement.
    Otherwise, ALL required fields must be present.
    """
    if not required:
        return False
    from hunting.contracts.hunt_spec import _ANSWER_FIELD_ALIASES
    canonical = {f.casefold() for f in _ANSWER_FIELD_ALIASES.get(answer_type.casefold(), ())}
    req_lower = {f.casefold() for f in required}
    if canonical and req_lower.issubset(canonical):
        return any(f in observed for f in req_lower)
    return all(f in observed for f in req_lower)


class AdaptiveOperationPlanner:
    """Select the next bounded semantic operation from observed capabilities."""

    def __init__(
        self,
        llm_generator: Callable[[str], str] | Any | None = None,
        llm_tracker: Any | None = None,
    ) -> None:
        self.llm_tracker = llm_tracker
        self.audit_logs: list[dict[str, Any]] = []
        if llm_generator is not None and hasattr(llm_generator, "call_raw"):
            from hunting.m2_abduction.provider import create_llm_caller
            self.llm_generator = create_llm_caller(
                llm_generator,
                tracker=llm_tracker,
                component="adaptive_planner",
            )
        else:
            self.llm_generator = llm_generator

    def _record_observability(
        self,
        phase: str,
        prompt_hash: str,
        selected_operation: str,
        search_terms: Any,
        validation_result: str,
        attempt: int = 1,
    ) -> None:
        terms_list = list(search_terms) if isinstance(search_terms, (list, tuple)) else [str(search_terms)]
        log_entry = {
            "phase": phase,
            "prompt_hash": prompt_hash,
            "selected_operation": selected_operation,
            "search_terms": terms_list,
            "validation_result": validation_result,
            "attempt": attempt,
        }
        self.audit_logs.append(log_entry)
        logger.info(
            "[LLM_OBSERVABILITY] phase=%s prompt_hash=%s selected_operation=%s search_terms=%s validation_result=%s attempt=%d",
            phase,
            prompt_hash,
            selected_operation,
            terms_list,
            validation_result,
            attempt,
        )

    def choose(
        self,
        spec: HuntSpec,
        descriptor: VersionedCapabilityDescriptor | Any,
        observed_fields: set[str] | list[str] = (),
        attempted_operations: set[str] | list[str] = (),
        iteration: int = 0,
    ) -> AdaptiveDecision:
        answer_type = spec.answer_contract.answer_type.casefold()
        required = tuple(spec.answer_contract.required_fields)
        fields = {str(value).casefold() for value in observed_fields}
        spec_terms = tuple(term.value for term in spec.search_terms)
        fallback_terms = _extract_fallback_terms(spec.question, spec_terms)

        if _fields_satisfied(required, fields, answer_type):
            return AdaptiveDecision(
                operation_id=None,
                reason="answer fields already observed",
                required_fields=required,
                ready_for_answer=True,
                search_terms=spec_terms,
                validation_result="FIELDS_SATISFIED",
            )

        operations = list(getattr(descriptor, "operations", ()) or ())
        if not operations:
            return AdaptiveDecision(
                operation_id=None,
                reason="provider exposes no operations",
                required_fields=required,
                ready_for_answer=False,
                search_terms=spec_terms,
                validation_result="NO_OPERATIONS",
            )

        attempted = {str(op).strip() for op in attempted_operations}
        available_operations = [
            op for op in operations
            if str(getattr(op, "id", "")).strip() not in attempted
        ]
        if not available_operations:
            return AdaptiveDecision(
                operation_id=None,
                reason="all candidate provider operations already attempted",
                required_fields=required,
                ready_for_answer=False,
                search_terms=spec_terms,
                validation_result="OPERATIONS_EXHAUSTED",
            )

        # Explicit semantic declarations are authoritative. Operation names
        # alone are not enough: `cdb_file_search` may contain hidden vendor
        # assumptions that do not match the current deployment.
        for operation in available_operations:
            op_id = str(getattr(operation, "id", ""))
            declared_intents = {
                str(value).casefold()
                for value in getattr(operation, "semantic_intents", ()) or ()
            }
            if answer_type in declared_intents:
                return AdaptiveDecision(
                    operation_id=op_id,
                    reason="selected from provider semantic capability",
                    required_fields=required,
                    ready_for_answer=False,
                    search_terms=spec_terms,
                    validation_result="DETERMINISTIC_CAPABILITY_MATCH",
                )

        # For deployment-specific or novel semantics, ask the LLM to select a
        # semantic operation. It receives metadata only; it never receives raw
        # events and never emits native SPL/SQL/KQL.
        if self.llm_generator is not None:
            operation_ids = [str(getattr(operation, "id", "")) for operation in available_operations]
            prompt = json.dumps({
                "task": "select_semantic_hunt_operation",
                "answer_type": answer_type,
                "required_fields": list(required),
                "available_operations": operation_ids,
                "attempted_operations": sorted(attempted),
                "iteration": iteration,
                "observable_fields": sorted(fields),
                "anchors": [anchor.value for anchor in spec.anchors],
                "search_terms": [term.value for term in spec.search_terms],
                "output_schema": {
                    "operation": "one available operation",
                    "operation_id": "one available operation",
                    "required_fields": ["semantic field names only"],
                    "search_terms": ["literal content terms only"],
                    "reason": "short explanation",
                },
            }, ensure_ascii=False)
            prompt_hash = hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:16]

            def _validate_response(raw_resp: str) -> tuple[bool, str, dict[str, Any]]:
                cleaned = str(raw_resp).strip()
                if cleaned.startswith("```json"):
                    cleaned = cleaned[7:]
                elif cleaned.startswith("```"):
                    cleaned = cleaned[3:]
                if cleaned.endswith("```"):
                    cleaned = cleaned[:-3]
                cleaned = cleaned.strip()

                if not cleaned.startswith("{") and "{" in cleaned and "}" in cleaned:
                    s_idx = cleaned.find("{")
                    e_idx = cleaned.rfind("}") + 1
                    cleaned = cleaned[s_idx:e_idx].strip()

                try:
                    payload = json.loads(cleaned) if isinstance(cleaned, str) else cleaned
                except (TypeError, json.JSONDecodeError) as jde:
                    return False, f"MALFORMED_JSON: {jde}", {}

                if not isinstance(payload, dict):
                    return False, "MALFORMED_JSON: not a json object", {}

                op = str(payload.get("operation") or payload.get("operation_id", "")).strip()

                # Strictly reject direct SPL/SQL/KQL query statements
                if _contains_native_query(op):
                    return False, f"REJECTED_NATIVE_QUERY: '{op}'", {}

                terms = payload.get("search_terms", ())
                if isinstance(terms, (list, tuple)):
                    for t in terms:
                        if _contains_native_query(str(t)):
                            return False, f"REJECTED_NATIVE_QUERY in terms: '{t}'", {}

                # Operation must be in runtime descriptor
                if op not in operation_ids:
                    return False, f"REJECTED_NOT_IN_DESCRIPTOR: '{op}'", {}

                return True, "VALID", payload

            is_valid = False
            val_reason = ""
            payload: dict[str, Any] = {}
            active_prompt_hash = prompt_hash
            timed_out = False

            # Attempt 1
            try:
                raw = self.llm_generator(prompt)
                is_valid, val_reason, payload = _validate_response(raw)
            except Exception as exc:
                exc_str = str(exc).lower()
                if "timeout" in exc_str or "timed out" in exc_str or isinstance(exc, TimeoutError):
                    val_reason = f"TIMEOUT: {exc}"
                    timed_out = True
                else:
                    val_reason = f"LLM_ERROR: {exc}"

            self._record_observability(
                phase="adaptive_planner",
                prompt_hash=prompt_hash,
                selected_operation=payload.get("operation") or payload.get("operation_id", ""),
                search_terms=payload.get("search_terms", ()),
                validation_result=val_reason,
                attempt=1,
            )

            # Attempt 2 (Retry with shorter prompt if invalid and not timed out)
            if not is_valid and not timed_out:
                retry_prompt = json.dumps({
                    "task": "select_operation_retry",
                    "error": val_reason,
                    "available_operations": operation_ids,
                    "instructions": "Return ONLY JSON with 'operation' from available_operations and 'search_terms' list.",
                    "output_schema": {
                        "operation": "one of available_operations",
                        "search_terms": ["literal terms"],
                    },
                }, ensure_ascii=False)
                retry_hash = hashlib.sha256(retry_prompt.encode("utf-8")).hexdigest()[:16]
                active_prompt_hash = retry_hash
                try:
                    retry_raw = self.llm_generator(retry_prompt)
                    is_valid, val_reason, payload = _validate_response(retry_raw)
                except Exception as retry_exc:
                    retry_str = str(retry_exc).lower()
                    if "timeout" in retry_str or "timed out" in retry_str or isinstance(retry_exc, TimeoutError):
                        val_reason = f"TIMEOUT: {retry_exc}"
                    else:
                        val_reason = f"LLM_RETRY_ERROR: {retry_exc}"

                self._record_observability(
                    phase="adaptive_planner",
                    prompt_hash=retry_hash,
                    selected_operation=payload.get("operation") or payload.get("operation_id", ""),
                    search_terms=payload.get("search_terms", ()),
                    validation_result=val_reason,
                    attempt=2,
                )

            if is_valid and payload:
                selected = str(payload.get("operation") or payload.get("operation_id", "")).strip()
                selected_fields = tuple(
                    str(value).strip() for value in payload.get("required_fields", required)
                    if str(value).strip()
                )
                terms = tuple(
                    str(value).strip() for value in payload.get("search_terms", ())
                    if str(value).strip()
                )
                return AdaptiveDecision(
                    operation_id=selected,
                    reason=str(payload.get("reason", "LLM semantic operation selection")).strip(),
                    required_fields=selected_fields or required,
                    ready_for_answer=False,
                    search_terms=terms or spec_terms or fallback_terms,
                    prompt_hash=active_prompt_hash,
                    validation_result="VALID",
                )

            # Fallback to search_text with terms from NL question
            if "search_text" in {str(getattr(operation, "id", "")) for operation in available_operations}:
                fb_terms = fallback_terms or spec_terms
                self._record_observability(
                    phase="adaptive_planner",
                    prompt_hash=active_prompt_hash,
                    selected_operation="search_text",
                    search_terms=fb_terms,
                    validation_result=f"FALLBACK_SEARCH_TEXT ({val_reason})",
                    attempt=0,
                )
                return AdaptiveDecision(
                    operation_id="search_text",
                    reason=f"LLM fallback ({val_reason}) to search_text with NL terms",
                    required_fields=required,
                    ready_for_answer=False,
                    search_terms=fb_terms,
                    prompt_hash=active_prompt_hash,
                    validation_result=f"FALLBACK ({val_reason})",
                )

        if "search_text" in {str(getattr(operation, "id", "")) for operation in available_operations}:
            return AdaptiveDecision(
                operation_id="search_text",
                reason="provider-neutral content fallback",
                required_fields=required,
                ready_for_answer=False,
                search_terms=spec_terms or fallback_terms,
                validation_result="DEFAULT_CONTENT_FALLBACK",
            )
        return AdaptiveDecision(
            operation_id=None,
            reason=f"no validated operation for answer type '{answer_type}'",
            required_fields=required,
            ready_for_answer=False,
            search_terms=spec_terms or fallback_terms,
            validation_result="NO_VALID_OPERATION",
        )

    def make_plan(
        self,
        decision: AdaptiveDecision,
        provider_id: str,
        scope_id: str,
        query_id: str,
        requirement_id: str,
        window: str,
        anchors: list[str],
    ) -> QueryPlan | None:
        if not decision.operation_id:
            return None
        return QueryPlan(
            id=query_id,
            requirement_id=requirement_id,
            provider_id=provider_id,
            scope_id=scope_id,
            operation_id=decision.operation_id,
            parameters={
                "window": window,
                "anchors": list(anchors),
                "required_fields": list(decision.required_fields),
                "search_terms": list(decision.search_terms),
                "purpose": decision.reason,
            },
            is_targeted=bool(anchors),
        )


__all__ = ["AdaptiveDecision", "AdaptiveOperationPlanner"]
