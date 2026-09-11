"""Conservative AST-shaped gate for LLM-proposed Splunk queries.

The project does not claim to parse all SPL. Unsupported syntax is rejected.
That is safer than accepting a query after a regex-only inspection.
"""
from __future__ import annotations

import hashlib
import re
from typing import Iterable

from hunting.contracts.native_query import NativeQueryCandidate, NativeQueryValidationResult
from hunting.m5_adapter.allowlist import validate_time_window_format

_FORBIDDEN_COMMANDS = frozenset({
    "collect", "delete", "dump", "eventstats", "outputlookup", "outputcsv",
    "sendemail", "script", "map", "run", "loadjob", "makeresults",
})
_ALLOWED_PIPE_COMMANDS = frozenset({
    "table", "fields", "head", "dedup", "stats", "where", "sort", "rex",
    "eval", "rename", "search", "format", "fillnull",
})
_IDENTIFIER = re.compile(r"\b[A-Za-z_][A-Za-z0-9_.:-]*\b")
_FIELD_ASSIGNMENT = re.compile(r"\b([A-Za-z_][A-Za-z0-9_.:-]*)\s*(?:=|!=|>=|<=|>|<)")
_INDEX = re.compile(r"\bindex\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|([^\s|]+))", re.IGNORECASE)
_WILDCARD_INDEX = re.compile(r"\bindex\s*=\s*(?:\"([^\"]*\*+[^\"]*)\"|'([^']*\*+[^']*)'|([^\s|]*\*+[^\s|]*))", re.IGNORECASE)


def compute_query_signature(query: str, time_window: str = "") -> str:
    """Compute deterministic semantic signature of a query for loop prevention."""
    norm_query = " ".join(query.strip().casefold().split())
    norm_window = time_window.strip().casefold()
    combined = f"{norm_query}::{norm_window}"
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()


def _split_pipeline(text: str) -> list[str]:
    parts: list[str] = []
    start = 0
    quote: str | None = None
    escaped = False
    for index, char in enumerate(text):
        if escaped:
            escaped = False
            continue
        if char == "\\" and quote:
            escaped = True
            continue
        if char in {"'", '"'}:
            quote = None if quote == char else (char if quote is None else quote)
        elif char == "|" and quote is None:
            parts.append(text[start:index].strip())
            start = index + 1
    parts.append(text[start:].strip())
    return parts


class NativeQueryGate:
    """Accept only bounded, read-only, census-bound SPL candidates."""

    def validate(
        self,
        candidate: NativeQueryCandidate,
        *,
        known_sources: Iterable[str],
        known_fields: Iterable[str],
        max_scan_cost: int = 1000,
        executed_query_signatures: Iterable[str] = (),
    ) -> NativeQueryValidationResult:
        query = candidate.query_text.strip()
        reasons: list[str] = []
        if not query:
            reasons.append("empty_query")
        if ";" in query or "\x00" in query:
            reasons.append("multiple_statements_or_nul")
        if not candidate.time_window.strip():
            reasons.append("explicit_time_window_required")
        else:
            try:
                validate_time_window_format(candidate.time_window)
            except ValueError:
                reasons.append("invalid_time_window")

        # Duplicate query signature loop detection
        query_sig = compute_query_signature(candidate.query_text, candidate.time_window)
        if query_sig in set(executed_query_signatures):
            reasons.append("duplicate_query_signature_blocked")

        # Wildcard index check
        if _WILDCARD_INDEX.search(query):
            reasons.append("broad_wildcard_query_rejected")

        # Wildcard search clause check
        if re.search(r"\bsearch\s+\*(\s|$|\|)", query, re.IGNORECASE):
            reasons.append("broad_wildcard_query_rejected")

        sources = {str(value).casefold() for value in known_sources}
        fields = {str(value).casefold() for value in known_fields}
        indexes = [next(value for value in match.groups() if value is not None) for match in _INDEX.finditer(query)]
        if not indexes:
            reasons.append("census_bound_index_required")
        elif any(index.casefold() not in sources for index in indexes):
            reasons.append("index_not_in_census")

        stages = _split_pipeline(query)
        if not stages or not stages[0].casefold().startswith("search"):
            reasons.append("query_must_start_with_search")

        # Primary search stage unconstrained check
        if stages and stages[0].casefold().startswith("search"):
            first_stage = stages[0]
            stripped_stage = re.sub(r"^\s*search\b", "", first_stage, flags=re.IGNORECASE)
            stripped_stage = _INDEX.sub("", stripped_stage).strip()
            has_explicit_field = bool(_FIELD_ASSIGNMENT.search(stripped_stage))
            if not has_explicit_field and (not stripped_stage or stripped_stage == "*"):
                reasons.append("broad_wildcard_query_rejected")

        commands: list[str] = []
        for stage in stages[1:]:
            command = stage.split(None, 1)[0].casefold() if stage else ""
            commands.append(command)
            if command in _FORBIDDEN_COMMANDS:
                reasons.append(f"forbidden_command:{command}")
            elif command not in _ALLOWED_PIPE_COMMANDS:
                reasons.append(f"unsupported_command:{command}")

        # A bounded query must state a result cap.  ``head`` is accepted only
        # when its integer is within the candidate's own declared bound.
        head_values = [int(value) for value in re.findall(r"\bhead\s+(\d+)\b", query, re.IGNORECASE)]
        if not head_values:
            reasons.append("explicit_head_limit_required")
        elif max(head_values) > candidate.max_rows:
            reasons.append("head_exceeds_candidate_limit")

        projection_fields: list[str] = []
        for stage in stages:
            if stage.split(None, 1)[0].casefold() in {"table", "fields", "dedup", "sort"}:
                projection_fields.extend(_IDENTIFIER.findall(stage.split(None, 1)[1] if " " in stage else ""))
        explicit_fields = [match.group(1) for match in _FIELD_ASSIGNMENT.finditer(query)]
        for field_name in [*projection_fields, *explicit_fields, *candidate.expected_fields]:
            if field_name.casefold() in {"index", "search", "head", "by", "as", "from"}:
                continue
            if field_name.casefold() not in fields:
                reasons.append(f"field_not_in_census:{field_name}")

        # The simple gate cannot prove provider scan cost; it enforces a hard
        # proxy bound so future adapters can replace it with a native estimate.
        estimated_cost = len(query) + 100 * len(stages)
        if estimated_cost > max_scan_cost * 10:
            reasons.append("estimated_cost_exceeds_bound")

        accepted = not reasons
        return NativeQueryValidationResult(
            accepted=accepted,
            normalized_query=query if accepted else "",
            estimated_cost=estimated_cost,
            reasons=tuple(dict.fromkeys(reasons)),
            ast={
                "kind": "limited_spl_pipeline",
                "stages": len(stages),
                "commands": commands,
                "query_signature": query_sig,
            },
            query_signature=query_sig,
        )


__all__ = ["NativeQueryGate", "compute_query_signature"]
