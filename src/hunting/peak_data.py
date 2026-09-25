"""PEAK data location: minimap row, confirmed by a count, then linked to a goal.

A row is usable only when its sourcetype has events. The link is shared words
between the goal (relation and roles) and the row (evidence name and fields).
"""
from __future__ import annotations

import re
from typing import Any


def minimap_entries(manifest: dict[str, Any] | None) -> list[dict[str, Any]]:
    bindings = (manifest or {}).get("bindings") or {}
    entries = []
    for evidence, raw in bindings.items():
        if not isinstance(raw, dict):
            continue
        sourcetype = str(raw.get("sourcetype") or "").strip()
        fields = tuple(str(name) for name in (raw.get("extractions") or {}))
        entries.append({"evidence": str(evidence), "sourcetype": sourcetype, "fields": fields})
    return entries


def confirm_entries(entries: list[dict[str, Any]], counts: dict[str, int]) -> list[dict[str, Any]]:
    """Keep minimap rows whose sourcetype the count query actually saw."""
    confirmed = []
    for entry in entries:
        sourcetype = entry["sourcetype"]
        if not sourcetype or sourcetype == "*":
            continue
        count = int(counts.get(sourcetype, 0) or 0)
        if count <= 0:
            continue
        confirmed.append({**entry, "count": count})
    return confirmed


def _tokens(*parts: str) -> set[str]:
    words: set[str] = set()
    for part in parts:
        for token in re.split(r"[^a-z0-9]+", str(part).lower()):
            if len(token) > 3:
                words.add(token)
    return words


def link_goal(relation: str, roles: tuple[str, ...], entries: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Return confirmed rows that talk about the same thing as the goal."""
    wanted = _tokens(relation, *roles)
    hits = []
    for entry in entries:
        have = _tokens(entry["evidence"], *entry.get("fields", ()))
        if wanted & have:
            hits.append(entry)
    return hits
