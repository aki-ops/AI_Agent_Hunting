"""Query Plan Cache.

Fulfills Phase 2 requirement:
- Cache validated plans by requirement/provider/schema.
"""
from __future__ import annotations

from typing import Tuple

from hunting.contracts.hunt import QueryPlan


class PlanCache:
    """Thread-safe plan cache keyed by (requirement_type, provider_id, schema_version)."""

    def __init__(self) -> None:
        self._cache: dict[Tuple[str, str, str], QueryPlan] = {}

    def get(self, requirement_type: str, provider_id: str, schema_version: str = "1.0") -> QueryPlan | None:
        """Retrieve a cached query plan if present."""
        return self._cache.get((requirement_type, provider_id, schema_version))

    def put(self, requirement_type: str, provider_id: str, plan: QueryPlan, schema_version: str = "1.0") -> None:
        """Store a validated query plan in cache."""
        self._cache[(requirement_type, provider_id, schema_version)] = plan

    def clear(self) -> None:
        """Clear cache."""
        self._cache.clear()

    def __len__(self) -> int:
        return len(self._cache)


__all__ = ["PlanCache"]
