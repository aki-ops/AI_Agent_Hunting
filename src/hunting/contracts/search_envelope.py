"""SearchEnvelope Contracts.

Defines the explicit bounding envelope for hunting operations:
- HardConstraints: Immutable invariants (pinned entities, verified bindings,
  outer time window, allowed providers, relation direction, proof obligations).
  Strictly non-relaxable.
- ExpandableRetrievalHints: Bounded relaxable hints (lexical variants,
  field aliases, source priority order, optional predicates, alternate routes)
  with explicit maximum expansion level.
- BudgetEnvelope: Quantitative vector budget across queries, LLM calls, tokens,
  frontier expansions, replans, discriminators, and wall time.
- SearchEnvelope: The unified boundary versioned as E_0 -> E_1 -> E_2 with
  parent tracking, change logs, derivation reasoning, and candidate fanout clamping.
"""
from __future__ import annotations

import copy
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone


@dataclass(frozen=True)
class HardConstraints:
    """Immutable boundary constraints that must never be widened or violated during a hunt."""

    pinned_entities: frozenset[str] = field(default_factory=frozenset)
    verified_bindings: tuple[tuple[str, str], ...] = field(default_factory=tuple)
    time_window_start: str | None = None
    time_window_end: str | None = None
    allowed_providers: frozenset[str] = field(default_factory=frozenset)
    relation_direction: str | None = None
    proof_obligations: tuple[str, ...] = field(default_factory=tuple)
    max_total_budget_usd: float = 1.0

    def get_verified_binding(self, role: str) -> str | None:
        """Get the verified value bound to a semantic role."""
        for r, val in self.verified_bindings:
            if r == role:
                return val
        return None

    def with_verified_binding(self, role: str, value: str) -> HardConstraints:
        """Return a new HardConstraints adding a verified binding monotonically."""
        current = dict(self.verified_bindings)
        if role in current and current[role] != value:
            raise ValueError(
                f"Cannot override verified binding for {role}: existing={current[role]}, new={value}"
            )
        current[role] = value
        return HardConstraints(
            pinned_entities=self.pinned_entities,
            verified_bindings=tuple(sorted(current.items())),
            time_window_start=self.time_window_start,
            time_window_end=self.time_window_end,
            allowed_providers=self.allowed_providers,
            relation_direction=self.relation_direction,
            proof_obligations=self.proof_obligations,
            max_total_budget_usd=self.max_total_budget_usd,
        )


@dataclass
class ExpandableRetrievalHints:
    """Retrieval hints that may be progressively relaxed within declared bounds."""

    lexical_variants: list[str] = field(default_factory=list)
    field_aliases: dict[str, list[str]] = field(default_factory=dict)
    source_priority_order: list[str] = field(default_factory=list)
    optional_predicates: list[str] = field(default_factory=list)
    alternative_routes: list[str] = field(default_factory=list)
    current_expansion_level: int = 0
    max_expansion_level: int = 3

    def can_expand(self) -> bool:
        """Check whether hints can be expanded further."""
        return self.current_expansion_level < self.max_expansion_level

    def clone(self) -> ExpandableRetrievalHints:
        """Deep copy of retrieval hints."""
        return copy.deepcopy(self)


@dataclass
class BudgetEnvelope:
    """Quantitative vector budget for search operations."""

    max_queries: int = 20
    max_llm_calls: int = 5
    max_llm_tokens: int = 15000
    max_frontier_expansions: int = 3
    max_replans: int = 1
    max_discriminators: int = 2
    max_wall_clock_seconds: float = 120.0

    consumed_queries: int = 0
    consumed_llm_calls: int = 0
    consumed_llm_tokens: int = 0
    consumed_frontier_expansions: int = 0
    consumed_replans: int = 0
    consumed_discriminators: int = 0

    @property
    def is_exhausted(self) -> bool:
        """Check if any primary budget ceiling has been exhausted."""
        return (
            self.consumed_queries >= self.max_queries
            or self.consumed_llm_calls >= self.max_llm_calls
            or self.consumed_llm_tokens >= self.max_llm_tokens
            or self.consumed_frontier_expansions >= self.max_frontier_expansions
            or self.consumed_replans >= self.max_replans
        )

    def remaining_tokens(self) -> int:
        """Remaining tokens in run budget."""
        return max(0, self.max_llm_tokens - self.consumed_llm_tokens)

    def remaining_calls(self) -> int:
        """Remaining LLM calls in run budget."""
        return max(0, self.max_llm_calls - self.consumed_llm_calls)

    def remaining_queries(self) -> int:
        """Remaining queries in run budget."""
        return max(0, self.max_queries - self.consumed_queries)

    def has_budget_for(
        self,
        queries: int = 0,
        llm_calls: int = 0,
        tokens: int = 0,
        frontier_expansions: int = 0,
    ) -> bool:
        """Check whether requested resources fit inside remaining budget."""
        if queries > 0 and self.consumed_queries + queries > self.max_queries:
            return False
        if llm_calls > 0 and self.consumed_llm_calls + llm_calls > self.max_llm_calls:
            return False
        if tokens > 0 and self.consumed_llm_tokens + tokens > self.max_llm_tokens:
            return False
        if (
            frontier_expansions > 0
            and self.consumed_frontier_expansions + frontier_expansions > self.max_frontier_expansions
        ):
            return False
        return True

    def consume(
        self,
        queries: int = 0,
        llm_calls: int = 0,
        tokens: int = 0,
        frontier_expansions: int = 0,
        replans: int = 0,
        discriminators: int = 0,
    ) -> None:
        """Record resource consumption."""
        self.consumed_queries += queries
        self.consumed_llm_calls += llm_calls
        self.consumed_llm_tokens += tokens
        self.consumed_frontier_expansions += frontier_expansions
        self.consumed_replans += replans
        self.consumed_discriminators += discriminators

    def clone(self) -> BudgetEnvelope:
        """Deep copy of budget envelope."""
        return copy.deepcopy(self)


@dataclass
class SearchEnvelope:
    """The unified boundary envelope governing a search phase.

    Enforces:
    - Immutability of hard constraints.
    - Controlled relaxation of declared hints through versioned derivation (E_0 -> E_1 -> ...).
    - Candidate fanout cap to prevent branch explosion.
    - Preflight boundary checks.
    """

    envelope_id: str = field(default_factory=lambda: f"env-{uuid.uuid4().hex[:8]}")
    version: int = 0
    parent_envelope_id: str | None = None
    hard_constraints: HardConstraints = field(default_factory=HardConstraints)
    retrieval_hints: ExpandableRetrievalHints = field(default_factory=ExpandableRetrievalHints)
    budgets: BudgetEnvelope = field(default_factory=BudgetEnvelope)
    changed_constraints: list[str] = field(default_factory=list)
    derivation_reason: str = ""
    max_candidate_fanout: int = 5
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def validate_candidate_fanout(self, candidate_count: int) -> bool:
        """Check if candidate fanout is within bounded limits."""
        return candidate_count <= self.max_candidate_fanout

    def is_in_bounds(
        self,
        entity_id: str | None = None,
        timestamp_iso: str | None = None,
        provider: str | None = None,
    ) -> bool:
        """Check if a query target, timestamp, or provider conforms to hard constraints."""
        if provider and self.hard_constraints.allowed_providers:
            if provider not in self.hard_constraints.allowed_providers:
                return False

        if timestamp_iso:
            if self.hard_constraints.time_window_start and timestamp_iso < self.hard_constraints.time_window_start:
                return False
            if self.hard_constraints.time_window_end and timestamp_iso > self.hard_constraints.time_window_end:
                return False

        return True

    def derive_next(
        self,
        new_hints: ExpandableRetrievalHints | None = None,
        reason: str = "",
        changed_descriptions: list[str] | None = None,
        new_hard_constraints: HardConstraints | None = None,
    ) -> SearchEnvelope:
        """Derive the next versioned envelope (E_{i+1}) from this envelope.

        Rules:
        - Hard constraints can only be narrowed (e.g. adding verified bindings), never loosened.
        - If new_hard_constraints is passed, it must not violate existing pinned entities,
          providers, or time windows.
        - Retrieval hints can only be expanded if current_expansion_level < max_expansion_level.
        """
        # Validate hints expansion level
        hints_to_use = new_hints.clone() if new_hints else self.retrieval_hints.clone()
        if new_hints:
            if not self.retrieval_hints.can_expand():
                raise ValueError(
                    f"Cannot expand beyond maximum retrieval expansion level ({self.retrieval_hints.max_expansion_level})"
                )
            hints_to_use.current_expansion_level = self.retrieval_hints.current_expansion_level + 1

        # Validate hard constraints immutability / monotonic narrowing
        hc_to_use = self.hard_constraints
        if new_hard_constraints:
            # Check pinned entities were not removed
            if not self.hard_constraints.pinned_entities.issubset(new_hard_constraints.pinned_entities):
                raise ValueError("Cannot remove pinned entities from hard constraints")
            # Check allowed providers were not widened
            if self.hard_constraints.allowed_providers:
                if not new_hard_constraints.allowed_providers.issubset(self.hard_constraints.allowed_providers):
                    raise ValueError("Cannot expand allowed providers beyond initial hard constraints")
            # Check time window was not widened
            if self.hard_constraints.time_window_start and new_hard_constraints.time_window_start:
                if new_hard_constraints.time_window_start < self.hard_constraints.time_window_start:
                    raise ValueError("Cannot widen time window start before hard constraints boundary")
            if self.hard_constraints.time_window_end and new_hard_constraints.time_window_end:
                if new_hard_constraints.time_window_end > self.hard_constraints.time_window_end:
                    raise ValueError("Cannot widen time window end after hard constraints boundary")
            hc_to_use = new_hard_constraints

        # Record changes
        changes = list(changed_descriptions) if changed_descriptions else []
        if not changes:
            changes.append(f"Derived E_{self.version + 1} from E_{self.version}")

        return SearchEnvelope(
            envelope_id=f"env-{uuid.uuid4().hex[:8]}",
            version=self.version + 1,
            parent_envelope_id=self.envelope_id,
            hard_constraints=hc_to_use,
            retrieval_hints=hints_to_use,
            budgets=self.budgets.clone(),
            changed_constraints=changes,
            derivation_reason=reason or f"Progressive relaxation/narrowing at step {self.version + 1}",
            max_candidate_fanout=self.max_candidate_fanout,
        )
