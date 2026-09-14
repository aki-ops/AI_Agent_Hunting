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
from dataclasses import dataclass, field, replace
from datetime import datetime, timezone
from enum import Enum
from typing import Any


class LLMPhase(str, Enum):
    """Canonical v9 touchpoint taxonomy (C1 - C6)."""
    C1_COMPILER = "C1_COMPILER"
    C1V_AMBIGUITY = "C1V_AMBIGUITY"
    C2_SOURCE_PROFILER = "C2_SOURCE_PROFILER"
    C3_QUERY_GEN = "C3_QUERY_GEN"
    C4_DISCRIMINATOR = "C4_DISCRIMINATOR"
    C5_REPLAN = "C5_REPLAN"
    C6_NARRATIVE = "C6_NARRATIVE"


def normalize_phase(name: str | LLMPhase) -> LLMPhase:
    """Map component names or abbreviations to canonical LLMPhase."""
    if isinstance(name, LLMPhase):
        return name
    n = str(name).strip().upper()
    if n in ("C1", "C1_COMPILER", "COMPILER", "SEMANTIC_COMPILER"):
        return LLMPhase.C1_COMPILER
    if n in ("C1V", "C1V_AMBIGUITY", "AMBIGUITY", "CLARIFICATION", "AMBIGUITY_CHECK"):
        return LLMPhase.C1V_AMBIGUITY
    if n in ("C2", "C2_SOURCE_PROFILER", "SOURCE_PROFILER", "PROFILER"):
        return LLMPhase.C2_SOURCE_PROFILER
    if n in ("C3", "C3_QUERY_GEN", "QUERY_GEN", "PLANNER", "ADAPTIVE_PLANNER", "NATIVE_QUERY"):
        return LLMPhase.C3_QUERY_GEN
    if n in ("C4", "C4_DISCRIMINATOR", "DISCRIMINATOR", "EVALUATOR"):
        return LLMPhase.C4_DISCRIMINATOR
    if n in ("C5", "C5_REPLAN", "REPLAN", "DEADLOCK_REPLAN"):
        return LLMPhase.C5_REPLAN
    if n in ("C6", "C6_NARRATIVE", "NARRATIVE"):
        return LLMPhase.C6_NARRATIVE
    return LLMPhase.C3_QUERY_GEN


@dataclass(frozen=True)
class PhaseReservationPolicy:
    """Reservation rule for an individual LLM touchpoint."""
    phase: LLMPhase
    is_mandatory: bool
    max_calls: int
    max_input_tokens: int
    max_output_tokens: int
    description: str = ""


@dataclass
class LLMBudgetPolicy:
    """Authoritative shared policy governing all LLM calls across CLI, tracker, SearchEnvelope, and Engine.

    Eliminates max-call drift between 4 and 5 (unified default: 5 calls).
    """
    max_total_calls: int = 5
    max_total_tokens: int = 15000
    model_name: str = "stub"
    phase_policies: dict[str, PhaseReservationPolicy] = field(default_factory=lambda: {
        LLMPhase.C1_COMPILER.value: PhaseReservationPolicy(
            phase=LLMPhase.C1_COMPILER,
            is_mandatory=True,
            max_calls=2,  # 1 initial + at most 1 repair
            max_input_tokens=2500,
            max_output_tokens=1200,
            description="Semantic compilation (1 mandatory + at most 1 repair)",
        ),
        LLMPhase.C1V_AMBIGUITY.value: PhaseReservationPolicy(
            phase=LLMPhase.C1V_AMBIGUITY,
            is_mandatory=True,
            max_calls=1,  # ambiguity only
            max_input_tokens=1500,
            max_output_tokens=600,
            description="Ambiguity and clarification verification",
        ),
        LLMPhase.C2_SOURCE_PROFILER.value: PhaseReservationPolicy(
            phase=LLMPhase.C2_SOURCE_PROFILER,
            is_mandatory=False,
            max_calls=1,  # cache miss only, bounded batches
            max_input_tokens=1800,
            max_output_tokens=700,
            description="Telemetry source profiling (cache miss only)",
        ),
        LLMPhase.C3_QUERY_GEN.value: PhaseReservationPolicy(
            phase=LLMPhase.C3_QUERY_GEN,
            is_mandatory=False,
            max_calls=1,  # deterministic compiler unsupported only
            max_input_tokens=1800,
            max_output_tokens=700,
            description="Native query generation (unsupported ops only)",
        ),
        LLMPhase.C4_DISCRIMINATOR.value: PhaseReservationPolicy(
            phase=LLMPhase.C4_DISCRIMINATOR,
            is_mandatory=False,
            max_calls=1,  # grouped ambiguity only
            max_input_tokens=2500,
            max_output_tokens=800,
            description="Candidate discriminator / evaluator",
        ),
        LLMPhase.C5_REPLAN.value: PhaseReservationPolicy(
            phase=LLMPhase.C5_REPLAN,
            is_mandatory=False,
            max_calls=1,  # one material-deadlock replan
            max_input_tokens=2000,
            max_output_tokens=900,
            description="Material-deadlock replan",
        ),
        LLMPhase.C6_NARRATIVE.value: PhaseReservationPolicy(
            phase=LLMPhase.C6_NARRATIVE,
            is_mandatory=False,
            max_calls=0,  # disabled
            max_input_tokens=0,
            max_output_tokens=0,
            description="Narrative generation (disabled)",
        ),
    })

    def get_phase_policy(self, phase: str | LLMPhase) -> PhaseReservationPolicy:
        norm = normalize_phase(phase)
        return self.phase_policies.get(
            norm.value,
            PhaseReservationPolicy(
                phase=norm,
                is_mandatory=False,
                max_calls=1,
                max_input_tokens=2000,
                max_output_tokens=800,
                description=f"Fallback policy for {norm.value}",
            ),
        )


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
        current[role] = value
        return HardConstraints(
            pinned_entities=self.pinned_entities | {value},
            verified_bindings=tuple(sorted(current.items())),
            time_window_start=self.time_window_start,
            time_window_end=self.time_window_end,
            allowed_providers=self.allowed_providers,
            relation_direction=self.relation_direction,
            proof_obligations=self.proof_obligations,
            max_total_budget_usd=self.max_total_budget_usd,
        )


@dataclass(frozen=True)
class ExpandableRetrievalHints:
    """Bounded relaxable hints for retrieval operations."""

    lexical_variants: frozenset[str] = field(default_factory=frozenset)
    field_aliases: tuple[tuple[str, str], ...] = field(default_factory=tuple)
    source_priority_order: tuple[str, ...] = field(default_factory=tuple)
    optional_predicates: tuple[str, ...] = field(default_factory=tuple)
    alternate_routes: tuple[str, ...] = field(default_factory=tuple)
    current_expansion_level: int = 0
    max_expansion_level: int = 2

    def can_expand(self) -> bool:
        """True if hints can be widened further."""
        return self.current_expansion_level < self.max_expansion_level

    def clone(self) -> ExpandableRetrievalHints:
        """Deep copy of retrieval hints."""
        return copy.deepcopy(self)


@dataclass
class BudgetEnvelope:
    """Quantitative vector budget for search operations governed by LLMBudgetPolicy."""

    policy: LLMBudgetPolicy = field(default_factory=LLMBudgetPolicy)
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

    def __post_init__(self) -> None:
        if self.policy:
            self.max_llm_calls = self.policy.max_total_calls
            self.max_llm_tokens = self.policy.max_total_tokens

    @classmethod
    def from_policy(cls, policy: LLMBudgetPolicy, **kwargs: Any) -> BudgetEnvelope:
        """Construct BudgetEnvelope strictly aligned with an authoritative LLMBudgetPolicy."""
        return cls(
            policy=policy,
            max_llm_calls=policy.max_total_calls,
            max_llm_tokens=policy.max_total_tokens,
            **kwargs,
        )

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
        hints_to_use = new_hints.clone() if new_hints else self.retrieval_hints.clone()
        if new_hints:
            if not self.retrieval_hints.can_expand():
                raise ValueError(
                    f"Cannot expand beyond maximum retrieval expansion level ({self.retrieval_hints.max_expansion_level})"
                )
            hints_to_use = replace(hints_to_use, current_expansion_level=self.retrieval_hints.current_expansion_level + 1)

        hc_to_use = self.hard_constraints
        if new_hard_constraints:
            if not self.hard_constraints.pinned_entities.issubset(new_hard_constraints.pinned_entities):
                raise ValueError("Cannot remove pinned entities from hard constraints")
            if self.hard_constraints.allowed_providers:
                if not new_hard_constraints.allowed_providers.issubset(self.hard_constraints.allowed_providers):
                    raise ValueError("Cannot expand allowed providers beyond initial hard constraints")
            if self.hard_constraints.time_window_start:
                if (
                    not new_hard_constraints.time_window_start
                    or new_hard_constraints.time_window_start < self.hard_constraints.time_window_start
                ):
                    raise ValueError("Cannot expand start time beyond initial boundary")
            if self.hard_constraints.time_window_end:
                if (
                    not new_hard_constraints.time_window_end
                    or new_hard_constraints.time_window_end > self.hard_constraints.time_window_end
                ):
                    raise ValueError("Cannot expand end time beyond initial boundary")
            hc_to_use = new_hard_constraints

        return SearchEnvelope(
            version=self.version + 1,
            parent_envelope_id=self.envelope_id,
            hard_constraints=hc_to_use,
            retrieval_hints=hints_to_use,
            budgets=self.budgets.clone(),
            changed_constraints=list(changed_descriptions or []),
            derivation_reason=reason,
            max_candidate_fanout=self.max_candidate_fanout,
        )


__all__ = [
    "LLMPhase",
    "normalize_phase",
    "PhaseReservationPolicy",
    "LLMBudgetPolicy",
    "HardConstraints",
    "ExpandableRetrievalHints",
    "BudgetEnvelope",
    "SearchEnvelope",
]
