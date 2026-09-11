"""Mixed-Initiative Clarification and Discriminator Planning.

Component of Phase 4 (Controlled Binding and Mixed-Initiative Control):
- Synthesizes cheap DISCRIMINATOR query when multiple candidate bindings exist.
- Triggers interactive clarification or non-interactive NEEDS_DISAMBIGUATION halt with checkpoint.
- Anti-heuristics: Substring matches ('air'), first row, or edit distance never win.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from enum import Enum
from typing import Any

from hunting.contracts.bindings import CandidateSet


class DisambiguationAction(str, Enum):
    AUTO_BOUND = "AUTO_BOUND"
    DISCRIMINATE = "DISCRIMINATE"
    CLARIFY_INTERACTIVE = "CLARIFY_INTERACTIVE"
    NEEDS_DISAMBIGUATION = "NEEDS_DISAMBIGUATION"


@dataclass(frozen=True)
class DiscriminatorQuerySpec:
    """Bounded, narrow query intended to distinguish between candidate bindings."""
    target_variable_id: str
    candidate_values: tuple[str, ...]
    discriminator_relation: str
    discriminator_field: str
    estimated_cost: int = 1
    description: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "target_variable_id": self.target_variable_id,
            "candidate_values": list(self.candidate_values),
            "discriminator_relation": self.discriminator_relation,
            "discriminator_field": self.discriminator_field,
            "estimated_cost": self.estimated_cost,
            "description": self.description,
        }


@dataclass
class DisambiguationCheckpoint:
    """Resumable checkpoint emitted when non-interactive execution requires clarification."""
    checkpoint_id: str
    request_id: str
    variable_id: str
    candidate_values: tuple[str, ...]
    supporting_citations: tuple[str, ...]
    expected_cost: int
    prompt_question: str
    resume_token: str
    status: str = "NEEDS_DISAMBIGUATION"
    resolved_value: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "checkpoint_id": self.checkpoint_id,
            "request_id": self.request_id,
            "variable_id": self.variable_id,
            "candidate_values": list(self.candidate_values),
            "supporting_citations": list(self.supporting_citations),
            "expected_cost": self.expected_cost,
            "prompt_question": self.prompt_question,
            "resume_token": self.resume_token,
            "status": self.status,
            "resolved_value": self.resolved_value,
        }


class ClarificationController:
    """Manages candidate disambiguation, discriminator queries, and human-in-the-loop checkpoints."""

    def __init__(self, *, interactive: bool = False, max_discriminator_attempts: int = 1) -> None:
        self.interactive = interactive
        self.max_discriminator_attempts = max_discriminator_attempts
        self._discriminator_attempts: dict[str, int] = {}

    def resolve_candidate_set(
        self,
        candidate_set: CandidateSet,
        *,
        request_id: str = "req",
        context_description: str = "",
    ) -> tuple[DisambiguationAction, Any]:
        """Determine next action for a CandidateSet: auto-bind, discriminate, or clarify/halt."""
        # 1. Try auto-binding if unique and proof-supported
        if candidate_set.can_autobind:
            binding = candidate_set.try_autobind()
            return DisambiguationAction.AUTO_BOUND, binding

        valid = candidate_set.valid_candidates

        # 2. If ambiguous (multiple candidates exist)
        if len(valid) > 1:
            var_id = candidate_set.variable_id
            attempts = self._discriminator_attempts.get(var_id, 0)

            # Step 1: Synthesize a cheap discriminator query if budget allows
            if attempts < self.max_discriminator_attempts:
                self._discriminator_attempts[var_id] = attempts + 1
                cand_vals = tuple(c.value for c in valid)
                discriminator = DiscriminatorQuerySpec(
                    target_variable_id=var_id,
                    candidate_values=cand_vals,
                    discriminator_relation="logged_on_to" if candidate_set.entity_type in {"host", "endpoint"} else "observed",
                    discriminator_field="host" if candidate_set.entity_type in {"host", "endpoint"} else "entity",
                    estimated_cost=1,
                    description=f"Differentiate {len(cand_vals)} candidates for '{var_id}': {cand_vals}",
                )
                return DisambiguationAction.DISCRIMINATE, discriminator

            # Step 2: Discriminator exhausted or unavailable -> Clarification / Halt
            all_citations: list[str] = []
            for c in valid:
                all_citations.extend(c.supporting_fact_ids)

            cand_vals = tuple(c.value for c in valid)
            question = (
                f"Multiple candidate {candidate_set.entity_type}s were found for '{var_id}': {list(cand_vals)}. "
                "Which entity should be used for downstream investigation?"
            )
            token = hashlib.sha256(f"{request_id}:{var_id}:{cand_vals}".encode("utf-8")).hexdigest()[:16]

            checkpoint = DisambiguationCheckpoint(
                checkpoint_id=f"chk-{var_id}-{token[:8]}",
                request_id=request_id,
                variable_id=var_id,
                candidate_values=cand_vals,
                supporting_citations=tuple(sorted(set(all_citations))),
                expected_cost=1,
                prompt_question=question,
                resume_token=token,
                status="NEEDS_DISAMBIGUATION",
            )

            if self.interactive:
                return DisambiguationAction.CLARIFY_INTERACTIVE, checkpoint
            else:
                return DisambiguationAction.NEEDS_DISAMBIGUATION, checkpoint

        # 0 valid candidates
        return DisambiguationAction.NEEDS_DISAMBIGUATION, None


__all__ = [
    "DisambiguationAction",
    "DiscriminatorQuerySpec",
    "DisambiguationCheckpoint",
    "ClarificationController",
]
