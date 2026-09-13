"""LoopGuard: Action deduplication and progress monotonicity enforcement.

Prevents unbounded agent cycling and infinite query loops by tracking ActionSignatures,
detecting absence of material delta, and transitioning routes to NO_PROGRESS / EXHAUSTED.
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from hunting.contracts.observation_class import ActionSignature, RouteStatus


@dataclass
class ActionExecutionRecord:
    """Audit record of an executed action signature."""

    signature_hash: str
    turn_index: int
    rows_count: int
    new_candidates_count: int
    cursor: str | None
    result_hash: str
    is_material_delta: bool
    timestamp_iso: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )


class LoopGuard:
    """Deterministic guard enforcing loop termination and progress monotonicity."""

    def __init__(self, max_consecutive_stalls: int = 2) -> None:
        self.max_consecutive_stalls = max_consecutive_stalls
        self.history: list[ActionExecutionRecord] = []
        self.action_counts: dict[str, int] = {}
        self.consecutive_stalls: dict[str, int] = {}
        self.exhausted_routes: set[str] = set()
        self.route_statuses: dict[str, RouteStatus] = {}

    def record_action(
        self,
        signature: ActionSignature,
        turn_index: int,
        rows_count: int = 0,
        new_candidates_count: int = 0,
        cursor: str | None = None,
        result_payload: Any = None,
    ) -> bool:
        """Record an executed action and determine if material progress was made.

        Returns:
            True if material progress was made; False if this action was a stall/duplicate.
        """
        sig_hash = signature.compute_hash()
        self.action_counts[sig_hash] = self.action_counts.get(sig_hash, 0) + 1

        # Fingerprint the result payload
        res_str = str(result_payload) if result_payload is not None else ""
        res_hash = hashlib.sha256(res_str.encode("utf-8")).hexdigest()[:12]

        # Check if previous executions of this signature produced identical results
        previous_records = [r for r in self.history if r.signature_hash == sig_hash]

        is_material_delta = False
        if not previous_records:
            # First execution of this signature is considered progress unless it's a zero-yield empty call
            is_material_delta = True
        else:
            last_record = previous_records[-1]
            # Progress requires new rows, new candidates, advancing cursor, or distinct result hash
            if new_candidates_count > 0:
                is_material_delta = True
            elif rows_count > 0 and last_record.rows_count == 0:
                is_material_delta = True
            elif cursor and cursor != last_record.cursor:
                is_material_delta = True
            elif res_hash != last_record.result_hash and (rows_count > 0 or new_candidates_count > 0):
                is_material_delta = True

        record = ActionExecutionRecord(
            signature_hash=sig_hash,
            turn_index=turn_index,
            rows_count=rows_count,
            new_candidates_count=new_candidates_count,
            cursor=cursor,
            result_hash=res_hash,
            is_material_delta=is_material_delta,
        )
        self.history.append(record)

        route_key = f"{signature.source_id}:{signature.op_id}"
        if not is_material_delta:
            stalls = self.consecutive_stalls.get(sig_hash, 0) + 1
            self.consecutive_stalls[sig_hash] = stalls
            if stalls >= self.max_consecutive_stalls:
                self.route_statuses[route_key] = RouteStatus.NO_PROGRESS
                self.exhausted_routes.add(route_key)
        else:
            self.consecutive_stalls[sig_hash] = 0
            self.route_statuses[route_key] = RouteStatus.ACTIVE

        return is_material_delta

    def is_stalled(self, signature: ActionSignature) -> bool:
        """Check if an action signature has exceeded stall limits."""
        sig_hash = signature.compute_hash()
        return self.consecutive_stalls.get(sig_hash, 0) >= self.max_consecutive_stalls

    def is_route_exhausted(self, source_id: str, op_id: str) -> bool:
        """Check if a telemetry route is exhausted or marked NO_PROGRESS."""
        route_key = f"{source_id}:{op_id}"
        return route_key in self.exhausted_routes

    def mark_route_exhausted(self, source_id: str, op_id: str, reason: str = "") -> None:
        """Explicitly mark a route as exhausted."""
        route_key = f"{source_id}:{op_id}"
        self.exhausted_routes.add(route_key)
        self.route_statuses[route_key] = RouteStatus.EXHAUSTED
