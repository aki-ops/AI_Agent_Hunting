"""Bounded provider probe execution for runtime capabilities."""
from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from hunting.contracts.queries import QueryResult
from hunting.contracts.source_profile import ProbeSpec, TelemetrySourceProfile


@dataclass(frozen=True)
class ProbeExecution:
    succeeded: bool
    query_id: str
    result: QueryResult | None = None
    reasons: tuple[str, ...] = ()


class BoundedProbeExecutor:
    """Call only an adapter-owned bounded probe hook."""

    def run(
        self,
        adapter: Any,
        profile: TelemetrySourceProfile,
        probe: ProbeSpec,
        *,
        query_id: str,
        time_window: str | None = None,
    ) -> ProbeExecution:
        method = getattr(adapter, "execute_capability_probe", None)
        if not callable(method):
            return ProbeExecution(False, query_id, reasons=("adapter_probe_unsupported",))
        try:
            result = method(
                profile=profile,
                probe=probe,
                time_window=time_window or probe.time_window,
                query_id=query_id,
            )
        except Exception as error:
            return ProbeExecution(False, query_id, reasons=(f"probe_error:{error}",))
        if not isinstance(result, QueryResult):
            return ProbeExecution(False, query_id, reasons=("adapter_probe_returned_invalid_result",))
        if not result.executed_ok:
            return ProbeExecution(False, query_id, result=result, reasons=("probe_query_failed",))
        if not result.complete:
            return ProbeExecution(False, query_id, result=result, reasons=("probe_incomplete",))
        if not result.rows:
            return ProbeExecution(False, query_id, result=result, reasons=("probe_returned_no_rows",))
        return ProbeExecution(True, query_id, result=result)


__all__ = ["ProbeExecution", "BoundedProbeExecutor"]
