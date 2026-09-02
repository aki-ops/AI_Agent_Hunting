"""Protected raw event storage and parsing error diagnostics.

Invariants:
  - Raw event content is kept in protected storage and is NEVER forwarded to an LLM.
  - Parse failures produce typed diagnostics (Diagnostic.PARSE_FAILED); events are never dropped silently.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

from hunting.contracts.queries import Diagnostic, DiagnosticClass


@dataclass(frozen=True)
class RawReference:
    """Safe handle to a raw event in protected storage."""
    ref_id: str
    sha256_digest: str
    stored_at: str


@dataclass(frozen=True)
class ParseResult:
    """Outcome of attempting to parse a raw telemetry record."""
    data: dict[str, Any] | None
    raw_ref: RawReference
    diagnostic: Diagnostic | None = None
    diagnostic_class: DiagnosticClass | None = None
    error_message: str | None = None

    @property
    def is_ok(self) -> bool:
        return self.data is not None and self.diagnostic is None


class ProtectedRawStore:
    """Append-only protected storage for raw log events.

    Maintains prompt-injection boundary: raw strings stay here.
    """

    def __init__(self) -> None:
        self._store: dict[str, str] = {}
        self._counter: int = 0

    def store(self, raw_content: str | bytes) -> RawReference:
        """Store raw log content and return a safe RawReference."""
        if isinstance(raw_content, bytes):
            text = raw_content.decode("utf-8", errors="replace")
        else:
            text = str(raw_content)

        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        self._counter += 1
        ref_id = f"raw-{self._counter:06d}-{digest[:8]}"
        now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

        self._store[ref_id] = text
        return RawReference(ref_id=ref_id, sha256_digest=digest, stored_at=now_iso)

    def retrieve_raw_for_local_parser(self, ref_id: str) -> str | None:
        """Internal only: retrieve raw text for deterministic parser."""
        return self._store.get(ref_id)

    def parse_and_store(self, raw_input: str | bytes | dict[str, Any]) -> ParseResult:
        """Store raw content, then attempt parsing. Never silently drops a failed record."""
        if isinstance(raw_input, dict):
            # Already a dict; serialize to canonical json for raw reference
            raw_text = json.dumps(raw_input, sort_keys=True)
            ref = self.store(raw_text)
            return ParseResult(data=raw_input, raw_ref=ref)

        ref = self.store(raw_input)
        raw_text = self._store[ref.ref_id]

        try:
            parsed = json.loads(raw_text)
            if not isinstance(parsed, dict):
                return ParseResult(
                    data=None,
                    raw_ref=ref,
                    diagnostic=Diagnostic.PARSE_FAILED,
                    diagnostic_class=DiagnosticClass.PERMANENT,
                    error_message=f"JSON root must be an object, got {type(parsed).__name__}",
                )
            return ParseResult(data=parsed, raw_ref=ref)
        except Exception as err:
            return ParseResult(
                data=None,
                raw_ref=ref,
                diagnostic=Diagnostic.PARSE_FAILED,
                diagnostic_class=DiagnosticClass.PERMANENT,
                error_message=str(err),
            )


__all__ = ["RawReference", "ParseResult", "ProtectedRawStore"]
