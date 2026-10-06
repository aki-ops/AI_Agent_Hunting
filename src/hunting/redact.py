"""Redaction of identifying telemetry values before they leave the machine (``--redact``).

The judge and the advisor receive evidence rows and a summary built from them. With a remote LLM
endpoint, hostnames, user names and IP addresses in that text are sent to a third party. ``Redactor``
replaces them with stable placeholders (``<HOST_1>``, ``<USER_2>``, ``<IP_3>``) in every outbound
prompt and puts the real values back into the reply, so reports keep real names while the provider
only sees placeholders.

What it covers, and what it does not:

* It learns the values to mask from the rows the adapter returns (``host``, ``user``, ``ip``) and
  from the PoC's own scope, and masks any IPv4 address it sees even if it was never learned.
* It matches whole tokens, case-insensitively, longest value first.
* It does NOT mask free text such as command lines, URLs or domains, nor the analyst-written PoC text
  and the aggregate data description sent to PEAK Prepare. Those can still carry sensitive strings.
  For data that must not leave the organisation use ``--offline`` or a local model.
"""
from __future__ import annotations

import json
import re
from typing import Any, Iterable

# a trailing "." is sentence punctuation, only "." followed by a digit continues the number
_IPV4 = re.compile(r"(?<!\d)(?<!\d\.)(?:\d{1,3}\.){3}\d{1,3}(?!\d)(?!\.\d)")
_TOKEN = re.compile(r"<?\b(HOST|USER|IP)_(\d+)\b>?")
_FIELD_KIND = {"host": "HOST", "user": "USER", "ip": "IP"}
_SKIP = {"", "-", "n/a", "none", "null", "unknown", "system", "local service", "network service", "localhost"}


class Redactor:
    def __init__(self) -> None:
        self._token_for: dict[str, str] = {}  # lower-cased real value -> token
        self._real_for: dict[str, str] = {}  # token -> first-seen real value
        self._counter: dict[str, int] = {}
        self._pattern: re.Pattern[str] | None = None

    # -- learning ----------------------------------------------------------------------
    def _register(self, kind: str, value: str) -> str:
        key = value.lower()
        if key in self._token_for:
            return self._token_for[key]
        self._counter[kind] = self._counter.get(kind, 0) + 1
        token = f"<{kind}_{self._counter[kind]}>"
        self._token_for[key] = token
        # the same value also appears JSON-escaped in evidence dumps (CORP\alice -> CORP\\alice)
        escaped = json.dumps(value, ensure_ascii=False)[1:-1].lower()
        self._token_for.setdefault(escaped, token)
        self._real_for[token] = value
        self._pattern = None
        return token

    def learn_values(self, field: str, values: Iterable[Any]) -> None:
        kind = _FIELD_KIND.get(field.lower())
        if kind is None:
            return
        for value in values:
            text = str(value).strip() if value is not None else ""
            if len(text) >= 3 and text.lower() not in _SKIP:
                self._register(kind, text)

    def learn_rows(self, rows: Iterable[dict[str, Any]] | None) -> None:
        for row in rows or []:
            for field in _FIELD_KIND:
                self.learn_values(field, [row.get(field)])

    # -- masking -----------------------------------------------------------------------
    def _compiled(self) -> re.Pattern[str] | None:
        if self._pattern is None and self._token_for:
            values = sorted(self._token_for, key=len, reverse=True)
            self._pattern = re.compile(
                r"(?<![A-Za-z0-9])(" + "|".join(re.escape(v) for v in values) + r")(?![A-Za-z0-9])", re.IGNORECASE
            )
        return self._pattern

    def mask(self, text: str | None) -> str:
        if not text:
            return text or ""
        out = text
        for match in _IPV4.findall(out):
            if all(0 <= int(part) <= 255 for part in match.split(".")):
                self._register("IP", match)
        pattern = self._compiled()
        if pattern is not None:
            out = pattern.sub(lambda m: self._token_for[m.group(1).lower()], out)
        return out

    def _restore(self, text: str) -> str:
        def back(match: re.Match[str]) -> str:
            token = f"<{match.group(1)}_{match.group(2)}>"
            return self._real_for.get(token, match.group(0))

        return _TOKEN.sub(back, text)

    def _restore_json(self, value: Any) -> Any:
        if isinstance(value, str):
            return self._restore(value)
        if isinstance(value, list):
            return [self._restore_json(v) for v in value]
        if isinstance(value, dict):
            return {k: self._restore_json(v) for k, v in value.items()}
        return value

    def unmask(self, text: str | None) -> str:
        """Put real values back. A JSON reply is restored value by value, so a user such as ``CORP\alice``
        cannot break the JSON by dropping a raw backslash into a string."""
        if not text or not self._real_for:
            return text or ""
        start, end = text.find("{"), text.rfind("}")
        if start != -1 and end > start:
            try:
                data = json.loads(text[start:end + 1])
            except ValueError:
                data = None
            if isinstance(data, dict):
                dumped = json.dumps(self._restore_json(data), ensure_ascii=False)
                return self._restore(text[:start]) + dumped + self._restore(text[end + 1:])
        return self._restore(text)

    @property
    def size(self) -> int:
        return len(self._token_for)


class RedactingAdapter:
    """Adapter proxy that feeds every returned row to a ``Redactor``; everything else is delegated."""

    def __init__(self, adapter: Any, redactor: Redactor) -> None:
        self._adapter = adapter
        self._redactor = redactor

    def execute_query(self, *args: Any, **kwargs: Any):
        result = self._adapter.execute_query(*args, **kwargs)
        self._redactor.learn_rows(getattr(result, "rows", None))
        return result

    def __getattr__(self, name: str) -> Any:
        return getattr(self._adapter, name)


__all__ = ["RedactingAdapter", "Redactor"]
