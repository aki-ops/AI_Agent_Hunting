"""AUTO gateway transport invariants.

These tests intentionally exercise the OpenAI-compatible path only.  Native
Google Gemini transport is a separate deployment concern and is not part of
the AUTO router contract.
"""

import json
import urllib.error
from unittest.mock import patch

import pytest

from hunting.controller.cost import LLMUsageTracker
from hunting.m2_abduction.provider import (
    ApiLLMConfig,
    ApiLLMProvider,
    LLMCommunicationError,
    create_llm_caller,
)


class _Headers(dict):
    def get(self, key, default=None):
        return super().get(key, default)


class _SSEResponse:
    status = 200

    def __init__(self):
        self.headers = _Headers({
            "Content-Type": "text/event-stream",
            "x-request-id": "req-auto-test",
        })
        self._lines = [
            b'data: {"model":"gpt-5.6-sol-omni","choices":[{"delta":{"content":"{\\"ok\\":true}"}}]}\n',
            b'data: {"model":"gpt-5.6-sol-omni","choices":[{"delta":{},"finish_reason":"stop"}],"usage":{"prompt_tokens":123,"completion_tokens":7}}\n',
            b"data: [DONE]\n",
        ]

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def readline(self):
        return self._lines.pop(0) if self._lines else b""


def _config() -> ApiLLMConfig:
    return ApiLLMConfig(
        endpoint="https://gateway.test/v1/chat/completions",
        model="auto",
        timeout_seconds=3,
        max_tokens=4000,
        api_key="test-key",
    )


def test_auto_sse_records_actual_model_usage_and_first_byte():
    provider = ApiLLMProvider(_config())
    with patch("urllib.request.urlopen", return_value=_SSEResponse()):
        response = provider.call_raw("{}", max_tokens=700)

    assert json.loads(response) == {"ok": True}
    assert provider.last_model == "gpt-5.6-sol-omni"
    assert provider.last_usage == {"prompt_tokens": 123, "completion_tokens": 7}
    assert provider.last_first_byte_ms is not None
    assert provider.last_request_id == "req-auto-test"


def test_phase_output_ceiling_is_sent_to_gateway():
    provider = ApiLLMProvider(_config())
    tracker = LLMUsageTracker(max_calls=5, max_total_tokens=10000, model_name="auto")
    caller = create_llm_caller(provider, tracker=tracker, component="source_profiler")

    captured = {}

    def _urlopen(request, timeout):
        captured["body"] = json.loads(request.data.decode("utf-8"))
        captured["timeout"] = timeout
        return _SSEResponse()

    with patch("urllib.request.urlopen", side_effect=_urlopen):
        caller("small source profile prompt")

    assert captured["body"]["max_tokens"] == 700
    assert captured["body"]["stream"] is True
    assert tracker.calls[0].configured_model == "auto"
    assert tracker.calls[0].actual_model == "gpt-5.6-sol-omni"
    assert tracker.calls[0].first_byte_ms is not None


def test_transport_failure_is_not_empty_json_fallback():
    provider = ApiLLMProvider(_config())
    tracker = LLMUsageTracker(max_calls=5, max_total_tokens=10000, model_name="auto")
    caller = create_llm_caller(provider, tracker=tracker, component="source_profiler")

    with patch("urllib.request.urlopen", side_effect=urllib.error.URLError("gateway unavailable")):
        with pytest.raises(LLMCommunicationError, match="gateway unavailable"):
            caller("small source profile prompt")

    assert tracker.calls[0].status == "FAILED"
    assert tracker.calls[0].error_class == "TRANSPORT_ERROR"
    assert "LLM API network error" in tracker.calls[0].error
