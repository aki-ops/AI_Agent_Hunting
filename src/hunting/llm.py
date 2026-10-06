"""LLM access for the whole pipeline, routed through PEAK Assistant's model factory.

PEAK Assistant builds its model clients from a ``model_config.json``. We do not
keep a second LLM stack: the endpoint, key and model come from ``.env``
(``LLM_ENDPOINT``, ``LLM_API_KEY``, ``LLM_MODEL``), a PEAK-format config is
generated at runtime with ``${ENV}`` placeholders only (no secret is written
to disk), and every call - PEAK agents and our own judge/advisor - uses it.
"""
from __future__ import annotations

import asyncio
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

_ENV_KEYS = ("LLM_ENDPOINT", "LLM_API_KEY", "LLM_MODEL", "LLM_TIMEOUT", "LLM_MAX_TOKENS")


class LlmUnavailable(RuntimeError):
    """No usable LLM configuration or PEAK Assistant is not installed."""


def load_dotenv(path: str | Path = ".env") -> dict[str, str]:
    """Parse a ``.env`` file (no third-party dependency). Missing file -> {}."""
    env: dict[str, str] = {}
    try:
        text = Path(path).read_text(encoding="utf-8-sig")
    except OSError:
        return env
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        env[key.strip()] = value.strip().strip("'\"")
    return env


@dataclass(frozen=True)
class LlmSettings:
    base_url: str
    api_key: str
    model: str
    timeout: int = 600
    max_tokens: int = 16000

    @classmethod
    def from_env(cls, env_path: str | Path = ".env") -> "LlmSettings":
        file_env = load_dotenv(env_path)
        merged = {**file_env, **{k: os.environ[k] for k in _ENV_KEYS if k in os.environ}}
        endpoint = merged.get("LLM_ENDPOINT", "").strip()
        key = merged.get("LLM_API_KEY", "").strip()
        model = merged.get("LLM_MODEL", "").strip()
        if not endpoint or not key or not model or key.startswith("sk-or-...") or "<" in endpoint:
            raise LlmUnavailable("LLM_ENDPOINT / LLM_API_KEY / LLM_MODEL are not configured in .env")
        # ``.env`` holds the full chat-completions URL; PEAK/OpenAI clients want the base.
        base = endpoint.rstrip("/")
        for suffix in ("/chat/completions", "/messages"):
            if base.endswith(suffix):
                base = base[: -len(suffix)]
        return cls(
            base_url=base,
            api_key=key,
            model=model,
            timeout=int(merged.get("LLM_TIMEOUT", 600) or 600),
            max_tokens=int(merged.get("LLM_MAX_TOKENS", 16000) or 16000),
        )

    def model_config(self) -> dict:
        """PEAK ``model_config.json`` content. Secrets are ``${ENV}`` placeholders."""
        return {
            "version": "1",
            "providers": {
                "hunting-llm": {
                    "type": "openai",
                    "config": {
                        "api_key": "${LLM_API_KEY}",
                        "base_url": "${PEAK_LLM_BASE_URL}",
                        "timeout": self.timeout,
                        "max_tokens": self.max_tokens,
                    },
                    "models": {
                        self.model: {
                            "model_info": {
                                "id": self.model,
                                "object": "model",
                                "owned_by": "custom",
                                "family": "unknown",
                                "vision": False,
                                "audio": False,
                                "function_calling": False,
                                "json_output": False,
                                "structured_output": False,
                                "input": {"max_tokens": 128000},
                                "output": {"max_tokens": self.max_tokens},
                                "tokenizer": "tiktoken-gpt-4o",
                            }
                        }
                    },
                }
            },
            "defaults": {"provider": "hunting-llm", "model": self.model},
        }


def configure_peak(settings: LlmSettings, work_dir: str | Path) -> Path:
    """Point PEAK Assistant at our endpoint. Returns the generated config path."""
    try:
        from peak_assistant.utils.model_config_loader import get_loader, reset_loader
    except ImportError as exc:  # pragma: no cover - depends on the environment
        raise LlmUnavailable(f"PEAK Assistant is not installed: {exc}") from exc
    os.environ["LLM_API_KEY"] = settings.api_key
    os.environ["PEAK_LLM_BASE_URL"] = settings.base_url
    work = Path(work_dir)
    work.mkdir(parents=True, exist_ok=True)
    path = work / "model_config.json"
    path.write_text(json.dumps(settings.model_config(), indent=2), encoding="utf-8")
    reset_loader()
    get_loader(path)  # PEAK keeps a process-wide loader; this pins it to our file
    return path


def _quiet_handler(loop: asyncio.AbstractEventLoop, context: dict) -> None:
    """Drop the harmless 'Event loop is closed' noise from HTTP clients collected after asyncio.run()."""
    exc = context.get("exception")
    if isinstance(exc, RuntimeError) and "Event loop is closed" in str(exc):
        return
    loop.default_exception_handler(context)


def run_async(coro):
    """Run a coroutine on a fresh loop (PEAK's agents are async; our pipeline is synchronous)."""
    loop = asyncio.new_event_loop()
    loop.set_exception_handler(_quiet_handler)
    try:
        return loop.run_until_complete(coro)
    finally:
        try:
            loop.run_until_complete(loop.shutdown_asyncgens())
        finally:
            loop.close()


class PeakLlm:
    """Synchronous ``(prompt, max_tokens) -> str`` caller backed by PEAK's model client."""

    def __init__(self, settings: LlmSettings, config_path: Path, agent_name: str = "hunting_advisor") -> None:
        self.settings = settings
        self.config_path = config_path
        self.agent_name = agent_name
        self.calls = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0

    async def _ask(self, prompt: str, system: str | None) -> str:
        from autogen_core.models import SystemMessage, UserMessage
        from peak_assistant.utils.llm_factory import get_model_client

        client = await get_model_client(agent_name=self.agent_name, config_path=self.config_path)
        messages = ([SystemMessage(content=system)] if system else []) + [UserMessage(content=prompt, source="user")]
        try:
            result = await client.create(messages)
        finally:
            close = getattr(client, "close", None)
            if close is not None:
                await close()
        self.calls += 1
        usage = getattr(result, "usage", None)
        if usage is not None:
            self.prompt_tokens += int(getattr(usage, "prompt_tokens", 0) or 0)
            self.completion_tokens += int(getattr(usage, "completion_tokens", 0) or 0)
        return str(result.content)

    def __call__(self, prompt: str, max_tokens: int = 0, system: str | None = None) -> str:
        return run_async(asyncio.wait_for(self._ask(prompt, system), timeout=self.settings.timeout))

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


def build_llm(env_path: str | Path = ".env", work_dir: str | Path = "artifacts/.peak") -> PeakLlm:
    settings = LlmSettings.from_env(env_path)
    return PeakLlm(settings, configure_peak(settings, work_dir))


Caller = Callable[[str, int], str]
