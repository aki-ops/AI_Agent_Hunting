"""LLM access for the whole pipeline, routed through PEAK Assistant's model factory.

PEAK Assistant builds its model clients from a ``model_config.json``. We do not
keep a second LLM stack: the endpoint, key and model come from ``.env``
(``LLM_ENDPOINT``, ``LLM_API_KEY``, ``LLM_MODEL``), a PEAK-format config is
generated at runtime with ``${ENV}`` placeholders only (no secret is written
to disk), and every call - PEAK agents and our own judge/advisor - uses it.

Operational hardening on top of that (all optional, all off the evidence path):

* ``UsageMeter``  - counts calls/tokens per model for *every* request, including the agents inside PEAK,
  and can enforce a per-PoC token budget. It also records which model really answered (``LLM_MODEL=auto``).
* ``LLM_MODEL_FALLBACKS`` - ordered fallback models, tried after a model keeps failing.
* ``LLM_TEMPERATURE`` / ``LLM_MIN_INTERVAL`` - sampling temperature for judge/advisor, and a minimum gap
  between their calls (useful for rate-limited free models).
* ``Redactor`` hook - masks hosts/users/IPs in prompts and restores them in replies (see ``hunting.redact``).
"""
from __future__ import annotations

import asyncio
import json
import os
import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Callable
from urllib.parse import urlparse

_ENV_KEYS = (
    "LLM_ENDPOINT", "LLM_API_KEY", "LLM_MODEL", "LLM_TIMEOUT", "LLM_MAX_TOKENS",
    "LLM_MODEL_FALLBACKS", "LLM_TEMPERATURE", "LLM_MIN_INTERVAL",
)
_LOCAL_HOSTS = ("localhost", "127.0.0.1", "::1", "0.0.0.0")


class LlmUnavailable(RuntimeError):
    """No usable LLM configuration or PEAK Assistant is not installed."""


class TokenBudgetExceeded(RuntimeError):
    """The per-PoC token budget is used up; further LLM calls are refused (not retried)."""


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


def _parse_temperature(raw: str) -> float | None:
    raw = (raw or "").strip().lower()
    if raw in ("", "none", "off", "default"):
        return None
    try:
        return float(raw)
    except ValueError:
        return 0.0


@dataclass(frozen=True)
class LlmSettings:
    base_url: str
    api_key: str
    model: str
    timeout: int = 600
    max_tokens: int = 16000
    fallbacks: tuple[str, ...] = ()
    temperature: float | None = 0.0  # judge/advisor only; None = provider default
    min_interval: float = 0.0  # seconds between judge/advisor calls

    @classmethod
    def from_env(cls, env_path: str | Path = ".env", model: str | None = None) -> "LlmSettings":
        file_env = load_dotenv(env_path)
        merged = {**file_env, **{k: os.environ[k] for k in _ENV_KEYS if k in os.environ}}
        if model:
            merged["LLM_MODEL"] = model
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
        fallbacks: list[str] = []
        for name in (merged.get("LLM_MODEL_FALLBACKS", "") or "").split(","):
            name = name.strip()
            if name and name != model and name not in fallbacks:
                fallbacks.append(name)
        try:
            interval = max(0.0, float(merged.get("LLM_MIN_INTERVAL", 0) or 0))
        except ValueError:
            interval = 0.0
        return cls(
            base_url=base,
            api_key=key,
            model=model,
            timeout=int(merged.get("LLM_TIMEOUT", 600) or 600),
            max_tokens=int(merged.get("LLM_MAX_TOKENS", 16000) or 16000),
            fallbacks=tuple(fallbacks),
            temperature=_parse_temperature(merged.get("LLM_TEMPERATURE", "0")),
            min_interval=interval,
        )

    @property
    def is_local(self) -> bool:
        """True when the endpoint is on this machine (telemetry does not leave it)."""
        host = (urlparse(self.base_url).hostname or "").lower()
        return host in _LOCAL_HOSTS or host.endswith(".localhost")

    def model_config(self) -> dict:
        """PEAK ``model_config.json`` content. Secrets are ``${ENV}`` placeholders."""
        def info(name: str) -> dict:
            return {
                "model_info": {
                    "id": name,
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
                    "models": {name: info(name) for name in (self.model, *self.fallbacks)},
                }
            },
            "defaults": {"provider": "hunting-llm", "model": self.model},
        }


# ---------------------------------------------------------------------------
# Usage metering (every request, including PEAK's own agents)
# ---------------------------------------------------------------------------

class UsageMeter:
    """Process-wide LLM usage counter with an optional per-PoC token budget."""

    def __init__(self) -> None:
        self.budget: int | None = None
        self.reset()

    def reset(self) -> None:
        self.calls = 0
        self.unmetered_calls = 0  # streamed replies carry no usage block
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.by_model: dict[str, dict[str, int]] = {}

    def begin(self, budget: int | None = None) -> None:
        """Start a new accounting period (one PoC)."""
        self.reset()
        self.budget = budget if budget and budget > 0 else None

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens

    def exceeded(self) -> bool:
        return self.budget is not None and self.total_tokens >= self.budget

    def check(self) -> None:
        if self.exceeded():
            raise TokenBudgetExceeded(f"token budget {self.budget} reached ({self.total_tokens} used)")

    def observe(self, result: object) -> None:
        self.calls += 1
        model = getattr(result, "model", None)
        usage = getattr(result, "usage", None)
        if not model or usage is None:
            self.unmetered_calls += 1
            return
        prompt = int(getattr(usage, "prompt_tokens", 0) or 0)
        completion = int(getattr(usage, "completion_tokens", 0) or 0)
        self.prompt_tokens += prompt
        self.completion_tokens += completion
        slot = self.by_model.setdefault(str(model), {"calls": 0, "prompt_tokens": 0, "completion_tokens": 0})
        slot["calls"] += 1
        slot["prompt_tokens"] += prompt
        slot["completion_tokens"] += completion

    def snapshot(self) -> dict:
        return {
            "calls": self.calls,
            "unmetered_calls": self.unmetered_calls,
            "prompt_tokens": self.prompt_tokens,
            "completion_tokens": self.completion_tokens,
            "total_tokens": self.total_tokens,
            "budget": self.budget,
            "by_model": {k: dict(v) for k, v in self.by_model.items()},
        }


METER = UsageMeter()


def install_usage_meter() -> bool:
    """Wrap the OpenAI SDK's async chat-completions call so every request is metered. Idempotent."""
    try:
        from openai.resources.chat.completions import AsyncCompletions
    except ImportError:  # pragma: no cover - openai ships with PEAK Assistant
        return False
    original = AsyncCompletions.create
    if getattr(original, "_hunting_metered", False):
        return True

    async def create(self, *args, **kwargs):  # noqa: ANN001
        METER.check()
        result = await original(self, *args, **kwargs)
        METER.observe(result)
        return result

    create._hunting_metered = True  # type: ignore[attr-defined]
    AsyncCompletions.create = create  # type: ignore[method-assign]
    return True


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
    install_usage_meter()
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


# This gateway intermittently answers 404 "model_not_found" for a model that exists, and the OpenAI
# client does not retry 404. Retrying with a short backoff is the fix; a real misconfiguration still
# fails after the last attempt with the original error.
RETRY_DELAYS = (3.0, 10.0, 25.0)


async def retry_async(factory, *, delays: tuple[float, ...] = RETRY_DELAYS, label: str = "LLM call", notes: list[str] | None = None):
    """Await ``factory()`` and retry on any exception with backoff; re-raise the last error.

    A spent token budget is never retried: waiting cannot fix it.
    """
    for attempt in range(len(delays) + 1):
        try:
            return await factory()
        except asyncio.CancelledError:
            raise
        except TokenBudgetExceeded:
            raise
        except Exception as exc:
            if attempt >= len(delays):
                raise
            if METER.exceeded():
                raise TokenBudgetExceeded(f"token budget {METER.budget} reached") from exc
            if notes is not None:
                notes.append(f"{label}: retry {attempt + 1}/{len(delays)} after {type(exc).__name__}")
            await asyncio.sleep(delays[attempt])


class PeakLlm:
    """Synchronous ``(prompt, max_tokens) -> str`` caller backed by PEAK's model client."""

    def __init__(
        self, settings: LlmSettings, config_path: Path, agent_name: str = "hunting_advisor", redactor=None,
    ) -> None:
        self.settings = settings
        self.config_path = config_path
        self.agent_name = agent_name
        self.redactor = redactor  # hunting.redact.Redactor or None
        self.calls = 0
        self.prompt_tokens = 0
        self.completion_tokens = 0
        self.model_switches: list[str] = []
        self._fallbacks = list(settings.fallbacks)
        self._temperature_ok = settings.temperature is not None
        self._last_call = 0.0

    # -- model fallback ------------------------------------------------------------------
    def switch_model(self) -> bool:
        """Move to the next fallback model (sticky: PEAK agents and later calls use it too)."""
        if not self._fallbacks:
            return False
        previous = self.settings.model
        self.settings = replace(self.settings, model=self._fallbacks.pop(0))
        self.config_path = configure_peak(self.settings, Path(self.config_path).parent)
        self.model_switches.append(f"{previous} -> {self.settings.model}")
        return True

    # -- one request -----------------------------------------------------------------------
    async def _ask(self, prompt: str, system: str | None) -> str:
        from autogen_core.models import SystemMessage, UserMessage
        from peak_assistant.utils.llm_factory import get_model_client

        client = await get_model_client(agent_name=self.agent_name, config_path=self.config_path)
        messages = ([SystemMessage(content=system)] if system else []) + [UserMessage(content=prompt, source="user")]
        try:
            extra = {"temperature": self.settings.temperature} if self._temperature_ok else None
            try:
                result = await (client.create(messages, extra_create_args=extra) if extra else client.create(messages))
            except Exception as exc:
                # some models (e.g. reasoning models) reject a temperature: drop it once and carry on
                if extra and "temperature" in str(exc).lower():
                    self._temperature_ok = False
                    result = await client.create(messages)
                else:
                    raise
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

    def _throttle(self) -> None:
        gap = self.settings.min_interval
        if gap > 0:
            wait = self._last_call + gap - time.monotonic()
            if wait > 0:
                time.sleep(wait)
        self._last_call = time.monotonic()

    def __call__(self, prompt: str, max_tokens: int = 0, system: str | None = None) -> str:
        outbound = self.redactor.mask(prompt) if self.redactor else prompt
        outbound_system = self.redactor.mask(system) if (self.redactor and system) else system

        async def _once():
            return await asyncio.wait_for(self._ask(outbound, outbound_system), timeout=self.settings.timeout)

        while True:
            self._throttle()
            try:
                text = run_async(retry_async(_once, label="LLM call"))
                break
            except TokenBudgetExceeded:
                raise
            except Exception:
                if not self.switch_model():
                    raise
        return self.redactor.unmask(text) if self.redactor else text

    @property
    def total_tokens(self) -> int:
        return self.prompt_tokens + self.completion_tokens


def build_llm(
    env_path: str | Path = ".env", work_dir: str | Path = "artifacts/.peak", model: str | None = None, redactor=None,
) -> PeakLlm:
    settings = LlmSettings.from_env(env_path, model=model)
    return PeakLlm(settings, configure_peak(settings, work_dir), redactor=redactor)


Caller = Callable[[str, int], str]

__all__ = [
    "METER", "Caller", "LlmSettings", "LlmUnavailable", "PeakLlm", "TokenBudgetExceeded", "UsageMeter",
    "build_llm", "configure_peak", "install_usage_meter", "load_dotenv", "retry_async", "run_async",
]
