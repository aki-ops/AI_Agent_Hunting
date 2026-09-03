"""M2 Abduction Provider interface, Stub provider, and external API provider.

Separates API endpoint/model/timeout/token limits and secrets from investigation state.
Local model inference is out of scope for the current deployment.
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from hunting.contracts.explanations import ExplanationClass


def load_dotenv(path: str = ".env") -> dict[str, str]:
    """Parse local .env file without external dependencies."""
    env: dict[str, str] = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip("'\"")
    except Exception:
        pass
    return env


@dataclass(frozen=True)
class ApiLLMConfig:
    """External LLM API configuration and secrets.

    Kept outside of InvestigationState to ensure deployment secrets never enter
    replay logs or investigation state.
    """
    endpoint: str = "https://api.openai.com/v1/chat/completions"
    model: str = "gpt-4o"
    timeout_seconds: int = 30
    max_tokens: int = 2000
    api_key: str = "secret-token-env"

    @classmethod
    def from_env(cls, env_path: str = ".env") -> ApiLLMConfig:
        """Load configuration from .env and environment variables."""
        file_env = load_dotenv(env_path)
        combined = {**file_env, **os.environ}

        base_url = combined.get("HERMES_API_BASE_URL", "")
        default_endpoint = (
            f"{base_url.rstrip('/')}/chat/completions"
            if base_url
            else "https://api.openai.com/v1/chat/completions"
        )

        endpoint = combined.get("LLM_ENDPOINT", default_endpoint)
        api_key = combined.get("LLM_API_KEY", combined.get("HERMES_API_KEY", combined.get("OPENAI_API_KEY", "secret-token-env")))
        model = combined.get("LLM_MODEL", combined.get("HERMES_MODEL_NAME", "1/grok-4.6"))
        timeout = int(combined.get("LLM_TIMEOUT", 30))
        max_tokens = int(combined.get("LLM_MAX_TOKENS", 2000))

        return cls(
            endpoint=endpoint,
            model=model,
            timeout_seconds=timeout,
            max_tokens=max_tokens,
            api_key=api_key,
        )


class LLMProvider(ABC):

    """Abstract interface for LLM abduction."""

    @abstractmethod
    def generate(self, prompt_context: dict[str, Any]) -> str:
        """Generate structured text/JSON from structured prompt context."""
        raise NotImplementedError


class StubAbductionProvider(LLMProvider):
    """Deterministic stub provider for offline, replayable MVP testing.

    Never makes network calls. Emits schema-valid hypotheses with explanation
    diversity (benign, malicious, unknown) and EvidenceRequirements.
    """

    def __init__(self, preferred_class: ExplanationClass = ExplanationClass.MALICIOUS) -> None:
        self.preferred_class = preferred_class

    def generate(self, prompt_context: dict[str, Any]) -> str:
        """Produce deterministic, schema-valid JSON response."""
        observations = prompt_context.get("observations", [])
        obs_ids = [o["id"] for o in observations] if observations else ["obs-default-1"]
        first_obs_id = obs_ids[0]

        # Ensure explanation diversity: benign, malicious, and unknown
        payload = {
            "explanations": [
                {
                    "id": "expl-mal-01",
                    "label": "T1059.001 PowerShell execution with encoded command",
                    "class_": "malicious",
                    "attributions": [
                        {"observation_id": first_obs_id, "cause": "attacker initiated encoded script"}
                    ],
                },
                {
                    "id": "expl-benign-01",
                    "label": "Administrative routine maintenance script",
                    "class_": "benign",
                    "attributions": [
                        {"observation_id": first_obs_id, "cause": "scheduled health check"}
                    ],
                },
                {
                    "id": "expl-unknown-01",
                    "label": "Unclassified novel telemetry anomaly",
                    "class_": "unknown",
                    "attributions": [
                        {"observation_id": first_obs_id, "cause": "anomaly needing further discrimination"}
                    ],
                },
            ],
            "expectations": [
                {
                    "id": "exp-proc-lineage",
                    "owner_explanation_id": "expl-mal-01",
                    "evidence_requirement": "process_ancestry",
                    "predicted_observation": "parent process is wsmprovhost or services",
                    "entity_ref": {"type": "Host", "name": "HOST-01"},
                    "provider_scope_id": "cdb_security",
                    "time_window": prompt_context.get("window", "2026-09-01T10:00:00Z/2026-09-01T11:00:00Z"),
                    "field_predicate": {
                        "field": "cmdline",
                        "op": "contains",
                        "value": "powershell",
                    },
                },
                {
                    "id": "exp-auth-activity",
                    "owner_explanation_id": "expl-benign-01",
                    "evidence_requirement": "authentication_activity",
                    "predicted_observation": "service account logon event",
                    "entity_ref": {"type": "Host", "name": "HOST-01"},
                    "provider_scope_id": "cdb_security",
                    "time_window": prompt_context.get("window", "2026-09-01T10:00:00Z/2026-09-01T11:00:00Z"),
                    "field_predicate": {
                        "field": "user",
                        "op": "equals",
                        "value": "svc_admin",
                    },
                },
            ],
        }
        return json.dumps(payload)


class ApiLLMProvider(LLMProvider):

    """External API LLM provider executing real HTTP requests to an LLM API endpoint.

    Compatible with standard OpenAI / Anthropic / Gemini / vLLM / Ollama REST endpoints.
    """

    def __init__(self, config: ApiLLMConfig) -> None:
        self.config = config

    def generate(self, prompt_context: dict[str, Any]) -> str:
        """Execute real HTTP POST request to external LLM API and return structured JSON string."""
        # Strictly structured input: verify no raw text entered context
        if "raw_log" in prompt_context or "raw_payload" in prompt_context:
            raise ValueError("Security violation: raw log content cannot be sent to external LLM API")

        system_instruction = (
            "You are an expert Threat Hunting Abduction Engine (M2).\n"
            "Propose diverse hypotheses (benign, malicious, unknown) and concrete testable expectations.\n"
            "Output strictly valid JSON with no markdown fences, matching this exact schema:\n"
            "{\n"
            '  "explanations": [\n'
            '    {\n'
            '      "id": "expl-01",\n'
            '      "label": "Brief descriptive title of hypothesis",\n'
            '      "class_": "malicious",\n'
            '      "attributions": [{"observation_id": "<observation_id_from_prompt>", "cause": "reason"}]\n'
            '    }\n'
            '  ],\n'
            '  "expectations": [\n'
            '    {\n'
            '      "id": "exp-01",\n'
            '      "owner_explanation_id": "expl-01",\n'
            '      "evidence_requirement": "process_ancestry",\n'
            '      "predicted_observation": "parent process is explorer or cmd",\n'
            '      "entity_ref": {"type": "Host", "name": "<host_or_entity_from_prompt>"},\n'
            '      "time_window": "<window_from_prompt>",\n'
            '      "field_predicate": {"field": "process_image", "op": "CONTAINS", "value": "powershell"}\n'
            '    }\n'
            '  ]\n'
            "}\n"

            "Valid class_ values: 'malicious', 'benign', 'unknown'.\n"
            "Valid evidence_requirement values: 'process_ancestry', 'authentication_activity', 'network_connection', 'persistence_change', 'file_modification', 'dns_activity', 'scope_records'.\n"
            "Valid field_predicate ops: 'EQUALS', 'CONTAINS', 'EXISTS', 'ABSENT'."
        )



        payload = {
            "model": self.config.model,
            "messages": [
                {"role": "system", "content": system_instruction},
                {"role": "user", "content": json.dumps(prompt_context, indent=2)},
            ],
            "temperature": 0.0,
            "max_tokens": self.config.max_tokens,
            "stream": False,
        }

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config.api_key}",
            "User-Agent": "AI-Agent-Hunting/1.0",
        }

        req = urllib.request.Request(
            self.config.endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.config.timeout_seconds) as resp:
                content_type = resp.headers.get("Content-Type", "")
                if "text/event-stream" in content_type:
                    # Gateway returned Server-Sent Events (SSE) stream
                    chunks: list[str] = []
                    for line in resp:
                        line_str = line.decode("utf-8", errors="replace").strip()
                        if line_str == "data: [DONE]":
                            break
                        if line_str.startswith("data:"):
                            try:
                                chunk_json = json.loads(line_str[5:].strip())
                                for choice in chunk_json.get("choices", []):
                                    delta = choice.get("delta", {})
                                    if "content" in delta and delta["content"]:
                                        chunks.append(delta["content"])
                            except Exception:
                                continue
                    content = "".join(chunks).strip()
                else:
                    resp_bytes = resp.read()
                    resp_json = json.loads(resp_bytes.decode("utf-8"))
                    choices = resp_json.get("choices", [])
                    if not choices:
                        raise ValueError(f"LLM API returned no choices: {resp_json}")
                    content = str(choices[0].get("message", {}).get("content", "")).strip()

                # Strip reasoning / thinking blocks (<think>...</think>)
                content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()

                # Strip markdown code fences if model enclosed JSON in ```json ... ```
                if content.startswith("```json"):
                    content = content[7:]
                elif content.startswith("```"):
                    content = content[3:]
                if content.endswith("```"):
                    content = content[:-3]
                content = content.strip()

                # Extract JSON object substring if model added conversational preamble
                if not content.startswith("{") and "{" in content and "}" in content:
                    start_idx = content.find("{")
                    end_idx = content.rfind("}") + 1
                    content = content[start_idx:end_idx].strip()

                return content


        except urllib.error.HTTPError as http_err:
            error_body = http_err.read().decode("utf-8", errors="replace")
            raise ConnectionError(f"LLM API HTTP {http_err.code} error: {error_body}") from http_err
        except urllib.error.URLError as url_err:
            raise ConnectionError(f"LLM API network connection failed: {url_err.reason}") from url_err



__all__ = [
    "ApiLLMConfig",
    "LLMProvider",
    "StubAbductionProvider",
    "ApiLLMProvider",
]
