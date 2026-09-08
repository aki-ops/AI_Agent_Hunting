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
from typing import Any, Callable

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


class LLMTimeoutError(TimeoutError):
    """Raised when request to LLM API times out."""
    pass


class LLMCommunicationError(ConnectionError):
    """Raised when request to LLM API fails due to network/server errors."""
    pass


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

    @property
    def is_anthropic(self) -> bool:
        """Return True if endpoint targets an Anthropic Messages API."""
        return "messages" in self.endpoint.lower() or "anthropic" in self.endpoint.lower()

    @classmethod
    def from_env(cls, env_path: str = ".env") -> ApiLLMConfig:
        """Load configuration from .env and environment variables."""
        file_env = load_dotenv(env_path)
        combined = {**file_env, **os.environ}

        anthropic_base = combined.get("ANTHROPIC_BASE_URL", "")
        hermes_base = combined.get("HERMES_API_BASE_URL", "")

        if anthropic_base:
            default_endpoint = f"{anthropic_base.rstrip('/')}/messages"
        elif hermes_base:
            default_endpoint = f"{hermes_base.rstrip('/')}/chat/completions"
        else:
            default_endpoint = "https://api.openai.com/v1/chat/completions"

        endpoint = combined.get("LLM_ENDPOINT", default_endpoint)
        api_key = combined.get(
            "LLM_API_KEY",
            combined.get(
                "ANTHROPIC_API_KEY",
                combined.get("HERMES_API_KEY", combined.get("OPENAI_API_KEY", "secret-token-env")),
            ),
        )
        model = combined.get(
            "LLM_MODEL",
            combined.get(
                "ANTHROPIC_MODEL",
                combined.get(
                    "CLAUDE_MODEL",
                    combined.get("HERMES_MODEL_NAME", "1/gemini-flash-3.8-high-omni"),
                ),
            ),
        )
        timeout = int(combined.get("LLM_TIMEOUT", 120))
        max_tokens = int(combined.get("LLM_MAX_TOKENS", 4000))

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



        if self.config.is_anthropic:
            payload = {
                "model": self.config.model,
                "max_tokens": self.config.max_tokens,
                "system": system_instruction,
                "messages": [
                    {"role": "user", "content": json.dumps(prompt_context, indent=2)},
                ],
                "temperature": 0.0,
            }
        else:
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
            "x-api-key": self.config.api_key,
            "anthropic-version": "2023-06-01",
            "User-Agent": "AI-Agent-Hunting/1.0",
        }

        req = urllib.request.Request(
            self.config.endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )

        max_retries = 2
        last_err: Exception | None = None
        for attempt in range(1, max_retries + 1):
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
                        if isinstance(resp_json.get("content"), list):
                            content = "".join(
                                b.get("text", "") for b in resp_json["content"]
                                if isinstance(b, dict) and b.get("type") == "text"
                            ).strip()
                        else:
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
                last_err = LLMCommunicationError(f"LLM API HTTP {http_err.code} error: {error_body}")
                if http_err.code in (429, 500, 502, 503, 504) and attempt < max_retries:
                    import time as _t
                    _t.sleep(1.5 * attempt)
                    continue
                raise last_err from http_err
            except (urllib.error.URLError, TimeoutError) as url_err:
                reason = getattr(url_err, "reason", str(url_err))
                if "timed out" in str(reason).lower() or isinstance(url_err, TimeoutError) or "timeout" in str(url_err).lower():
                    last_err = LLMTimeoutError(f"LLM API request timed out after {self.config.timeout_seconds}s: {reason}")
                else:
                    last_err = LLMCommunicationError(f"LLM API network error: {reason}")
                if attempt < max_retries:
                    import time as _t
                    _t.sleep(1.5 * attempt)
                    continue
                raise last_err from url_err
            except Exception as e:
                last_err = e
                if attempt < max_retries:
                    import time as _t
                    _t.sleep(1.0)
                    continue
                raise
        if last_err:
            raise last_err

    def call_raw(self, prompt: str, system_instruction: str | None = None) -> str:
        """Execute HTTP POST request for generic prompt to external LLM API and return response text."""
        sys_inst = (
            system_instruction
            or "You are an expert Threat Hunting AI Agent. Return structured JSON matching the requested format."
        )
        if self.config.is_anthropic:
            payload = {
                "model": self.config.model,
                "max_tokens": self.config.max_tokens,
                "system": sys_inst,
                "messages": [
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.0,
            }
        else:
            payload = {
                "model": self.config.model,
                "messages": [
                    {"role": "system", "content": sys_inst},
                    {"role": "user", "content": prompt},
                ],
                "temperature": 0.0,
                "max_tokens": self.config.max_tokens,
                "stream": False,
            }

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config.api_key}",
            "x-api-key": self.config.api_key,
            "anthropic-version": "2023-06-01",
            "User-Agent": "AI-Agent-Hunting/1.0",
        }

        req = urllib.request.Request(
            self.config.endpoint,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )

        max_retries = 2
        last_err: Exception | None = None
        for attempt in range(1, max_retries + 1):
            try:
                with urllib.request.urlopen(req, timeout=self.config.timeout_seconds) as resp:
                    content_type = resp.headers.get("Content-Type", "")
                    if "text/event-stream" in content_type:
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
                        # Extract usage metadata (OpenAI, Gemini, or Anthropic format)
                        usage = resp_json.get("usage") or resp_json.get("usageMetadata") or {}
                        p_tok = (
                            usage.get("prompt_tokens")
                            or usage.get("promptTokenCount")
                            or usage.get("input_tokens")
                        )
                        c_tok = (
                            usage.get("completion_tokens")
                            or usage.get("candidatesTokenCount")
                            or usage.get("output_tokens")
                        )
                        self.last_usage = {
                            "prompt_tokens": int(p_tok) if p_tok is not None else None,
                            "completion_tokens": int(c_tok) if c_tok is not None else None,
                        }
                        if isinstance(resp_json.get("content"), list):
                            content = "".join(
                                b.get("text", "") for b in resp_json["content"]
                                if isinstance(b, dict) and b.get("type") == "text"
                            ).strip()
                        else:
                            choices = resp_json.get("choices", [])
                            if not choices:
                                raise ValueError(f"LLM API returned no choices: {resp_json}")
                            content = str(choices[0].get("message", {}).get("content", "")).strip()

                    content = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL).strip()
                    if content.startswith("```json"):
                        content = content[7:]
                    elif content.startswith("```"):
                        content = content[3:]
                    if content.endswith("```"):
                        content = content[:-3]
                    content = content.strip()

                    if not content.startswith("{") and "{" in content and "}" in content:
                        start_idx = content.find("{")
                        end_idx = content.rfind("}") + 1
                        content = content[start_idx:end_idx].strip()

                    return content

            except urllib.error.HTTPError as http_err:
                error_body = http_err.read().decode("utf-8", errors="replace")
                last_err = LLMCommunicationError(f"LLM API HTTP {http_err.code} error: {error_body}")
                if http_err.code in (429, 500, 502, 503, 504) and attempt < max_retries:
                    import time as _t
                    _t.sleep(1.5 * attempt)
                    continue
                raise last_err from http_err
            except (urllib.error.URLError, TimeoutError) as url_err:
                reason = getattr(url_err, "reason", str(url_err))
                if "timed out" in str(reason).lower() or isinstance(url_err, TimeoutError) or "timeout" in str(url_err).lower():
                    last_err = LLMTimeoutError(f"LLM API request timed out after {self.config.timeout_seconds}s: {reason}")
                else:
                    last_err = LLMCommunicationError(f"LLM API network error: {reason}")
                if attempt < max_retries:
                    import time as _t
                    _t.sleep(1.5 * attempt)
                    continue
                raise last_err from url_err
            except Exception as e:
                last_err = e
                if attempt < max_retries:
                    import time as _t
                    _t.sleep(1.0)
                    continue
                raise
        if last_err:
            raise last_err


def create_llm_caller(
    provider: ApiLLMProvider | LLMProvider,
    tracker: Any | None = None,
    component: str = "generic",
) -> Callable[[str], str]:
    """Factory creating a tracked, bounded LLM caller function for engine components."""
    import logging
    import sys
    import time
    logger = logging.getLogger(__name__)

    def caller(prompt: str) -> str:
        if tracker is not None and tracker.is_exhausted:
            raise RuntimeError(f"LLM budget exhausted for component '{component}' - maximum {tracker.max_calls} calls exceeded")
        t0 = time.perf_counter()
        resp = "{}"
        try:
            if hasattr(provider, "call_raw"):
                resp = provider.call_raw(prompt)
            elif hasattr(provider, "generate"):
                resp = provider.generate({"prompt": prompt})
            else:
                resp = "{}"
        except Exception as err:
            is_timeout = (
                isinstance(err, (TimeoutError, LLMTimeoutError))
                or "timed out" in str(err).lower()
                or "timeout" in str(err).lower()
            )
            if is_timeout:
                print(f"\n[-] [LLM ERROR] Request timed out for component '{component}': {err}", file=sys.stderr)
                logger.error(f"LLM request timed out for component '{component}': {err}")
                raise LLMTimeoutError(f"LLM API request timed out for component '{component}': {err}") from err

            if component == "compiler":
                print(f"\n[-] [LLM ERROR] Compilation request failed for component 'compiler': {err}", file=sys.stderr)
                logger.error(f"LLM compilation request failed: {err}")
                raise

            print(f"[-] [AI SUB-SYSTEM WARNING] LLM call failed for component '{component}': {err}", file=sys.stderr)
            logger.warning(f"LLM call failed for component '{component}': {err} - falling back to deterministic processing")
            return "{}"

        elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
        if tracker is not None:
            model = getattr(getattr(provider, "config", None), "model", getattr(tracker, "model_name", "stub"))
            last_usage = getattr(provider, "last_usage", {}) or {}
            actual_prompt = last_usage.get("prompt_tokens")
            actual_completion = last_usage.get("completion_tokens")
            try:
                tracker.record_call(
                    component=component,
                    prompt=prompt,
                    response=resp,
                    duration_ms=elapsed_ms,
                    model=model,
                    actual_prompt_tokens=actual_prompt,
                    actual_completion_tokens=actual_completion,
                )
            except Exception as rec_err:
                logger.debug(f"Failed to record call in tracker: {rec_err}")
        return resp

    return caller



class StubSemanticCompiler:
    """Deterministic semantic compiler stub for offline testing and evaluation.

    Fulfills the semantic compilation schema without live network or external
    LLMs. The fixture is selected explicitly by the caller; it never infers a
    scenario from words in the request.
    """

    def __init__(self, scenario: str = "generic") -> None:
        allowed = {"generic", "database", "web", "amber", "lookup"}
        if scenario not in allowed:
            raise ValueError(f"Unsupported semantic fixture scenario: {scenario}")
        self.scenario = scenario

    def __call__(self, prompt: str) -> str:
        return self.compile(prompt)

    def compile(self, prompt: str) -> str:
        prompt_lower = prompt.lower()
        if "request content:" in prompt_lower:
            idx = prompt_lower.index("request content:") + len("request content:")
            content = prompt[idx:]
            if "\n\n" in content:
                content = content.split("\n\n", 1)[0].strip()
        else:
            content = prompt.strip()

        # Explicit fixture: Amber Turing / person investigation.  The fixture
        # must be selected by the caller; matching words in user content would
        # turn the test double into a hidden scenario classifier.
        if self.scenario in ("amber", "lookup"):
            data = {
                "normalized_claim": {
                    "text": "Amber Turing visited an external website",
                    "status": "UNVERIFIED",
                },
                "entities": [
                    {"type": "user", "value": "Amber Turing", "role": "actor"}
                ],
                "mechanism_status": "UNKNOWN",
                "answer_spec": {
                    "mode": "lookup",
                    "answer_type": "website_domain",
                    "evidence_types": ["web_request", "dns_activity"],
                    "question": "What website domain did Amber Turing visit?",
                },
                "semantic_intent": {
                    "original_request": content,
                    "question": "What website domain did Amber Turing visit?",
                    "subject": {"type": "person", "value": "Amber Turing"},
                    "requested_object": {"type": "website_domain", "role": "answer"},
                    "behavior": "visited a website to find executive contact information",
                    "evidence_requirements": [
                        {
                            "semantic_intent": "identity_binding",
                            "required_fields": ["user", "host", "src_ip"],
                            "necessity": "CRITICAL",
                            "description": "Correlate Amber Turing to workstation endpoint and client IP",
                        },
                        {
                            "semantic_intent": "web_navigation",
                            "required_fields": ["site", "uri", "query", "src_ip"],
                            "necessity": "CRITICAL",
                            "description": "Web or DNS requests originating from Amber Turing's client IP",
                        },
                    ],
                    "required_correlations": [
                        "person_to_endpoint",
                        "endpoint_to_client_ip",
                        "client_ip_to_web_or_dns_event",
                    ],
                    "assumptions": ["Amber Turing used corporate network infrastructure"],
                    "uncertainties": ["User endpoint hostname unknown", "Client IP address unassigned"],
                },
                "hypotheses": [
                    {
                        "id": "hypo-amber-visit",
                        "statement": "Amber Turing navigated to a website represented in web or DNS telemetry",
                        "class": "unclassified",
                        "assumptions": ["Amber Turing initiated outbound browsing session"],
                        "requirements": ["req-amber-identity", "req-amber-web"],
                    },
                    {
                        "id": "hypo-amber-no-visit",
                        "statement": "Amber Turing did not initiate external website navigation in the monitored period",
                        "class": "unclassified",
                        "assumptions": ["No external DNS/HTTP sessions tied to Amber Turing"],
                        "requirements": ["req-amber-identity"],
                    },
                ],
                "requirements": [
                    {
                        "id": "req-amber-identity",
                        "semantic_intent": "identity_binding",
                        "necessity": "CRITICAL",
                        "search_hints": ["Amber Turing", "aturing", "Amber"],
                        "falsification_condition": "no authentication or host logon records associated with Amber Turing",
                        "description": "Identify workstation hostname or client IP used by Amber Turing",
                        "source_refs": ["DIRECTORY_SERVICE"],
                    },
                    {
                        "id": "req-amber-web",
                        "semantic_intent": "web_navigation",
                        "necessity": "CRITICAL",
                        "search_hints": [],
                        "falsification_condition": "no outbound HTTP requests or DNS queries recorded from user workstation",
                        "description": "Identify external domains accessed from Amber Turing's workstation",
                        "source_refs": ["PROXY_DNS_TELEMETRY"],
                    },
                ],
            }
            return json.dumps(data)

        # Explicit fixture: database compromise
        if self.scenario == "database":
            data = {
                "normalized_claim": {
                    "text": "Attacker compromised database db01",
                    "status": "UNVERIFIED",
                },
                "entities": [
                    {"type": "host", "value": "db01", "role": "target"}
                ],
                "mechanism_status": "UNKNOWN",
                "semantic_intent": {
                    "original_request": content,
                    "question": "Did attacker compromise database db01?",
                    "subject": {"type": "host", "value": "db01"},
                    "requested_object": {"type": "database_compromise", "role": "answer"},
                    "behavior": "unauthorized database access",
                    "evidence_requirements": [
                        {"semantic_intent": "remote_authentication", "required_fields": ["user", "host"], "necessity": "CRITICAL", "description": "Audit authentication events for database host db01"},
                        {"semantic_intent": "server_side_execution", "required_fields": ["cmdline", "host"], "necessity": "SUPPORTING", "description": "Audit process lineage for database server db01"},
                        {"semantic_intent": "operational_baseline", "required_fields": ["host"], "necessity": "SUPPORTING", "description": "Verified operational telemetry baseline for database host"},
                    ],
                    "required_correlations": ["host_to_process", "host_to_authentication"],
                    "assumptions": ["Attacker acquired database administrative credentials"],
                    "uncertainties": [],
                },
                "hypotheses": [
                    {
                        "id": "hypo-db-cred",
                        "statement": "Unauthorized database access via credential misuse or privilege abuse",
                        "class": "credential_access",
                        "assumptions": ["Attacker acquired database administrative credentials"],
                        "requirements": ["req-db-auth", "req-db-proc"],
                    },
                    {
                        "id": "hypo-db-benign",
                        "statement": "Normal operational database baseline without unauthorized access",
                        "class": "benign_baseline",
                        "assumptions": ["Routine DBA query execution and administrative maintenance"],
                        "requirements": ["req-db-baseline"],
                    },
                ],
                "requirements": [
                    {
                        "id": "req-db-auth",
                        "semantic_intent": "remote_authentication",
                        "necessity": "CRITICAL",
                        "search_hints": ["db01"],
                        "falsification_condition": "authentication logs confirm only authorized DBA sessions",
                        "description": "Audit authentication events for database host db01",
                        "source_refs": ["MITRE-T1078"],
                    },
                    {
                        "id": "req-db-proc",
                        "semantic_intent": "server_side_execution",
                        "necessity": "SUPPORTING",
                        "search_hints": ["db01"],
                        "falsification_condition": "process lineage shows zero anomalous binaries on database server",
                        "description": "Audit process lineage for database server db01",
                        "source_refs": ["MITRE-T1059"],
                    },
                    {
                        "id": "req-db-baseline",
                        "semantic_intent": "operational_baseline",
                        "necessity": "SUPPORTING",
                        "search_hints": ["db01"],
                        "falsification_condition": "telemetry partition gap or audit failure",
                        "description": "Verified operational telemetry baseline for database host",
                        "source_refs": ["SENSOR_BASELINE"],
                    },
                ],
            }
            return json.dumps(data)

        # Explicit fixture: web/domain access. Domain extraction is entity
        # parsing for the fixture, not semantic classification.
        domain_match = re.search(r"(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}", content)
        extracted_domain = domain_match.group(0) if domain_match else "www.imreallynotbatman.com"

        if self.scenario == "web":
            data = {
                "normalized_claim": {
                    "text": f"Attacker gained access to {extracted_domain}",
                    "status": "UNVERIFIED",
                },
                "entities": [
                    {"type": "domain", "value": extracted_domain, "role": "target"}
                ],
                "mechanism_status": "UNKNOWN",
                "semantic_intent": {
                    "original_request": content,
                    "question": f"Did attacker gain access to {extracted_domain}?",
                    "subject": {"type": "domain", "value": extracted_domain},
                    "requested_object": {"type": "web_compromise", "role": "answer"},
                    "behavior": f"external adversary web compromise of {extracted_domain}",
                    "evidence_requirements": [
                        {"semantic_intent": "web_request_activity", "required_fields": ["uri", "client_ip"], "necessity": "CRITICAL", "description": f"Inbound HTTP/web requests targeting {extracted_domain}"},
                        {"semantic_intent": "server_side_execution", "required_fields": ["cmdline", "host"], "necessity": "CRITICAL", "description": f"Process execution and server-side lineage audit associated with {extracted_domain}"},
                    ],
                    "required_correlations": ["client_ip_to_web_request", "web_request_to_process"],
                    "assumptions": ["Web service exposed externally with exploitable vulnerability"],
                    "uncertainties": [],
                },
                "hypotheses": [
                    {
                        "id": "hypo-web-exploit",
                        "statement": f"External adversary exploited web vulnerability on {extracted_domain}",
                        "class": "external_exploitation",
                        "assumptions": ["Web service exposed externally with exploitable vulnerability"],
                        "requirements": ["req-web-activity", "req-web-proc", "req-web-file"],
                    },
                    {
                        "id": "hypo-web-cred",
                        "statement": f"Adversary accessed infrastructure supporting {extracted_domain} via stolen credentials",
                        "class": "credential_access",
                        "assumptions": ["Valid credentials compromised and reused"],
                        "requirements": ["req-web-auth", "req-web-proc"],
                    },
                    {
                        "id": "hypo-web-benign",
                        "statement": f"Normal operational baseline without security compromise on {extracted_domain}",
                        "class": "benign_baseline",
                        "assumptions": ["Routine inbound traffic and standard administrative operations"],
                        "requirements": ["req-web-baseline"],
                    },
                ],
                "requirements": [
                    {
                        "id": "req-web-activity",
                        "semantic_intent": "web_request_activity",
                        "necessity": "CRITICAL",
                        "search_hints": [extracted_domain, extracted_domain[4:] if extracted_domain.startswith("www.") else extracted_domain],
                        "falsification_condition": "web telemetry shows zero malicious requests or exploit signatures",
                        "description": f"Inbound HTTP/web requests targeting {extracted_domain}",
                        "source_refs": ["MITRE-T1190"],
                    },
                    {
                        "id": "req-web-proc",
                        "semantic_intent": "server_side_execution",
                        "necessity": "CRITICAL",
                        "search_hints": [extracted_domain],
                        "falsification_condition": "process lineage shows zero spawned shells or command interpreters",
                        "description": f"Process execution and server-side lineage audit associated with {extracted_domain}",
                        "source_refs": ["MITRE-T1059"],
                    },
                    {
                        "id": "req-web-file",
                        "semantic_intent": "file_artifact",
                        "necessity": "SUPPORTING",
                        "search_hints": [extracted_domain],
                        "falsification_condition": "filesystem inspection shows zero web shells or modified scripts",
                        "description": f"File modifications and artifact drops associated with {extracted_domain}",
                        "source_refs": ["MITRE-T1505"],
                    },
                    {
                        "id": "req-web-auth",
                        "semantic_intent": "remote_authentication",
                        "necessity": "SUPPORTING",
                        "search_hints": [extracted_domain],
                        "falsification_condition": "authentication audit shows standard administrative sessions",
                        "description": "Authentication and logon activity audit",
                        "source_refs": ["MITRE-T1078"],
                    },
                    {
                        "id": "req-web-baseline",
                        "semantic_intent": "operational_baseline",
                        "necessity": "SUPPORTING",
                        "search_hints": [extracted_domain],
                        "falsification_condition": "telemetry gap or unobservable audit partition",
                        "description": "Verified operational telemetry baseline",
                        "source_refs": ["SENSOR_BASELINE"],
                    },
                ],
            }
            return json.dumps(data)

        # Generic fallback
        data = {
            "normalized_claim": {
                "text": "Generic free-text threat inquiry",
                "status": "UNVERIFIED",
            },
            "entities": [],
            "mechanism_status": "UNKNOWN",
            "hypotheses": [
                {
                    "id": "hypo-gen-active",
                    "statement": "Anomalous or unauthorized threat activity in environment",
                    "class": "unclassified",
                    "assumptions": ["Adversary activity present in monitored telemetry"],
                    "requirements": ["req-gen-proc"],
                },
                {
                    "id": "hypo-gen-benign",
                    "statement": "Normal operational behavior and clean baseline",
                    "class": "benign_baseline",
                    "assumptions": ["Telemetry reflects standard operational baseline"],
                    "requirements": ["req-gen-baseline"],
                },
            ],
            "requirements": [
                {
                    "id": "req-gen-proc",
                    "semantic_intent": "server_side_execution",
                    "necessity": "CRITICAL",
                    "search_hints": [],
                    "falsification_condition": "process lineage confirms zero anomalous executions",
                    "description": "Process execution and command line audit",
                    "source_refs": ["BEHAVIORAL_BASELINE"],
                },
                {
                    "id": "req-gen-baseline",
                    "semantic_intent": "operational_baseline",
                    "necessity": "SUPPORTING",
                    "search_hints": [],
                    "falsification_condition": "telemetry gap or unobservable audit partition",
                    "description": "Verified operational telemetry baseline",
                    "source_refs": ["SENSOR_BASELINE"],
                },
            ],
        }
        return json.dumps(data)


__all__ = [
    "ApiLLMConfig",
    "LLMProvider",
    "StubAbductionProvider",
    "StubSemanticCompiler",
    "ApiLLMProvider",
    "create_llm_caller",
]
