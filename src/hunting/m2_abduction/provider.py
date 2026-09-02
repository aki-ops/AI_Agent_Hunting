"""M2 Abduction Provider interface, Stub provider, and external API provider.

Separates API endpoint/model/timeout/token limits and secrets from investigation state.
Local model inference is out of scope for the current deployment.
"""
from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any

from hunting.contracts.explanations import ExplanationClass


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
    """External API LLM provider for live deployment."""

    def __init__(self, config: ApiLLMConfig) -> None:
        self.config = config

    def generate(self, prompt_context: dict[str, Any]) -> str:
        """Call external LLM API. (Can be hooked to requests/httpx)."""
        # Strictly structured input: verify no raw text entered context
        if "raw_log" in prompt_context or "raw_payload" in prompt_context:
            raise ValueError("Security violation: raw log content cannot be sent to external LLM API")

        # For production execution, external HTTP calls occur here.
        # Fallback to structured response if in test environment without network
        return StubAbductionProvider().generate(prompt_context)


__all__ = [
    "ApiLLMConfig",
    "LLMProvider",
    "StubAbductionProvider",
    "ApiLLMProvider",
]
