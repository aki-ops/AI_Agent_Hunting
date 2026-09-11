"""Registry for human-approved, versioned proof contracts.

This registry is the authoritative control plane for semantic proof capabilities.
A telemetry operation can only achieve PROOF_CAPABLE status if backed by an
approved contract in this registry.
"""
from __future__ import annotations

from typing import Iterable

from hunting.contracts.proof_contract import (
    ProofContract,
    ProofContractStatus,
)


class ProofContractRegistry:
    """Registry managing human-reviewed and approved ProofContract specifications."""

    def __init__(self, contracts: Iterable[ProofContract] | None = None) -> None:
        self._contracts: dict[str, ProofContract] = {}
        if contracts:
            for c in contracts:
                self.register(c)
        else:
            self._register_canonical_defaults()

    def register(self, contract: ProofContract) -> None:
        """Register a proof contract. Overwrites existing contract with same ID."""
        self._contracts[contract.contract_id] = contract

    def get(self, contract_id: str) -> ProofContract | None:
        """Retrieve a contract by its ID."""
        return self._contracts.get(contract_id)

    def list_all(self) -> tuple[ProofContract, ...]:
        """List all registered contracts."""
        return tuple(self._contracts.values())

    def list_approved(self) -> tuple[ProofContract, ...]:
        """List all approved contracts."""
        return tuple(c for c in self._contracts.values() if c.is_approved)

    def find_matching_contract(
        self,
        *,
        relation: str,
        input_roles: dict[str, str],
        output_roles: dict[str, str],
        action_roles: dict[str, str] | None = None,
        state_roles: dict[str, str] | None = None,
        artifact_identity_roles: dict[str, str] | None = None,
    ) -> tuple[ProofContract | None, tuple[str, ...]]:
        """Find the first approved contract satisfied by the declared operation roles."""
        rel = str(relation).strip().casefold()
        candidates = [c for c in self._contracts.values() if c.is_approved and c.relation == rel]
        if not candidates:
            return None, (f"no_approved_proof_contract_for_relation:{rel}",)

        rejection_reasons: list[str] = []
        for contract in candidates:
            ok, reasons = contract.validate_capability_conformance(
                relation=rel,
                input_roles=input_roles,
                output_roles=output_roles,
                action_roles=action_roles,
                state_roles=state_roles,
                artifact_identity_roles=artifact_identity_roles,
            )
            if ok:
                return contract, ()
            rejection_reasons.extend(reasons)

        return None, tuple(rejection_reasons)

    def _register_canonical_defaults(self) -> None:
        """Initialize built-in approved contracts for canonical security relations."""
        canonical = [
            # 1. State transition / file encryption proof
            ProofContract(
                contract_id="proof-transition-v1",
                version="1.0.0",
                relation="observed_transition",
                required_entity_roles=("source_artifact",),
                required_value_roles=("target_artifact",),
                required_action_roles=("action",),
                required_state_roles=("before_state", "after_state"),
                artifact_identity_roles=("artifact_id",),
                temporal_bound_seconds=3600.0,
                min_completeness_required=True,
                status=ProofContractStatus.APPROVED,
                description="Proves artifact transition (e.g. rename, encrypt) across paired ledger rows with stable identity and timestamp ordering.",
            ),
            # 2. Person to endpoint association proof
            ProofContract(
                contract_id="proof-person-endpoint-v1",
                version="1.0.0",
                relation="associated_with",
                required_entity_roles=("person",),
                required_value_roles=("endpoint",),
                status=ProofContractStatus.APPROVED,
                description="Proves that an endpoint workstation belongs to or is assigned to a named person.",
            ),
            # 3. Account logon to host proof
            ProofContract(
                contract_id="proof-account-logon-v1",
                version="1.0.0",
                relation="logged_on_to",
                required_entity_roles=("account",),
                required_value_roles=("endpoint",),
                status=ProofContractStatus.APPROVED,
                description="Proves interactive or network logon by an authenticated account onto an endpoint host.",
            ),
            # 4. Web domain visit proof
            ProofContract(
                contract_id="proof-web-visit-v1",
                version="1.0.0",
                relation="visited",
                required_entity_roles=("endpoint",),
                required_value_roles=("domain",),
                status=ProofContractStatus.APPROVED,
                description="Proves HTTP/S connection to a fully-qualified domain name initiated from an endpoint host.",
            ),
            # 5. Email transmission proof
            ProofContract(
                contract_id="proof-email-sent-v1",
                version="1.0.0",
                relation="sent_email",
                required_entity_roles=("person",),
                required_value_roles=("email_address",),
                status=ProofContractStatus.APPROVED,
                description="Proves an outbound email message sent by a person from or to an email address.",
            ),
            # 6. Process execution proof
            ProofContract(
                contract_id="proof-process-spawn-v1",
                version="1.0.0",
                relation="executed_process",
                required_entity_roles=("endpoint",),
                required_value_roles=("process_name",),
                status=ProofContractStatus.APPROVED,
                description="Proves execution of a binary/script image on a client endpoint.",
            ),
            # 7. Tor Browser install/run proof
            ProofContract(
                contract_id="proof-software-install-v1",
                version="1.0.0",
                relation="installed_on",
                required_entity_roles=("artifact",),
                required_value_roles=("endpoint",),
                status=ProofContractStatus.APPROVED,
                description="Proves software package or binary artifact presence on an endpoint.",
            ),
        ]
        for c in canonical:
            self.register(c)


_DEFAULT_REGISTRY: ProofContractRegistry | None = None


def get_default_proof_contract_registry() -> ProofContractRegistry:
    """Singleton getter for the default canonical ProofContractRegistry."""
    global _DEFAULT_REGISTRY
    if _DEFAULT_REGISTRY is None:
        _DEFAULT_REGISTRY = ProofContractRegistry()
    return _DEFAULT_REGISTRY


__all__ = [
    "ProofContractRegistry",
    "get_default_proof_contract_registry",
]
