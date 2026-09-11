"""Deterministic Relation Verifier (v5.0).

The gatekeeper of the Investigation Case Graph.
Verifies candidate edges against observation ledgers, enforcing strict field roles
(client_ip ≠ server_ip, host ≠ sensor), web server isolation, and valid citations
before minting RelationProofs and updating graph state.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from email.utils import parseaddr
from typing import Any

from hunting.contracts.case_graph import (
    GraphEdge,
    GraphNode,
    InvestigationGraph,
    NodeStatus,
    RelationProof,
    RelationStatus,
    RelationType,
)
from hunting.contracts.observations import EpistemicType, Observation
from hunting.contracts.proof_contract import ProofContract
from hunting.contracts.queries import ProviderOperation, QueryResult
from hunting.m1_ledger.ledger import ObservationLedger

SERVER_ROLE_FIELDS = (
    "asset_role", "host_role", "endpoint_role", "device_role",
    "telemetry_role", "server_role", "is_server", "is_web_server",
)
SERVER_ROLE_VALUES = {
    "server", "web_server", "web-server", "server_endpoint", "collector",
    "sensor", "true", "1", "yes",
}


def observation_declares_server_role(fields: dict[str, object] | None) -> bool:
    """Return whether telemetry explicitly declares a server-like role.

    Host names and native event/source names are not reliable role evidence:
    an endpoint can be named ``srv-*`` and a server can have a user session.
    The verifier rejects an endpoint binding only when the provider actually
    emits a typed role flag/value. Missing role metadata remains unknown.
    """
    if not isinstance(fields, dict):
        return False
    for key, value in fields.items():
        if str(key).casefold() not in SERVER_ROLE_FIELDS:
            continue
        normalized = str(value).strip().casefold()
        if normalized in SERVER_ROLE_VALUES:
            return True
        if normalized in {"endpoint", "workstation", "client", "user_device", "desktop", "laptop"}:
            return False
    return False


def _parse_timestamp(ts: Any) -> datetime | None:
    """Parse string/numeric/datetime into UTC timezone-aware datetime."""
    if isinstance(ts, datetime):
        return ts if ts.tzinfo else ts.replace(tzinfo=timezone.utc)
    if isinstance(ts, (int, float)):
        try:
            return datetime.fromtimestamp(float(ts), tz=timezone.utc)
        except Exception:
            return None
    if not isinstance(ts, str) or not ts.strip():
        return None
    s = ts.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        pass
    for fmt in (
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d %H:%M:%S",
        "%Y-%m-%d %H:%M:%S.%f",
        "%Y-%m-%dT%H:%M:%S.%f",
    ):
        try:
            dt = datetime.strptime(s, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


@dataclass
class VerificationResult:
    """Outcome of deterministic relation verification."""
    verified: bool
    proof: RelationProof | None = None
    target_value: str | None = None
    diagnostic: str = ""
    violations: list[str] = field(default_factory=list)

    @property
    def cited_observation_ids(self) -> list[str]:
        return self.proof.citations if self.proof else []

    @property
    def field_matches(self) -> dict[str, str]:
        return self.proof.field_matches if self.proof else {}


def verify_relation_proof_contract(
    proof_contract: ProofContract,
    observations: list[Observation],
    ledger: ObservationLedger | None = None,
    expected_bindings: dict[str, str] | None = None,
) -> VerificationResult:
    """Evaluate ledger-backed cited observations against an approved ProofContract.

    Enforces strict non-negotiable invariants:
    - Only APPROVED proof contracts can grant proof authority.
    - All cited observations must be backed by the ledger.
    - Invariant 1: DNS lookup does not prove person visited domain.
    - Invariant 2: Generic file creation does not prove ransomware encryption.
    - All required entity, value, action, state, and artifact identity roles must be satisfied.
    - Expected bindings must match observed roles with zero contradiction.
    """
    if not observations:
        return VerificationResult(
            verified=False,
            diagnostic="no_observations_cited",
            violations=["No observations provided to verify proof contract."],
        )

    if not proof_contract.is_approved:
        return VerificationResult(
            verified=False,
            diagnostic=f"contract_{proof_contract.contract_id}_is_{proof_contract.status.value}",
            violations=[f"ProofContract {proof_contract.contract_id} is {proof_contract.status.value}, not APPROVED."],
        )

    if ledger is not None:
        ledger_ids = {obs.id for obs in ledger.observations}
        unbacked = [obs.id for obs in observations if obs.id not in ledger_ids]
        if unbacked:
            return VerificationResult(
                verified=False,
                diagnostic="unbacked_observations",
                violations=[f"Observation {oid} is not backed by ledger" for oid in unbacked],
            )

    # Invariant 1: DNS lookup does not prove person visited domain or entity association
    if proof_contract.relation in ("person_visited_domain", "visited_domain", "user_accessed_web", "domain_visit", "associated_with"):
        is_dns_only = all(
            "dns" in str(getattr(obs, "native_type", "")).lower()
            or "dns" in str(getattr(obs, "fields", {}).get("sourcetype", "")).lower()
            or ("query" in obs.fields and "http_method" not in obs.fields and "uri" not in obs.fields and "site" not in obs.fields and "process" not in obs.fields)
            for obs in observations
        )
        if is_dns_only:
            return VerificationResult(
                verified=False,
                diagnostic="dns_lookup_cannot_prove_web_visit",
                violations=["DNS lookup demonstrates host domain resolution only; does not prove person visited domain or entity association."],
            )

    # Invariant 2: Generic file creation or process execution does not prove ransomware encryption
    if proof_contract.relation in ("ransomware_encrypted_file", "encrypted_file", "file_encrypted"):
        is_generic_creation = all(
            str(obs.fields.get("EventCode", "")) in ("11", "1", "")
            and not any(k in obs.fields for k in ("ransom_note", "encryption_key", "cipher", "original_file_path", "state_transition", "ransom_extension"))
            and not str(obs.fields.get("action", "")).lower().startswith("encrypt")
            for obs in observations
        )
        if is_generic_creation:
            return VerificationResult(
                verified=False,
                diagnostic="file_creation_does_not_prove_ransomware_encryption",
                violations=["Generic file creation does not prove ransomware encryption without state transition and cryptographic proof."],
            )

    # Invariant 3: Domain traffic or resolution event does not prove domain ownership
    if proof_contract.relation in ("owns_domain", "domain_ownership", "registered_domain"):
        is_traffic_only = any(
            any(k in obs.fields for k in ("url", "uri", "http_method", "site", "dest_port", "query"))
            and not any(k in obs.fields for k in ("registrar", "whois", "registrant", "zone_admin"))
            for obs in observations
        )
        if is_traffic_only:
            return VerificationResult(
                verified=False,
                diagnostic="domain_event_does_not_prove_ownership",
                violations=["Domain traffic or resolution event does not prove domain ownership."],
            )

    # Invariant 4: Email address transaction does not prove person is CEO or holds title
    if proof_contract.relation in ("holds_title", "is_role", "organization_title", "is_ceo"):
        is_mail_transaction = any(
            any(k in obs.fields for k in ("sender", "recipient", "subject", "message_id"))
            and not any(k in obs.fields for k in ("hr_title", "job_role", "employment_title", "directory_role"))
            for obs in observations
        )
        if is_mail_transaction:
            return VerificationResult(
                verified=False,
                diagnostic="email_does_not_prove_title",
                violations=["Email transaction or message presence does not prove executive title or role."],
            )


    # Extract all fields across observations
    combined_fields: dict[str, str] = {}
    for obs in observations:
        raw_ev = getattr(obs, "raw_event", {}) or obs.fields.get("raw_event", {})
        if isinstance(raw_ev, dict):
            for k, v in raw_ev.items():
                if v not in (None, "", [], {}):
                    combined_fields[str(k).casefold()] = str(v[0] if isinstance(v, list) else v).strip()
        for k, v in obs.fields.items():
            if v not in (None, "", [], {}):
                combined_fields[str(k).casefold()] = str(v[0] if isinstance(v, list) else v).strip()

    field_matches: dict[str, str] = {}
    violations: list[str] = []

    all_required_roles = [
        *proof_contract.required_entity_roles,
        *proof_contract.required_value_roles,
        *proof_contract.required_action_roles,
        *proof_contract.required_state_roles,
        *proof_contract.artifact_identity_roles,
    ]

    for role in all_required_roles:
        aliases = RelationVerifier._contract_role_aliases(role)
        matched_field = next((alias for alias in aliases if alias in combined_fields), None)
        if not matched_field:
            violations.append(f"Missing required role: {role}")
        else:
            field_matches[role] = combined_fields[matched_field]

    if expected_bindings:
        for key, exp_val in expected_bindings.items():
            k_clean = str(key).strip().casefold()
            aliases = RelationVerifier._contract_role_aliases(k_clean)
            obs_val = next((combined_fields[alias] for alias in aliases if alias in combined_fields), None)
            if obs_val is None:
                violations.append(f"Expected binding {key}={exp_val} not found in observation fields")
            elif exp_val.strip().casefold() not in obs_val.strip().casefold() and obs_val.strip().casefold() not in exp_val.strip().casefold():
                violations.append(f"Binding contradiction: {key} expected '{exp_val}', but observed '{obs_val}'")

    if violations:
        return VerificationResult(
            verified=False,
            diagnostic="proof_contract_requirements_not_satisfied",
            violations=violations,
        )

    citations = [obs.id for obs in observations]
    source_val = field_matches.get("host") or field_matches.get("user") or (observations[0].id if observations else "")
    target_val = field_matches.get("ip") or field_matches.get("domain") or field_matches.get("file_path") or ""
    proof = RelationProof(
        id=f"proof-{proof_contract.contract_id}-{citations[0] if citations else '0'}",
        edge_id=f"edge-{proof_contract.relation}",
        source_node_id="src-node",
        source_value=str(source_val),
        target_node_id="tgt-node",
        target_value=str(target_val),
        relation_type=proof_contract.relation,
        citations=citations,
        field_matches=field_matches,
    )
    return VerificationResult(
        verified=True,
        proof=proof,
        target_value=str(target_val),
    )


class RelationVerifier:
    """Deterministic authority that verifies graph edges from ledger observations."""

    USER_FIELDS = ("user", "username", "targetusername", "account_name", "samaccountname")
    HOST_FIELDS = ("host", "computername", "workstationname", "workstation_name", "target_host", "hostname", "name")
    CLIENT_IP_FIELDS = ("ipaddress", "src_ip", "client_ip", "c_ip", "source_ip", "host_addr")
    SERVER_IP_FIELDS = ("dest_ip", "server_ip", "s_ip", "destination_ip")
    DOMAIN_FIELDS = ("site", "cs_host", "query", "domain", "url", "uri")
    VERSION_FIELDS = (
        "version", "productversion", "product_version", "fileversion", "file_version",
        "software_version", "app_version", "displayversion", "package_version",
    )
    ARTIFACT_FIELDS = ("image", "targetfilename", "target_filename", "file_path", "path", "commandline", "cmdline")
    # Provider-neutral aliases used only to evaluate a ClaimEvidenceRequirement
    # against the fields returned by an already-bound provider operation.  They
    # are not scenario routes: a claim declares its fact kind/roles and the
    # adapter declares which native fields it emits.
    CONTRACT_FIELD_ALIASES = {
        "email": {"email", "mail", "sender", "sender_email", "receiver", "receiver_email", "recipient_email"},
        "email_address": {"email", "mail", "sender", "sender_email", "receiver", "receiver_email", "recipient_email"},
        "domain": {"domain", "site", "cs_host", "query", "url", "uri", "dest_host"},
        "ip": {"ip", "ipaddress", "src_ip", "source_ip", "client_ip", "c_ip", "dest_ip", "destination_ip", "server_ip"},
        "account": {"user", "username", "account", "account_name", "targetusername", "samaccountname"},
        "person": {"user", "username", "displayname", "display_name", "sender", "receiver", "name"},
        "endpoint": {"host", "hostname", "computername", "workstationname", "workstation_name", "target_host"},
        "host": {"host", "hostname", "computername", "workstationname", "workstation_name", "target_host"},
        "process": {"image", "process", "process_name", "commandline", "cmdline", "pid"},
        "file": {"file", "file_path", "path", "targetfilename", "target_filename"},
        "software": {"software", "product", "product_name", "application", "image", "file_path"},
        "software_version": {"version", "productversion", "product_version", "fileversion", "file_version", "software_version", "app_version", "displayversion"},
        "message": {"message", "message_id", "msg_id", "subject", "sender", "receiver", "body"},
        "role": {"role", "title", "job_title", "department"},
    }

    CONTRACT_ROLE_ALIASES = {
        "account_name": {"user", "username", "account", "account_name", "targetusername", "samaccountname"},
        "person_name": {"user", "username", "displayname", "display_name", "sender", "receiver", "name"},
        "email_address": {"email", "mail", "sender", "sender_email", "receiver", "receiver_email", "recipient_email"},
        "sender_email": {"mail", "sender", "sender_email", "from", "from_email"},
        "recipient_email": {"receiver", "receiver_email", "recipient", "recipient_email", "to", "to_email"},
        "domain_name": {"domain", "site", "cs_host", "query", "url", "uri", "dest_host"},
        "client_ip": {"ip", "ipaddress", "src_ip", "source_ip", "client_ip", "c_ip", "host_addr"},
        "source_ip": {"ip", "ipaddress", "src_ip", "source_ip", "client_ip", "c_ip", "host_addr"},
        "destination_ip": {"dest_ip", "destination_ip", "server_ip", "s_ip"},
        "endpoint_host": {"host", "hostname", "computername", "workstationname", "workstation_name", "target_host"},
        "process_name": {"image", "process", "process_name", "commandline", "cmdline"},
        "file_path": {"file", "file_path", "path", "targetfilename", "target_filename"},
        "uri_path": {"uri", "url", "uri_path", "path"},
        "message_id": {"message", "message_id", "msg_id", "id"},
        "role_name": {"role", "title", "job_title", "department"},
    }

    @staticmethod
    def _contract_fields(observation: Observation) -> dict[str, str]:
        """Flatten native/raw fields into a case-insensitive scalar view."""
        merged: dict[str, str] = {}
        raw_event = getattr(observation, "raw_event", {}) or {}
        sources = [raw_event, getattr(observation, "fields", {}) or {}]
        for source in sources:
            if not isinstance(source, dict):
                continue
            for key, value in source.items():
                if isinstance(value, list):
                    value = value[0] if value else ""
                if isinstance(value, dict) or value in (None, "", [], {}):
                    continue
                merged[str(key).casefold()] = str(value).strip()
        return merged

    @classmethod
    def _contract_aliases(cls, value: str) -> set[str]:
        normalized = str(value or "").strip().casefold()
        return set(cls.CONTRACT_FIELD_ALIASES.get(normalized, {normalized}))

    @classmethod
    def _contract_role_aliases(cls, value: str) -> set[str]:
        normalized = str(value or "").strip().casefold()
        return set(
            cls.CONTRACT_ROLE_ALIASES.get(
                normalized,
                cls.CONTRACT_FIELD_ALIASES.get(normalized, {normalized}),
            )
        )

    @staticmethod
    def _contract_contains(fields: dict[str, str], needle: str) -> bool:
        target = str(needle or "").strip().casefold()
        if not target or target == "?":
            return True
        target_tokens = [token for token in re.split(r"[^a-z0-9@._-]+", target) if token]
        values = [value.casefold() for value in fields.values()]
        return any(target in value or (target_tokens and all(token in value for token in target_tokens)) for value in values)

    @classmethod
    def _verify_claim_contract(
        cls,
        edge: GraphEdge,
        source_node: GraphNode,
        target_node: GraphNode,
        candidate_obs: list[Observation],
    ) -> VerificationResult:
        """Verify an edge using only its declared claim contract.

        This is deliberately small and deterministic: the LLM may propose the
        fact kind and field roles, but it cannot promote an observation.  The
        provider adapter has already been selected from those same contracts.
        """
        predicate = edge.acceptance_predicate or {}
        if predicate.get("completeness_required") and not predicate.get("query_complete", False):
            return VerificationResult(
                verified=False,
                diagnostic="Claim contract requires a complete query result.",
                violations=["query_result_incomplete"],
            )
        required_fields = {
            str(value).strip().casefold()
            for value in predicate.get("required_fields", [])
            if str(value).strip()
        }
        min_observations = max(1, int(predicate.get("min_observations", 1) or 1))
        target_type = str(getattr(target_node.type, "value", target_node.type)).casefold()
        source_type = str(getattr(source_node.type, "value", source_node.type)).casefold()
        source_value = str(source_node.value or "").strip()
        target_value = str(target_node.value or "").strip()
        source_role = edge.required_field_roles.get("source") if edge.required_field_roles else None
        target_role = edge.required_field_roles.get("target") if edge.required_field_roles else None
        target_aliases = cls._contract_role_aliases(str(target_role or target_type))
        required_aliases = set(required_fields)
        for field_name in list(required_fields):
            required_aliases.update(cls._contract_aliases(field_name))

        matches: list[tuple[Observation, dict[str, str]]] = []
        for observation in candidate_obs:
            fields = cls._contract_fields(observation)
            if not fields:
                continue

            # Required fields are satisfied by native aliases declared by the
            # contract/adapter, never by a prose keyword match.
            if required_fields and any(
                not cls._contract_aliases(field_name).intersection(fields)
                for field_name in required_fields
            ):
                continue

            if source_role:
                source_aliases = cls._contract_role_aliases(str(source_role))
                source_fields = {key: value for key, value in fields.items() if key in source_aliases}
                if source_fields and not cls._contract_contains(source_fields, source_value):
                    continue

            value_must_match = str(predicate.get("value_must_match") or "").strip()
            if value_must_match and not cls._contract_contains(fields, value_must_match):
                continue
            if target_value and target_value != "?" and not cls._contract_contains(fields, target_value):
                continue

            matches.append((observation, fields))

        if len(matches) < min_observations:
            return VerificationResult(
                verified=False,
                diagnostic=(
                    "Claim contract not satisfied: required fields/value were not "
                    f"observed in at least {min_observations} row(s)."
                ),
                violations=["claim_acceptance_rule_not_satisfied"],
            )

        first_obs, first_fields = matches[0]
        discovered = target_value if target_value and target_value != "?" else None
        field_matches: dict[str, str] = {}
        if target_value and target_value != "?":
            field_matches["target"] = target_value
        else:
            preferred_target_keys = {
                "message": ("message_id", "msg_id", "message", "id", "subject"),
                "email_address": ("email", "mail", "sender_email", "receiver_email", "sender", "receiver"),
                "identity": ("identity", "signer", "user", "username", "account"),
                "domain": ("domain", "site", "cs_host", "query", "url", "uri"),
                "ip": ("ip", "ipaddress", "client_ip", "src_ip", "source_ip", "dest_ip", "server_ip"),
                "role": ("role", "title", "job_title", "department"),
            }.get(target_type, ())
            # Typed relation direction supplies an additional deterministic
            # ordering when a row contains both sides of a communication.
            # This is not an email route: it is the same source/target role
            # constraint used for any directed relation.
            if source_type == "message" and target_type == "email_address":
                preferred_target_keys = (
                    "receiver_email", "recipient_email", "receiver", "recipient",
                    *preferred_target_keys,
                )
            for key in (*preferred_target_keys, *sorted(target_aliases)):
                value = first_fields.get(key)
                if key in target_aliases and value:
                    discovered = value
                    field_matches[key] = value
                    break
            if discovered is None and required_fields:
                for key, value in first_fields.items():
                    if key in required_aliases and value:
                        discovered = value
                        field_matches[key] = value
                        break

        if discovered is None:
            return VerificationResult(
                verified=False,
                diagnostic="Claim contract matched rows but yielded no target value.",
                violations=["target_value_not_observed"],
            )

        citations = [observation.id for observation, _ in matches]
        proof = RelationProof(
            id=f"proof-{edge.id}",
            edge_id=edge.id,
            source_node_id=source_node.id,
            source_value=source_node.value,
            target_node_id=target_node.id,
            target_value=str(discovered),
            relation_type=edge.relation_type if isinstance(edge.relation_type, str) else edge.relation_type.value,
            citations=citations,
            field_matches=field_matches,
            verified_by="ClaimContractVerifier",
        )
        return VerificationResult(
            verified=True,
            proof=proof,
            target_value=str(discovered),
            diagnostic=f"Claim contract verified with {len(citations)} observation(s).",
        )

    @classmethod
    def _artifact_value(
        cls,
        fields: dict[str, str],
        edge: GraphEdge,
        target_type: str,
    ) -> tuple[str | None, dict[str, str]]:
        """Return an artifact value only when the row carries target evidence.

        This is intentionally a verifier, not an answer generator.  A row is
        eligible only if it contains a product hint derived from the semantic
        request.  A version is accepted only from an explicit version field or
        a version-shaped token in the same cited row.
        """
        terms = [str(t).strip().lower() for t in (edge.acceptance_predicate or {}).get("software_terms", []) if str(t).strip()]
        searchable = " ".join(str(v).lower() for v in fields.values())
        if terms and not any(term in searchable for term in terms):
            return None, {}
        if not terms:
            return None, {}

        if target_type in ("software_version", "version"):
            for key in cls.VERSION_FIELDS:
                val = str(fields.get(key, "") or "").strip()
                if val and val not in ("-", "unknown", "none"):
                    match = re.search(r"\b\d+(?:\.\d+){1,4}\b", val)
                    if match:
                        return match.group(0), {"software_term": next(t for t in terms if t in searchable), "version": match.group(0), key: val}

            # Some native feeds expose only _raw or a filename.  Still require
            # the product term before accepting a version-shaped token.
            match = re.search(r"(?<![A-Za-z0-9])v?(\d+(?:\.\d+){1,4})(?![A-Za-z0-9])", searchable)
            if match:
                return match.group(1), {"software_term": next(t for t in terms if t in searchable), "version": match.group(1)}
            return None, {}

        preferred = ("image", "targetfilename", "target_filename", "file_path", "path", "commandline", "cmdline")
        for key in preferred:
            val = str(fields.get(key, "") or "").strip()
            if val and val not in ("-", "unknown", "none"):
                return val, {"software_term": next(t for t in terms if t in searchable), key: val}
        return None, {}

    def _admit_evidence(
        self,
        edge: GraphEdge,
        ledger: ObservationLedger,
        supplied_observations: list[Observation] | None = None,
        query_results: list[QueryResult] | dict[str, QueryResult] | None = None,
    ) -> tuple[list[Observation] | None, VerificationResult | None]:
        """Universal admission gate for all relation verification.

        Enforces:
        - Edge must have explicit citations.
        - All cited observations must exist in the ledger.
        - Supplied observations must be cited and in the ledger.
        - All candidate observations must be EpistemicType.OBSERVED (testimony rejected).
        - QueryResult completeness: observations from failed, incomplete, or truncated
          queries are rejected as proof.
        """
        if not edge.citations:
            return None, VerificationResult(
                verified=False,
                diagnostic="Verification failed: Edge requires explicit observation citations.",
                violations=["citations_required"],
            )

        ledger_obs_map: dict[str, Observation] = {o.id: o for o in ledger.observations}

        for cid in edge.citations:
            if cid not in ledger_obs_map:
                return None, VerificationResult(
                    verified=False,
                    diagnostic=f"Verification failed: Cited observation '{cid}' does not exist in ledger.",
                    violations=["cited_observation_not_in_ledger"],
                )

        if supplied_observations is not None:
            for so in supplied_observations:
                if so.id not in edge.citations:
                    return None, VerificationResult(
                        verified=False,
                        diagnostic=f"Verification failed: Supplied observation '{so.id}' is not cited on edge.",
                        violations=["supplied_observation_not_cited"],
                    )
                if so.id not in ledger_obs_map:
                    return None, VerificationResult(
                        verified=False,
                        diagnostic=f"Verification failed: Supplied observation '{so.id}' does not exist in ledger.",
                        violations=["supplied_observation_not_in_ledger"],
                    )

        candidate_obs = [ledger_obs_map[cid] for cid in edge.citations]

        for obs in candidate_obs:
            if getattr(obs, "epistemic_type", None) != EpistemicType.OBSERVED:
                return None, VerificationResult(
                    verified=False,
                    diagnostic=f"Verification failed: Observation '{obs.id}' epistemic type is not OBSERVED (found '{getattr(obs, 'epistemic_type', None)}').",
                    violations=["evidence_not_observed"],
                )

        qr_map: dict[str, QueryResult] = {}
        if query_results:
            if isinstance(query_results, dict):
                qr_map.update(query_results)
            elif isinstance(query_results, list):
                for qr in query_results:
                    if getattr(qr, "query_id", None):
                        qr_map[qr.query_id] = qr
        if hasattr(ledger, "query_results"):
            for qr in ledger.query_results:
                if getattr(qr, "query_id", None) and qr.query_id not in qr_map:
                    qr_map[qr.query_id] = qr

        for obs in candidate_obs:
            qid = getattr(obs, "query_id", None)
            if qid and qid in qr_map:
                qr = qr_map[qid]
                if not getattr(qr, "executed_ok", True):
                    return None, VerificationResult(
                        verified=False,
                        diagnostic=f"Verification failed: Originating query '{qid}' failed execution.",
                        violations=["query_result_failed"],
                    )
                if not getattr(qr, "complete", True):
                    return None, VerificationResult(
                        verified=False,
                        diagnostic=f"Verification failed: Originating query '{qid}' was incomplete or partial.",
                        violations=["incomplete_query_result"],
                    )
                if getattr(qr, "truncation_reason", None):
                    return None, VerificationResult(
                        verified=False,
                        diagnostic=f"Verification failed: Originating query '{qid}' was truncated: {qr.truncation_reason}.",
                        violations=["query_result_truncated"],
                    )

        return candidate_obs, None

    @classmethod
    def _verify_state_transition(
        cls,
        edge: GraphEdge,
        source_node: GraphNode,
        target_node: GraphNode,
        candidate_obs: list[Observation],
        operation: ProviderOperation | None = None,
    ) -> VerificationResult:
        """Generic ProviderOperation-driven state transition verifier.

        Enforces:
        - Cross-provider and cross-scope evidence rejection.
        - Minimum 2 observations (before and after states).
        - Valid timestamps and strict chronological ordering.
        - Correlation bound delta enforcement.
        - Operation artifact identity and action/state role proof.
        - Separation of ransomware causality from generic file transitions.
        """
        provider_ids = {obs.provider_scope.provider_id for obs in candidate_obs if obs.provider_scope}
        scope_ids = {obs.provider_scope.scope_id for obs in candidate_obs if obs.provider_scope}
        if len(provider_ids) > 1:
            return VerificationResult(
                verified=False,
                diagnostic="Verification failed: Cross-provider observations cannot prove a state transition.",
                violations=["cross_provider_evidence"],
            )
        if len(scope_ids) > 1:
            return VerificationResult(
                verified=False,
                diagnostic="Verification failed: Cross-scope observations cannot prove a state transition.",
                violations=["cross_scope_evidence"],
            )

        if len(candidate_obs) < 2:
            return VerificationResult(
                verified=False,
                diagnostic="Verification failed: State transition requires at least two chronological observations (before and after).",
                violations=["insufficient_transition_observations"],
            )

        parsed_timestamps: list[tuple[datetime, Observation]] = []
        for obs in candidate_obs:
            if not obs.timestamp:
                return VerificationResult(
                    verified=False,
                    diagnostic=f"Verification failed: Observation '{obs.id}' has missing timestamp.",
                    violations=["missing_timestamp"],
                )
            dt = _parse_timestamp(obs.timestamp)
            if dt is None:
                return VerificationResult(
                    verified=False,
                    diagnostic=f"Verification failed: Observation '{obs.id}' has invalid timestamp '{obs.timestamp}'.",
                    violations=["invalid_timestamp"],
                )
            parsed_timestamps.append((dt, obs))

        for i in range(len(parsed_timestamps) - 1):
            if parsed_timestamps[i][0] > parsed_timestamps[i + 1][0]:
                return VerificationResult(
                    verified=False,
                    diagnostic="Verification failed: Observations are in reversed temporal ordering.",
                    violations=["reversed_temporal_ordering"],
                )

        parsed_timestamps.sort(key=lambda x: x[0])
        t_before, obs_before = parsed_timestamps[0]
        t_after, obs_after = parsed_timestamps[-1]
        delta_s = (t_after - t_before).total_seconds()
        if delta_s < 0:
            return VerificationResult(
                verified=False,
                diagnostic="Verification failed: Reversed temporal ordering detected.",
                violations=["reversed_temporal_ordering"],
            )

        pred = edge.acceptance_predicate or {}
        max_delta = pred.get("max_time_delta_seconds")
        if max_delta is not None and delta_s > float(max_delta):
            return VerificationResult(
                verified=False,
                diagnostic=f"Verification failed: Transition delta {delta_s}s exceeds declared bound {max_delta}s.",
                violations=["temporal_bound_exceeded"],
            )

        if operation is None:
            return VerificationResult(
                verified=False,
                diagnostic="Verification failed: State transition verification requires an exact validated ProviderOperation.",
                violations=["operation_declaration_required"],
            )

        id_fields: list[str] = []
        if operation.artifact_identity_roles:
            for roles in operation.artifact_identity_roles.values():
                id_fields.extend(roles)
        if not id_fields:
            return VerificationResult(
                verified=False,
                diagnostic="Verification failed: ProviderOperation does not declare artifact_identity_roles.",
                violations=["missing_artifact_identity_role"],
            )

        fields_before = cls._contract_fields(obs_before)
        fields_after = cls._contract_fields(obs_after)

        id_val_before = next((fields_before[f.casefold()] for f in id_fields if f.casefold() in fields_before), None)
        id_val_after = next((fields_after[f.casefold()] for f in id_fields if f.casefold() in fields_after), None)

        if not id_val_before or not id_val_after:
            return VerificationResult(
                verified=False,
                diagnostic="Verification failed: Artifact identity field not observed in transition records.",
                violations=["missing_artifact_identity"],
            )
        if id_val_before.casefold() != id_val_after.casefold():
            return VerificationResult(
                verified=False,
                diagnostic=f"Verification failed: Artifact identity mismatch ('{id_val_before}' vs '{id_val_after}').",
                violations=["artifact_identity_mismatch"],
            )

        action_fields: list[str] = []
        if operation.action_roles:
            for roles in operation.action_roles.values():
                action_fields.extend(roles)
        state_fields: list[str] = []
        if operation.state_roles:
            for roles in operation.state_roles.values():
                state_fields.extend(roles)

        if not action_fields and not state_fields:
            return VerificationResult(
                verified=False,
                diagnostic="Verification failed: ProviderOperation does not declare action_roles or state_roles.",
                violations=["missing_action_or_state_role"],
            )

        state_before = next((fields_before[f.casefold()] for f in state_fields if f.casefold() in fields_before), None)
        state_after = next((fields_after[f.casefold()] for f in state_fields if f.casefold() in fields_after), None)
        if state_fields and state_before is not None and state_after is not None:
            if state_before.casefold() == state_after.casefold():
                return VerificationResult(
                    verified=False,
                    diagnostic=f"Verification failed: No state change observed between records (both '{state_before}').",
                    violations=["state_transition_not_observed"],
                )

        is_ransomware = (
            edge.relation_type in ("encrypted", "ransomware_encrypted")
            or pred.get("qualifier") == "ransomware"
            or edge.metadata.get("qualifier") == "ransomware"
        )
        if is_ransomware:
            has_ransomware_evidence = bool(
                pred.get("ransomware_indicators_verified")
                or pred.get("ransomware_evidence")
                or edge.metadata.get("ransomware_indicators_verified")
            )
            if not has_ransomware_evidence:
                return VerificationResult(
                    verified=False,
                    diagnostic="Verification failed: File modification observed, but ransomware causality requires independent qualifier evidence.",
                    violations=["ransomware_qualifier_unproven"],
                )

        citations = [obs.id for obs in candidate_obs]
        target_val = str(target_node.value if target_node.value and target_node.value != "?" else id_val_after)
        proof = RelationProof(
            id=f"proof-{edge.id}",
            edge_id=edge.id,
            source_node_id=source_node.id,
            source_value=source_node.value,
            target_node_id=target_node.id,
            target_value=target_val,
            relation_type=edge.relation_type if isinstance(edge.relation_type, str) else edge.relation_type.value,
            citations=citations,
            field_matches={
                "artifact_identity": id_val_after,
                "delta_seconds": str(delta_s),
                "state_before": str(state_before or ""),
                "state_after": str(state_after or ""),
            },
            verified_by="StateTransitionVerifier",
        )
        return VerificationResult(
            verified=True,
            proof=proof,
            target_value=target_val,
            diagnostic=f"State transition verified with {len(citations)} observation(s) across {delta_s}s.",
        )

    def verify_proof_contract(
        self,
        proof_contract: ProofContract,
        observations: list[Observation],
        ledger: ObservationLedger | None = None,
        expected_bindings: dict[str, str] | None = None,
    ) -> VerificationResult:
        """Evaluate ledger-backed cited observations against an approved ProofContract."""
        return verify_relation_proof_contract(
            proof_contract=proof_contract,
            observations=observations,
            ledger=ledger,
            expected_bindings=expected_bindings,
        )

    def verify_candidate_edge(
        self,
        edge: GraphEdge,
        source_node: GraphNode,
        target_node: GraphNode,
        ledger: ObservationLedger,
        observations: list[Observation] | None = None,
        query_results: list[QueryResult] | dict[str, QueryResult] | None = None,
        operation: ProviderOperation | None = None,
    ) -> VerificationResult:
        candidate_obs, admission_failure = self._admit_evidence(
            edge, ledger, observations, query_results
        )
        if admission_failure is not None:
            return admission_failure
        assert candidate_obs is not None

        if (
            edge.metadata.get("verification_mode") in ("state_transition", "transition")
            or (operation is not None and operation.proof_mode in ("state_transition", "transition"))
        ):
            return self._verify_state_transition(
                edge, source_node, target_node, candidate_obs, operation
            )

        if edge.metadata.get("verification_mode") == "claim_contract":
            return self._verify_claim_contract(
                edge,
                source_node,
                target_node,
                candidate_obs,
            )

        src_type = source_node.type if isinstance(source_node.type, str) else source_node.type.value
        tgt_type = target_node.type if isinstance(target_node.type, str) else target_node.type.value
        src_val = source_node.value.strip().lower()

        discovered_target_val: str | None = None
        matching_obs_ids: list[str] = []
        field_matches: dict[str, str] = {}
        diagnostic_violations: list[str] = []
        domain_candidates: list[tuple[int, str, str, str]] = []

        for obs in candidate_obs:
            raw_ev = getattr(obs, "raw_event", {}) or obs.fields.get("raw_event", {})
            combined_fields = {}
            if isinstance(raw_ev, dict):
                for k, v in raw_ev.items():
                    if isinstance(v, list) and v:
                        combined_fields[k.lower()] = str(v[0])
                    elif not isinstance(v, dict) and v is not None:
                        combined_fields[k.lower()] = str(v)
            for k, v in obs.fields.items():
                if isinstance(v, list) and v:
                    combined_fields[k.lower()] = str(v[0])
                elif not isinstance(v, dict) and v is not None:
                    combined_fields[k.lower()] = str(v)
            fields = combined_fields

            if tgt_type in ("endpoint", "host"):
                if observation_declares_server_role(fields):
                    diagnostic_violations.append("Telemetry explicitly declares a server-like role; it cannot prove a user endpoint binding.")
                    continue
            if tgt_type == "ip":
                has_client_ip = any(k.lower() in self.CLIENT_IP_FIELDS for k in fields)
                has_server_ip = any(k.lower() in self.SERVER_IP_FIELDS for k in fields)
                if has_server_ip and not has_client_ip:
                    diagnostic_violations.append("Found server/destination IP, but target requires client IP.")
                    continue

            # 0. Person -> Account verification
            if src_type == "person" and tgt_type == "account":
                first_name = src_val.split()[0].lower() if src_val else ""
                last_name = src_val.split()[-1].lower() if src_val and len(src_val.split()) > 1 else ""
                matched_user = None
                for uf in (*self.USER_FIELDS, "sender", "receiver", "sender_email", "receiver_email", "displayName"):
                    val = str(fields.get(uf, "")).lower()
                    if val and (src_val.lower() in val or (first_name and first_name in val) or (last_name and last_name in val)):
                        raw_match = fields.get(uf)
                        m = re.search(r'[\w\.-]+@[\w\.-]+', str(raw_match))
                        if m:
                            matched_user = m.group(0).split('@')[0].lower()
                        elif uf in self.USER_FIELDS:
                            matched_user = str(raw_match)
                        break
                if not matched_user and first_name:
                    h_val = str(fields.get("host", "")).lower()
                    if "wrk-" in h_val and (first_name in h_val or (last_name and last_name in h_val)):
                        matched_user = h_val.split("wrk-")[-1].split(".")[0]

                if matched_user:
                    discovered_target_val = matched_user
                    matching_obs_ids.append(obs.id)
                    field_matches["person"] = source_node.value
                    field_matches["account"] = matched_user
                    break

            # 0.1 Account -> Email Address verification
            elif (src_type == "account" and tgt_type == "email_address") or edge.relation_type in ("has_email", RelationType.HAS_EMAIL):
                matched_email = None
                user_tokens = [t for t in re.split(r'[\._\s]+', src_val.lower()) if len(t) > 1]
                user_prefix = src_val.split('@')[0].split('.')[0].lower() if '.' in src_val else src_val.lower()

                # Try structured sender and receiver pairs first
                for disp_k, mail_k in [("sender", "sender_email"), ("receiver", "receiver_email")]:
                    disp_v = str(fields.get(disp_k) or "").strip()
                    mail_v = str(fields.get(mail_k) or "").strip()
                    d_name, parsed = parseaddr(disp_v)
                    eff_email = parsed or mail_v
                    eff_name = d_name or disp_v
                    if eff_email and "@" in eff_email:
                        if src_val.lower() in eff_email.lower() or user_prefix in eff_email.lower():
                            matched_email = eff_email.lower()
                            break
                        if eff_name and user_tokens and all(tok in eff_name.lower() for tok in user_tokens):
                            matched_email = eff_email.lower()
                            break

                # Fallback to scanning individual fields
                if not matched_email:
                    for obs_field in ("sender_email", "sender", "receiver_email", "receiver", "mail", "userPrincipalName", "user"):
                        val = str(fields.get(obs_field, "") or "")
                        if val:
                            d_name, email_parsed = parseaddr(val)
                            if email_parsed and "@" in email_parsed:
                                if src_val.lower() in email_parsed.lower() or user_prefix in email_parsed.lower():
                                    matched_email = email_parsed.lower()
                                    break
                                if d_name and user_tokens and all(tok in d_name.lower() for tok in user_tokens):
                                    matched_email = email_parsed.lower()
                                    break
                            m = re.search(r'[\w\.-]+@[\w\.-]+', val)
                            if m and (src_val.lower() in m.group(0).lower() or user_prefix in m.group(0).lower()):
                                matched_email = m.group(0).lower()
                                break

                if matched_email:
                    discovered_target_val = matched_email
                    matching_obs_ids.append(obs.id)
                    field_matches["account"] = source_node.value
                    field_matches["email"] = matched_email
                    break

            # 0.2 Email -> Outbound Message verification
            elif (src_type == "email_address" and tgt_type == "message") or edge.relation_type in ("sent_message", RelationType.SENT_MESSAGE):
                matched_obs = None
                pred = edge.acceptance_predicate or {}
                external_only = bool(pred.get("recipient_external") or pred.get("external"))

                # Sort candidate observations chronologically to inspect initial messages
                sorted_candidates = sorted(
                    candidate_obs,
                    key=lambda o: str(o.timestamp or o.fields.get("timestamp") or o.fields.get("_time") or "")
                )
                has_any_msg_id = any(bool(o.fields.get("msg_id") or o.fields.get("message_id")) for o in sorted_candidates)
                for obs_item in sorted_candidates:
                    raw_f = obs_item.fields
                    msg_id_val = raw_f.get("msg_id") or raw_f.get("message_id")
                    if has_any_msg_id and not msg_id_val:
                        # Skip telemetry that lacks a message identifier when actual message events are present
                        continue

                    s_raw = str(raw_f.get("sender_email", "") or raw_f.get("sender", "")).strip().lower()
                    _, s_email = parseaddr(s_raw)
                    if not s_email:
                        m = re.search(r'[\w\.-]+@[\w\.-]+', s_raw)
                        s_email = m.group(0).lower() if m else s_raw

                    if not src_val or (s_email and src_val.lower() in s_email) or (s_email and s_email in src_val.lower()):
                        if external_only:
                            r_raw = str(raw_f.get("receiver_email", "") or raw_f.get("receiver", "")).strip().lower()
                            _, r_email = parseaddr(r_raw)
                            if not r_email:
                                m = re.search(r'[\w\.-]+@[\w\.-]+', r_raw)
                                r_email = m.group(0).lower() if m else ""
                            s_dom = s_email.split("@")[-1] if "@" in s_email else ""
                            r_dom = r_email.split("@")[-1] if "@" in r_email else ""
                            if not r_dom or (s_dom and r_dom == s_dom):
                                continue

                        matched_obs = obs_item
                        break

                if matched_obs:
                    msg_id = matched_obs.fields.get("msg_id") or matched_obs.fields.get("message_id") or f"msg-{matched_obs.id}"
                    discovered_target_val = str(msg_id)
                    matching_obs_ids.append(matched_obs.id)
                    field_matches["sender"] = str(matched_obs.fields.get("sender") or matched_obs.fields.get("sender_email"))
                    field_matches["message_id"] = str(msg_id)
                    if matched_obs.fields.get("subject"):
                        field_matches["subject"] = str(matched_obs.fields.get("subject"))
                    break

            # 0.3 Message -> Recipient Identity verification
            elif (src_type == "message" and tgt_type in ("email_address", "person")) or edge.relation_type in ("received_message", RelationType.RECEIVED_MESSAGE):
                matched_obs = None
                for obs_item in candidate_obs:
                    m_id = str(obs_item.fields.get("msg_id") or obs_item.fields.get("message_id") or f"msg-{obs_item.id}").lower().strip()
                    if src_val and (src_val.lower() == m_id or src_val.lower() in m_id or m_id in src_val.lower()):
                        matched_obs = obs_item
                        break

                if not matched_obs and candidate_obs:
                    for obs_item in candidate_obs:
                        r_f = str(obs_item.fields.get("receiver_email") or obs_item.fields.get("receiver") or "")
                        if "@" in r_f:
                            matched_obs = obs_item
                            break

                if matched_obs:
                    re_val = matched_obs.fields.get("receiver_email") or matched_obs.fields.get("receiver")
                    if isinstance(re_val, list):
                        re_val = re_val[0]
                    re_str = str(re_val or "").strip()
                    parsed_name, parsed_email = parseaddr(re_str)
                    if not parsed_email:
                        m = re.search(r'[\w\.-]+@[\w\.-]+', re_str)
                        parsed_email = m.group(0) if m else re_str

                    if not parsed_name and matched_obs.fields.get("receiver"):
                        rec_sec = str(matched_obs.fields.get("receiver") or "").strip()
                        sec_name, _ = parseaddr(rec_sec)
                        if sec_name:
                            parsed_name = sec_name

                    discovered_target_val = parsed_email.strip()
                    matching_obs_ids.append(matched_obs.id)
                    field_matches["recipient_email"] = parsed_email.strip()
                    clean_name = parsed_name.strip().strip("'\"") if parsed_name else ""
                    if clean_name and "@" not in clean_name and clean_name.lower() != parsed_email.lower():
                        field_matches["recipient_name"] = clean_name
                    if matched_obs.fields.get("subject"):
                        field_matches["subject"] = str(matched_obs.fields.get("subject"))
                    break

            # 0.4 Recipient -> Role verification
            elif tgt_type == "role" or edge.relation_type in ("holds_role", RelationType.HOLDS_ROLE):
                title_val = fields.get("title") or fields.get("role") or fields.get("department") or fields.get("job_title")
                if title_val:
                    if target_node.value and target_node.value != "?":
                        if target_node.value.lower() in str(title_val).lower():
                            discovered_target_val = str(title_val)
                            matching_obs_ids.append(obs.id)
                            field_matches["role"] = str(title_val)
                            break
                    else:
                        discovered_target_val = str(title_val)
                        matching_obs_ids.append(obs.id)
                        field_matches["role"] = str(title_val)
                        break
                else:
                    diagnostic_violations.append(f"Recipient executive role for '{src_val}' cannot be verified from message telemetry alone without directory/LDAP evidence.")

            # Artifact requirements are anchored to the resolved endpoint.  Do
            # not route them through IP/web telemetry and do not accept an
            # arbitrary row merely because it contains a version-looking value.
            elif src_type in ("endpoint", "host") and tgt_type == "event":
                terms = [str(t).strip().lower() for t in (edge.acceptance_predicate or {}).get("software_terms", []) if str(t).strip()]
                searchable = " ".join(str(v).lower() for v in fields.values())
                if terms and any(term in searchable for term in terms):
                    for domain_key in self.DOMAIN_FIELDS:
                        value = str(fields.get(domain_key, "") or "").strip()
                        if value and value not in ("-", "unknown"):
                            discovered_target_val = value
                            matching_obs_ids.append(obs.id)
                            field_matches["endpoint"] = source_node.value
                            field_matches["web_field"] = domain_key
                            field_matches["web_value"] = value
                            break
                    if discovered_target_val:
                        break

            # Artifact requirements are anchored to the resolved endpoint.  Do
            # not route them through IP/web telemetry and do not accept an
            # arbitrary row merely because it contains a version-looking value.
            elif src_type in ("endpoint", "host") and tgt_type in (
                "software", "software_version", "application", "version",
                "file", "file_artifact", "process", "process_name",
            ):
                artifact_value, artifact_matches = self._artifact_value(fields, edge, tgt_type)
                if artifact_value:
                    discovered_target_val = artifact_value
                    matching_obs_ids.append(obs.id)
                    field_matches.update(artifact_matches)
                    field_matches["endpoint"] = source_node.value
                    break

            # A. Person/Account -> Endpoint logon verification
            elif src_type in ("person", "account") and tgt_type in ("endpoint", "host"):
                # Check user field
                first_name = src_val.split()[0] if src_val else src_val
                matched_user = None
                for uf in self.USER_FIELDS:
                    val = fields.get(uf, "").lower()
                    if src_val in val or (first_name and first_name in val):
                        matched_user = fields.get(uf)
                        break

                if matched_user:
                    # Extract endpoint host, prioritizing specific workstation name
                    candidate_host = None
                    ws_val = fields.get("workstationname") or fields.get("workstation_name")
                    if ws_val and not observation_declares_server_role(fields) and ws_val.lower() not in ("source", "-", "unknown", ""):
                        candidate_host = ws_val
                    elif fields.get("host", "").lower().startswith("wrk") or fields.get("computername", "").lower().startswith("wrk"):
                        candidate_host = fields.get("host") or fields.get("computername")
                    else:
                        for hf in ("workstationname", "workstation_name", "host", "computername", "target_host"):
                            hval = fields.get(hf)
                            if hval and not observation_declares_server_role(fields) and hval.lower() not in ("source", "-", "unknown", ""):
                                candidate_host = hval
                                break
                    if candidate_host and not observation_declares_server_role(fields):
                        discovered_target_val = candidate_host
                        matching_obs_ids.append(obs.id)
                        field_matches["user"] = matched_user
                        field_matches["host"] = candidate_host
                        break

            # B. Endpoint -> Client IP verification
            elif src_type in ("endpoint", "host") and tgt_type == "ip":
                matched_host = None
                candidate_host_fields = list(self.HOST_FIELDS) + ["targetusername", "user", "account_name"]
                for hf in candidate_host_fields:
                    val = str(fields.get(hf, "")).lower()
                    if src_val in val:
                        matched_host = fields.get(hf)
                        break

                if matched_host or not src_val:
                    for cf in self.CLIENT_IP_FIELDS:
                        ip_val = fields.get(cf)
                        if ip_val and str(ip_val) not in ("127.0.0.1", "0.0.0.0", "-"):
                            discovered_target_val = str(ip_val)
                            matching_obs_ids.append(obs.id)
                            field_matches["host"] = str(matched_host or src_val)
                            field_matches["client_ip"] = str(ip_val)
                            break
                    if discovered_target_val:
                        break

            # C. Client IP -> Web / Domain verification
            elif src_type == "ip" and (
                tgt_type in ("domain", "event", "software", "url", "uri", "site", "website", "fqdn", "fully_qualified_domain_name")
                or "domain" in tgt_type
                or "web" in tgt_type
                or "site" in tgt_type
                or "url" in tgt_type
            ):
                matched_ip = None
                for cf in self.CLIENT_IP_FIELDS:
                    ip_val = str(fields.get(cf, "")).lower()
                    if src_val in ip_val:
                        matched_ip = fields.get(cf)
                        break

                if matched_ip or not src_val:
                    for df in self.DOMAIN_FIELDS:
                        dval = fields.get(df)
                        if dval and str(dval).strip() not in ("-", ""):
                            dval_clean = str(dval).lower().strip()
                            if target_node.value and target_node.value != "?" and target_node.value.lower() in dval_clean:
                                priority = 0
                            else:
                                priority = 1
                            domain_candidates.append((priority, str(dval).strip(), obs.id, str(matched_ip or src_val)))

        if domain_candidates and not discovered_target_val:
            domain_candidates.sort(key=lambda c: c[0])
            top_prio, top_dval, top_obs_id, top_ip = domain_candidates[0]
            discovered_target_val = top_dval
            matching_obs_ids = [c[2] for c in domain_candidates if c[1] == top_dval]
            field_matches["client_ip"] = top_ip
            field_matches["domain"] = top_dval

        if not discovered_target_val:
            diag_v = list(set(diagnostic_violations)) if diagnostic_violations else ["Predicate match failure."]
            return VerificationResult(
                verified=False,
                diagnostic=f"Verification rejected by epistemic rules: {'; '.join(diag_v)}",
                violations=diag_v,
            )

        # 5. Success: mint RelationProof
        proof = RelationProof(
            id=f"proof-{edge.id}",
            edge_id=edge.id,
            source_node_id=source_node.id,
            source_value=source_node.value,
            target_node_id=target_node.id,
            target_value=discovered_target_val,
            relation_type=edge.relation_type if isinstance(edge.relation_type, str) else edge.relation_type.value,
            citations=list(set(matching_obs_ids)),
            field_matches=field_matches,
        )

        return VerificationResult(
            verified=True,
            proof=proof,
            target_value=discovered_target_val,
            diagnostic=f"Verified relation {source_node.value} -> {discovered_target_val} with {len(proof.citations)} observation(s).",
        )

    def apply_verification_to_graph(
        self,
        result: VerificationResult,
        edge: GraphEdge,
        target_node: GraphNode,
        graph: InvestigationGraph,
    ) -> None:
        """Apply a successful verification to update the InvestigationGraph."""
        if not result.verified or not result.proof:
            return

        edge.status = RelationStatus.VERIFIED
        edge.citations = list(set(edge.citations + result.proof.citations))
        graph.proofs[result.proof.id] = result.proof

        if result.target_value:
            target_node.value = result.target_value
        target_node.status = NodeStatus.KNOWN
