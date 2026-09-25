"""Canonical security ontology definitions.

Provides provider-neutral relation vocabulary, directional inversion,
and role synonym compatibility mapping.
"""
from __future__ import annotations

from dataclasses import dataclass

CANONICAL_ROLE_SYNONYMS: dict[str, set[str]] = {
    "endpoint": {
        "endpoint", "host", "device", "workstation", "computer",
        "client", "server", "endpoint_host", "target_host",
        "endpoint_identity",
    },
    "process": {
        "process", "process_name", "command_execution", "command",
        "image", "cmdline", "commandline",
    },
    "file": {
        "file", "artifact", "document", "file_artifact",
        "source_artifact", "target_artifact", "file_path",
        "file_name", "filename",
    },
    "account": {
        "account", "user", "username", "account_identity",
        "subject_identity", "account_name", "targetusername",
    },
    "person": {
        "person", "user", "username", "employee", "person_name",
        "subject_identity",
    },
    "domain": {
        "domain", "site", "url", "fqdn", "web_domain", "domain_name",
    },
    "ip": {
        "ip", "ip_address", "destination_ip", "source_ip",
        "client_ip", "server_ip", "host_addr",
    },
    "email_address": {
        "email_address", "email", "mail", "sender", "receiver",
        "recipient", "sender_email", "recipient_email",
    },
    "version": {
        "version", "software_version", "productversion", "fileversion",
        "product_version", "file_version",
    },
}


def canonicalize_role(role: str) -> str:
    """Return the canonical role name for a given role or synonym."""
    r = str(role or "").strip().casefold()
    for canonical, synonyms in CANONICAL_ROLE_SYNONYMS.items():
        if r == canonical or r in synonyms:
            return canonical
    return r


def roles_are_compatible(role1: str, role2: str) -> bool:
    """Check whether two role names represent the same semantic entity role."""
    r1 = str(role1 or "").strip().casefold()
    r2 = str(role2 or "").strip().casefold()
    if not r1 or not r2:
        return False
    if r1 == r2:
        return True
    return canonicalize_role(r1) == canonicalize_role(r2)


def types_are_compatible(left: str, right: str) -> bool:
    """Return whether two entity or slot labels denote compatible types.

    Empty labels are not compatible.  Callers that skip a gate when an
    operation omits kinds must do so explicitly; empty kinds are not
    type-compatible and do not make an operation EXECUTABLE.  ``any`` matches
    a declared type.  Remaining comparisons use the role ontology only —
    there is no token intersection and no scenario aliasing.
    """
    left_norm = str(left or "").strip().casefold()
    right_norm = str(right or "").strip().casefold()
    if not left_norm or not right_norm:
        return False
    if left_norm == "any" or right_norm == "any":
        return True
    return roles_are_compatible(left_norm, right_norm)


PRIMARY_ENTITY_KINDS: frozenset[str] = frozenset({
    "endpoint", "process", "file", "account", "person", "domain", "ip", "email_address",
})
FILE_IDENTITY_ANSWER_TYPES: frozenset[str] = frozenset({
    "file_name", "filename", "hash", "sha256", "md5", "attachment_name",
})
UNCONSTRAINED_RELATION_ROLES: frozenset[str] = frozenset({"", "entity", "value", "any"})


def native_field_compatible_with_kind(field_name: str, kind: str) -> bool:
    """Return whether a native field may fill a typed entity port.

    Known entity kinds that do not match the port are rejected.  Native names
    that are not in the role vocabulary stay on the declared port so provider
    field aliases are not required in the kernel.
    """
    field_canon = canonicalize_role(field_name)
    kind_canon = canonicalize_role(kind)
    if not field_canon or not kind_canon:
        return False
    if types_are_compatible(field_canon, kind_canon):
        return True
    if field_canon in PRIMARY_ENTITY_KINDS or field_canon in CANONICAL_ROLE_SYNONYMS:
        return False
    return True


def infer_object_port_kinds(
    *,
    output_binding_entity_kinds: dict[str, str] | None = None,
    output_entity_kinds: tuple[str, ...] = (),
) -> dict[str, str]:
    """Declare the object port kind from a unique typed output kind.

    Column names are not a type declaration and must not invent a port kind.
    """
    existing = {
        str(key).strip(): str(value).strip()
        for key, value in dict(output_binding_entity_kinds or {}).items()
        if str(key).strip() and str(value).strip()
    }
    if existing:
        return existing
    unique_kinds = tuple(dict.fromkeys(
        str(kind).strip()
        for kind in output_entity_kinds
        if str(kind).strip() and str(kind).strip().casefold() != "any"
    ))
    if len(unique_kinds) == 1:
        return {"object": unique_kinds[0]}
    return {}


@dataclass(frozen=True)
class CanonicalRelationDef:
    """Specification of a canonical graph relation and its directional properties."""

    name: str
    inverse_name: str | None = None
    subject_entity_role: str = "endpoint"
    object_value_role: str = "entity"
    proof_contract_id: str | None = None
    description: str = ""


CANONICAL_RELATIONS: dict[str, CanonicalRelationDef] = {
    "executed_process": CanonicalRelationDef(
        name="executed_process",
        inverse_name="executed_on",
        subject_entity_role="endpoint",
        object_value_role="process",
        proof_contract_id="proof-process-spawn-v1",
        description="Endpoint executed a process binary or script.",
    ),
    "spawned": CanonicalRelationDef(
        name="spawned",
        inverse_name="executed_on",
        subject_entity_role="endpoint",
        object_value_role="process",
        proof_contract_id="proof-process-spawned-v1",
        description="Endpoint spawned a process.",
    ),
    "executed": CanonicalRelationDef(
        name="executed",
        inverse_name="executed_on",
        subject_entity_role="endpoint",
        object_value_role="process",
        proof_contract_id="proof-process-executed-v1",
        description="Endpoint executed a process.",
    ),
    "executed_on": CanonicalRelationDef(
        name="executed_on",
        inverse_name="executed",
        subject_entity_role="process",
        object_value_role="endpoint",
        proof_contract_id="proof-process-executed-on-v1",
        description="Process or command executed on an endpoint host.",
    ),
    "visited": CanonicalRelationDef(
        name="visited",
        inverse_name="visited_by",
        subject_entity_role="endpoint",
        object_value_role="domain",
        proof_contract_id="proof-web-visit-v1",
        description="Endpoint initiated HTTP/S connection to a domain.",
    ),
    "visited_by": CanonicalRelationDef(
        name="visited_by",
        inverse_name="visited",
        subject_entity_role="domain",
        object_value_role="endpoint",
        proof_contract_id="proof-web-visit-v1",
        description="Domain visited by an endpoint.",
    ),
    "wrote": CanonicalRelationDef(
        name="wrote",
        inverse_name="written_by",
        subject_entity_role="endpoint",
        object_value_role="file",
        proof_contract_id="proof-file-wrote-v1",
        description="Endpoint or process wrote a file.",
    ),
    "written_by": CanonicalRelationDef(
        name="written_by",
        inverse_name="wrote",
        subject_entity_role="file",
        object_value_role="endpoint",
        proof_contract_id="proof-file-wrote-v1",
        description="File written by an endpoint or process.",
    ),
    "modified": CanonicalRelationDef(
        name="modified",
        inverse_name="modified_by",
        subject_entity_role="endpoint",
        object_value_role="file",
        proof_contract_id="proof-file-modified-v1",
        description="Endpoint or process modified a file.",
    ),
    "modified_by": CanonicalRelationDef(
        name="modified_by",
        inverse_name="modified",
        subject_entity_role="file",
        object_value_role="endpoint",
        proof_contract_id="proof-file-modified-v1",
        description="File modified by an endpoint or process.",
    ),
    "connected_to": CanonicalRelationDef(
        name="connected_to",
        inverse_name="connected_from",
        subject_entity_role="endpoint",
        object_value_role="ip",
        proof_contract_id="proof-network-connected-v1",
        description="Endpoint connected to an IP address.",
    ),
    "connected_from": CanonicalRelationDef(
        name="connected_from",
        inverse_name="connected_to",
        subject_entity_role="ip",
        object_value_role="endpoint",
        proof_contract_id="proof-network-connected-v1",
        description="Network connection originated from an endpoint.",
    ),
    "associated_with": CanonicalRelationDef(
        name="associated_with",
        inverse_name="associated_with",
        subject_entity_role="person",
        object_value_role="endpoint",
        proof_contract_id="proof-person-endpoint-v1",
        description="Person or entity associated with an endpoint.",
    ),
    "logged_on_to": CanonicalRelationDef(
        name="logged_on_to",
        inverse_name="authenticated_user",
        subject_entity_role="account",
        object_value_role="endpoint",
        proof_contract_id="proof-account-logon-v1",
        description="Account logged on to an endpoint.",
    ),
    "owns": CanonicalRelationDef(
        name="owns",
        inverse_name="owned_by",
        subject_entity_role="person",
        object_value_role="endpoint",
        proof_contract_id="proof-person-endpoint-v1",
        description="Person or entity owns or is assigned an asset.",
    ),
    "assigned_ip": CanonicalRelationDef(
        name="assigned_ip",
        inverse_name="assigned_to",
        subject_entity_role="endpoint",
        object_value_role="ip",
        proof_contract_id="proof-network-connected-v1",
        description="Endpoint assigned an IP address.",
    ),
    "originated_from": CanonicalRelationDef(
        name="originated_from",
        inverse_name="originated",
        subject_entity_role="endpoint",
        object_value_role="ip",
        proof_contract_id="proof-network-connected-v1",
        description="Activity originated from an endpoint or IP address.",
    ),
    "requested": CanonicalRelationDef(
        name="requested",
        inverse_name="requested_by",
        subject_entity_role="endpoint",
        object_value_role="domain",
        proof_contract_id="proof-web-visit-v1",
        description="Endpoint requested a web resource or domain.",
    ),
    "resolved_to": CanonicalRelationDef(
        name="resolved_to",
        inverse_name="resolved_from",
        subject_entity_role="domain",
        object_value_role="ip",
        description="Domain resolved to an IP address.",
    ),
    "resolved": CanonicalRelationDef(
        name="resolved",
        inverse_name="resolved_by",
        subject_entity_role="endpoint",
        object_value_role="domain",
        description="Endpoint resolved a DNS domain name.",
    ),
    "accessed": CanonicalRelationDef(
        name="accessed",
        inverse_name="accessed_by",
        subject_entity_role="endpoint",
        object_value_role="file",
        proof_contract_id="proof-file-modified-v1",
        description="Endpoint or user accessed a file or resource.",
    ),
    "communicated_with": CanonicalRelationDef(
        name="communicated_with",
        inverse_name="communicated_with",
        subject_entity_role="endpoint",
        object_value_role="ip",
        proof_contract_id="proof-network-connected-v1",
        description="Endpoint communicated with remote IP address.",
    ),
    "has_email": CanonicalRelationDef(
        name="has_email",
        inverse_name="email_of",
        subject_entity_role="person",
        object_value_role="email_address",
        description="Person has email address.",
    ),
    "sent_email": CanonicalRelationDef(
        name="sent_email",
        inverse_name="received_email",
        subject_entity_role="person",
        object_value_role="email_address",
        proof_contract_id="proof-email-sent-v1",
        description="Person sent an outbound email message.",
    ),
    "sent_message": CanonicalRelationDef(
        name="sent_message",
        inverse_name="received_message",
        subject_entity_role="person",
        object_value_role="email_address",
        proof_contract_id="proof-email-sent-v1",
        description="Person sent a message.",
    ),
    "received_message": CanonicalRelationDef(
        name="received_message",
        inverse_name="sent_message",
        subject_entity_role="email_address",
        object_value_role="person",
        proof_contract_id="proof-email-sent-v1",
        description="Person or address received a message.",
    ),
    "holds_role": CanonicalRelationDef(
        name="holds_role",
        inverse_name="held_by",
        subject_entity_role="person",
        object_value_role="role",
        description="Person holds an organizational role or title.",
    ),
    "belongs_to_org": CanonicalRelationDef(
        name="belongs_to_org",
        inverse_name="has_member",
        subject_entity_role="person",
        object_value_role="organization",
        description="Person belongs to an organization.",
    ),
    "has_attribute": CanonicalRelationDef(
        name="has_attribute",
        inverse_name="attribute_of",
        subject_entity_role="entity",
        object_value_role="value",
        description="Entity has attribute property.",
    ),
    "created": CanonicalRelationDef(
        name="created",
        inverse_name="created_by",
        subject_entity_role="endpoint",
        object_value_role="file",
        proof_contract_id="proof-file-wrote-v1",
        description="Endpoint or process created a file.",
    ),
    "downloaded": CanonicalRelationDef(
        name="downloaded",
        inverse_name="downloaded_by",
        subject_entity_role="endpoint",
        object_value_role="file",
        proof_contract_id="proof-file-wrote-v1",
        description="Endpoint downloaded an artifact or file.",
    ),
    "located_at": CanonicalRelationDef(
        name="located_at",
        inverse_name="location_of",
        subject_entity_role="file",
        object_value_role="endpoint",
        description="File or artifact is located at a path or endpoint.",
    ),
    "stored_on": CanonicalRelationDef(
        name="stored_on",
        inverse_name="stores",
        subject_entity_role="file",
        object_value_role="endpoint",
        description="File is stored on an endpoint.",
    ),
    "installed_on": CanonicalRelationDef(
        name="installed_on",
        inverse_name="has_installed",
        subject_entity_role="artifact",
        object_value_role="endpoint",
        proof_contract_id="proof-software-install-v1",
        description="Software package or binary artifact installed on an endpoint.",
    ),
    "observed_transition": CanonicalRelationDef(
        name="observed_transition",
        inverse_name="observed_transition",
        subject_entity_role="source_artifact",
        object_value_role="target_artifact",
        proof_contract_id="proof-transition-v1",
        description="Artifact transitioned state (e.g. encrypted, renamed) across paired events.",
    ),
}

CANONICAL_RELATION_VOCABULARY: frozenset[str] = frozenset(CANONICAL_RELATIONS.keys())

CANONICAL_RELATION_ALIASES: dict[str, str] = {
    # Message / Email
    "sent_message": "sent_email",
    "sent_mail": "sent_email",
    "received_message": "received_email",
    "received_mail": "received_email",
    # Person / Asset ownership
    "owns": "associated_with",
    "owned_by": "associated_with",
    "assigned_to": "associated_with",
    "belongs_to": "associated_with",
    "user_endpoint": "associated_with",
    # File modification
    "created": "modified",
    "wrote": "modified",
    "changed": "modified",
    "file_modification": "modified",
    "file_created": "modified",
    "file_written": "modified",
    "file_change": "modified",
    # Web navigation
    "browsed": "visited",
    "navigated_to": "visited",
    "web_activity": "visited",
    "web_request": "visited",
    # Process execution
    "started": "spawned",
    "launched": "spawned",
    "process_execution": "spawned",
    "process_lineage": "spawned",
    # Version / Containment
    "has_version": "contains",
    "runs": "contains",
    "running": "contains",
    "installed": "contains",
    # DNS resolution
    "queried": "resolved",
    "dns_query": "resolved",
    "looked_up": "resolved",
}


def canonicalize_relation(relation: str) -> str:
    """Return the canonical relation name for a given relation or alias."""
    r = str(relation or "").strip().casefold()
    if r in CANONICAL_RELATION_ALIASES:
        return CANONICAL_RELATION_ALIASES[r]
    if r in CANONICAL_RELATIONS:
        return r
    return r


def get_canonical_relation(name: str) -> CanonicalRelationDef | None:
    """Retrieve canonical relation metadata by relation name."""
    norm = canonicalize_relation(name)
    return CANONICAL_RELATIONS.get(norm)


def get_inverse_relation(name: str) -> str | None:
    """Retrieve the inverse relation name for a given relation name."""
    rel = get_canonical_relation(name)
    return rel.inverse_name if rel else None


def proof_contract_id_for_relation(name: str) -> str | None:
    """Return the proof-contract identity declared by a semantic relation.

    Directional aliases may intentionally share one evidence contract.  This
    lookup keeps that equivalence explicit at the ontology boundary instead of
    making the proof engine compare unrelated relation strings heuristically.
    """
    rel = get_canonical_relation(name)
    return rel.proof_contract_id if rel else None


__all__ = [
    "CANONICAL_RELATIONS",
    "CANONICAL_RELATION_ALIASES",
    "CANONICAL_RELATION_VOCABULARY",
    "CANONICAL_ROLE_SYNONYMS",
    "PRIMARY_ENTITY_KINDS",
    "UNCONSTRAINED_RELATION_ROLES",
    "CanonicalRelationDef",
    "canonicalize_relation",
    "canonicalize_role",
    "get_canonical_relation",
    "get_inverse_relation",
    "infer_object_port_kinds",
    "native_field_compatible_with_kind",
    "proof_contract_id_for_relation",
    "roles_are_compatible",
    "types_are_compatible",
]
