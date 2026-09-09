"""Tests for Phase 1 contracts: Claim, ClaimGraph, AcceptanceRule, RefutationRule.

These tests enforce the invariants specified in 01_FINAL-ARCHITECTURE.md §3.2
and 04-IMPLEMENTATION-CHECKLIST.md Phase 1.

Required test cases (per user specification):
1. test_valid_claim_graph               — ClaimGraph hop valide
2. test_missing_acceptance_rule_rejected — ClaimGraph thieu acceptance rule bi tu choi
3. test_raw_spl_rejected                — Claim co raw SPL bi tu choi
4. test_claim_not_from_request_rejected  — Claim khong xuat phat tu request bi tu choi
5. test_counterfactual_email_no_email_class — email -> Claim thuong, khong phai EmailClaim
6. test_counterfactual_tor_no_tor_class  — Tor -> Claim thuong, khong phai TorClaim
"""
from __future__ import annotations

import pytest

from hunting.contracts.claim import (
    AcceptanceRule,
    Claim,
    ClaimGraph,
    ClaimStatus,
    RefutationCondition,
    RefutationRule,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_claim(
    id: str = "claim-1",
    claim_type: str = "attribute",
    subject: str = "user:amber.turing",
    predicate: str = "has_version",
    provenance: str = "request",
    source_request_id: str = "req-001",
    object_or_value: str | None = "Tor Browser",
    value_type: str | None = "software_version",
    acceptance_rule: AcceptanceRule | None = None,
    **kwargs,
) -> Claim:
    if acceptance_rule is None:
        acceptance_rule = AcceptanceRule(min_observations=1)
    return Claim(
        id=id,
        claim_type=claim_type,
        subject=subject,
        predicate=predicate,
        provenance=provenance,
        source_request_id=source_request_id,
        object_or_value=object_or_value,
        value_type=value_type,
        acceptance_rule=acceptance_rule,
        **kwargs,
    )


def _make_graph(claims: list[Claim] | None = None) -> ClaimGraph:
    if claims is None:
        claims = [_make_claim()]
    return ClaimGraph(
        id="graph-001",
        request_id="req-001",
        objective="Determine if amber.turing installed Tor Browser and its version",
        claims=claims,
    )


# ---------------------------------------------------------------------------
# Test 1: Valid ClaimGraph
# ---------------------------------------------------------------------------


def test_valid_claim_graph() -> None:
    """A well-formed ClaimGraph with all required fields must be accepted."""
    claim_presence = _make_claim(
        id="claim-presence",
        predicate="installed_software",
        value_type="software_version",
        reason="Request asks whether Tor Browser was installed",
    )
    claim_version = _make_claim(
        id="claim-version",
        predicate="has_version",
        value_type="software_version",
        dependencies=("claim-presence",),
        reason="Request asks for the specific version of Tor Browser",
        acceptance_rule=AcceptanceRule(
            min_observations=1,
            required_fields=("TargetFilename",),
        ),
    )
    graph = ClaimGraph(
        id="graph-tor-version",
        request_id="req-tor-001",
        objective="Was Tor Browser installed by amber.turing and if so what version?",
        claims=[claim_presence, claim_version],
    )
    assert len(graph.claims) == 2
    assert graph.get_claim("claim-presence") is not None
    assert graph.get_claim("claim-version") is not None
    assert graph.unresolved_claims() == graph.claims  # none resolved yet
    assert not graph.is_resolved()


# ---------------------------------------------------------------------------
# Test 2: Missing acceptance rule is rejected
# ---------------------------------------------------------------------------


def test_missing_acceptance_rule_rejected() -> None:
    """A Claim with acceptance_rule=None must raise ValueError."""
    with pytest.raises((ValueError, TypeError)):
        Claim(
            id="claim-bad",
            claim_type="attribute",
            subject="user:amber.turing",
            predicate="has_version",
            provenance="request",
            source_request_id="req-001",
            acceptance_rule=None,  # type: ignore[arg-type]
        )


# ---------------------------------------------------------------------------
# Test 3: Raw SPL in predicate is rejected
# ---------------------------------------------------------------------------


def test_raw_spl_rejected() -> None:
    """A Claim whose predicate contains raw SPL syntax must be rejected."""
    # SPL: pipe command
    with pytest.raises(ValueError, match="raw SPL"):
        _make_claim(predicate="| stats count by host")

    # SPL: index=
    with pytest.raises(ValueError, match="raw SPL"):
        _make_claim(predicate="search index=botsv2")

    # KQL: table pipe
    with pytest.raises(ValueError, match="raw SPL"):
        _make_claim(predicate="DeviceEvents | where Timestamp")


def test_raw_spl_in_object_rejected() -> None:
    """Raw SPL in object_or_value must also be rejected."""
    with pytest.raises(ValueError, match="raw SPL"):
        _make_claim(object_or_value="index=botsv2 *amber*")


def test_raw_spl_in_acceptance_rule_rejected() -> None:
    """Raw SPL in AcceptanceRule.value_must_match must be rejected."""
    with pytest.raises(ValueError, match="raw SPL"):
        AcceptanceRule(value_must_match="index=botsv2")


# ---------------------------------------------------------------------------
# Test 4: Claim not originating from request is rejected
# ---------------------------------------------------------------------------


def test_claim_not_from_request_rejected() -> None:
    """A non-prerequisite Claim with empty source_request_id must be rejected."""
    with pytest.raises(ValueError, match="source_request_id"):
        _make_claim(source_request_id="")  # empty = untraced claim

    with pytest.raises(ValueError, match="source_request_id"):
        _make_claim(source_request_id="   ")  # whitespace only


def test_prerequisite_claim_allowed_without_request_id() -> None:
    """A prerequisite Claim (is_prerequisite=True) may have any source_request_id."""
    # Prerequisites from operation contracts are allowed to have empty request IDs
    # since they are derived from capability contracts, not directly from the request.
    claim = Claim(
        id="claim-prereq",
        claim_type="attribute",
        subject="host:wrk-aturing",
        predicate="has_active_session",
        provenance="verified_observation",
        source_request_id="",  # OK for prerequisites
        is_prerequisite=True,
        acceptance_rule=AcceptanceRule(min_observations=1),
    )
    assert claim.is_prerequisite is True


# ---------------------------------------------------------------------------
# Test 5: Email request produces generic Claim, not EmailClaim
# ---------------------------------------------------------------------------


def test_counterfactual_email_no_email_class() -> None:
    """An email-related hunt must produce a standard Claim with email predicate,
    NOT a special EmailClaim subclass.

    This enforces the v6 constraint: no scenario-specific subclasses.
    See 01_FINAL-ARCHITECTURE.md §1: 'The runtime must not branch on email...'
    """
    # Simulate what the semantic compiler should produce for an email question
    email_claim = Claim(
        id="claim-email-sender",
        claim_type="attribute",
        subject="user:amber.turing",
        predicate="sent_email_to",          # generic relation predicate
        object_or_value=None,               # unknown recipient — to be discovered
        value_type="email_address",
        provenance="request",
        source_request_id="req-email-001",
        evidence_requirements=("authentication_activity",),
        acceptance_rule=AcceptanceRule(
            min_observations=1,
            required_fields=("sender_email", "recipient_email"),
        ),
        reason="Request asks who amber.turing sent emails to",
    )

    # Must be a plain Claim, not a scenario subclass
    assert type(email_claim) is Claim, (
        "email_claim must be an instance of Claim, not a scenario-specific subclass"
    )
    assert email_claim.value_type == "email_address"
    assert "email" in email_claim.predicate


# ---------------------------------------------------------------------------
# Test 6: Tor request produces generic Claim, not TorClaim
# ---------------------------------------------------------------------------


def test_counterfactual_tor_no_tor_class() -> None:
    """A Tor-related hunt must produce a standard Claim with tor predicate,
    NOT a special TorClaim subclass.

    This enforces the v6 constraint: no scenario-specific subclasses.
    """
    tor_claim = Claim(
        id="claim-tor-version",
        claim_type="attribute",
        subject="user:amber.turing",
        predicate="installed_software",
        object_or_value="Tor Browser",       # product name as object, not a type branch
        value_type="software_version",
        provenance="request",
        source_request_id="req-tor-001",
        evidence_requirements=("file_modification", "process_ancestry"),
        acceptance_rule=AcceptanceRule(
            min_observations=1,
            required_fields=("TargetFilename",),
            custom_doc="Version must be extractable from installer filename or PE metadata",
        ),
        reason="Request asks for the installed Tor Browser version",
    )

    # Must be a plain Claim
    assert type(tor_claim) is Claim, (
        "tor_claim must be an instance of Claim, not a scenario-specific TorClaim"
    )
    assert tor_claim.value_type == "software_version"
    # The object name mentions "Tor Browser" but the TYPE is plain Claim
    assert "Tor Browser" in (tor_claim.object_or_value or "")


# ---------------------------------------------------------------------------
# Additional edge cases
# ---------------------------------------------------------------------------


def test_duplicate_claim_id_in_graph_rejected() -> None:
    """ClaimGraph with duplicate claim IDs must raise ValueError."""
    claim_a = _make_claim(id="dup-id")
    claim_b = _make_claim(id="dup-id", predicate="executed")  # same ID
    with pytest.raises(ValueError, match="Duplicate"):
        ClaimGraph(
            id="graph-bad",
            request_id="req-001",
            objective="Test",
            claims=[claim_a, claim_b],
        )


def test_unknown_dependency_in_graph_rejected() -> None:
    """ClaimGraph where a dependency ID doesn't exist must raise ValueError."""
    claim = _make_claim(dependencies=("nonexistent-claim-id",))
    with pytest.raises(ValueError, match="nonexistent-claim-id"):
        ClaimGraph(
            id="graph-bad",
            request_id="req-001",
            objective="Test",
            claims=[claim],
        )


def test_cyclic_dependency_in_graph_rejected() -> None:
    """ClaimGraph with cyclic dependencies must raise ValueError."""
    claim_a = _make_claim(id="claim-a", dependencies=("claim-b",))
    claim_b = _make_claim(id="claim-b", dependencies=("claim-a",), predicate="executed")
    with pytest.raises(ValueError, match="cycle"):
        ClaimGraph(
            id="graph-cyclic",
            request_id="req-001",
            objective="Test",
            claims=[claim_a, claim_b],
        )


def test_claim_status_lifecycle() -> None:
    """Claim starts UNPROVEN; can reach terminal states."""
    claim = _make_claim()
    assert claim.status == ClaimStatus.UNPROVEN
    assert not claim.is_resolved()

    claim.status = ClaimStatus.SUPPORTED
    assert claim.is_resolved()

    claim2 = _make_claim(id="claim-2")
    claim2.status = ClaimStatus.REFUTED
    assert claim2.is_resolved()


def test_claim_cite_observation() -> None:
    """Claim.cite() adds observation IDs to the internal list."""
    claim = _make_claim()
    claim.cite("obs-001")
    claim.cite("obs-002")
    claim.cite("obs-001")  # duplicate — should not add twice
    assert claim._cited_observation_ids == ["obs-001", "obs-002"]


def test_refutation_rule_contradictory_requires_claim_id() -> None:
    """RefutationRule with CONTRADICTORY_CLAIM must specify contradicts_claim_id."""
    with pytest.raises(ValueError, match="contradicts_claim_id"):
        RefutationRule(
            condition=RefutationCondition.CONTRADICTORY_CLAIM,
            reason="contradicts presence claim",
        )


def test_valid_refutation_rule() -> None:
    """A well-formed RefutationRule must be accepted."""
    rule = RefutationRule(
        condition=RefutationCondition.FIELD_ABSENT,
        field="TargetFilename",
        reason="No filename observed means version cannot be determined",
    )
    assert rule.condition == RefutationCondition.FIELD_ABSENT


def test_claimgraph_to_dict_round_trip() -> None:
    """ClaimGraph.to_dict() must return a serializable dict."""
    graph = _make_graph()
    d = graph.to_dict()
    assert d["id"] == "graph-001"
    assert d["request_id"] == "req-001"
    assert isinstance(d["claims"], list)
    assert len(d["claims"]) == 1
    claim_d = d["claims"][0]
    assert "acceptance_rule" in claim_d
    assert claim_d["status"] == ClaimStatus.UNPROVEN.value
