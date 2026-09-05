"""Deterministic reasoning engine.

Enforces:
- Exact predicates and temporal correlations are evaluated deterministically.
- Multi-hypothesis compatibility: an observation can support multiple hypotheses.
- Competing hypotheses remain active (LIVE or WEAKENED) until genuinely refuted.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import datetime
from typing import Any

from hunting.contracts.expectations import (
    Expectation,
    FieldOp,
    FieldPredicate,
    TestStatus,
)
from hunting.contracts.hunt import EvidenceCard, Hypothesis, HypothesisStatus


def evaluate_field_predicate(field_value: Any, predicate: FieldPredicate) -> bool:
    """Deterministically evaluate whether a field value satisfies a predicate."""
    if predicate.op == FieldOp.EXISTS:
        return field_value is not None and field_value != ""
    if predicate.op == FieldOp.ABSENT:
        return field_value is None or field_value == ""

    if field_value is None:
        return False

    val_str = str(field_value).strip().lower()
    target_str = str(predicate.value).strip().lower()

    if predicate.op == FieldOp.EQUALS:
        return val_str == target_str
    elif predicate.op == FieldOp.CONTAINS:
        return target_str in val_str

    return False


def evaluate_temporal_correlation(t1_iso: str, t2_iso: str, max_delta_seconds: float) -> bool:
    """Evaluate whether two ISO timestamps fall within a temporal delta bound."""
    if not t1_iso or not t2_iso:
        return True
    try:
        dt1 = datetime.fromisoformat(t1_iso.replace("Z", "+00:00"))
        dt2 = datetime.fromisoformat(t2_iso.replace("Z", "+00:00"))
        delta = abs((dt2 - dt1).total_seconds())
        return delta <= max_delta_seconds
    except Exception:
        return False


def verify_attack_chain_correlation(
    evidence_cards: list[EvidenceCard],
    max_delta_seconds: float = 86400.0,
    host_aliases: dict[str, set[str]] | None = None,
) -> bool:
    """Verify that multi-stage compromise evidence is co-located on the same host and temporally correlated."""
    if not evidence_cards:
        return True

    web_cards = [c for c in evidence_cards if c.fact_type in ("web_request", "web_activity")]
    proc_cards = [c for c in evidence_cards if c.fact_type == "process_execution"]
    file_cards = [c for c in evidence_cards if c.fact_type in ("file_modification", "persistence_change")]

    # If only one category exists, cross-stage co-location does not apply
    if not web_cards or not proc_cards:
        return True

    def card_hosts(card: EvidenceCard) -> set[str]:
        hosts = {str(h).lower() for h in card.entity_summary.get("hosts", [])}
        for rel in card.relations:
            if "host" in rel and rel["host"]:
                hosts.add(str(rel["host"]).lower())
            if "target" in rel and rel["target"]:
                hosts.add(str(rel["target"]).lower())
        return hosts

    def card_ips(card: EvidenceCard) -> set[str]:
        ips = {str(ip).lower() for ip in card.entity_summary.get("destination_ips", [])}
        ips.update(str(ip).lower() for ip in card.entity_summary.get("ips", []))
        ips.update(str(ip).lower() for ip in card.field_summary.get("dest_ips", []))
        for rel in card.relations:
            for k in ("dest_ip", "destination_ip", "server_ip", "s_ip"):
                if k in rel and rel[k]:
                    ips.add(str(rel[k]).lower())
        return ips

    def card_time(card: EvidenceCard) -> str:
        return card.time_summary.get("earliest") or card.time_summary.get("latest") or ""

    web_target_hosts = set()
    web_target_ips = set()
    for wc in web_cards:
        web_target_hosts.update(card_hosts(wc))
        web_target_ips.update(card_ips(wc))

    # Host-to-IP mapping from endpoint cards
    host_to_ips: dict[str, set[str]] = defaultdict(set)
    if host_aliases:
        for h, ips in host_aliases.items():
            host_to_ips[str(h).lower()].update(str(ip).lower() for ip in ips)
    for c in evidence_cards:
        c_h = card_hosts(c)
        c_i = card_ips(c)
        for h in c_h:
            host_to_ips[h].update(c_i)

    # For each candidate host, check co-location across all present stages
    candidate_hosts: set[str] = set()
    for pc in proc_cards:
        candidate_hosts.update(card_hosts(pc))

    has_valid_chain = False
    for h in candidate_hosts:
        # 1. Host must be target of web activity (by name or by IP)
        is_web_target = (h in web_target_hosts) or bool(host_to_ips[h].intersection(web_target_ips))
        if (web_target_hosts or web_target_ips) and not is_web_target:
            continue

        # 2. Host must have process execution
        h_proc_cards = [pc for pc in proc_cards if h in card_hosts(pc)]
        if not h_proc_cards:
            continue

        # 3. If file modification evidence exists, it MUST also be on this same host
        if file_cards:
            h_file_cards = [fc for fc in file_cards if h in card_hosts(fc)]
            if not h_file_cards:
                continue
        else:
            h_file_cards = []

        # 4. Temporal correlation on host h
        h_web_cards = [wc for wc in web_cards if (h in card_hosts(wc)) or bool(card_ips(wc).intersection(host_to_ips[h]))]
        temporal_ok = True
        if h_web_cards:
            web_times = [card_time(c) for c in h_web_cards if card_time(c)]
            proc_times = [card_time(c) for c in h_proc_cards if card_time(c)]
            if web_times and proc_times:
                pair_ok = any(
                    evaluate_temporal_correlation(tw, tp, max_delta_seconds)
                    for tw in web_times
                    for tp in proc_times
                )
                if not pair_ok:
                    temporal_ok = False

        if temporal_ok and h_file_cards:
            file_times = [card_time(c) for c in h_file_cards if card_time(c)]
            proc_times = [card_time(c) for c in h_proc_cards if card_time(c)]
            if proc_times and file_times:
                pair_ok = any(
                    evaluate_temporal_correlation(tp, tf, max_delta_seconds)
                    for tp in proc_times
                    for tf in file_times
                )
                if not pair_ok:
                    temporal_ok = False

        if temporal_ok:
            has_valid_chain = True
            break

    return has_valid_chain


class HypothesisReasoningEngine:
    """Manages competing hypothesis compatibility and status lifecycle."""

    def evaluate_compatibility(
        self,
        card: EvidenceCard,
        hypotheses: list[Hypothesis],
        expectations: list[Expectation] | None = None,
    ) -> dict[str, bool]:
        """Check compatibility of an EvidenceCard against multiple hypotheses simultaneously.

        Invariant: An evidence card can be compatible with multiple hypotheses.
        'Consistent with H1' does NOT prove H1 nor refute H2.
        """
        compatibility: dict[str, bool] = {h.id: False for h in hypotheses}
        if not expectations:
            return compatibility

        def fact_matches(expectation: Expectation) -> bool:
            allowed_facts = {
                "process_ancestry": {"process_execution"},
                "authentication_activity": {"authentication_activity"},
                "network_connection": {"network_connection"},
                "file_modification": {"file_modification"},
                "dns_activity": {"dns_activity"},
                "persistence_change": {"persistence_change"},
                "web_request": {"web_request", "web_activity", "http_traffic"},
                "scope_records": {
                    "process_execution", "authentication_activity", "network_connection",
                    "file_modification", "dns_activity", "persistence_change",
                    "web_request", "web_activity", "telemetry",
                },
            }
            req = expectation.evidence_requirement.value
            return card.fact_type in allowed_facts.get(req, {"telemetry"})

        for expectation in expectations:
            if fact_matches(expectation) and expectation.owner_explanation_id in compatibility:
                compatibility[expectation.owner_explanation_id] = True
        return compatibility

    def update_hypothesis_status(
        self,
        hypothesis: Hypothesis,
        has_confirming_evidence: bool,
        has_refuting_evidence: bool,
    ) -> None:
        """Update hypothesis status following rigorous epistemic rules.

        - LIVE: Default active state.
        - SUPPORTED: Confirmed by observable evidence.
        - WEAKENED: At least one expectation refuted, but not all.
        - REFUTED: Genuinely refuted by complete observable negative evidence.
        """
        if has_refuting_evidence:
            if has_confirming_evidence:
                hypothesis.status = HypothesisStatus.WEAKENED
            else:
                hypothesis.status = HypothesisStatus.REFUTED
        elif has_confirming_evidence:
            hypothesis.status = HypothesisStatus.SUPPORTED

    def evaluate_hypothesis_network(
        self,
        hypotheses: list[Hypothesis],
        expectations: list[Expectation],
        evidence_cards: list[EvidenceCard],
    ) -> None:
        """Update competing hypothesis lifecycle based on confirmed/refuted expectations."""
        exps_by_owner: dict[str, list[Expectation]] = {}
        for exp in expectations:
            exps_by_owner.setdefault(exp.owner_explanation_id, []).append(exp)

        for h in hypotheses:
            owned = exps_by_owner.get(h.id, [])
            if not owned:
                continue

            confirmed = [e for e in owned if e.test_status == TestStatus.CONFIRMED]
            refuted = [e for e in owned if e.test_status == TestStatus.REFUTED]
            untested = [e for e in owned if e.test_status == TestStatus.UNTESTED]
            inconclusive = [e for e in owned if e.test_status in (TestStatus.INCONCLUSIVE, TestStatus.UNTESTABLE)]

            if confirmed and not refuted and not untested and not inconclusive:
                requires_attack_chain = any(
                    e.evidence_requirement.value == "web_request" for e in owned
                )
                if requires_attack_chain and evidence_cards:
                    if not verify_attack_chain_correlation(evidence_cards):
                        h.status = HypothesisStatus.WEAKENED
                    else:
                        h.status = HypothesisStatus.SUPPORTED
                else:
                    h.status = HypothesisStatus.SUPPORTED
            elif confirmed and (refuted or untested or inconclusive):
                # A web request alone is insufficient; require a typed execution
                # or artifact requirement to be confirmed as well.
                requires_attack_chain = any(
                    e.evidence_requirement.value == "web_request" for e in owned
                )
                if requires_attack_chain:
                    confirmed_types = {e.evidence_requirement.value for e in confirmed}
                    if confirmed_types.intersection({
                        "process_ancestry", "file_modification", "persistence_change"
                    }):
                        if evidence_cards:
                            if not verify_attack_chain_correlation(evidence_cards):
                                h.status = HypothesisStatus.WEAKENED
                            else:
                                h.status = HypothesisStatus.SUPPORTED
                        else:
                            h.status = HypothesisStatus.SUPPORTED
                    else:
                        h.status = HypothesisStatus.WEAKENED
                elif confirmed:
                    h.status = HypothesisStatus.SUPPORTED
                else:
                    h.status = HypothesisStatus.WEAKENED
            elif refuted and not confirmed and not untested and not inconclusive:
                h.status = HypothesisStatus.REFUTED
            elif inconclusive or untested or (not confirmed and not refuted):
                if h.status not in (HypothesisStatus.SUPPORTED, HypothesisStatus.REFUTED):
                    h.status = HypothesisStatus.UNKNOWN

        # Competing hypotheses resolution
        attack_hypos = [h for h in hypotheses if h.hypothesis_class != "benign_baseline"]
        benign_hypos = [h for h in hypotheses if h.hypothesis_class == "benign_baseline"]

        if any(h.status == HypothesisStatus.SUPPORTED for h in attack_hypos):
            for bh in benign_hypos:
                bh.status = HypothesisStatus.REFUTED
        elif all(h.status == HypothesisStatus.REFUTED for h in attack_hypos) and attack_hypos:
            for bh in benign_hypos:
                bh.status = HypothesisStatus.SUPPORTED


__all__ = [
    "evaluate_field_predicate",
    "evaluate_temporal_correlation",
    "verify_attack_chain_correlation",
    "HypothesisReasoningEngine",
]
