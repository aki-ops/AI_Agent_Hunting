"""Evidence grouping and EvidenceCard builder.

Compresses repeated observations into canonical EvidenceCards:
- Invariant semantic fingerprints group identical background telemetry.
- Malicious event indicators (anomalous cmdlines, external IPs) form distinct cards
  to preserve 100% malicious-event recall.
- Aggregates representative IDs, counts, entity summaries, and time windows.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict

from hunting.contracts.hunt import EvidenceCard
from hunting.contracts.observations import Observation
from hunting.evidence.facts import extract_facts


class EvidenceGroupBuilder:
    """Deterministic compression of observations into canonical EvidenceCards."""

    def __init__(self, max_representative_ids: int = 3) -> None:
        self.max_representative_ids = max_representative_ids

    def build_cards(self, observations: list[Observation]) -> list[EvidenceCard]:
        """Group observations and return compressed EvidenceCards."""
        groups: dict[str, list[Observation]] = defaultdict(list)

        # 1. Compute fingerprint for each observation
        for obs in observations:
            fp = self.compute_fingerprint(obs)
            groups[fp].append(obs)

        # 2. Build EvidenceCard for each group
        cards: list[EvidenceCard] = []
        for fp, group_obs in groups.items():
            rep_ids = [o.id for o in group_obs[: self.max_representative_ids]]
            count = len(group_obs)

            # Determine primary fact type from first observation
            facts = extract_facts(group_obs[0])
            primary_fact_type = facts[0].fact_type if facts else "telemetry"

            # Summaries
            timestamps = [o.timestamp for o in group_obs if o.timestamp]
            earliest = min(timestamps) if timestamps else ""
            latest = max(timestamps) if timestamps else ""

            # Entity summary
            entities_seen: dict[str, set[str]] = defaultdict(set)
            for o in group_obs:
                if "host" in o.fields:
                    entities_seen["hosts"].add(str(o.fields["host"]))
                if "user" in o.fields:
                    entities_seen["users"].add(str(o.fields["user"]))
                if "destination_ip" in o.fields:
                    entities_seen["destination_ips"].add(str(o.fields["destination_ip"]))

            entity_summary = {k: list(v) for k, v in entities_seen.items()}
            time_summary = {"earliest": earliest, "latest": latest, "span_events": count}

            # Field summary (sample of distinct commands or paths)
            field_summary: dict[str, list[str]] = {}
            cmdlines = {str(o.fields.get("cmdline")) for o in group_obs if "cmdline" in o.fields}
            if cmdlines:
                field_summary["cmdlines"] = list(cmdlines)[:5]

            relations_summary = []
            if facts and facts[0].relations:
                for rel in facts[0].relations:
                    relations_summary.append({
                        "relation": rel.relation_type,
                        "source": str(rel.source_entity),
                        "target": str(rel.target_entity),
                    })

            card = EvidenceCard(
                id=f"card-{fp[:12]}",
                fingerprint=fp,
                representative_observation_ids=rep_ids,
                count=count,
                entity_summary=entity_summary,
                time_summary=time_summary,
                field_summary=field_summary,
                fact_type=primary_fact_type,
                completeness="complete",
                relations=relations_summary,
            )
            cards.append(card)

        # Sort cards deterministically by count descending then id
        cards.sort(key=lambda c: (-c.count, c.id))
        return cards

    def compute_fingerprint(self, observation: Observation) -> str:
        """Compute an invariant semantic fingerprint for an observation.

        Attack-relevant fields (distinct commandlines, distinct destinations)
        produce distinct fingerprints, preserving malicious-event recall.
        """
        scope_id = observation.provider_scope.scope_id if observation.provider_scope else ""
        native_type = observation.native_type or ""
        semantic_val = ""
        if observation.semantic_type:
            semantic_val = (
                observation.semantic_type.value
                if hasattr(observation.semantic_type, "value")
                else str(observation.semantic_type)
            )

        # Key attack-discriminating attributes
        cmd = str(observation.fields.get("cmdline", "")).strip().lower()
        image = str(observation.fields.get("image", "")).strip().lower()
        dst_ip = str(observation.fields.get("destination_ip", "")).strip()
        path = str(observation.fields.get("file_path", "")).strip().lower()
        task = str(observation.fields.get("task_name", "")).strip().lower()

        # Build stable raw signature
        raw_sig = f"{scope_id}|{native_type}|{semantic_val}|{image}|{cmd}|{dst_ip}|{path}|{task}"
        return hashlib.sha256(raw_sig.encode("utf-8")).hexdigest()


__all__ = ["EvidenceGroupBuilder"]
