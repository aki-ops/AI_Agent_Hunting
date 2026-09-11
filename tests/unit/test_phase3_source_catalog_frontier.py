from __future__ import annotations

from hunting.capabilities.catalog_index import CatalogIndex
from hunting.capabilities.frontier import FrontierStage, ProgressiveFrontier
from hunting.capabilities.source_card_store import FieldSketch, SourceCard, SourceCardStore


def test_source_card_and_store_serialization() -> None:
    """Verify SourceCard serialization, fingerprint generation and compact summary."""
    card = SourceCard(
        source_id="stream:smtp",
        provider_id="splunk",
        scope="botsv2",
        event_count=50000,
        fields=(
            FieldSketch("sender_email", "string", cardinality=120, sample_values=("mallory@victim.com",), field_roles=("sender_email",)),
            FieldSketch("receiver_email", "string", cardinality=350, sample_values=("external@attacker.com",), field_roles=("recipient_email",)),
            FieldSketch("subject", "string", cardinality=4000, sample_values=("Important Q3 Update",), field_roles=("email_subject",)),
        ),
        field_roles={"sender_email": "sender_email", "receiver_email": "recipient_email"},
    )
    assert card.schema_fingerprint != ""
    assert "sender_email" in card.field_names

    summary = card.compact_summary(max_fields=2)
    assert summary["source_id"] == "stream:smtp"
    assert len(summary["fields"]) == 2
    assert summary["total_fields"] == 3

    store = SourceCardStore()
    store.register_card(card)
    assert store.count() == 1
    assert store.get_card("stream:smtp") == card

    d = card.to_dict()
    restored = SourceCard.from_dict(d)
    assert restored.source_id == "stream:smtp"
    assert restored.schema_fingerprint == card.schema_fingerprint
    assert len(restored.fields) == 3


def test_gate_misleading_source_name_with_correct_fields_is_selected() -> None:
    """Gate 08: Misleading source name with correct fields is selected based on semantics/roles."""
    misleading_card = SourceCard(
        source_id="misc_debug_stream_unrelated",
        provider_id="splunk",
        scope="botsv2",
        event_count=1000,
        fields=(
            FieldSketch("sender_email", "string", field_roles=("sender_email",)),
            FieldSketch("receiver_email", "string", field_roles=("recipient_email",)),
            FieldSketch("subject", "string", field_roles=("email_subject",)),
        ),
        field_roles={"sender_email": "sender_email", "receiver_email": "recipient_email"},
    )
    store = SourceCardStore()
    store.register_card(misleading_card)
    index = CatalogIndex(store)

    results = index.search(
        relation="sent_email",
        required_roles=("sender_email", "recipient_email"),
        search_terms=("email", "sender"),
    )
    assert len(results) == 1
    # Misleading name must be selected (above threshold and high score) because its fields are correct
    assert results[0].source_id == "misc_debug_stream_unrelated"
    assert results[0].above_threshold is True
    assert results[0].score_components["required_role_coverage"] > 1.0


def test_gate_deceptive_source_name_with_wrong_fields_is_rejected() -> None:
    """Gate 08: Deceptive source name with wrong fields is rejected, not selected by name."""
    deceptive_card = SourceCard(
        source_id="threat_ransomware_critical_activity_log",
        provider_id="splunk",
        scope="botsv2",
        event_count=50,
        fields=(
            FieldSketch("ui_button_click", "string"),
            FieldSketch("theme_color", "string"),
        ),
        field_roles={},
    )
    store = SourceCardStore()
    store.register_card(deceptive_card)
    index = CatalogIndex(store)

    results = index.search(
        relation="sent_email",
        required_roles=("sender_email", "recipient_email"),
        search_terms=("ransomware", "threat"),
    )
    assert len(results) == 1
    cand = results[0]
    # Must be rejected because it lacks the required roles, despite having 'threat' and 'ransomware' in name
    assert cand.above_threshold is False
    assert len(cand.rejection_reasons) > 0
    assert any("Missing required roles" in r for r in cand.rejection_reasons)


def test_gate_rename_source_does_not_lose_answer() -> None:
    """Gate 08: Renaming a source retains its ranking and selection if fields are equivalent."""
    card1 = SourceCard(
        source_id="stream:smtp",
        provider_id="splunk",
        scope="botsv2",
        event_count=5000,
        fields=(
            FieldSketch("sender_email", "string", field_roles=("sender_email",)),
            FieldSketch("receiver_email", "string", field_roles=("recipient_email",)),
        ),
        field_roles={"sender_email": "sender_email", "receiver_email": "recipient_email"},
    )
    renamed_card = SourceCard(
        source_id="arbitrary_vendor_telemetry_99",
        provider_id="splunk",
        scope="botsv2",
        event_count=5000,
        fields=(
            FieldSketch("sender_email", "string", field_roles=("sender_email",)),
            FieldSketch("receiver_email", "string", field_roles=("recipient_email",)),
        ),
        field_roles={"sender_email": "sender_email", "receiver_email": "recipient_email"},
    )

    store = SourceCardStore()
    store.register_card(card1)
    store.register_card(renamed_card)
    index = CatalogIndex(store)

    results = index.search(
        relation="sent_email",
        required_roles=("sender_email", "recipient_email"),
    )
    assert len(results) == 2
    # Both sources have identical scores because scores depend on fields and roles, not the name
    assert abs(results[0].total_score - results[1].total_score) < 1e-4
    assert results[0].above_threshold is True
    assert results[1].above_threshold is True


def test_gate_25_sources_617_fields_never_appear_in_a_single_prompt() -> None:
    """Gate 08: Bounded token pack guarantees no prompt sees 25 sources / 617 fields at once."""
    store = SourceCardStore()
    # Create 25 sources with 25 fields each = 625 fields total
    for i in range(25):
        fields = tuple(FieldSketch(f"field_{j}_{i}", "string") for j in range(25))
        card = SourceCard(
            source_id=f"source_{i:02d}",
            provider_id="splunk",
            scope="botsv2",
            event_count=100 * (i + 1),
            fields=fields,
        )
        store.register_card(card)

    index = CatalogIndex(store)
    frontier = ProgressiveFrontier(store, index, max_batch_cards=8, max_batch_fields=32)

    all_cards = store.list_cards()
    assert len(all_cards) == 25
    total_fields = sum(len(c.fields) for c in all_cards)
    assert total_fields == 625

    # Pack cards for prompt
    batches = frontier.pack_cards_for_prompt(all_cards)

    # Must be split into multiple bounded batches
    assert len(batches) >= 4  # 25 / 8 = 4 batches (8 + 8 + 8 + 1)
    for b in batches:
        assert len(b) <= 8  # Max 8 cards per prompt
        for card_summary in b:
            assert len(card_summary["fields"]) <= 32  # Bounded fields per card


def test_progressive_frontier_stages_and_coverage_manifest() -> None:
    """Verify F0 -> F1 -> F2 -> F3 -> F4 progressive expansion and gap tracking."""
    store = SourceCardStore()

    # S1: Certified F0 source
    s1 = SourceCard(
        source_id="win:security",
        provider_id="splunk",
        scope="botsv2",
        event_count=10000,
        fields=(FieldSketch("user", "string", field_roles=("account_name",)), FieldSketch("host", "string", field_roles=("endpoint_host",))),
        field_roles={"user": "account_name", "host": "endpoint_host"},
        adjacent_source_ids=("win:system",),
    )
    # S2: Adjacent F2 source
    s2 = SourceCard(
        source_id="win:system",
        provider_id="splunk",
        scope="botsv2",
        event_count=8000,
        fields=(FieldSketch("host", "string", field_roles=("endpoint_host",)),),
        adjacent_source_ids=("win:security",),
    )
    # S3: F1 Metadata source (matches terms)
    s3 = SourceCard(
        source_id="stream:dns",
        provider_id="splunk",
        scope="botsv2",
        event_count=50000,
        fields=(FieldSketch("query", "string", sample_values=("victim.com",)),),
    )
    # S4: Unrelated source that will remain unexamined
    s4 = SourceCard(
        source_id="cisco:asa",
        provider_id="splunk",
        scope="botsv2",
        event_count=200,
        fields=(FieldSketch("packet_len", "number"),),
    )

    store.register_card(s1)
    store.register_card(s2)
    store.register_card(s3)
    store.register_card(s4)

    index = CatalogIndex(store)
    frontier = ProgressiveFrontier(store, index)

    # Expand for logged_on_to with approved contract
    selected, manifest = frontier.expand(
        relation="logged_on_to",
        required_roles=("account_name", "endpoint_host"),
        search_terms=("logged", "host"),
        approved_contracts=("logged_on_to",),
        allow_exhaustive=False,
    )

    # 1. F0 Certified includes win:security
    assert any(c.source_id == "win:security" for c in selected)

    # 2. F2 Adjacent expansion includes win:system
    assert any(c.source_id == "win:system" for c in selected)

    # 3. Shortlist never proves absence: S4 remains in unexamined_source_ids as explicit coverage gap
    assert manifest.has_coverage_gaps is True
    assert "cisco:asa" in manifest.unexamined_source_ids
    assert "cisco:asa" not in manifest.examined_source_ids

    # 4. Manifest audit captures each stage
    stages = [a["stage"] for a in manifest.stage_audit]
    assert FrontierStage.F0_CERTIFIED.value in stages
    assert FrontierStage.F1_METADATA.value in stages
    assert FrontierStage.F2_ADJACENT.value in stages
