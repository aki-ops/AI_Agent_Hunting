"""Unit tests for Phase 2: EvidenceCard redesign, command line variation collapsing, and semantic summaries."""
from __future__ import annotations

from hunting.contracts.cells import ProviderScope
from hunting.contracts.observations import EpistemicType, Observation
from hunting.evidence.grouping import EvidenceGroupBuilder


def test_command_line_variations_under_same_parent_collapse_to_single_card():
    """Minor command line variations under the same parent/image/host context must form 1 card with a command list."""
    scope = ProviderScope(provider_id="splunk", native_partition={"index": "botsv1"})
    builder = EvidenceGroupBuilder()

    commands = [
        "cmd.exe /c whoami",
        "cmd.exe /c tasklist",
        "cmd.exe /c net user",
        "cmd.exe /c whoami /priv",
        "cmd.exe /c ipconfig /all",
    ]

    observations = [
        Observation(
            id=f"obs-cmd-{i}",
            provider_scope=scope,
            cell_id="2026-09-01/P1D",
            timestamp=f"2026-09-01T12:0{i}:00Z",
            epistemic_type=EpistemicType.OBSERVED,
            native_type="WinEventLog:Security",
            fields={
                "host": "we1149srv",
                "image": "cmd.exe",
                "parent_image": "php-cgi.exe",
                "cmdline": cmd,
                "user": "NT AUTHORITY\\SYSTEM",
            },
            query_id="q-proc-1",
        )
        for i, cmd in enumerate(commands)
    ]

    cards = builder.build_cards(observations)

    # Invariant: Must collapse into 1 card, not 5 separate cards!
    assert len(cards) == 1
    card = cards[0]
    assert card.count == 5
    assert card.fact_type == "process_execution"

    # Human-readable summary
    assert "php-cgi.exe spawned cmd.exe on we1149srv" in card.summary

    # Why it matters
    assert "web worker process spawned an interactive command shell" in card.why_it_matters.lower()
    assert card.confidence == "HIGH"

    # Preserves list of observed commands
    observed_cmds = card.field_summary.get("cmdlines", [])
    assert len(observed_cmds) == 5
    assert "cmd.exe /c whoami" in observed_cmds
    assert "cmd.exe /c tasklist" in observed_cmds
    assert "cmd.exe /c net user" in observed_cmds

    # Query ID & Replay
    assert "q-proc-1" in card.query_ids
    assert card.replay["artifact"] == "observations.jsonl"
    assert "show-observation" in card.replay["command"]


def test_distinct_process_lineages_form_distinct_cards():
    """Different parent-child executions (e.g. svchost vs php-cgi) form separate cards."""
    scope = ProviderScope(provider_id="splunk", native_partition={"index": "botsv1"})
    builder = EvidenceGroupBuilder()

    obs_benign = Observation(
        id="obs-svchost",
        provider_scope=scope,
        cell_id="c1",
        timestamp="2026-09-01T12:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        fields={"host": "we1149srv", "image": "svchost.exe", "parent_image": "services.exe", "cmdline": "svchost.exe -k netsvcs"},
    )
    obs_webshell = Observation(
        id="obs-webshell",
        provider_scope=scope,
        cell_id="c1",
        timestamp="2026-09-01T12:05:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        fields={"host": "we1149srv", "image": "cmd.exe", "parent_image": "php-cgi.exe", "cmdline": "cmd.exe /c whoami"},
    )

    cards = builder.build_cards([obs_benign, obs_webshell])
    assert len(cards) == 2


def test_eliminates_generic_telemetry_when_fields_permit_classification():
    """Observations with process or web fields are classified into concrete fact types rather than generic_telemetry."""
    scope = ProviderScope(provider_id="splunk", native_partition={"index": "botsv1"})
    builder = EvidenceGroupBuilder()

    obs_proc = Observation(
        id="obs-proc-fallback",
        provider_scope=scope,
        cell_id="c1",
        timestamp="2026-09-01T12:00:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        fields={"host": "host-a", "cmdline": "powershell.exe -enc AAAA"},
    )
    obs_web = Observation(
        id="obs-web-fallback",
        provider_scope=scope,
        cell_id="c1",
        timestamp="2026-09-01T12:01:00Z",
        epistemic_type=EpistemicType.OBSERVED,
        fields={"host": "host-b", "uri": "/index.php", "site": "www.imreallynotbatman.com"},
    )

    cards = builder.build_cards([obs_proc, obs_web])
    fact_types = {c.fact_type for c in cards}
    assert "generic_telemetry" not in fact_types
    assert "process_execution" in fact_types
    assert "web_request" in fact_types
