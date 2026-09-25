"""PEAK links a goal to a minimap row only after a count confirms the sourcetype."""
from __future__ import annotations

import yaml

from hunting.contracts.semantic_graph import SemanticGoalGraph, SemanticRelationGoal, SemanticVariable
from hunting.m5_adapter.splunk_adapter import SplunkLiveAdapter
from hunting.peak_data import confirm_entries, link_goal, minimap_entries
from hunting.planner.semantic_goal_planner import SemanticGoalPlanner

MANIFEST = yaml.safe_load(open("configs/splunk_botsv2.yaml", encoding="utf-8"))
WINDOW = "2017-08-01T00:00:00Z/2017-08-31T23:59:59Z"


def test_unconfirmed_sourcetype_is_not_a_location():
    entries = minimap_entries(MANIFEST)
    confirmed = confirm_entries(entries, {"stream:smtp": 0, "stream:dns": 12})
    assert [item["sourcetype"] for item in confirmed] == ["stream:dns"]


def test_sent_message_links_to_confirmed_smtp_and_becomes_a_sizing_step():
    confirmed = confirm_entries(minimap_entries(MANIFEST), {"stream:smtp": 40})
    hits = link_goal("sent_message", ("person", "email_address"), confirmed)
    assert hits[0]["evidence"] == "outbound_message_metadata"
    assert hits[0]["sourcetype"] == "stream:smtp"
    graph = SemanticGoalGraph(
        id="g",
        request_id="req",
        objective="mail",
        variables=[
            SemanticVariable(id="sender", entity_type="person"),
            SemanticVariable(id="recipient", entity_type="email_address"),
        ],
        relations=[SemanticRelationGoal(
            id="goal-1", subject="sender", relation="sent_message", object="recipient", goal_class="behavior",
        )],
    )
    graph.data_locations = hits
    steps = SemanticGoalPlanner._with_behavior_sizing([], graph)
    assert steps[0].mode == "SIZING"
    assert steps[0].operation_id == "outbound_message_metadata"
    assert steps[0].input_bindings == {}


def test_linked_operation_searches_the_confirmed_sourcetype():
    adapter = SplunkLiveAdapter(
        splunk_url="http://offline",
        index="botsv2",
        manifest_path="configs/splunk_botsv2.yaml",
        verify_ssl=False,
    )
    spl, _, _ = adapter._build_spl("outbound_message_metadata", None, WINDOW, None, 10)
    assert 'sourcetype="stream:smtp"' in spl
