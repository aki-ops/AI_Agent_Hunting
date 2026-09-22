"""PEAK Execute decision shared by the PoC agent and the hypothesis engine."""
from hunting.peak import peak_execute_cycle


def test_peak_cycle_escalates_when_observations_exist():
    cycle = peak_execute_cycle(observation_count=3)
    assert cycle[0]["phase"] == "analyze"
    assert cycle[-1]["action"] == "escalate_ir"
    assert cycle[-1]["ir_escalate"] is True


def test_peak_cycle_allows_one_refine_when_empty():
    cycle = peak_execute_cycle(observation_count=0)
    phases = [item["phase"] for item in cycle]
    assert phases == ["analyze", "refine", "stop"]
    assert cycle[-1]["ir_escalate"] is False
