from hunting.contracts.hunt import HuntState
from hunting.contracts.semantic_graph import LogicalPlan


def test_hunt_state_can_carry_generic_logical_plan() -> None:
    state = HuntState()
    state.semantic_logical_plan = LogicalPlan("p", "g", "provider")
    assert state.semantic_logical_plan.to_dict()["goal_graph_id"] == "g"
