from types import SimpleNamespace

from hunting.contracts.hunt_spec import AnswerContract, HuntSpec
from hunting.planner.adaptive import AdaptiveOperationPlanner


def test_adaptive_planner_selects_capability_without_native_query_syntax():
    spec = HuntSpec(
        question="Find the installed software version",
        answer_contract=AnswerContract("software_version", ("ProductVersion",)),
    )
    descriptor = SimpleNamespace(operations=(
        SimpleNamespace(id="search_text"),
        SimpleNamespace(id="inventory_search", semantic_intents=("software_version",)),
        SimpleNamespace(id="web_search"),
    ))

    decision = AdaptiveOperationPlanner().choose(spec, descriptor)

    assert decision.operation_id == "inventory_search"
    assert "ProductVersion" in decision.required_fields


def test_adaptive_planner_reports_ready_when_required_fields_are_observed():
    spec = HuntSpec(
        question="Find version",
        answer_contract=AnswerContract("software_version", ("ProductVersion",)),
    )
    decision = AdaptiveOperationPlanner().choose(
        spec,
        SimpleNamespace(operations=(SimpleNamespace(id="search_text"),)),
        observed_fields=["ProductVersion"],
    )

    assert decision.ready_for_answer is True
    assert decision.operation_id is None


def test_adaptive_planner_uses_llm_for_undeclared_provider_operation():
    spec = HuntSpec(
        question="Find the answer",
        answer_contract=AnswerContract("novel_answer", ("custom_field",)),
    )
    calls: list[str] = []

    def llm(prompt: str) -> str:
        calls.append(prompt)
        return '{"operation_id":"custom_search","required_fields":["custom_field"],"search_terms":["artifact"],"reason":"schema-compatible search"}'

    decision = AdaptiveOperationPlanner(llm_generator=llm).choose(
        spec,
        SimpleNamespace(operations=(
            SimpleNamespace(id="search_text"),
            SimpleNamespace(id="custom_search"),
        )),
    )

    assert decision.operation_id == "custom_search"
    assert decision.search_terms == ("artifact",)
    assert calls
