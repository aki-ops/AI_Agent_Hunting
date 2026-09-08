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


def test_adaptive_planner_does_not_treat_schema_only_fields_as_observed():
    """A provider schema is capability metadata, not answer evidence."""
    spec = HuntSpec(
        question="Find version",
        answer_contract=AnswerContract("software_version", ("ProductVersion",)),
    )
    decision = AdaptiveOperationPlanner().choose(
        spec,
        SimpleNamespace(operations=(SimpleNamespace(id="search_text"),)),
        # The engine must pass only fields with non-empty values here.  An
        # empty set models the case where discover_schema listed ProductVersion
        # but no event contained a ProductVersion value.
        observed_fields=[],
    )

    assert decision.ready_for_answer is False
    assert decision.validation_result != "FIELDS_SATISFIED"


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


def test_compatible_operations_filters_by_output_fields_and_excludes_forbidden():
    from hunting.planner.adaptive import compatible_operations

    descriptor = SimpleNamespace(operations=(
        SimpleNamespace(id="resolve_person_to_account", semantic_intents=(), output_fields=("user", "account")),
        SimpleNamespace(id="resolve_account_to_endpoint", semantic_intents=(), output_fields=("host", "endpoint")),
        SimpleNamespace(id="find_web_activity", semantic_intents=(), output_fields=("site", "uri")),
        SimpleNamespace(id="find_dns_activity", semantic_intents=(), output_fields=("query", "domain")),
        SimpleNamespace(id="cdb_network_connections", semantic_intents=(), output_fields=("dest_ip", "dest_port")),
        SimpleNamespace(id="resolve_account_to_email", semantic_intents=(), output_fields=("sender_email", "receiver_email")),
        SimpleNamespace(id="find_process_from_endpoint", semantic_intents=("software_version",), output_fields=("ProductVersion", "FileVersion", "Version")),
        SimpleNamespace(id="cdb_file_search", semantic_intents=(), output_fields=("TargetFilename", "ProductVersion")),
    ))

    compat = compatible_operations("software_version", descriptor)
    compat_ids = [op.id for op in compat]

    # Must contain version-capable operations
    assert "find_process_from_endpoint" in compat_ids
    assert "cdb_file_search" in compat_ids

    # Strictly must NOT contain identity, email, DNS, or network operations
    assert "resolve_person_to_account" not in compat_ids
    assert "resolve_account_to_endpoint" not in compat_ids
    assert "find_web_activity" not in compat_ids
    assert "find_dns_activity" not in compat_ids
    assert "cdb_network_connections" not in compat_ids
    assert "resolve_account_to_email" not in compat_ids


def test_adaptive_planner_excludes_incompatible_operations_for_software_version():
    spec = HuntSpec(
        question="Find version of Tor Browser",
        answer_contract=AnswerContract("software_version", ("ProductVersion",)),
    )
    descriptor = SimpleNamespace(operations=(
        SimpleNamespace(id="resolve_person_to_account", output_fields=("user",)),
        SimpleNamespace(id="find_web_activity", output_fields=("site",)),
        SimpleNamespace(id="cdb_file_search", output_fields=("ProductVersion",)),
    ))

    decision = AdaptiveOperationPlanner().choose(spec, descriptor)
    assert decision.operation_id == "cdb_file_search"

