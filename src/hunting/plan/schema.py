"""The hand-off contract between this project (Prepare) and the team that executes hunts (Execute/Act).

A ``HuntPlan`` is data, not code: stages of the attack, the observables each stage leaves, read-only Splunk searches
written with placeholders (no internal index, host or field names are known here), the limits to respect and the
conditions at which to stop. The executing team answers with a ``ResultBundle``; ``verify`` decides what happens next.

Both documents carry ``schema_version``; ``HuntPlan.model_json_schema()`` is published as ``plan.schema.json``.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator

SCHEMA_VERSION = "1"
RESULT_SCHEMA_VERSION = "1"

DataSource = Literal["web", "proxy", "endpoint", "network", "dns", "auth", "app"]
Significance = Literal["context", "indicator", "impact"]
StopWhen = Literal["zero_hits", "hits_ge", "no_data", "truncated", "error", "budget_exceeded"]
StopAction = Literal["continue", "stop_stage", "stop_plan", "escalate", "collect_data", "narrow"]
Origin = Literal["core", "llm"]  # core: built by code from the intel (model-independent); llm: a suggestion a person must accept
MAX_LOOKBACK_DAYS = 90
ObservableKind = Literal[
    "http_path", "http_param", "http_header", "uri_pattern", "user_agent", "command", "file_name", "file_path", "oast_domain",
    "url_scheme", "process", "network", "log_message", "other",
]


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Observable(_Strict):
    kind: ObservableKind
    value: str = Field(min_length=2, max_length=300)
    basis: Literal["from_poc", "inferred"] = "inferred"  # from_poc: the literal appears in the collected PoC/CVE text
    note: str = ""


class Query(_Strict):
    query_id: str
    purpose: str
    data_source: DataSource
    language: Literal["spl"] = "spl"
    spl: str  # placeholders: {{INDEX_*}}, {{EARLIEST}}, {{LATEST}}, {{MAX_ROWS}}
    expected_fields: list[str] = Field(default_factory=list)
    benign_notes: str = ""
    role: Literal["detect", "coverage", "pivot"] = "detect"
    grounded: bool | None = None  # a quoted literal of the search appears in the collected PoC/CVE text
    origin: Origin = "core"


class StopCondition(_Strict):
    when: StopWhen
    threshold: int | None = None  # for hits_ge
    action: StopAction
    note: str = ""


class Stage(_Strict):
    stage_id: str
    name: str
    phase: str  # ATT&CK tactic name, lower-case with underscores
    technique_ids: list[str] = Field(default_factory=list)
    significance: Significance
    description: str
    observables: list[Observable] = Field(default_factory=list)
    data_sources: list[DataSource] = Field(default_factory=list)
    queries: list[Query] = Field(default_factory=list)
    depends_on: list[str] = Field(default_factory=list)
    stop_conditions: list[StopCondition] = Field(default_factory=list)
    origin: Origin = "core"

    @field_validator("technique_ids")
    @classmethod
    def _techniques(cls, value: list[str]) -> list[str]:
        import re

        return [v.upper() for v in value if re.fullmatch(r"(?i)T\d{4}(\.\d{3})?", v.strip())]


class Applicability(_Strict):
    products: list[str] = Field(default_factory=list)
    affected_versions: list[str] = Field(default_factory=list)
    preconditions: list[str] = Field(default_factory=list)
    not_applicable_if: list[str] = Field(default_factory=list)


def parse_iso(value: str) -> datetime:
    return datetime.fromisoformat(str(value).strip().replace("Z", "+00:00")).astimezone(timezone.utc)


def lookback_delta(value: str) -> timedelta:
    match = re.fullmatch(r"([1-9]\d{0,3})([mhdw])", str(value).strip())
    if not match:
        raise ValueError(f"lookback {value!r} must look like 30m, 12h, 14d or 2w")
    amount, unit = int(match.group(1)), match.group(2)
    names = {"m": "minutes", "h": "hours", "d": "days", "w": "weeks"}
    return timedelta(**{names[unit]: amount})


class Limits(_Strict):
    """Bounds every search must respect. A search without a bounded time range reads the whole index, so the range is
    always explicit: a relative lookback (at most 90 days) or an absolute window (at most 90 days wide)."""

    lookback: str = "14d"
    window: dict[str, str] | None = None  # {"earliest": ISO-8601, "latest": ISO-8601}; set by refine iterations
    max_rows_per_query: int = Field(default=200, ge=1, le=1000)
    max_queries: int = Field(default=30, ge=1, le=100)
    query_timeout_s: int = Field(default=300, ge=10, le=1800)
    total_runtime_s: int = Field(default=3600, ge=60, le=14400)
    max_iterations: int = Field(default=3, ge=1, le=10)
    read_only: bool = True

    @field_validator("lookback")
    @classmethod
    def _lookback(cls, value: str) -> str:
        if lookback_delta(value) > timedelta(days=MAX_LOOKBACK_DAYS):
            raise ValueError(f"lookback {value!r} is longer than {MAX_LOOKBACK_DAYS} days")
        return value.strip()

    @field_validator("window")
    @classmethod
    def _window(cls, value: dict[str, str] | None) -> dict[str, str] | None:
        if value is None:
            return None
        if set(value) != {"earliest", "latest"}:
            raise ValueError('window needs exactly "earliest" and "latest"')
        start, end = parse_iso(value["earliest"]), parse_iso(value["latest"])
        if not start < end:
            raise ValueError("window: earliest must be before latest")
        if end - start > timedelta(days=MAX_LOOKBACK_DAYS):
            raise ValueError(f"window is wider than {MAX_LOOKBACK_DAYS} days")
        return value


class PocRef(_Strict):
    name: str
    url: str
    stars: int
    archived: bool = False


class IntelRef(_Strict):
    cve_ids: list[str] = Field(default_factory=list)
    summary: str = ""
    severity: str = ""
    cvss: float | None = None
    kev: bool = False
    poc_repos: list[PocRef] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


class VerificationSpec(_Strict):
    result_schema_version: str = RESULT_SCHEMA_VERSION
    escalate_if: str = "một truy vấn của giai đoạn 'impact' trả về ít nhất một sự kiện"
    accept_clear_if: str = (
        "mọi truy vấn phát hiện đã chạy (status ok, không bị cắt), mọi truy vấn độ phủ đều có dữ liệu "
        "và không giai đoạn nào có sự kiện"
    )
    refine_if: str = "có sự kiện ở giai đoạn context/indicator hoặc kết quả bị cắt: pivot theo các giá trị quan sát được"
    collect_data_if: str = "truy vấn độ phủ không có dữ liệu ở một nguồn mà kế hoạch cần"


class RunbookStep(_Strict):
    """One step of the procedure people follow. Generated by code from the plan (never by an LLM)."""

    step_id: str
    kind: Literal["precheck", "bind", "coverage", "query", "gate", "handoff", "decision"]
    title: str
    do: list[str] = Field(default_factory=list)
    query_ids: list[str] = Field(default_factory=list)
    record: list[str] = Field(default_factory=list)
    stop_if: list[str] = Field(default_factory=list)
    human_decision: str = ""  # the question only a person may answer; the tool never answers it
    optional: bool = False  # suggested by the LLM: runs only if the reviewer accepted it


class Provenance(_Strict):
    created_at: str
    tool_version: str
    llm_model: str | None = None
    peak_used: bool = False
    input_digest: str = ""
    core_digest: str = ""  # sha256 of the code-built part: identical for any LLM (or none) given the same intel
    plan_digest: str = ""  # sha256 of everything a reviewer approves; results must quote it
    untrusted_input: bool = True  # PoC text is internet content; it is data for the planner, never instructions
    poc_executed: bool = False  # always false: PoCs are read, never cloned, installed or run
    internal_data_used: bool = False  # always false: Prepare never touches internal systems


class PeakNotes(_Strict):
    able_markdown: str = ""
    hunt_plan_markdown: str = ""
    notes: list[str] = Field(default_factory=list)


class HuntPlan(_Strict):
    schema_version: str = SCHEMA_VERSION
    plan_id: str
    iteration: int = 1
    parent_plan_id: str | None = None
    title: str
    hypothesis: str
    applicability: Applicability = Field(default_factory=Applicability)
    stages: list[Stage]
    coverage_probes: list[Query] = Field(default_factory=list)
    limits: Limits = Field(default_factory=Limits)
    stop_rules: list[str] = Field(default_factory=list)
    verification: VerificationSpec = Field(default_factory=VerificationSpec)
    intel: IntelRef = Field(default_factory=IntelRef)
    provenance: Provenance
    peak: PeakNotes | None = None
    dropped: list[str] = Field(default_factory=list)  # queries removed by validation, with the reason
    leads: list[dict[str, Any]] = Field(default_factory=list)  # refine iterations: values that justify the new queries
    runbook: list[RunbookStep] = Field(default_factory=list)
    manual_todo: list[str] = Field(default_factory=list)  # what the code could not decide and a person has to supply

    def all_queries(self) -> list[Query]:
        return [*self.coverage_probes, *[q for s in self.stages for q in s.queries]]


# ---------------------------------------------------------------------------------------------
# What the executing team sends back
# ---------------------------------------------------------------------------------------------

class QueryResult(_Strict):
    query_id: str
    status: Literal["ok", "error", "timeout", "skipped"]
    row_count: int = 0
    truncated: bool = False
    earliest: str | None = None
    latest: str | None = None
    error: str | None = None
    sample: list[dict[str, Any]] = Field(default_factory=list)  # at most 25 rows


class ResultBundle(_Strict):
    schema_version: str = RESULT_SCHEMA_VERSION
    plan_id: str
    iteration: int = 1
    executor: str = ""  # free text: team / tool; not interpreted
    executed_at: str = ""
    plan_digest: str = ""  # copy of plan.provenance.plan_digest: proves the approved plan is the one that ran
    approved_by: str = ""  # the person who reviewed and approved the plan before it ran
    approved_at: str = ""
    accepted_llm_stages: list[str] = Field(default_factory=list)  # ids of LLM suggestions the reviewer accepted and ran
    results: list[QueryResult]
