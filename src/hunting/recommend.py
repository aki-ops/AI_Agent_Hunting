"""Decision support: turn a finished PoC hunt into a recommendation for the human hunter.

The disposition is computed by fixed rules from the evidence and the data coverage.
The LLM (judge) can move the disposition by at most one step and never creates evidence;
the advisor adds next steps and questions drawn from the PEAK hunt plan. A human always
makes the final call: every recommendation carries ``decision_required = True``.

Dispositions
------------
ESCALATE_TO_IR           complete chain matched and the judge agrees it looks malicious
INVESTIGATE_FURTHER      hits exist but the chain is partial or the context is unproven
TUNE_POC_OR_CLOSE        complete chain matched but the judge sees legitimate activity
COLLECT_DATA_THEN_RERUN  no hits and a required telemetry source is absent in the window
CLOSE_WITH_CAVEAT        no hits and the sources exist; only literal predicates were tested
"""
from __future__ import annotations

import json
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Callable

from hunting.peak import able_drive
from hunting.poc.agent import PocHuntResult
from hunting.poc.judge import FALSE_POSITIVE, TRUE_POSITIVE, Judgment
from hunting.poc.models import PoC

ESCALATE = "ESCALATE_TO_IR"
INVESTIGATE = "INVESTIGATE_FURTHER"
TUNE = "TUNE_POC_OR_CLOSE"
COLLECT = "COLLECT_DATA_THEN_RERUN"
CLOSE = "CLOSE_WITH_CAVEAT"

DISPOSITION_LABEL = {
    ESCALATE: "Chuyển IR (escalate)",
    INVESTIGATE: "Điều tra sâu hơn",
    TUNE: "Tinh chỉnh PoC hoặc đóng (nghi false positive)",
    COLLECT: "Bổ sung telemetry rồi chạy lại",
    CLOSE: "Đóng, kèm cảnh báo giới hạn",
}

_OUTCOME_FIELDS = ("status", "action", "result", "response", "outcome")
_PIVOT_FIELDS = ("host", "user", "ip", "domain")
_SAMPLE_KEYS = ("timestamp", "host", "user", "image", "cmdline", "ip", "domain", "action")


@dataclass
class StepEvidence:
    step_id: str
    description: str
    predicate: str
    source_kind: str
    row_count: int
    source_rows_in_window: int | None  # None = coverage cannot be checked
    source_rows_in_scope: int | None = None  # same, restricted to the host the PoC scope implies
    matched_total: int = 0  # rows passing the operator among those scanned (row_count is capped)
    scan_truncated: bool = False  # scan hit its row limit: matched_total is a lower bound

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


@dataclass
class EvidenceSummary:
    window: str
    steps: list[StepEvidence]
    matched_steps: int
    total_steps: int
    observations: int
    first_seen: str | None
    last_seen: str | None
    pivots: dict[str, list[tuple[str, int]]]
    top_values: dict[str, list[tuple[str, int]]]
    samples: list[dict[str, Any]]
    scope: dict[str, Any] = field(default_factory=dict)  # filters added on top of the predicates (from ABLE)
    source_breakdown: dict[str, list[tuple[str, int]]] = field(default_factory=dict)  # event types searched
    source_hosts: dict[str, list[tuple[str, int]]] = field(default_factory=dict)  # who really logs a source
    unscoped_probe: dict[str, int] | None = None  # same PoC re-run without the ABLE host filter

    @property
    def scope_empty_sources(self) -> list[str]:
        """Sources with data in the window but none inside the host scope the PoC implies."""
        return sorted({s.source_kind for s in self.steps if s.source_rows_in_window and s.source_rows_in_scope == 0})

    @property
    def capped_steps(self) -> list[StepEvidence]:
        return [s for s in self.steps if s.matched_total > s.row_count or s.scan_truncated]

    @property
    def chain_complete(self) -> bool:
        return self.total_steps > 0 and self.matched_steps == self.total_steps

    @property
    def missing_sources(self) -> list[str]:
        return sorted({s.source_kind for s in self.steps if s.source_rows_in_window == 0})

    @property
    def unverifiable_sources(self) -> list[str]:
        return sorted({s.source_kind for s in self.steps if s.source_rows_in_window is None})

    def to_dict(self) -> dict[str, Any]:
        return {
            "window": self.window,
            "steps": [s.to_dict() for s in self.steps],
            "matched_steps": self.matched_steps,
            "total_steps": self.total_steps,
            "observations": self.observations,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "pivots": {k: [list(x) for x in v] for k, v in self.pivots.items()},
            "top_values": {k: [list(x) for x in v] for k, v in self.top_values.items()},
            "samples": self.samples,
            "chain_complete": self.chain_complete,
            "missing_sources": self.missing_sources,
            "unverifiable_sources": self.unverifiable_sources,
            "scope": self.scope,
            "scope_empty_sources": self.scope_empty_sources,
            "capped_steps": [s.step_id for s in self.capped_steps],
            "source_breakdown": {k: [list(x) for x in v] for k, v in self.source_breakdown.items()},
            "source_hosts": {k: [list(x) for x in v] for k, v in self.source_hosts.items()},
            "unscoped_probe": self.unscoped_probe,
        }


@dataclass
class Option:
    action: str
    rank: int
    rationale: str

    def to_dict(self) -> dict[str, Any]:
        return dict(self.__dict__)


@dataclass
class Recommendation:
    poc_id: str
    poc_name: str
    disposition: str
    confidence: str  # HIGH | MEDIUM | LOW
    headline: str
    reasons: list[str]
    caveats: list[str]
    options: list[Option]
    evidence: EvidenceSummary
    judge: Judgment | None = None
    next_steps: list[dict[str, str]] = field(default_factory=list)
    questions_for_hunter: list[str] = field(default_factory=list)
    risks: list[str] = field(default_factory=list)
    decision_required: bool = True
    advisor_note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "poc_id": self.poc_id,
            "poc_name": self.poc_name,
            "disposition": self.disposition,
            "disposition_label": DISPOSITION_LABEL[self.disposition],
            "confidence": self.confidence,
            "headline": self.headline,
            "reasons": self.reasons,
            "caveats": self.caveats,
            "options": [o.to_dict() for o in self.options],
            "evidence": self.evidence.to_dict(),
            "judge": self.judge.to_dict() if self.judge else None,
            "next_steps": self.next_steps,
            "questions_for_hunter": self.questions_for_hunter,
            "risks": self.risks,
            "decision_required": self.decision_required,
            "advisor_note": self.advisor_note,
        }


# ---------------------------------------------------------------------------
# Evidence summary (deterministic)
# ---------------------------------------------------------------------------

def _counter(values: list[Any], limit: int = 5) -> list[tuple[str, int]]:
    cleaned = [str(v) for v in values if v not in (None, "", "-")]
    return Counter(cleaned).most_common(limit)


def summarize_evidence(poc: PoC, result: PocHuntResult, adapter: Any, window: str) -> EvidenceSummary:
    primary_ids = {s.step_id for s in poc.steps}
    steps: list[StepEvidence] = []
    presence_cache: dict[str, int | None] = {}
    scope_cache: dict[str, int | None] = {}
    breakdown: dict[str, list[tuple[str, int]]] = {}
    hosts_by_source: dict[str, list[tuple[str, int]]] = {}
    checker = getattr(adapter, "source_presence", None)
    break_fn = getattr(adapter, "source_breakdown", None)
    hosts_fn = getattr(adapter, "source_top_hosts", None)
    drive = able_drive(poc.actor, poc.behavior, poc.location, poc.evidence)  # the same filters the executor applies
    scope = {"host": drive.host, "actor": drive.actor, "observables": list(drive.observables)}
    for step in poc.steps:
        kind = step.source_kind
        if kind not in presence_cache:
            presence_cache[kind] = checker(window, kind) if callable(checker) else None
            scope_cache[kind] = presence_cache[kind]
            if drive.host and callable(checker):
                scope_cache[kind] = checker(window, kind, host=drive.host)
            if callable(break_fn):
                breakdown[kind] = break_fn(window, kind)
            if drive.host and callable(hosts_fn) and presence_cache[kind] and scope_cache[kind] == 0:
                hosts_by_source[kind] = hosts_fn(window, kind)
        hits = [r for r in result.step_results if r.step_id == step.step_id and not r.used_fallback]
        rows_hit = max((r.row_count for r in hits), default=0)
        steps.append(StepEvidence(
            step_id=step.step_id,
            description=step.description,
            predicate=f"{step.target_field} {step.op.value} {step.value}",
            source_kind=kind,
            row_count=rows_hit,
            source_rows_in_window=presence_cache[kind],
            source_rows_in_scope=scope_cache[kind],
            matched_total=max((r.matched_total for r in hits), default=0),
            scan_truncated=any(r.scan_truncated for r in hits),
        ))
    rows = [row for r in result.step_results if r.step_id in primary_ids for row in r.rows]
    unique: dict[Any, dict[str, Any]] = {}
    for row in rows:
        unique.setdefault(row.get("id", id(row)), row)
    rows = list(unique.values())
    stamps = sorted(str(r["timestamp"]) for r in rows if r.get("timestamp"))
    pivots = {name: _counter([r.get(name) for r in rows]) for name in _PIVOT_FIELDS}
    top_values: dict[str, list[tuple[str, int]]] = {}
    for step in poc.steps:
        top_values.setdefault(step.target_field, _counter([r.get(step.target_field) for r in rows]))
    samples = [{k: r.get(k) for k in _SAMPLE_KEYS if r.get(k) not in (None, "")} for r in rows[:5]]
    return EvidenceSummary(
        window=window,
        steps=steps,
        matched_steps=sum(1 for s in steps if s.row_count > 0),
        total_steps=len(steps),
        observations=len(rows),
        first_seen=stamps[0] if stamps else None,
        last_seen=stamps[-1] if stamps else None,
        pivots={k: v for k, v in pivots.items() if v},
        top_values={k: v for k, v in top_values.items() if v},
        samples=samples,
        scope=scope,
        source_breakdown={k: v for k, v in breakdown.items() if v},
        source_hosts=hosts_by_source,
    )


# ---------------------------------------------------------------------------
# Disposition rules (deterministic)
# ---------------------------------------------------------------------------

def decide(poc: PoC, ev: EvidenceSummary, judge: Judgment | None) -> Recommendation:
    reasons: list[str] = []
    caveats: list[str] = []
    judge_ok = judge is not None and judge.confidence >= 0.7
    # Without a step on an outcome field (status/action) a hit shows attempted activity, not success.
    outcome_observed = any(step.target_field.lower() in _OUTCOME_FIELDS for step in poc.steps)

    if ev.observations > 0:
        reasons.append(f"{ev.matched_steps}/{ev.total_steps} bước PoC có kết quả, tổng {ev.observations} bản ghi khớp.")
        if ev.first_seen:
            reasons.append(f"Khoảng thời gian hit: {ev.first_seen} → {ev.last_seen}.")
        missing = [s for s in ev.steps if s.row_count == 0]
        if ev.chain_complete:
            if judge_ok and judge.verdict == TRUE_POSITIVE:
                disposition, confidence = ESCALATE, "HIGH" if judge.confidence >= 0.8 else "MEDIUM"
                reasons.append(f"Judge (advisory) đánh giá TRUE_POSITIVE, độ tin cậy {judge.confidence:.2f}.")
                if not outcome_observed and confidence == "HIGH":
                    confidence = "MEDIUM"
                    reasons.append("Độ tin cậy bị hạ xuống MEDIUM: PoC không có bước nào kiểm tra kết quả (status/action) nên chưa chứng minh được tấn công thành công.")
            elif judge_ok and judge.verdict == FALSE_POSITIVE:
                disposition, confidence = TUNE, "MEDIUM"
                reasons.append(f"Judge (advisory) đánh giá FALSE_POSITIVE, độ tin cậy {judge.confidence:.2f}.")
            else:
                disposition, confidence = INVESTIGATE, "MEDIUM"
                if judge is None:
                    caveats.append("Không có judge: chuỗi khớp đủ nhưng chưa ai đánh giá ngữ cảnh (parent process, payload, kết quả).")
                else:
                    reasons.append(
                        f"Judge (advisory) trả {judge.verdict} ({judge.confidence:.2f}): chuỗi khớp đủ nhưng ngữ cảnh chưa đủ để kết luận."
                    )
        else:
            disposition, confidence = INVESTIGATE, "LOW" if judge is None else "MEDIUM"
            for s in missing:
                if s.source_rows_in_window == 0:
                    note = "không có bản ghi nguồn trong cửa sổ"
                elif s.source_rows_in_scope == 0:
                    note = f"nguồn có dữ liệu nhưng không có bản ghi nào của host `{ev.scope.get('host')}` (phạm vi lọc)"
                else:
                    note = "nguồn có dữ liệu nhưng predicate không khớp"
                reasons.append(f"Bước `{s.step_id}` ({s.predicate}) không khớp: {note}.")
        caveats.append("Khớp predicate literal chứng minh có hoạt động tương ứng trong dữ liệu; tự nó chưa chứng minh thành công hay tác động (cần xem response/status và hậu quả trên host).")
    else:
        reasons.append("Không có bản ghi nào khớp bất kỳ bước nào của PoC trong cửa sổ đã chạy.")
        if ev.missing_sources or ev.scope_empty_sources:
            disposition, confidence = COLLECT, "HIGH"
            for kind in ev.missing_sources:
                reasons.append(f"Nguồn telemetry `{kind}` có 0 bản ghi trong cửa sổ: không có dữ liệu để săn, kết quả rỗng KHÔNG có nghĩa là sạch.")
            for kind in ev.scope_empty_sources:
                in_window = next(s.source_rows_in_window for s in ev.steps if s.source_kind == kind)
                who = ", ".join(f"{h} ({n:,})" for h, n in ev.source_hosts.get(kind, [])) or "host khác"
                reasons.append(
                    f"Nguồn `{kind}` có {in_window:,} bản ghi trong cửa sổ nhưng 0 bản ghi của host `{ev.scope.get('host')}` "
                    f"(host lọc suy ra từ `able.location`); host thực sự ghi nguồn này: {who}."
                )
            probe = ev.unscoped_probe
            if not ev.missing_sources and probe is not None:
                if probe["observations"] > 0:
                    disposition, confidence = INVESTIGATE, "LOW"
                    reasons.append(
                        f"Chạy lại cùng PoC KHÔNG lọc host: {probe['observations']} bản ghi khớp ({probe['matched_steps']}/{probe['total_steps']} bước) "
                        "ở host khác. PoC không khớp trên host đã nêu nhưng có dấu hiệu ở nơi khác; cần người săn xem lại phạm vi."
                    )
                else:
                    disposition, confidence = CLOSE, "MEDIUM"
                    reasons.append(
                        "Chạy lại cùng PoC KHÔNG lọc host: 0 bản ghi khớp ở bất kỳ host nào trong cửa sổ. "
                        "Dữ liệu hiện có không chứa dấu hiệu này ở đâu cả, nhưng phát hiện này chỉ đúng với predicate literal, "
                        "loại sự kiện đang có và cửa sổ đã quét; host nêu trong PoC không hề ghi nguồn này nên PoC chưa từng được thử trên host đó."
                    )
            elif not ev.missing_sources:
                reasons.append("Phạm vi tìm kiếm không có dữ liệu nên kết quả rỗng KHÔNG có nghĩa là sạch.")
        elif ev.unverifiable_sources:
            disposition, confidence = CLOSE, "LOW"
            caveats.append(f"Không kiểm tra được độ phủ của nguồn: {', '.join(ev.unverifiable_sources)}.")
        else:
            disposition, confidence = CLOSE, "MEDIUM"
            reasons.append("Các nguồn telemetry cần thiết có dữ liệu trong cửa sổ nhưng predicate không khớp.")
        caveats.append("Nguồn có dữ liệu chưa chắc chứa đúng loại sự kiện cần tìm (ví dụ chỉ có đăng nhập thành công, không có đăng nhập thất bại); hệ thống chưa tự đối chiếu với predicate.")
        for kind, items in ev.source_breakdown.items():
            listing = ", ".join(f"{name} ({n:,})" for name, n in items)
            caveats.append(
                f"Loại sự kiện của nguồn `{kind}` trong cửa sổ (mọi host): {listing}. "
                "Hãy xác nhận loại sự kiện mà PoC cần (ví dụ đăng nhập thất bại 4625) có trong danh sách này."
            )
        caveats.append("PoC chỉ kiểm tra các predicate literal đã khai báo; biến thể (obfuscation, tên khác, field khác) không được thử.")
        caveats.append(f"Chỉ quét cửa sổ {ev.window}; hoạt động ngoài cửa sổ không được xem.")

    if ev.scope.get("host") or ev.scope.get("actor") or ev.scope.get("observables"):
        extra = []
        if ev.scope.get("host"):
            extra.append(f"host = `{ev.scope['host']}`")
        if ev.scope.get("actor"):
            extra.append(f"tài khoản chứa `{ev.scope['actor']}`")
        if ev.scope.get("observables"):
            extra.append("chuỗi bổ sung (AND) " + ", ".join(f"`{o}`" for o in ev.scope["observables"]))
        caveats.append(
            "Ngoài predicate của từng bước, truy vấn còn bị giới hạn bởi các điều kiện suy ra từ ABLE của PoC: "
            + "; ".join(extra) + "."
        )
    for s in ev.capped_steps:
        bound = "ít nhất " if s.scan_truncated else ""
        caveats.append(
            f"Bước `{s.step_id}`: chỉ hiển thị {s.row_count} bản ghi trong {bound}{s.matched_total} bản ghi khớp"
            + (" (quét đã dừng ở giới hạn hàng nên tổng thực tế có thể lớn hơn)." if s.scan_truncated else ".")
        )

    options = _options(disposition, poc, ev)
    headline = f"{DISPOSITION_LABEL[disposition]} — độ tin cậy {confidence}"
    return Recommendation(
        poc_id=poc.poc_id, poc_name=poc.name, disposition=disposition, confidence=confidence,
        headline=headline, reasons=reasons, caveats=caveats, options=options, evidence=ev, judge=judge,
    )


def _options(chosen: str, poc: PoC, ev: EvidenceSummary) -> list[Option]:
    hosts = ", ".join(h for h, _ in ev.pivots.get("host", [])[:3]) or "host liên quan"
    catalogue = {
        ESCALATE: f"Chuyển gói bằng chứng cho IR và giữ nguyên log gốc; trước khi cô lập, xác nhận vai trò thật của {hosts} (nạn nhân, nguồn tấn công hay sensor ghi log).",
        INVESTIGATE: (
            f"Bỏ hoặc sửa lọc host `{ev.scope.get('host')}` trong `able.location` rồi chạy lại; "
            f"{ev.unscoped_probe['observations']} bản ghi khớp ở host khác (xem thư mục `unscoped_probe/`)."
            if ev.unscoped_probe and ev.unscoped_probe["observations"] > 0 and ev.observations == 0
            else f"Pivot theo {hosts}: xem process/network/auth cùng khoảng {ev.first_seen or 'thời gian hit'}; xác định bước nào của chuỗi còn thiếu bằng chứng."
        ),
        TUNE: "Xem mẫu bản ghi, thêm điều kiện loại trừ hoạt động hợp lệ (parent, signer, tài khoản dịch vụ) rồi chạy lại; đóng nếu xác nhận là noise.",
        COLLECT: (
            f"Bật/nạp telemetry còn thiếu ({', '.join(ev.missing_sources)}) rồi chạy lại cùng PoC."
            if ev.missing_sources
            else (
                f"Kiểm tra phạm vi host của PoC (`{ev.scope.get('host')}`): nguồn {', '.join(ev.scope_empty_sources)} có dữ liệu "
                "nhưng ở host khác; sửa `able.location` hoặc bổ sung telemetry của host đó rồi chạy lại."
                if ev.scope_empty_sources
                else "Nguồn đã có dữ liệu; chỉ cần nếu muốn bổ sung loại telemetry khác (vd. sysmon, network flow) để bắt biến thể ngoài predicate."
            )
        ),
        CLOSE: "Đóng hunt, ghi rõ giới hạn; cân nhắc mở rộng cửa sổ hoặc biến thể predicate trước khi coi là sạch.",
    }
    order = [chosen] + [d for d in (ESCALATE, INVESTIGATE, TUNE, COLLECT, CLOSE) if d != chosen and _applicable(d, ev)]
    return [Option(action=d, rank=i + 1, rationale=catalogue[d]) for i, d in enumerate(order)]


def _applicable(disposition: str, ev: EvidenceSummary) -> bool:
    if ev.observations > 0:
        return disposition in (ESCALATE, INVESTIGATE, TUNE)
    if ev.unscoped_probe and ev.unscoped_probe["observations"] > 0:
        return disposition in (INVESTIGATE, COLLECT, CLOSE)
    return disposition in (COLLECT, CLOSE)


# ---------------------------------------------------------------------------
# Advisor: next steps from the PEAK hunt plan (LLM, advisory only)
# ---------------------------------------------------------------------------

ADVISOR_PROMPT = """You are a senior threat hunter advising the analyst who will make the decision.
A deterministic executor already ran the hunt. You must not invent evidence or change facts.
Use ONLY the facts below. Reply in Vietnamese WITH full diacritics (tiếng Việt có dấu), as STRICT JSON (no markdown):
{{"next_steps": [{{"action": "...", "why": "..."}}], "questions_for_hunter": ["..."], "risks": ["..."]}}
At most 5 items per list. Next steps must be concrete pivots or checks the analyst can do with the
available telemetry (or name the telemetry that is missing). Use the PEAK hunt plan for guidance.
Fact: EQUALS, CONTAINS, STARTS_WITH and ENDS_WITH comparisons are case-insensitive; do not suggest case variants.

HYPOTHESIS: {hypothesis}
DISPOSITION COMPUTED BY RULES: {disposition} (confidence {confidence})
REASONS:
{reasons}

EVIDENCE SUMMARY (JSON):
{evidence}

PEAK ABLE TABLE:
{able}

PEAK HUNT PLAN (may be truncated):
{plan}
"""


def _json_object(text: str) -> dict[str, Any] | None:
    """Parse the first JSON object in an LLM reply (tolerates code fences and prose)."""
    text = re.sub(r"^```(?:json)?|```$", "", (text or "").strip(), flags=re.M).strip()
    candidates = [text]
    braces = re.search(r"\{.*\}", text, flags=re.S)
    if braces:
        candidates.append(braces.group(0))
    for candidate in candidates:
        try:
            data = json.loads(candidate)
        except ValueError:
            continue
        if isinstance(data, dict):
            return data
    return None


def _step_item(item: Any) -> dict[str, str] | None:
    """Accept {"action","why"} and the shapes models drift into (plain string, step/title/reason keys)."""
    if isinstance(item, str):
        return {"action": item.strip(), "why": ""} if item.strip() else None
    if not isinstance(item, dict):
        return None
    action = next((str(item[k]).strip() for k in ("action", "step", "title", "check") if str(item.get(k, "")).strip()), "")
    why = next((str(item[k]).strip() for k in ("why", "reason", "rationale", "description") if str(item.get(k, "")).strip()), "")
    return {"action": action, "why": why} if action else None


ADVISOR_ATTEMPTS = 3


def advise(rec: Recommendation, poc: PoC, able_md: str, plan_md: str, llm: Callable[[str, int], str]) -> None:
    """Fill next steps / questions / risks. Retries when the reply is unusable (models drift off strict JSON)."""
    prompt = ADVISOR_PROMPT.format(
        hypothesis=f"{poc.name}. {poc.summary}",
        disposition=rec.disposition,
        confidence=rec.confidence,
        reasons="\n".join(f"- {r}" for r in rec.reasons),
        evidence=json.dumps(rec.evidence.to_dict(), ensure_ascii=False)[:6000],
        able=able_md[:2500],
        plan=plan_md[:6000],
    )
    problem = ""
    for attempt in range(1, ADVISOR_ATTEMPTS + 1):
        try:
            raw = llm(prompt, 3000)
        except Exception as exc:  # advisory only
            problem = f"Advisor LLM lỗi ({type(exc).__name__}): không có gợi ý bổ sung."
            break  # the LLM layer already retried transport errors
        data = _json_object(raw)
        if not data:
            problem = f"Advisor LLM trả về định dạng không hợp lệ sau {attempt} lần thử: không có gợi ý bổ sung."
            continue

        def _items(key: str) -> list[Any]:
            value = data.get(key)
            return list(value)[:5] if isinstance(value, list) else []

        steps = [step for step in (_step_item(i) for i in _items("next_steps")) if step]
        if not steps:
            problem = f"Advisor LLM không đưa ra bước tiếp theo nào dùng được sau {attempt} lần thử."
            continue
        rec.next_steps = steps
        rec.questions_for_hunter = [str(q).strip() for q in _items("questions_for_hunter") if str(q).strip()]
        rec.risks = [str(r).strip() for r in _items("risks") if str(r).strip()]
        rec.advisor_note = "Gợi ý bước tiếp theo do LLM tạo từ kế hoạch PEAK; chỉ mang tính tham khảo."
        if attempt > 1:
            rec.advisor_note += f" (đạt ở lần thử {attempt}/{ADVISOR_ATTEMPTS})"
        return
    rec.advisor_note = problem
