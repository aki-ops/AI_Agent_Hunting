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
    checker = getattr(adapter, "source_presence", None)
    for step in poc.steps:
        if step.source_kind not in presence_cache:
            presence_cache[step.source_kind] = checker(window, step.source_kind) if callable(checker) else None
        rows_hit = max((r.row_count for r in result.step_results if r.step_id == step.step_id and not r.used_fallback), default=0)
        steps.append(StepEvidence(
            step_id=step.step_id,
            description=step.description,
            predicate=f"{step.target_field} {step.op.value} {step.value}",
            source_kind=step.source_kind,
            row_count=rows_hit,
            source_rows_in_window=presence_cache[step.source_kind],
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
                note = "không có bản ghi nguồn trong cửa sổ" if s.source_rows_in_window == 0 else "nguồn có dữ liệu nhưng predicate không khớp"
                reasons.append(f"Bước `{s.step_id}` ({s.predicate}) không khớp: {note}.")
        caveats.append("Khớp predicate literal chứng minh có hoạt động tương ứng trong dữ liệu; tự nó chưa chứng minh thành công hay tác động (cần xem response/status và hậu quả trên host).")
    else:
        reasons.append("Không có bản ghi nào khớp bất kỳ bước nào của PoC trong cửa sổ đã chạy.")
        if ev.missing_sources:
            disposition, confidence = COLLECT, "HIGH"
            for kind in ev.missing_sources:
                reasons.append(f"Nguồn telemetry `{kind}` có 0 bản ghi trong cửa sổ: không có dữ liệu để săn, kết quả rỗng KHÔNG có nghĩa là sạch.")
        elif ev.unverifiable_sources:
            disposition, confidence = CLOSE, "LOW"
            caveats.append(f"Không kiểm tra được độ phủ của nguồn: {', '.join(ev.unverifiable_sources)}.")
        else:
            disposition, confidence = CLOSE, "MEDIUM"
            reasons.append("Các nguồn telemetry cần thiết có dữ liệu trong cửa sổ nhưng predicate không khớp.")
        caveats.append("Nguồn có dữ liệu chưa chắc chứa đúng loại sự kiện cần tìm (ví dụ chỉ có đăng nhập thành công, không có đăng nhập thất bại); hệ thống chưa xác minh điều này.")
        caveats.append("PoC chỉ kiểm tra các predicate literal đã khai báo; biến thể (obfuscation, tên khác, field khác) không được thử.")
        caveats.append(f"Chỉ quét cửa sổ {ev.window}; hoạt động ngoài cửa sổ không được xem.")

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
        INVESTIGATE: f"Pivot theo {hosts}: xem process/network/auth cùng khoảng {ev.first_seen or 'thời gian hit'}; xác định bước nào của chuỗi còn thiếu bằng chứng.",
        TUNE: "Xem mẫu bản ghi, thêm điều kiện loại trừ hoạt động hợp lệ (parent, signer, tài khoản dịch vụ) rồi chạy lại; đóng nếu xác nhận là noise.",
        COLLECT: (
            f"Bật/nạp telemetry còn thiếu ({', '.join(ev.missing_sources)}) rồi chạy lại cùng PoC."
            if ev.missing_sources
            else "Nguồn đã có dữ liệu; chỉ cần nếu muốn bổ sung loại telemetry khác (vd. sysmon, network flow) để bắt biến thể ngoài predicate."
        ),
        CLOSE: "Đóng hunt, ghi rõ giới hạn; cân nhắc mở rộng cửa sổ hoặc biến thể predicate trước khi coi là sạch.",
    }
    order = [chosen] + [d for d in (ESCALATE, INVESTIGATE, TUNE, COLLECT, CLOSE) if d != chosen and _applicable(d, ev)]
    return [Option(action=d, rank=i + 1, rationale=catalogue[d]) for i, d in enumerate(order)]


def _applicable(disposition: str, ev: EvidenceSummary) -> bool:
    if ev.observations > 0:
        return disposition in (ESCALATE, INVESTIGATE, TUNE)
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


def advise(rec: Recommendation, poc: PoC, able_md: str, plan_md: str, llm: Callable[[str, int], str]) -> None:
    prompt = ADVISOR_PROMPT.format(
        hypothesis=f"{poc.name}. {poc.summary}",
        disposition=rec.disposition,
        confidence=rec.confidence,
        reasons="\n".join(f"- {r}" for r in rec.reasons),
        evidence=json.dumps(rec.evidence.to_dict(), ensure_ascii=False)[:6000],
        able=able_md[:2500],
        plan=plan_md[:6000],
    )
    try:
        data = _json_object(llm(prompt, 3000))
    except Exception as exc:  # advisory only
        rec.advisor_note = f"Advisor LLM lỗi ({type(exc).__name__}): không có gợi ý bổ sung."
        return
    if not data:
        rec.advisor_note = "Advisor LLM trả về định dạng không hợp lệ: không có gợi ý bổ sung."
        return

    def _items(key: str) -> list[Any]:
        value = data.get(key)
        return list(value)[:5] if isinstance(value, list) else []

    rec.next_steps = [
        {"action": str(i.get("action", "")).strip(), "why": str(i.get("why", "")).strip()}
        for i in _items("next_steps") if isinstance(i, dict) and str(i.get("action", "")).strip()
    ]
    rec.questions_for_hunter = [str(q).strip() for q in _items("questions_for_hunter") if str(q).strip()]
    rec.risks = [str(r).strip() for r in _items("risks") if str(r).strip()]
    rec.advisor_note = "Gợi ý bước tiếp theo do LLM tạo từ kế hoạch PEAK; chỉ mang tính tham khảo."
