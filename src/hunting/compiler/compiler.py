"""Knowledge and Behavior Compiler.

Component 1 of Canonical v4 Threat Hunting Architecture:
1. Translates HuntRequest (CVE, TTP, IOC, NL_QUESTION) into testable HuntObjective,
   Hypotheses, and EvidenceRequirements.
2. Enforces deterministic-first compilation: structured templates compile with 0 LLM calls.
3. Bounds LLM normalization fallback to max 1 call for unstructured input.
4. Enforces strict schema validation, falsification conditions, source citations,
   and prompt injection defense.
"""
from __future__ import annotations

import json
import re
from typing import Callable

from hunting.compiler.knowledge_base import build_default_knowledge_base
from hunting.compiler.models import BehaviorTemplate, KnowledgeRecord
from hunting.compiler.templates import build_default_templates
from hunting.contracts.expectations import FieldOp, FieldPredicate
from hunting.contracts.hunt import (
    EvidenceRequirementV4,
    HuntObjective,
    HuntRequest,
    HuntRequestKind,
    Hypothesis,
    HypothesisOrigin,
    HypothesisStatus,
    RequirementStatus,
)

# Common prompt injection signatures targeting security agents
INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous\s+)?instructions", re.IGNORECASE),
    re.compile(r"mark\s+(as\s+)?(benign|malicious|clean)", re.IGNORECASE),
    re.compile(r"system\s*prompt", re.IGNORECASE),
    re.compile(r"override\s+state", re.IGNORECASE),
    re.compile(r"bypass\s+(controls|checks)", re.IGNORECASE),
]


class KnowledgeBehaviorCompiler:
    """Canonical compiler transforming threat requests into executable hypotheses."""

    def __init__(
        self,
        knowledge_base: dict[str, KnowledgeRecord] | None = None,
        templates: dict[str, BehaviorTemplate] | None = None,
        llm_caller: Callable[[str], str] | None = None,
    ) -> None:
        self.knowledge_base = knowledge_base if knowledge_base is not None else build_default_knowledge_base()
        self.templates = templates if templates is not None else build_default_templates()
        self.llm_caller = llm_caller
        self.llm_calls_made = 0

    def compile(
        self,
        request: HuntRequest,
        time_window: str | None = None,
    ) -> tuple[HuntObjective, list[Hypothesis], list[EvidenceRequirementV4]]:
        """Compile a HuntRequest into a HuntObjective, competing Hypotheses, and EvidenceRequirements."""
        # 1. Prompt injection guard on input content
        if self._detect_prompt_injection(request.content):
            raise ValueError(f"Security boundary: Prompt injection pattern detected in HuntRequest '{request.id}'")

        # 2. Derive time window
        effective_window = time_window or self._derive_time_window(request)

        # 3. Compile based on request kind
        if request.kind == HuntRequestKind.CVE:
            return self._compile_cve(request, effective_window)
        elif request.kind in (HuntRequestKind.TTP, HuntRequestKind.IOC):
            return self._compile_ttp_or_ioc(request, effective_window)
        elif request.kind == HuntRequestKind.NL_QUESTION:
            return self._compile_unstructured(request, effective_window)
        else:
            # HYPOTHESIS, SCHEDULED, CTI_REPORT
            return self._compile_general_structured(request, effective_window)

    def _compile_cve(
        self,
        request: HuntRequest,
        time_window: str,
    ) -> tuple[HuntObjective, list[Hypothesis], list[EvidenceRequirementV4]]:
        """Deterministically compile a CVE request into competing hypotheses and phased requirements."""
        cve_id = self._extract_cve_id(request.content)
        record = self.knowledge_base.get(cve_id)

        if record and record.phases:
            # Known CVE with full 5-phase decomposition
            hypo_exploited = Hypothesis(
                id=f"hypo-{cve_id}-exploited",
                statement=f"Adversary successfully exploited {cve_id} ({record.title}) and established presence",
                origin=HypothesisOrigin.RULE,
                status=HypothesisStatus.LIVE,
                source_refs=list(record.source_citations),
                requirements=[f"req-{cve_id}-exploit", f"req-{cve_id}-post"],
            )

            hypo_benign = Hypothesis(
                id=f"hypo-{cve_id}-benign",
                statement=f"No exploitation of {cve_id} occurred; telemetry reflects clean baseline",
                origin=HypothesisOrigin.RULE,
                status=HypothesisStatus.LIVE,
                source_refs=list(record.source_citations),
                requirements=[f"req-{cve_id}-baseline"],
            )

            exploit_predicate = FieldPredicate(field="cmdline", op=FieldOp.EXISTS)
            if cve_id == "CVE-2024-21887" or any("python" in ind.lower() for ind in record.phases.exploitation_indicators):
                exploit_predicate = FieldPredicate(field="cmdline", op=FieldOp.CONTAINS, value="python")
            elif any("sql" in ind.lower() for ind in record.phases.exploitation_indicators):
                exploit_predicate = FieldPredicate(field="cmdline", op=FieldOp.CONTAINS, value="sql")

            req_exploit = EvidenceRequirementV4(
                id=f"req-{cve_id}-exploit",
                description=f"Evidence of exploitation attempts targeting {cve_id}: {'; '.join(record.phases.exploitation_indicators)}",
                evidence_type="process_ancestry",
                predicate=exploit_predicate,
                falsification_condition=f"telemetry confirms zero exploitation indicators for {cve_id}",
                source_refs=list(record.source_citations),
                status=RequirementStatus.VALIDATED,
            )

            req_post = EvidenceRequirementV4(
                id=f"req-{cve_id}-post",
                description=f"Post-exploitation indicators for {cve_id}: {'; '.join(record.phases.post_exploitation)}",
                evidence_type="file_modification",
                predicate=FieldPredicate(field="file_path", op=FieldOp.EXISTS),
                falsification_condition="filesystem inspection shows zero web shells or unauthorized artifacts",
                source_refs=list(record.source_citations),
                status=RequirementStatus.VALIDATED,
            )

            req_baseline = EvidenceRequirementV4(
                id=f"req-{cve_id}-baseline",
                description="Verified operational telemetry showing standard application execution",
                evidence_type="scope_records",
                falsification_condition="telemetry gap or unobservable audit partition",
                source_refs=list(record.source_citations),
                status=RequirementStatus.VALIDATED,
            )

            objective = HuntObjective(
                request_id=request.id,
                target_hypotheses=[hypo_exploited.id, hypo_benign.id],
                time_window=time_window,
                target_scopes=request.provider_hints or ["cdb_native_scope"],
            )

            return objective, [hypo_exploited, hypo_benign], [req_exploit, req_post, req_baseline]
        else:
            # Unknown CVE without template -> fallback or general structured
            return self._compile_general_structured(request, time_window)

    def _compile_ttp_or_ioc(
        self,
        request: HuntRequest,
        time_window: str,
    ) -> tuple[HuntObjective, list[Hypothesis], list[EvidenceRequirementV4]]:
        """Deterministically compile a MITRE TTP or IOC without LLM."""
        ttp_match = None
        for key in self.knowledge_base:
            if key in request.content:
                ttp_match = self.knowledge_base[key]
                break

        template = self.templates.get("tmpl-proc-anomalous-lineage")
        if "T1053" in request.content or "task" in request.content.lower():
            template = self.templates.get("tmpl-pers-scheduled-task", template)
        elif "T1071" in request.content or "c2" in request.content.lower():
            template = self.templates.get("tmpl-net-c2-beacon", template)

        hypo_attack = Hypothesis(
            id=f"hypo-{request.id}-active",
            statement=f"Threat actor executing behavior related to {request.content}",
            origin=HypothesisOrigin.RULE,
            status=HypothesisStatus.LIVE,
            source_refs=list(ttp_match.source_citations) if ttp_match else ["INTERNAL_TEMPLATE"],
            requirements=[r.id for r in template.requirements] if template else [],
        )

        hypo_benign = Hypothesis(
            id=f"hypo-{request.id}-benign",
            statement="No matching behavior observed in environment",
            origin=HypothesisOrigin.RULE,
            status=HypothesisStatus.LIVE,
            source_refs=list(ttp_match.source_citations) if ttp_match else ["INTERNAL_TEMPLATE"],
            requirements=[],
        )

        requirements = template.requirements if template else []

        objective = HuntObjective(
            request_id=request.id,
            target_hypotheses=[hypo_attack.id, hypo_benign.id],
            time_window=time_window,
            target_scopes=request.provider_hints or ["cdb_native_scope"],
        )

        return objective, [hypo_attack, hypo_benign], requirements

    def _compile_unstructured(
        self,
        request: HuntRequest,
        time_window: str,
    ) -> tuple[HuntObjective, list[Hypothesis], list[EvidenceRequirementV4]]:
        """Normalize unstructured or novel natural language questions using bounded LLM with schema validation."""
        if self.llm_caller is None:
            # Deterministic fallback when no LLM caller configured
            return self._compile_general_structured(request, time_window)

        if self.llm_calls_made >= 1:
            raise RuntimeError("LLM cost policy: max 1 LLM call allowed for objective compilation")

        prompt = (
            f"You are the Knowledge/Behavior Compiler for an autonomous threat hunter.\n"
            f"Normalize the following hunt request into a structured objective and evidence requirements.\n"
            f"Request Content: {request.content}\n\n"
            "Respond with strict JSON adhering to schema:\n"
            "{\n"
            '  "hypotheses": [{"id": "str", "statement": "str"}],\n'
            '  "requirements": [{\n'
            '    "id": "str", "description": "str", "evidence_type": "str",\n'
            '    "falsification_condition": "str", "source_refs": ["str"]\n'
            "  }]\n"
            "}"
        )

        self.llm_calls_made += 1
        raw_resp = self.llm_caller(prompt)

        # Parse and validate JSON schema strictly
        try:
            data = json.loads(raw_resp)
            hypotheses: list[Hypothesis] = []
            for h in data.get("hypotheses", []):
                hypotheses.append(
                    Hypothesis(
                        id=h["id"],
                        statement=h["statement"],
                        origin=HypothesisOrigin.LLM_PROPOSAL,
                        status=HypothesisStatus.LIVE,
                    )
                )

            requirements: list[EvidenceRequirementV4] = []
            for r in data.get("requirements", []):
                # Validate mandatory fields
                if not r.get("falsification_condition", "").strip():
                    continue
                if not r.get("source_refs"):
                    continue

                requirements.append(
                    EvidenceRequirementV4(
                        id=r["id"],
                        description=r["description"],
                        evidence_type=r["evidence_type"],
                        falsification_condition=r["falsification_condition"],
                        source_refs=r["source_refs"],
                        status=RequirementStatus.VALIDATED,
                    )
                )

            if not hypotheses:
                return self._compile_general_structured(request, time_window)

            objective = HuntObjective(
                request_id=request.id,
                target_hypotheses=[h.id for h in hypotheses],
                time_window=time_window,
                target_scopes=request.provider_hints or ["cdb_native_scope"],
            )

            return objective, hypotheses, requirements

        except Exception:
            # Fallback cleanly if LLM output fails schema validation
            return self._compile_general_structured(request, time_window)

    def _compile_general_structured(
        self,
        request: HuntRequest,
        time_window: str,
    ) -> tuple[HuntObjective, list[Hypothesis], list[EvidenceRequirementV4]]:
        """General deterministic compilation when templates are not matched."""
        hypo = Hypothesis(
            id=f"hypo-{request.id}",
            statement=f"Investigate activity described by: {request.content}",
            origin=HypothesisOrigin.INPUT,
            status=HypothesisStatus.LIVE,
            requirements=[f"req-{request.id}-scope"],
        )

        req = EvidenceRequirementV4(
            id=f"req-{request.id}-scope",
            description=f"Evidence matching inquiry: {request.content}",
            evidence_type="scope_records",
            falsification_condition="verified sensor coverage with zero matching events",
            source_refs=["INPUT_REQUEST"],
            status=RequirementStatus.VALIDATED,
        )

        objective = HuntObjective(
            request_id=request.id,
            target_hypotheses=[hypo.id],
            time_window=time_window,
            target_scopes=request.provider_hints or ["cdb_native_scope"],
        )

        return objective, [hypo], [req]

    def _detect_prompt_injection(self, text: str) -> bool:
        """Scan input for prompt injection signatures."""
        for pattern in INJECTION_PATTERNS:
            if pattern.search(text):
                return True
        return False

    def _extract_cve_id(self, content: str) -> str:
        """Extract standard CVE identifier (e.g. CVE-2024-21887) from text."""
        match = re.search(r"CVE-\d{4}-\d{4,7}", content, re.IGNORECASE)
        return match.group(0).upper() if match else ""

    def _derive_time_window(self, request: HuntRequest) -> str:
        """Calculate ISO time window based on request TimePolicy."""
        if request.time_policy and request.time_policy.start and request.time_policy.end:
            return f"{request.time_policy.start}/{request.time_policy.end}"
        lookback = request.time_policy.lookback_days if request.time_policy else 14
        return f"NOW-{lookback}d/NOW"


__all__ = ["KnowledgeBehaviorCompiler"]
