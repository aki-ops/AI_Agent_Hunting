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
from typing import Any, Callable

from hunting.compiler.knowledge_base import build_default_knowledge_base
from hunting.compiler.models import BehaviorTemplate, KnowledgeRecord
from hunting.compiler.templates import build_default_templates
from hunting.contracts.case_graph import (
    EvidenceGoal,
    GraphEdge,
    GraphNode,
    InvestigationCase,
    InvestigationGraph,
    InvestigationUnknown,
    NodeStatus,
    NodeType,
    RelationStatus,
    RelationType,
    build_investigation_case_from_intent,
)
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
from hunting.contracts.investigation_model import (
    build_investigation_model_from_intent,
)
from hunting.contracts.semantic_intent import (
    RequestedObject,
    SemanticEvidenceRequirement,
    SemanticHuntIntent,
    SubjectEntity,
)

# Common prompt injection signatures targeting security agents
INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous\s+)?instructions", re.IGNORECASE),
    re.compile(r"mark\s+(as\s+)?(benign|malicious|clean)", re.IGNORECASE),
    re.compile(r"system\s*prompt", re.IGNORECASE),
    re.compile(r"override\s+state", re.IGNORECASE),
    re.compile(r"bypass\s+(controls|checks)", re.IGNORECASE),
]

ALLOWED_EVIDENCE_TYPES = {
    "process_ancestry",
    "network_connection",
    "file_modification",
    "persistence_change",
    "authentication_activity",
    "web_request",
    "scope_records",
    "dns_query",
    "dns_activity",
}

SEMANTIC_INTENT_TO_EVIDENCE_TYPE = {
    "web_request_activity": "web_request",
    "web_navigation": "web_request",
    "server_side_execution": "process_ancestry",
    "process_execution": "process_ancestry",
    "file_artifact": "file_modification",
    "remote_authentication": "authentication_activity",
    "identity_binding": "authentication_activity",
    "network_c2_communication": "network_connection",
    "network_traffic": "network_connection",
    "dns_resolution": "dns_activity",
    "dns_query": "dns_activity",
    "operational_baseline": "scope_records",
}
ALLOWED_SEMANTIC_INTENTS = set(SEMANTIC_INTENT_TO_EVIDENCE_TYPE.keys())

DISALLOWED_SPL_PATTERNS = [
    re.compile(r"\bindex\s*=", re.IGNORECASE),
    re.compile(r"\bsourcetype\s*=", re.IGNORECASE),
    re.compile(r"\|\s*(table|stats|eval|rex|where|rename|dedup|head)\b", re.IGNORECASE),
]

DISALLOWED_VENDOR_TERMS = [
    "sysmon",
    "wineventlog",
    "pan:traffic",
    "stream:http",
    "stream:dns",
    "crowdstrike",
]


def validate_compiler_output_integrity(data: dict) -> list[str]:
    """Strictly prohibit raw SPL, vendor terms, or fabricated bindings in compiler output."""
    violations: list[str] = []

    def scan_val(val: Any, path: str = "") -> None:
        if isinstance(val, str):
            for pat in DISALLOWED_SPL_PATTERNS:
                if pat.search(val):
                    violations.append(f"Raw SPL syntax detected at {path}: '{val}'")
            val_lower = val.lower()
            for v_term in DISALLOWED_VENDOR_TERMS:
                if v_term in val_lower:
                    violations.append(f"Vendor-specific telemetry term '{v_term}' detected at {path}: '{val}'")
        elif isinstance(val, dict):
            for k, v in val.items():
                scan_val(v, f"{path}.{k}" if path else str(k))
        elif isinstance(val, list):
            for i, elem in enumerate(val):
                scan_val(elem, f"{path}[{i}]")

    scan_val(data)
    return violations


def parse_and_validate_semantic_intent(
    data: dict | str,
    original_request: str = "",
) -> tuple[list[Hypothesis], list[EvidenceRequirementV4], SemanticHuntIntent]:
    """Strictly validate LLM output for hypotheses, evidence requirements, and semantic hunt intent."""
    if isinstance(data, str):
        raw_text = data.strip()
        if raw_text.startswith("```"):
            lines = raw_text.splitlines()
            if lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].startswith("```"):
                lines = lines[:-1]
            raw_text = "\n".join(lines).strip()
        try:
            data = json.loads(raw_text)
        except Exception as exc:
            raise ValueError(f"LLM output is not valid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise ValueError("LLM output must be a JSON object")

    violations = validate_compiler_output_integrity(data)
    if violations:
        raise ValueError(f"Compiler output validation failure: {'; '.join(violations)}")

    requirements: list[EvidenceRequirementV4] = []
    for r in data.get("requirements", []):
        if not isinstance(r, dict):
            continue
        r_id = str(r.get("id", "")).strip()
        description = str(r.get("description", "")).strip()
        falsification = str(r.get("falsification_condition", "")).strip()
        source_refs = r.get("source_refs")
        if source_refs is None:
            source_refs = ["SEMANTIC_INFERENCE"]

        # Support both semantic_intent and direct evidence_type
        semantic_intent = str(r.get("semantic_intent", "")).strip()
        evidence_type = str(r.get("evidence_type", "")).strip()
        if semantic_intent and semantic_intent in SEMANTIC_INTENT_TO_EVIDENCE_TYPE:
            evidence_type = SEMANTIC_INTENT_TO_EVIDENCE_TYPE[semantic_intent]
        elif evidence_type in ALLOWED_EVIDENCE_TYPES:
            for s_intent, ev_type in SEMANTIC_INTENT_TO_EVIDENCE_TYPE.items():
                if ev_type == evidence_type and not semantic_intent:
                    semantic_intent = s_intent
                    break
        else:
            continue

        if not r_id or not description or not falsification:
            continue
        if evidence_type not in ALLOWED_EVIDENCE_TYPES:
            continue
        if not isinstance(source_refs, list) or not source_refs:
            continue

        search_hints = [str(s).strip() for s in r.get("search_hints", []) if str(s).strip()]
        necessity = str(r.get("necessity", "CRITICAL")).upper()
        if necessity not in ("CRITICAL", "SUPPORTING"):
            necessity = "CRITICAL"

        pred = None
        if "predicate" in r and isinstance(r["predicate"], dict):
            p = r["predicate"]
            op_str = str(p.get("op", "EXISTS")).upper()
            op_enum = getattr(FieldOp, op_str, FieldOp.EXISTS)
            pred = FieldPredicate(field=str(p.get("field", "cmdline")), op=op_enum, value=str(p.get("value", "")))
        elif evidence_type == "web_request":
            pred = FieldPredicate(field="uri", op=FieldOp.EXISTS)
        elif evidence_type == "process_ancestry":
            pred = FieldPredicate(field="cmdline", op=FieldOp.EXISTS)
        elif evidence_type == "file_modification":
            pred = FieldPredicate(field="file_path", op=FieldOp.EXISTS)
        elif evidence_type == "network_connection":
            pred = FieldPredicate(field="destination_port", op=FieldOp.EXISTS)
        elif evidence_type == "authentication_activity":
            pred = FieldPredicate(field="user", op=FieldOp.EXISTS)
        elif evidence_type == "persistence_change":
            pred = FieldPredicate(field="registry_key", op=FieldOp.EXISTS)

        requirements.append(
            EvidenceRequirementV4(
                id=r_id,
                description=description,
                evidence_type=evidence_type,
                predicate=pred,
                falsification_condition=falsification,
                source_refs=[str(s) for s in source_refs if str(s).strip()],
                status=RequirementStatus.DEFINED,
                semantic_intent=semantic_intent,
                necessity=necessity,
                search_hints=search_hints,
            )
        )

    hypotheses: list[Hypothesis] = []
    for h in data.get("hypotheses", []):
        if not isinstance(h, dict):
            continue
        h_id = str(h.get("id", "")).strip()
        statement = str(h.get("statement", "")).strip()
        if not h_id or not statement:
            continue
        assumptions = [str(a).strip() for a in h.get("assumptions", []) if str(a).strip()]
        h_class = str(h.get("class", h.get("hypothesis_class", "unclassified"))).strip()
        req_ids = [str(rid).strip() for rid in h.get("requirements", []) if str(rid).strip()]
        if not req_ids and requirements:
            req_ids = [r.id for r in requirements]
        edge_ids = [str(eid).strip() for eid in h.get("required_edges", h.get("required_edge_ids", [])) if str(eid).strip()]
        ev_types = [str(et).strip() for et in h.get("required_evidence", h.get("required_evidence_types", [])) if str(et).strip()]

        # Invariant: website browsing or information lookup claims must never be classified as benign_baseline
        if h_class == "benign_baseline" and any(
            word in statement.lower() for word in ("visit", "brows", "navigat", "domain", "lookup")
        ):
            h_class = "unclassified"

        status = HypothesisStatus.LIVE if requirements else HypothesisStatus.INSUFFICIENTLY_SPECIFIED
        hypotheses.append(
            Hypothesis(
                id=h_id,
                statement=statement,
                origin=HypothesisOrigin.LLM_PROPOSAL,
                status=status,
                requirements=req_ids,
                assumptions=assumptions,
                hypothesis_class=h_class,
                required_edge_ids=edge_ids,
                required_evidence_types=ev_types,
            )
        )

    # Parse or derive SemanticHuntIntent
    intent_raw = data.get("semantic_intent")
    if isinstance(intent_raw, dict):
        intent = SemanticHuntIntent.from_dict(intent_raw)
        if not intent.original_request and original_request:
            intent.original_request = original_request
    else:
        # Reconstruct SemanticHuntIntent from available fields
        subj = SubjectEntity(type="unknown", value="")
        entities = data.get("entities", [])
        if isinstance(entities, list) and entities:
            first_ent = entities[0]
            if isinstance(first_ent, dict):
                subj = SubjectEntity(
                    type=str(first_ent.get("type", "unknown")),
                    value=str(first_ent.get("value", "")),
                )
        req_obj = RequestedObject(type="unknown", role="answer")
        ans_spec = data.get("answer_spec", {})
        if isinstance(ans_spec, dict) and ans_spec.get("answer_type"):
            req_obj = RequestedObject(type=str(ans_spec["answer_type"]), role="answer")

        claim_text = ""
        norm_claim = data.get("normalized_claim")
        if isinstance(norm_claim, dict):
            claim_text = str(norm_claim.get("text", ""))

        sem_reqs = [
            SemanticEvidenceRequirement(
                semantic_intent=r.semantic_intent or r.evidence_type,
                required_fields=[],
                necessity=r.necessity,
                description=r.description,
            )
            for r in requirements
        ]

        intent = SemanticHuntIntent(
            original_request=original_request or claim_text,
            question=str(ans_spec.get("question", original_request or claim_text)) if isinstance(ans_spec, dict) else (original_request or claim_text),
            subject=subj,
            requested_object=req_obj,
            behavior=claim_text,
            evidence_requirements=sem_reqs,
            required_correlations=[],
            assumptions=[a for h in hypotheses for a in h.assumptions],
            uncertainties=[],
        )

    # Provider isolation validation
    leaks = intent.validate_provider_isolation()
    if leaks:
        raise ValueError(f"Provider isolation violation in semantic compiler output: {'; '.join(leaks)}")

    return hypotheses, requirements, intent


def validate_compiler_llm_output(data: dict | str) -> tuple[list[Hypothesis], list[EvidenceRequirementV4]]:
    """Strictly validate LLM output for hypotheses and evidence requirements with semantic schema support."""
    hypotheses, requirements, _ = parse_and_validate_semantic_intent(data)
    return hypotheses, requirements


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
        elif request.kind in (HuntRequestKind.NL_QUESTION, HuntRequestKind.HYPOTHESIS):
            structured = self._try_compile_structured_hypothesis(request, effective_window)
            if structured is not None:
                return structured
            if self.llm_caller is not None:
                return self._compile_semantic_llm(request, effective_window)
            return self._compile_general_structured(request, effective_window)
        else:
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
                hypothesis_class="external_exploitation",
                source_refs=list(record.source_citations),
                requirements=[f"req-{cve_id}-exploit", f"req-{cve_id}-post"],
            )

            hypo_benign = Hypothesis(
                id=f"hypo-{cve_id}-benign",
                statement=f"No exploitation of {cve_id} occurred; telemetry reflects clean baseline",
                origin=HypothesisOrigin.RULE,
                status=HypothesisStatus.LIVE,
                hypothesis_class="benign_baseline",
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
                status=RequirementStatus.DEFINED,
            )

            req_post = EvidenceRequirementV4(
                id=f"req-{cve_id}-post",
                description=f"Post-exploitation indicators for {cve_id}: {'; '.join(record.phases.post_exploitation)}",
                evidence_type="file_modification",
                predicate=FieldPredicate(field="file_path", op=FieldOp.EXISTS),
                falsification_condition="filesystem inspection shows zero web shells or unauthorized artifacts",
                source_refs=list(record.source_citations),
                status=RequirementStatus.DEFINED,
            )

            req_baseline = EvidenceRequirementV4(
                id=f"req-{cve_id}-baseline",
                description="Verified operational telemetry showing standard application execution",
                evidence_type="scope_records",
                falsification_condition="telemetry gap or unobservable audit partition",
                source_refs=list(record.source_citations),
                status=RequirementStatus.DEFINED,
            )

            inv_case = self._build_cve_case(cve_id, record, request, [hypo_exploited, hypo_benign], [req_exploit, req_post])
            objective = HuntObjective(
                request_id=request.id,
                target_hypotheses=[hypo_exploited.id, hypo_benign.id],
                time_window=time_window,
                target_scopes=request.provider_hints or ["cdb_native_scope"],
                kind=request.kind,
                statement=request.content,
                case=inv_case,
                case_graph=inv_case.graph,
            )

            return objective, [hypo_exploited, hypo_benign], [req_exploit, req_post, req_baseline]
        else:
            # Unknown CVE without template -> fallback or general structured
            return self._compile_general_structured(request, time_window)

    def _build_cve_case(
        self,
        cve_id: str,
        record: KnowledgeRecord,
        request: HuntRequest,
        hypotheses: list[Hypothesis],
        requirements: list[EvidenceRequirementV4],
    ) -> InvestigationCase:
        graph = InvestigationGraph()
        n_endpoint = GraphNode(id="node-endpoint", type=NodeType.ENDPOINT, value="?", status=NodeStatus.UNKNOWN)
        n_proc = GraphNode(
            id="node-exploit-proc",
            type=NodeType.PROCESS,
            value="python" if any("python" in ind.lower() for ind in getattr(record.phases, "exploitation_indicators", [])) else "?",
            status=NodeStatus.UNKNOWN,
        )
        n_file = GraphNode(id="node-webshell-file", type=NodeType.FILE, value="?", status=NodeStatus.UNKNOWN)

        graph.add_node(n_endpoint)
        graph.add_node(n_proc)
        graph.add_node(n_file)

        e1 = GraphEdge(
            id=f"edge-{cve_id}-spawn",
            source_id="node-endpoint",
            source_entity_type=NodeType.ENDPOINT,
            relation_type=RelationType.SPAWNED,
            target_id="node-exploit-proc",
            target_entity_type=NodeType.PROCESS,
            acceptable_operations=["find_process_from_endpoint"],
            status=RelationStatus.UNPROVEN,
        )
        e2 = GraphEdge(
            id=f"edge-{cve_id}-write",
            source_id="node-exploit-proc",
            source_entity_type=NodeType.PROCESS,
            relation_type=RelationType.WROTE,
            target_id="node-webshell-file",
            target_entity_type=NodeType.FILE,
            acceptable_operations=["find_file_change_from_process"],
            status=RelationStatus.UNPROVEN,
        )
        graph.add_edge(e1)
        graph.add_edge(e2)

        unknowns = [
            InvestigationUnknown(
                id="unk-cve-proc",
                entity_type=NodeType.PROCESS,
                variable_name="exploit_process",
                description=f"Exploitation child process execution for {cve_id}",
                resolving_edge_id=e1.id,
            ),
            InvestigationUnknown(
                id="unk-cve-file",
                entity_type=NodeType.FILE,
                variable_name="webshell_artifact",
                description=f"Web shell file modification for {cve_id}",
                resolving_edge_id=e2.id,
            ),
        ]
        goals = [
            EvidenceGoal(id="goal-cve-proc", target_edge_id=e1.id, description=f"Prove anomalous process lineage for {cve_id}"),
            EvidenceGoal(id="goal-cve-file", target_edge_id=e2.id, description=f"Prove unauthorized file writes for {cve_id}"),
        ]
        claims = [
            {"claim_id": h.id, "statement": h.statement, "hypothesis_class": getattr(h, "hypothesis_class", "unclassified")}
            for h in hypotheses
        ]
        return InvestigationCase(
            id=f"case-{cve_id}",
            request_content=request.content,
            question=f"Was {cve_id} exploited in the monitored scope?",
            graph=graph,
            claims=claims,
            unknowns=unknowns,
            evidence_goals=goals,
            acceptance_criteria=[
                {"criterion": f"Multi-stage process-to-file correlation verified for {cve_id}."}
            ],
            status="READY_FOR_DISCOVERY",
        )

    def _build_ttp_case(
        self,
        request: HuntRequest,
        hypotheses: list[Hypothesis],
        requirements: list[EvidenceRequirementV4],
    ) -> InvestigationCase:
        graph = InvestigationGraph()
        n_endpoint = GraphNode(id="node-endpoint", type=NodeType.ENDPOINT, value="?", status=NodeStatus.UNKNOWN)
        n_activity = GraphNode(id="node-activity", type=NodeType.EVENT, value="?", status=NodeStatus.UNKNOWN)
        graph.add_node(n_endpoint)
        graph.add_node(n_activity)

        e1 = GraphEdge(
            id=f"edge-{request.id}-activity",
            source_id="node-endpoint",
            source_entity_type=NodeType.ENDPOINT,
            relation_type=RelationType.CONNECTED_TO,
            target_id="node-activity",
            target_entity_type=NodeType.EVENT,
            status=RelationStatus.UNPROVEN,
        )
        graph.add_edge(e1)

        unknowns = [
            InvestigationUnknown(
                id=f"unk-{request.id}-act",
                entity_type=NodeType.EVENT,
                variable_name="observed_behavior",
                description=f"Observable behavioral event matching {request.content}",
                resolving_edge_id=e1.id,
            ),
        ]
        goals = [
            EvidenceGoal(id=f"goal-{request.id}-act", target_edge_id=e1.id, description=f"Prove behavioral event for {request.content}"),
        ]
        claims = [
            {"claim_id": h.id, "statement": h.statement, "hypothesis_class": getattr(h, "hypothesis_class", "unclassified")}
            for h in hypotheses
        ]
        return InvestigationCase(
            id=f"case-{request.id}",
            request_content=request.content,
            question=request.content,
            graph=graph,
            claims=claims,
            unknowns=unknowns,
            evidence_goals=goals,
            acceptance_criteria=[
                {"criterion": f"Behavioral correlation verified for {request.content}."}
            ],
            status="READY_FOR_DISCOVERY",
        )

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
        if "T1053" in request.content.upper():
            template = self.templates.get("tmpl-pers-scheduled-task", template)
        elif "T1071" in request.content.upper():
            template = self.templates.get("tmpl-net-c2-beacon", template)

        hypo_attack = Hypothesis(
            id=f"hypo-{request.id}-active",
            statement=f"Threat actor executing behavior related to {request.content}",
            origin=HypothesisOrigin.RULE,
            status=HypothesisStatus.LIVE,
            hypothesis_class="unclassified",
            source_refs=list(ttp_match.source_citations) if ttp_match else ["INTERNAL_TEMPLATE"],
            requirements=[r.id for r in template.requirements] if template else [],
        )

        hypo_benign = Hypothesis(
            id=f"hypo-{request.id}-benign",
            statement="No matching behavior observed in environment",
            origin=HypothesisOrigin.RULE,
            status=HypothesisStatus.LIVE,
            hypothesis_class="benign_baseline",
            source_refs=list(ttp_match.source_citations) if ttp_match else ["INTERNAL_TEMPLATE"],
            requirements=[],
        )

        requirements = template.requirements if template else []

        inv_case = self._build_ttp_case(request, [hypo_attack, hypo_benign], requirements)
        objective = HuntObjective(
            request_id=request.id,
            target_hypotheses=[hypo_attack.id, hypo_benign.id],
            time_window=time_window,
            target_scopes=request.provider_hints or ["cdb_native_scope"],
            kind=request.kind,
            statement=request.content,
            case=inv_case,
            case_graph=inv_case.graph,
        )

        return objective, [hypo_attack, hypo_benign], requirements

    def _compile_semantic_llm(
        self,
        request: HuntRequest,
        time_window: str,
    ) -> tuple[HuntObjective, list[Hypothesis], list[EvidenceRequirementV4]]:
        """Normalize unstructured natural language questions using bounded LLM with strict semantic schema validation."""
        if self.llm_caller is None:
            hypo_insufficient = Hypothesis(
                id=f"hypo-{request.id}-insufficient",
                statement=f"Free-text hypothesis requires semantic compilation via LLM (--llm api): '{request.content}'",
                origin=HypothesisOrigin.INPUT,
                status=HypothesisStatus.INSUFFICIENTLY_SPECIFIED,
                requirements=[],
            )
            objective = HuntObjective(
                request_id=request.id,
                target_hypotheses=[hypo_insufficient.id],
                time_window=time_window,
                target_scopes=request.provider_hints or ["cdb_native_scope"],
                kind=request.kind,
                statement=request.content,
            )
            return objective, [hypo_insufficient], []

        if self.llm_calls_made >= 1:
            raise RuntimeError("LLM cost policy: max 1 LLM call allowed for objective compilation")

        prompt = (
            "You are the Semantic Threat Hunting Knowledge & Behavior Compiler.\n"
            "Analyze the semantic meaning, entities, implied mechanisms, and hypotheses for the following threat hunt request.\n"
            "Do NOT simply match keywords. Recognize that target entities (domains, hosts, IPs, users, files) do not dictate the attack vector.\n"
            "If the mechanism is not proven or specified, mark mechanism_status as UNKNOWN and generate competing hypotheses (e.g., exploitation, credential misuse, benign baseline) with explicit assumptions.\n"
            "Do NOT generate raw SPL/SQL queries. You only emit semantic intent, necessity, search hints, and falsification conditions.\n"
            "The claim in the request is NOT an established fact; mark claim status as UNVERIFIED.\n\n"
            "Allowed semantic_intent values:\n"
            "- web_request_activity\n"
            "- server_side_execution\n"
            "- process_execution\n"
            "- file_artifact\n"
            "- remote_authentication\n"
            "- network_c2_communication\n"
            "- dns_resolution\n"
            "- operational_baseline\n\n"
            f"Request Content: {request.content}\n\n"
            "Respond strictly with a JSON object matching this schema:\n"
            "{\n"
            '  "normalized_claim": {\n'
            '    "text": "Cleaned summary of the user claim",\n'
            '    "status": "UNVERIFIED"\n'
            "  },\n"
            '  "entities": [\n'
            "    {\n"
            '      "type": "domain" | "host" | "user" | "ip" | "file",\n'
            '      "value": "extracted entity value",\n'
            '      "role": "target" | "actor" | "infrastructure" | "unknown"\n'
            "    }\n"
            "  ],\n"
            '  "mechanism_status": "KNOWN" | "UNKNOWN",\n'
            '  "answer_spec": {\n'
            '    "mode": "lookup" | "hunt",\n'
            '    "answer_type": "semantic type of the requested answer; do not restrict it to a fixed vocabulary",\n'
            '    "evidence_types": ["web_request", "dns_activity"],\n'
            '    "question": "The exact information the hunt must answer"\n'
            "  },\n"
            '  "hypotheses": [\n'
            "    {\n"
            '      "id": "hypo-1",\n'
            '      "statement": "Precise testable proposition of threat activity",\n'
            '      "class": "external_exploitation" | "credential_access" | "lateral_movement" | "persistence" | "data_exfiltration" | "benign_baseline" | "unclassified",\n'
            '      "assumptions": ["Explicit assumption necessary for this hypothesis to hold"],\n'
            '      "requirements": ["req-id-1", "req-id-2"]\n'
            "    }\n"
            "  ],\n"
            '  "requirements": [\n'
            "    {\n"
            '      "id": "req-id-1",\n'
            '      "semantic_intent": "web_request_activity",\n'
            '      "necessity": "CRITICAL" | "SUPPORTING",\n'
            '      "search_hints": ["search term or string to look for in provider logs"],\n'
            '      "falsification_condition": "Observable telemetry condition that refutes this requirement",\n'
            '      "description": "Human-readable requirement description",\n'
            '      "source_refs": ["Authoritative or behavioral citation"]\n'
            "    }\n"
            "  ]\n"
            "}"
        )

        self.llm_calls_made += 1
        raw_resp = self.llm_caller(prompt)

        # Parse and validate JSON schema strictly
        try:
            try:
                raw_json = json.loads(raw_resp) if isinstance(raw_resp, str) else raw_resp
            except (TypeError, json.JSONDecodeError):
                raw_json = {}
            answer_spec = raw_json.get("answer_spec", {}) if isinstance(raw_json, dict) else {}
            if not isinstance(answer_spec, dict):
                answer_spec = {}
            answer_type = str(answer_spec.get("answer_type", "unspecified")).strip().lower() or "unspecified"
            answer_evidence_types = [
                str(value).strip()
                for value in answer_spec.get("evidence_types", [])
                if str(value).strip() in ALLOWED_EVIDENCE_TYPES
            ]
            normalized_answer_spec = {
                "mode": "lookup" if str(answer_spec.get("mode", "hunt")).lower() == "lookup" else "hunt",
                "answer_type": answer_type,
                "evidence_types": answer_evidence_types,
                "question": str(answer_spec.get("question", request.content)).strip() or request.content,
            }
            hypotheses, requirements, intent = parse_and_validate_semantic_intent(raw_resp, request.content)
            if not hypotheses or all(h.status == HypothesisStatus.INSUFFICIENTLY_SPECIFIED for h in hypotheses):
                hypo_insufficient = Hypothesis(
                    id=f"hypo-{request.id}-insufficient",
                    statement=f"Semantic compilation was insufficient to derive verifiable requirements: '{request.content}'",
                    origin=HypothesisOrigin.LLM_PROPOSAL,
                    status=HypothesisStatus.INSUFFICIENTLY_SPECIFIED,
                    requirements=[],
                )
                objective = HuntObjective(
                    request_id=request.id,
                    target_hypotheses=[hypo_insufficient.id],
                    time_window=time_window,
                    target_scopes=request.provider_hints or ["cdb_native_scope"],
                    kind=request.kind,
                    statement=request.content,
                    semantic_intent=intent,
                )
                return objective, [hypo_insufficient], []

            # Set domain predicate strictly from LLM-provided search hints (NO regex on request.content)
            for r in requirements:
                if r.evidence_type in ("web_request", "dns_activity", "dns_query") and r.search_hints:
                    dom = None
                    for hint in r.search_hints:
                        if "." in hint and not hint.startswith("*") and not hint.endswith(".exe"):
                            dom = hint
                            break
                    if dom:
                        root_domain = dom[4:] if dom.lower().startswith("www.") else dom
                        r.predicate = FieldPredicate(field="site", op=FieldOp.CONTAINS, value=root_domain)

            # Add baseline requirement if competing benign hypothesis exists
            if any(h.hypothesis_class == "benign_baseline" for h in hypotheses):
                if not any(r.evidence_type == "scope_records" for r in requirements):
                    req_baseline = EvidenceRequirementV4(
                        id=f"req-{request.id}-baseline",
                        description=f"Verified operational telemetry baseline for: {request.content}",
                        evidence_type="scope_records",
                        semantic_intent="operational_baseline",
                        necessity="SUPPORTING",
                        falsification_condition="telemetry gap or unobservable audit partition",
                        source_refs=["SENSOR_BASELINE"],
                        status=RequirementStatus.DEFINED,
                    )
                    requirements.append(req_baseline)
                    for h in hypotheses:
                        if h.hypothesis_class == "benign_baseline":
                            if req_baseline.id not in h.requirements:
                                h.requirements.append(req_baseline.id)

            inv_model = build_investigation_model_from_intent(intent, hypotheses, requirements)
            inv_case = build_investigation_case_from_intent(intent, hypotheses, requirements)
            objective = HuntObjective(
                request_id=request.id,
                target_hypotheses=[h.id for h in hypotheses],
                time_window=time_window,
                target_scopes=request.provider_hints or ["cdb_native_scope"],
                kind=request.kind,
                statement=request.content,
                answer_spec=normalized_answer_spec,
                semantic_intent=intent,
                investigation_model=inv_model,
                case=inv_case,
                case_graph=inv_case.graph,
            )

            return objective, hypotheses, requirements

        except Exception:
            # Under strict anti-hallucination policy, DO NOT fallback to keyword guessing!
            hypo_insufficient = Hypothesis(
                id=f"hypo-{request.id}-insufficient",
                statement=f"Semantic compilation failed schema validation: '{request.content}'",
                origin=HypothesisOrigin.LLM_PROPOSAL,
                status=HypothesisStatus.INSUFFICIENTLY_SPECIFIED,
                requirements=[],
            )
            objective = HuntObjective(
                request_id=request.id,
                target_hypotheses=[hypo_insufficient.id],
                time_window=time_window,
                target_scopes=request.provider_hints or ["cdb_native_scope"],
            )
            return objective, [hypo_insufficient], []

    def _compile_unstructured(
        self,
        request: HuntRequest,
        time_window: str,
    ) -> tuple[HuntObjective, list[Hypothesis], list[EvidenceRequirementV4]]:
        """Alias to _compile_semantic_llm for backward compatibility."""
        return self._compile_semantic_llm(request, time_window)

    def _try_compile_structured_hypothesis(
        self,
        request: HuntRequest,
        time_window: str,
    ) -> tuple[HuntObjective, list[Hypothesis], list[EvidenceRequirementV4]] | None:
        """Deterministically parse and compile structured hypothesis definitions (YAML/JSON)."""
        if "{" not in request.content and "requirements:" not in request.content and "statement:" not in request.content:
            return None
        try:
            import yaml
            data = yaml.safe_load(request.content)
            if isinstance(data, dict) and "statement" in data and "requirements" in data:
                custom_reqs = []
                for r_dict in data.get("requirements", []):
                    pred = None
                    if "predicate" in r_dict and isinstance(r_dict["predicate"], dict):
                        p = r_dict["predicate"]
                        op_str = str(p.get("op", "EXISTS")).upper()
                        op_enum = getattr(FieldOp, op_str, FieldOp.EXISTS)
                        pred = FieldPredicate(field=str(p.get("field", "cmdline")), op=op_enum, value=p.get("value"))
                    custom_reqs.append(
                        EvidenceRequirementV4(
                            id=str(r_dict.get("id", f"req-{len(custom_reqs)+1}")),
                            description=str(r_dict.get("description", "Custom requirement")),
                            evidence_type=str(r_dict.get("evidence_type", "process_ancestry")),
                            predicate=pred or FieldPredicate(field="cmdline", op=FieldOp.EXISTS),
                            falsification_condition=str(r_dict.get("falsification_condition", "No matching evidence in telemetry")),
                            source_refs=list(r_dict.get("source_refs", ["CUSTOM_HYPOTHESIS"])),
                            status=RequirementStatus.DEFINED,
                        )
                    )
                req_baseline = EvidenceRequirementV4(
                    id=f"req-{request.id}-baseline",
                    description=f"Verified operational telemetry baseline for: {data['statement']}",
                    evidence_type="scope_records",
                    falsification_condition="telemetry gap or unobservable audit partition",
                    source_refs=["SENSOR_BASELINE"],
                    status=RequirementStatus.DEFINED,
                )
                hypo_active = Hypothesis(
                    id=f"hypo-{request.id}-active",
                    statement=str(data["statement"]),
                    origin=HypothesisOrigin.INPUT,
                    status=HypothesisStatus.LIVE,
                    hypothesis_class="unclassified",
                    requirements=[r.id for r in custom_reqs],
                )
                hypo_benign = Hypothesis(
                    id=f"hypo-{request.id}-benign",
                    statement=f"Telemetry reflects normal operational baseline; refuted hypothesis: '{data['statement']}'",
                    origin=HypothesisOrigin.RULE,
                    status=HypothesisStatus.LIVE,
                    hypothesis_class="benign_baseline",
                    requirements=[req_baseline.id],
                )
                objective = HuntObjective(
                    request_id=request.id,
                    target_hypotheses=[hypo_active.id, hypo_benign.id],
                    time_window=time_window,
                    target_scopes=request.provider_hints or ["cdb_native_scope"],
                    kind=request.kind,
                    statement=request.content,
                )
                return objective, [hypo_active, hypo_benign], [*custom_reqs, req_baseline]
        except Exception:
            pass
        return None

    def _compile_general_structured(
        self,
        request: HuntRequest,
        time_window: str,
    ) -> tuple[HuntObjective, list[Hypothesis], list[EvidenceRequirementV4]]:
        """General deterministic compilation when templates are not matched.

        Requires structured definitions (YAML/JSON with statement and requirements).
        Unstructured/free-text input without an LLM caller is marked INSUFFICIENTLY_SPECIFIED.
        """
        structured = self._try_compile_structured_hypothesis(request, time_window)
        if structured is not None:
            return structured

        # Unstructured free-text without an LLM caller cannot be compiled safely.
        hypo_insufficient = Hypothesis(
            id=f"hypo-{request.id}-insufficient",
            statement=f"Free-text hypothesis requires semantic compilation via LLM (--llm api): '{request.content}'",
            origin=HypothesisOrigin.INPUT,
            status=HypothesisStatus.INSUFFICIENTLY_SPECIFIED,
            requirements=[],
        )
        objective = HuntObjective(
            request_id=request.id,
            target_hypotheses=[hypo_insufficient.id],
            time_window=time_window,
            target_scopes=request.provider_hints or ["cdb_native_scope"],
            kind=request.kind,
            statement=request.content,
        )
        return objective, [hypo_insufficient], []

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


__all__ = [
    "KnowledgeBehaviorCompiler",
    "parse_and_validate_semantic_intent",
    "validate_compiler_llm_output",
]
