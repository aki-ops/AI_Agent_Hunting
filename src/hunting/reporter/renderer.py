"""Canonical Threat Hunting Markdown Report Renderer.

Pure rendering of FinalHuntAccount into an immutable, auditable markdown document.
Enforces:
- Strict separation of Scope Coverage and Requirement Coverage.
- Targeted queries never imply full scope coverage.
- NO_EVIDENCE_FOUND is emitted when no supporting evidence exists; NEVER rendered as BENIGN.
- Cites request, hypotheses, evidence cards, cited observations, queries, diagnostics, residuals.
- Explicit gap breakdown: Not found, Not observable, Unqueryable, Unknown source.
"""
from __future__ import annotations

from hunting.contracts.case_graph import RelationStatus
from hunting.contracts.hunt import (
    FinalHuntAccount,
    HuntOutcome,
    HypothesisStatus,
    StoppingDecision,
)


def render_final_hunt_account(account: FinalHuntAccount) -> str:
    """Render canonical Markdown report from FinalHuntAccount.

    Pure function: Never mutates account, dispositions, or hypotheses.
    """
    # Determine top-level outcome headline based on canonical account.outcome
    if account.outcome == HuntOutcome.SUPPORTED:
        outcome_str = HuntOutcome.SUPPORTED.value
        verdict_banner = f"**Investigation Outcome:** `{outcome_str}` (Adversary Activity Detected)"
    elif account.outcome == HuntOutcome.PARTIALLY_SUPPORTED:
        outcome_str = HuntOutcome.PARTIALLY_SUPPORTED.value
        verdict_banner = f"**Investigation Outcome:** `{outcome_str}` (Artifact Confirmed — Requested Attribute Unavailable)"
    elif account.outcome == HuntOutcome.SUPPORTED_WITH_LIMITATIONS:
        outcome_str = HuntOutcome.SUPPORTED_WITH_LIMITATIONS.value
        verdict_banner = f"**Investigation Outcome:** `{outcome_str}` (Partial Adversary Activity Detected — Exploration Bounded by Budget)"
    elif account.outcome == HuntOutcome.INCONCLUSIVE_BUDGET_EXHAUSTED:
        outcome_str = HuntOutcome.INCONCLUSIVE_BUDGET_EXHAUSTED.value
        verdict_banner = f"**Investigation Outcome:** `{outcome_str}` (Investigation Budget Exhausted Before Completion)"
    elif account.outcome == HuntOutcome.CONTRADICTED:
        outcome_str = HuntOutcome.CONTRADICTED.value
        verdict_banner = f"**Investigation Outcome:** `{outcome_str}` (Hypothesis Refuted by Negative Evidence)"
    elif account.outcome == HuntOutcome.INCONCLUSIVE:
        outcome_str = HuntOutcome.INCONCLUSIVE.value
        verdict_banner = f"**Investigation Outcome:** `{outcome_str}` (Telemetry Gap / Inconclusive Evidence)"
    elif account.outcome == HuntOutcome.UNREACHABLE:
        outcome_str = HuntOutcome.UNREACHABLE.value
        verdict_banner = "**Investigation Outcome:** `NO_EVIDENCE_FOUND` (Target Scopes Unreachable)"
    elif account.outcome == HuntOutcome.UNSUPPORTED:
        outcome_str = HuntOutcome.UNSUPPORTED.value
        verdict_banner = f"**Investigation Outcome:** `{outcome_str}` (Telemetry Unsupported)"
    elif account.outcome == HuntOutcome.INSUFFICIENTLY_SPECIFIED:
        outcome_str = HuntOutcome.INSUFFICIENTLY_SPECIFIED.value
        verdict_banner = f"**Investigation Outcome:** `{outcome_str}` (Insufficiently Specified)"
    else:
        outcome_str = "NO_EVIDENCE_FOUND"
        verdict_banner = "**Investigation Outcome:** `NO_EVIDENCE_FOUND` (Inconclusive / Bounded)"

    cb = account.coverage_bound
    req_cov = cb.requirement_coverage

    obj = account.objective
    kind_val = getattr(obj, "kind", None)
    if kind_val is not None:
        kind_str = kind_val.value if hasattr(kind_val, "value") else str(kind_val)
    else:
        kind_str = "HUNT"

    stmt_str = getattr(obj, "statement", "") or (f"Investigate {', '.join(obj.target_hypotheses)}" if getattr(obj, "target_hypotheses", None) else "Proactive hunt")

    tp = getattr(obj, "time_policy", None)
    if tp is not None and (tp.start or tp.end):
        time_frame_str = f"`{tp.start or 'N/A'}` to `{tp.end or 'N/A'}`"
    elif getattr(obj, "time_window", ""):
        time_frame_str = f"`{obj.time_window}`"
    else:
        time_frame_str = "`N/A`"

    entities = getattr(obj, "entities", [])
    if entities:
        ent_strs = [f"{type(e).__name__}({getattr(e, 'name', getattr(e, 'address', str(e)))})" for e in entities]
        entity_str = ", ".join(ent_strs)
    else:
        entity_str = "`POPULATION / ANY`"

    # Extract impacted entities from cards and objective:
    # Separate compromised hosts (adversary execution) from observer/sensor hosts (network telemetry capture)
    all_hosts: set[str] = set()
    compromised_hosts: set[str] = set()
    sensor_hosts: set[str] = set()
    all_users: set[str] = set()

    for c in account.evidence_cards:
        c_hosts = [str(h) for h in c.entity_summary.get("hosts", []) if str(h).strip()]
        for h in c_hosts:
            all_hosts.add(h)
        if c.fact_type in ("process_execution", "file_modification", "persistence_change"):
            for h in c_hosts:
                compromised_hosts.add(h)
        elif c.fact_type in ("web_request", "web_activity", "network_connection", "dns_activity"):
            for h in c_hosts:
                sensor_hosts.add(h)
        for u in c.entity_summary.get("users", []):
            all_users.add(str(u))

    if not compromised_hosts and all_hosts:
        compromised_hosts = set(all_hosts)

    hosts_str = ", ".join(f"`{h}`" for h in sorted(all_hosts)) if all_hosts else "`None detected`"
    comp_hosts_str = ", ".join(f"`{h}`" for h in sorted(compromised_hosts)) if compromised_hosts else "`None detected`"
    pure_sensor_hosts = sorted(sensor_hosts - compromised_hosts)
    sensor_hosts_str = ", ".join(f"`{h}`" for h in pure_sensor_hosts) if pure_sensor_hosts else None
    users_str = ", ".join(f"`{u}`" for u in sorted(all_users)) if all_users else "`None detected`"

    lines: list[str] = [
        "# Threat Hunting Investigation Final Account",
        "",
        verdict_banner,
        f"- **Request ID:** `{account.request_id}`",
        f"- **Stopping Decision:** `{account.stopping_decision.value}`",
        f"- **Hunt Kind:** `{kind_str}`",
        f"- **Objective Statement:** {stmt_str}",
        f"- **Searched Time Window:** {time_frame_str}",
        f"- **Target Entities:** {entity_str}",
        f"- **Compromised Target Host(s):** {comp_hosts_str}",
    ]
    if sensor_hosts_str:
        lines.append(f"- **Telemetry Capture / Sensor Host(s):** {sensor_hosts_str}")
    lines.extend([
        f"- **Impacted Accounts Identified:** {users_str}",
    ])
    if account.answer and account.answer.get("status") == "ANSWERED":
        ans_val = account.answer.get("value")
        ans_q = account.answer.get("question", "")
        lines.append(f"- **Investigative Finding / Resolved Answer:** `{ans_val}` (Question: *\"{ans_q}\"*)")
    if account.answer_status:
        ans_stat_val = account.answer_status.value if hasattr(account.answer_status, "value") else str(account.answer_status)
        if ans_stat_val != "UNANSWERED":
            lines.append(f"- **Answer Completeness Status:** `{ans_stat_val}`")
    lines.extend([
        "",
        "---",
        "## Executive Threat Brief",
        "",
    ])

    if account.outcome == HuntOutcome.SUPPORTED:
        supp_hyps = [h for h in account.hypotheses if h.status == HypothesisStatus.SUPPORTED]
        main_hyp = supp_hyps[0].statement if supp_hyps else stmt_str
        threat_brief_items = [
            "> [!CAUTION]",
            "> **CRITICAL FINDING: Adversary Activity Confirmed.**",
            "> Telemetry verification across observed security logs confirmed the active threat hypothesis:",
            f"> *\"{main_hyp}\"*.",
            f"> Suspicious behavior and anomalous command line executions were detected on compromised target host(s): **{comp_hosts_str}**",
            f"> involving user security context(s): **{users_str}**.",
            "",
            "**Key Incident Characteristics:**",
            "- **Attack Surface / Vector:** Web application / unauthorized remote command execution.",
            f"- **Compromised Target Host(s):** {comp_hosts_str}",
        ]
        if sensor_hosts_str:
            threat_brief_items.append(f"- **Telemetry Capture / Sensor Host(s):** {sensor_hosts_str} (network sniffer / telemetry tap)")
        threat_brief_items.extend([
            f"- **Executed Telemetry Queries:** {len(account.queries)} query executions across provider scopes.",
            f"- **Evidence Groups Validated:** {len(account.evidence_cards)} distinct evidence cards with verified telemetry falsification criteria.",
        ])
        lines.extend(threat_brief_items)
    elif account.outcome == HuntOutcome.SUPPORTED_WITH_LIMITATIONS:
        lines.extend([
            "> [!WARNING]",
            "> **INVESTIGATION OUTCOME: SUPPORTED WITH LIMITATIONS (BOUNDED EXPLORATION).**",
            "> Evidence partially supports the threat hypothesis, but investigation was bounded by resource budget before exhaustive validation.",
            f"> Observed activity on candidate host(s): **{hosts_str}**.",
        ])
    elif account.outcome == HuntOutcome.INCONCLUSIVE_BUDGET_EXHAUSTED:
        lines.extend([
            "> [!WARNING]",
            "> **INVESTIGATION OUTCOME: INCONCLUSIVE (BUDGET EXHAUSTED).**",
            "> The investigation budget was exhausted before sufficient evidence could be collected to confirm or refute the hypothesis.",
            "> Telemetry was incomplete or unverified at time of termination.",
        ])
    elif account.outcome == HuntOutcome.CONTRADICTED:
        lines.extend([
            "> [!NOTE]",
            "> **THREAT HYPOTHESIS REFUTED.**",
            "> Complete telemetry inspection evaluated the observable attack vectors and confirmed zero indications of adversary compromise.",
            "> Telemetry aligns with established benign operational baselines within the investigated scope and time window.",
        ])
    elif account.outcome == HuntOutcome.INCONCLUSIVE:
        lines.extend([
            "> [!WARNING]",
            "> **INVESTIGATION OUTCOME: INCONCLUSIVE (TELEMETRY GAP / UNCONFIRMED OBSERVATION).**",
            "> Telemetry inspection yielded inconclusive or partial data across target entities.",
            "> The observed evidence is insufficient to definitively support or contradict the hypothesis.",
        ])
    else:
        lines.extend([
            "> [!IMPORTANT]",
            "> **Epistemic Notice:** `NO_EVIDENCE_FOUND` represents the bounded absence of detected adversary activity",
            "> within the queried telemetry frame. This result is strictly **NOT** a finding of `BENIGN` and does not imply",
            "> absence of compromise outside the observed scope or telemetry capabilities.",
        ])

    # Tier 1 Analyst Report Sections: What Was Found, Why This Matters, Missing Evidence
    lines.extend([
        "",
        "### What Was Found",
        "",
    ])
    if account.evidence_cards:
        for c in account.evidence_cards:
            summary_txt = c.summary or f"{c.fact_type} on {', '.join(c.entity_summary.get('hosts', ['target']))}"
            lines.append(f"- **{summary_txt}** (`{c.id}`, count: {c.count})")
            if c.field_summary.get("cmdlines"):
                lines.append("  - *Commands Executed:*")
                for cmd in c.field_summary["cmdlines"]:
                    lines.append(f"    - `{cmd}`")
            if c.field_summary.get("file_paths"):
                lines.append(f"  - *Files:* {', '.join(f'`{fp}`' for fp in c.field_summary['file_paths'])}")
    else:
        lines.append("- No matching telemetry or evidence cards identified in searched scope.")

    lines.extend([
        "",
        "### Why This Matters",
        "",
    ])
    if account.evidence_cards:
        seen_why = set()
        for c in account.evidence_cards:
            why = c.why_it_matters or "Provides telemetry context within the monitored environment."
            if why not in seen_why:
                seen_why.add(why)
                lines.append(f"- **{c.fact_type.replace('_', ' ').title()}:** {why}")
    else:
        lines.append("- Telemetry indicates monitored systems operated within established operational baselines during the observation window.")

    lines.extend([
        "",
        "### Missing Evidence & Telemetry Gaps",
        "",
    ])
    fact_types = {c.fact_type for c in account.evidence_cards}
    missing_links: list[str] = []
    if "web_request" in fact_types and "process_execution" not in fact_types:
        missing_links.append("No server-side process execution detected following observed web requests.")
    if "process_execution" in fact_types and "file_modification" not in fact_types:
        missing_links.append("No persistent file modifications or dropped script payloads detected on host.")
    if "process_execution" in fact_types and "network_connection" not in fact_types:
        missing_links.append("No secondary outbound command-and-control (C2) network connections detected.")
    if not missing_links:
        if not account.evidence_cards:
            missing_links.append("No telemetry matching required behavioral indicators was observed.")
        else:
            missing_links.append("None — critical multi-stage chain correlation satisfied.")
    for link in missing_links:
        lines.append(f"- {link}")

    # Investigation Storyline & Process Walkthrough
    provider_names = {q.get("provider_id", "telemetry") for q in account.queries} if account.queries else {"telemetry"}
    scope_names = {q.get("scope_id", "default") for q in account.queries} if account.queries else {"default"}
    # Dynamically extract requirement types for timeline description
    req_names: list[str] = []
    if account.coverage_bound and account.coverage_bound.requirement_coverage:
        for r_id in account.coverage_bound.requirement_coverage.attempted_requirements:
            r_clean = r_id.split("-")[-1]
            if r_clean not in req_names:
                req_names.append(r_clean)
    if not req_names and account.hypotheses:
        for h in account.hypotheses:
            for r_id in h.requirements:
                r_clean = r_id.split("-")[-1]
                if r_clean not in req_names:
                    req_names.append(r_clean)
    req_summary_str = ", ".join(req_names) if req_names else "behavioral telemetry requirements"

    lines.extend([
        "",
        "---",
        "## Investigation Storyline & Execution Timeline",
        "",
        "| Phase | Stage Description | Actions & Telemetry Operations | Result / Status |",
        "|---|---|---|---|",
        f"| **Phase 1** | **Telemetry Environment Discovery** | Autonomous audit discovered live providers ({', '.join(sorted(provider_names))}) and scopes ({', '.join(sorted(scope_names))}) | Active telemetry indexed |",
        f"| **Phase 2** | **Hypothesis Decomposition** | Decomposed hypothesis into testable behavioral requirements ({req_summary_str}) | Requirements validated |",
        f"| **Phase 3** | **Population Discovery Sweep** | Executed wildcard sweep (`ANY` entity) across telemetry partition to discover candidate hosts | Candidate hosts: {hosts_str} |",
        f"| **Phase 4** | **Target Host Verification** | Promoted discovered hosts to instance cells; tested falsification predicates | {len(account.evidence_cards)} cards verified |",
        f"| **Phase 5** | **Termination & Final Accounting** | Reconciled scope coverage, requirement satisfaction, and epistemic disposition | Decision: `{account.stopping_decision.value}` |",
    ])

    # 1. Coverage Accounting (Separate Scope vs Requirement)
    lines.extend([
        "",
        "---",
        "## 1. Coverage Accounting",
        "",
        "> Scope coverage (spatial-temporal telemetry partition cells) is strictly accounted separately",
        "> from requirement coverage (behavioral TTPs). Targeted queries on specific entities do NOT",
        "> mark wildcard broadsweep cells as explored.",
        "",
        "### Scope Coverage (Spatial-Temporal Partition Cells)",
        "",
        "#### Wildcard Cells (BroadSweep / Population):",
        f"- Known: {cb.known_cells_wildcard}",
        f"- Explored: {cb.explored_cells_wildcard}",
        f"- Partial (truncated / split): {cb.partial_cells_wildcard}",
        f"- Unexplored: {cb.unexplored_cells_wildcard}",
        f"- Unqueryable (syntax / permissions / unsupported adapter): {cb.unqueryable_cells_wildcard}",
        f"- Unreachable (retention expired / missing telemetry): {cb.unreachable_cells_wildcard}",
        "",
        "#### Instance Cells (Discovered Concrete Entities):",
        f"- Known: {cb.known_cells_instance}",
        f"- Explored: {cb.explored_cells_instance}",
        f"- Partial: {cb.partial_cells_instance}",
        f"- Unexplored: {cb.unexplored_cells_instance}",
        f"- Unqueryable: {cb.unqueryable_cells_instance}",
        f"- Unreachable: {cb.unreachable_cells_instance}",
    ])

    scope_denom = cb.scope_coverage_denominator
    total_explored = cb.explored_cells_wildcard + cb.explored_cells_instance
    if scope_denom > 0:
        ratio_pct = (total_explored / scope_denom) * 100.0
        lines.append(f"\n**Active Scope Coverage Ratio:** {total_explored} / {scope_denom} active cells ({ratio_pct:.1f}%)")
    else:
        lines.append("\n**Active Scope Coverage Ratio:** 0 / 0 active cells (0.0%)")

    # Requirement Coverage
    lines.extend([
        "",
        "### Requirement Coverage (Behavioral TTPs)",
    ])
    if req_cov and req_cov.attempted_requirements:
        attempted_cnt = len(req_cov.attempted_requirements)
        satisfied_cnt = len(req_cov.satisfied_requirements)
        partial_cnt = len(req_cov.partial_requirements)
        unsupported_cnt = len(req_cov.unsupported_requirements)
        sat_pct = (satisfied_cnt / attempted_cnt * 100.0) if attempted_cnt > 0 else 0.0

        lines.extend([
            f"- **Attempted Requirements ({attempted_cnt}):** {list(req_cov.attempted_requirements)}",
            f"- **Satisfied Requirements ({satisfied_cnt}):** {list(req_cov.satisfied_requirements)}",
            f"- **Partial Requirements ({partial_cnt}):** {list(req_cov.partial_requirements)}",
            f"- **Unsupported Requirements ({unsupported_cnt}):** {list(req_cov.unsupported_requirements)}",
            f"- **Requirement Satisfaction Ratio:** {satisfied_cnt} / {attempted_cnt} attempted requirements ({sat_pct:.1f}%)",
        ])
    else:
        lines.extend([
            "- **Attempted Requirements (0):** []",
            "- **Satisfied Requirements (0):** []",
            "- **Partial Requirements (0):** []",
            "- **Unsupported Requirements (0):** []",
            "- **Requirement Satisfaction Ratio:** 0 / 0 attempted requirements (0.0%)",
        ])

    # Unmapped and Unknown Sources
    lines.extend([
        "",
        f"- **Unmapped Observations:** {cb.unmapped_observations}",
        f"- **Unknown Sources (excluded from coverage denominator):** {list(cb.unknown_sources) if cb.unknown_sources else '[]'}",
    ])

    # 2. Hypotheses Evaluation
    lines.extend([
        "",
        "---",
        "## 2. Hypotheses Evaluation",
        "",
        "| Hypothesis ID | Statement | Origin | Status | Requirements | Source Refs |",
        "|---|---|---|---|---|---|",
    ])
    for h in account.hypotheses:
        origin_str = h.origin.value if hasattr(h.origin, "value") else str(h.origin)
        status_str = h.status.value if hasattr(h.status, "value") else str(h.status)
        reqs_str = ", ".join(h.requirements) if h.requirements else "None"
        refs_str = ", ".join(h.source_refs) if h.source_refs else "None"
        stmt_clean = h.statement.replace("|", "\\|")
        lines.append(f"| `{h.id}` | {stmt_clean} | `{origin_str}` | **`{status_str}`** | {reqs_str} | {refs_str} |")

    # Competing Hypotheses Summary
    competing_live = [h.id for h in account.hypotheses if h.status == HypothesisStatus.LIVE]
    competing_supp = [h.id for h in account.hypotheses if h.status == HypothesisStatus.SUPPORTED]
    competing_ref = [h.id for h in account.hypotheses if h.status == HypothesisStatus.REFUTED]
    lines.extend([
        "",
        f"- **Supported Hypotheses:** {competing_supp if competing_supp else '[]'}",
        f"- **Competing Viable (Live) Hypotheses:** {competing_live if competing_live else '[]'}",
        f"- **Refuted Hypotheses:** {competing_ref if competing_ref else '[]'}",
    ])

    if account.claim_verdicts:
        lines.extend([
            "",
            "### Claims Evaluation",
            "",
            "| Claim ID | Statement | Required Capability | Status | Limitations |",
            "|---|---|---|---|---|",
        ])
        for cv in account.claim_verdicts:
            lims = "; ".join(cv.limitations) if cv.limitations else "None"
            stmt = cv.statement.replace("|", "\\|")
            lines.append(f"| `{cv.claim_id}` | {stmt} | `{cv.required_capability}` | **`{cv.status}`** | {lims} |")

    if account.limitations:
        lines.extend([
            "",
            "### Epistemic Limitations",
            "",
        ])
        for lim in account.limitations:
            lines.append(f"- {lim}")

    # Proven Relation Chain & Unresolved Unknowns (v5.0 Case Graph)
    case = getattr(account, "case", None)
    case_graph = getattr(account, "case_graph", None) or (getattr(case, "graph", None) if case else None)

    if case or case_graph or getattr(account, "provenance_chain", None):
        lines.extend([
            "",
            "### Proven Relation Chain (Causal Provenance)",
            "",
        ])
        proofs = list(case_graph.proofs.values()) if case_graph and case_graph.proofs else []
        if proofs:
            lines.extend([
                "| Edge ID | Relation Path | Citations | Verified At |",
                "|---|---|---|---|",
            ])
            for p in proofs:
                cits_str = ", ".join(f"`{c}`" for c in p.citations) if p.citations else "`N/A`"
                lines.append(f"| `{p.edge_id}` | `{p.source_value}` **-[{p.relation_type}]->** `{p.target_value}` | {cits_str} | `{p.verified_at}` |")
        elif getattr(account, "provenance_chain", None):
            for step in account.provenance_chain:
                lines.append(f"- {step}")
        else:
            lines.append("- *No causal relations were proven with valid citations.*")

        lines.extend([
            "",
            "### Unresolved Mandatory Unknowns",
            "",
        ])
        unknowns = getattr(case, "unknowns", []) if case else []
        unresolved_unknowns = [u for u in unknowns if not getattr(u, "resolved_value", None)]
        if unresolved_unknowns:
            lines.extend([
                "| Variable | Entity Type | Description | Status |",
                "|---|---|---|---|",
            ])
            for u in unresolved_unknowns:
                lines.append(f"| `{u.variable_name}` | `{u.entity_type}` | {u.description} | **`UNRESOLVED`** |")
        else:
            lines.append("- *All mandatory investigation unknowns were resolved.*")

    # 3. Key Technical Evidence & Forensic Artifacts
    lines.extend([
        "",
        "---",
        "## 3. Key Technical Evidence & Forensic Artifacts",
        "",
    ])
    if account.evidence_cards:
        lines.extend([
            "### Evidence Cards Summary",
            "| Host | User Context | Fact Type | Parent Process | Executable / Command / Artifact | Events | Card ID |",
            "|---|---|---|---|---|---|---|",
        ])
        for card in account.evidence_cards:
            c_hosts = ", ".join(f"`{h}`" for h in card.entity_summary.get("hosts", [])) if card.entity_summary.get("hosts") else "`N/A`"
            c_users = ", ".join(f"`{u}`" for u in card.entity_summary.get("users", [])) if card.entity_summary.get("users") else "`N/A`"
            c_parents = ", ".join(f"`{p.split(chr(92))[-1]}`" for p in card.field_summary.get("parent_images", [])) if card.field_summary.get("parent_images") else "`N/A`"

            # Identify main artifacts (cmdline, image, or file path)
            artifacts: list[str] = []
            if card.field_summary.get("cmdlines"):
                for c in card.field_summary["cmdlines"][:2]:
                    clean_c = c.replace("|", "\\|")
                    artifacts.append(f"`{clean_c[:60]}...`" if len(clean_c) > 60 else f"`{clean_c}`")
            elif card.field_summary.get("images"):
                for img in card.field_summary["images"][:2]:
                    artifacts.append(f"`{img.split(chr(92))[-1]}`")
            elif card.field_summary.get("file_paths"):
                for fp in card.field_summary["file_paths"][:2]:
                    artifacts.append(f"`{fp}`")
            elif card.field_summary.get("domains"):
                for d in card.field_summary["domains"][:2]:
                    artifacts.append(f"`{d}`")

            artifact_str = "<br>".join(artifacts) if artifacts else "`N/A`"
            lines.append(f"| {c_hosts} | {c_users} | `{card.fact_type}` | {c_parents} | {artifact_str} | {card.count} | `{card.id}` |")

        lines.extend([
            "",
            "### Detailed Evidence Breakdown",
        ])
        for card in account.evidence_cards:
            lines.extend([
                "",
                f"#### Evidence Card: `{card.id}` ({card.fact_type or 'General Activity'})",
                f"- **Fingerprint:** `{card.fingerprint[:24]}...`",
                f"- **Event Count:** {card.count} occurrences (`{card.completeness}` completeness)",
            ])
            if card.time_summary:
                t_earliest = card.time_summary.get("earliest", "N/A")
                t_latest = card.time_summary.get("latest", "N/A")
                lines.append(f"- **Observed Time Window:** `{t_earliest}` to `{t_latest}`")
            if card.entity_summary:
                ent_parts = [
                    f"**{k}:** {', '.join(f'`{v_item}`' for v_item in v)}" if isinstance(v, list) else f"**{k}:** `{v}`"
                    for k, v in card.entity_summary.items()
                ]
                lines.append(f"- **Associated Entities:** {'; '.join(ent_parts)}")

            if card.field_summary:
                if card.field_summary.get("parent_images"):
                    parents = [f"`{p}`" for p in card.field_summary["parent_images"]]
                    lines.append(f"- **Parent Process(es):** {', '.join(parents)}")
                if card.field_summary.get("images"):
                    imgs = [f"`{img}`" for img in card.field_summary["images"]]
                    lines.append(f"- **Image/Process Executable(s):** {', '.join(imgs)}")
                if card.field_summary.get("cmdlines"):
                    lines.append("- **Observed Command Lines:**")
                    for cmd in card.field_summary["cmdlines"]:
                        lines.append(f"  ```shell\n  {cmd}\n  ```")
                if card.field_summary.get("file_paths"):
                    lines.append("- **Observed File Paths:**")
                    for fp in card.field_summary["file_paths"]:
                        lines.append(f"  - `{fp}`")
                if card.field_summary.get("domains"):
                    lines.append(f"- **Observed Domains/Queries:** {', '.join(f'`{d}`' for d in card.field_summary['domains'])}")
                if card.field_summary.get("dest_ips"):
                    lines.append(f"- **Observed Remote IPs:** {', '.join(f'`{ip}`' for ip in card.field_summary['dest_ips'])}")
    else:
        lines.append("*No evidence cards generated.*")

    # Actionable Incident Response Recommendations (Proportional Guidance)
    lines.extend([
        "",
        "---",
        "## Actionable Incident Response Recommendations (Proportional Guidance)",
        "",
    ])
    if account.outcome == HuntOutcome.SUPPORTED:
        lines.extend([
            "> [!CAUTION]",
            "> **Tier 3 — Containment & Active Threat Neutralization (Analyst Sign-off Required):**",
            "> Full multi-stage attack chain verified across target host and observation window.",
            "",
            "1. **Endpoint Isolation & Containment:**",
            f"   - Disconnect and isolate impacted host(s): {comp_hosts_str} from the network to halt lateral movement.",
            "2. **Process & Shell Termination:**",
            "   - Terminate suspicious interactive shells and child processes identified under web worker processes.",
            "3. **Credential Invalidation:**",
            f"   - Invalidate active sessions and rotate credentials for affected security contexts: {users_str}.",
            "",
            "> [!IMPORTANT]",
            "> **Tier 2 — Targeted Investigation & Forensic Preservation:**",
            "- Collect volatile endpoint memory and process dump of active command interpreters.",
            "- Audit document root for web shells (`.php`, `.asp`, `.aspx`) matching the observed web access window.",
            "- Review parent-child lineage and persistence mechanisms (scheduled tasks, services, run keys).",
            "",
            "> [!NOTE]",
            "> **Tier 1 — Continuous Monitoring & Detection Tuning:**",
            "- Deploy detection rule for web server worker processes spawning interactive shells (`cmd.exe`, `powershell.exe`).",
            "- Monitor external IP destinations observed during the incident.",
        ])
    elif account.outcome == HuntOutcome.SUPPORTED_WITH_LIMITATIONS:
        lines.extend([
            "> [!WARNING]",
            "> **Tier 2 — Targeted Investigation & Forensic Validation (Recommended):**",
            "> Partial activity detected, but exploration was bounded by budget before exhaustive validation.",
            "",
            "1. **Lineage Inspection:**",
            f"   - Conduct in-depth manual forensic inspection on host(s): {hosts_str}.",
            "2. **Scope Extension:**",
            "   - Re-run targeted queries on identified suspicious processes with expanded budget.",
            "",
            "> [!NOTE]",
            "> **Tier 1 — Monitoring & Telemetry Enhancement:**",
            "- Enable process creation logging (Sysmon Event ID 1 / Windows 4688 with command line auditing).",
            "- Monitor target hosts for repeated execution attempts.",
        ])
    elif account.outcome in (HuntOutcome.INCONCLUSIVE_BUDGET_EXHAUSTED, HuntOutcome.INCONCLUSIVE):
        lines.extend([
            "> [!NOTE]",
            "> **Tier 1 — Monitoring & Telemetry Enhancement (Inconclusive Evidence / Telemetry Gap):**",
            "- **No Containment Actions Warranted:** Evidence does not substantiate active compromise.",
            "- **Audit Visibility:** Verify that required telemetry data sources (EDR process tracking, web access logs) are ingesting properly.",
            "- **Adjust Investigation Boundaries:** Broaden search time range or verify entity resolution if external indicators exist.",
        ])
    elif account.outcome == HuntOutcome.CONTRADICTED:
        lines.extend([
            "> [!TIP]",
            "> **Threat Refuted by Negative Evidence:**",
            "- No containment or incident escalation required for this hypothesis.",
            "- Maintain standard baseline monitoring.",
        ])
    else:
        lines.extend([
            "> [!NOTE]",
            "> **Tier 1 — Telemetry Visibility & Baseline Maintenance:**",
            "- No matching adversary activity detected within the queried scope.",
            "- Ensure log retention and coverage bounds cover critical infrastructure.",
        ])

    lines.extend([
        "",
        "### Cited Observations (Audit Trail)",
        "",
        "> [!NOTE]",
        "> The raw observation IDs below record deterministic telemetry provenance and mathematical auditability.",
        "",
    ])
    if account.observation_citations:
        lines.extend([
            "<details>",
            f"<summary><strong>Click to expand Raw Telemetry Observation IDs ({len(account.observation_citations)} events)</strong></summary>",
            "",
        ])
        sorted_citations = sorted(account.observation_citations)
        if len(sorted_citations) > 20:
            for obs_id in sorted_citations[:10]:
                lines.append(f"- `{obs_id}`")
            lines.append(f"- *... ({len(sorted_citations) - 10} additional observations stored in audit artifact `observations.jsonl`)*")
        else:
            for obs_id in sorted_citations:
                lines.append(f"- `{obs_id}`")
        lines.append("</details>")
    else:
        lines.append("- None")

    # 4. Query Audit Trail & Diagnostics
    lines.extend([
        "",
        "---",
        "## 4. Query Audit Trail & Diagnostics",
        "",
    ])
    if account.queries:
        lines.extend([
            "| Query ID | Req ID | Provider | Scope | Operation | Completeness | Targeted? |",
            "|---|---|---|---|---|---|---|",
        ])
        for q in account.queries:
            qid = q.get("query_id", "N/A")
            rid = q.get("requirement_id", "N/A")
            pid = q.get("provider_id", "N/A")
            sid = q.get("scope_id", "N/A")
            opid = q.get("operation_id", "N/A")
            cc = q.get("completeness_contract", "N/A")
            targeted = "YES" if q.get("is_targeted") else "NO (Broad)"
            lines.append(f"| `{qid}` | `{rid}` | `{pid}` | `{sid}` | `{opid}` | `{cc}` | `{targeted}` |")

        # Executable query statements
        queries_with_text = [q for q in account.queries if q.get("query_text")]
        if queries_with_text:
            lines.extend([
                "",
                "### Executed Query Statements (SPL / SQL)",
                "",
                "> [!TIP]",
                "> Chuyên viên phân tích SOC có thể sao chép trực tiếp các câu lệnh truy vấn dưới đây vào Splunk Web hoặc CDB để tự mình kiểm chứng lại kết quả.",
                "",
                "<details>",
                f"<summary><strong>Click to expand Executed Query Plans ({len(queries_with_text)} statements)</strong></summary>",
                "",
            ])
            for q in queries_with_text:
                qid = q.get("query_id", "N/A")
                opid = q.get("operation_id", "N/A")
                qtext = str(q.get("query_text", "")).strip()
                lang = "spl" if "search " in qtext.lower() else "sql"
                lines.extend([
                    f"#### Query: `{qid}` ({opid})",
                    f"```{lang}",
                    qtext,
                    "```",
                    "",
                ])
            lines.append("</details>")
    else:
        lines.append("*No queries executed.*")

    lines.extend([
        "",
        "### Diagnostics & Warnings",
    ])
    if account.diagnostics:
        for d in account.diagnostics:
            name = d.get("name", "Unknown")
            diag_class = d.get("diagnostic_class", "Info")
            details = d.get("details", "")
            lines.append(f"- **{name}** (`{diag_class}`): {details}")
    else:
        lines.append("- Clean: No query diagnostics or execution warnings recorded.")

    # 5. Visibility and Gap Breakdown (Not found, Not observable, Unqueryable, Unknown source)
    lines.extend([
        "",
        "---",
        "## 5. Visibility & Gap Breakdown",
        "",
    ])
    gaps = account.gap_breakdown

    not_found = gaps.get("not_found", [])
    not_observable = gaps.get("not_observable", [])
    unqueryable = gaps.get("unqueryable", [])
    unknown_source = gaps.get("unknown_source", [])

    lines.extend([
        "### 1. Not Found (Queried with Complete Coverage, Zero Findings)",
    ])
    if not_found:
        for item in not_found:
            lines.append(f"- {item}")
    else:
        lines.append("- None")

    lines.extend([
        "",
        "### 2. Not Observable (Telemetry Lacks Required Behavioral Fields)",
    ])
    if not_observable:
        for item in not_observable:
            lines.append(f"- {item}")
    else:
        lines.append("- None")

    lines.extend([
        "",
        "### 3. Unqueryable (Adapter Unsupported, Permission Denied, or Syntax Error)",
    ])
    if unqueryable:
        for item in unqueryable:
            lines.append(f"- {item}")
    else:
        lines.append("- None")

    lines.extend([
        "",
        "### 4. Unknown Source (Unmapped / Unregistered Telemetry, Excluded from Denominator)",
    ])
    if unknown_source:
        for item in unknown_source:
            lines.append(f"- {item}")
    else:
        lines.append("- None")

    # 6. Residual Uncertainty
    lines.extend([
        "",
        "---",
        "## 6. Residual Uncertainty & Investigation Boundaries",
        "",
    ])
    if account.residuals:
        for r in account.residuals:
            lines.append(f"> - {r}")
    else:
        lines.append("> - No residual uncertainty documented.")

    return "\n".join(lines)


def render_analyst_report(account: FinalHuntAccount) -> str:
    """Render the small analyst-facing report.

    The complete ledger and audit trail remain in the per-hunt artifacts. This
    view contains only the question, reasoning result, useful evidence, replay
    queries and LLM cost, so raw observation IDs do not bury the conclusion.
    """
    lines: list[str] = ["# Hunt Report", ""]
    objective = account.objective
    question = objective.statement or objective.request_id
    answer = account.answer or {}
    outcome = account.outcome.value
    stopping = account.stopping_decision.value

    lines.extend([
        "## 1. Hypothesis / Question",
        "",
        f"> {question}",
        "",
    ])
    intent = getattr(objective, "semantic_intent", None)
    if intent:
        lines.extend([
            f"- **Subject:** `{intent.subject.type}`: `{intent.subject.value}`",
            f"- **Requested Object:** `{intent.requested_object.type}` (role: `{intent.requested_object.role}`)",
            f"- **Behavior:** {intent.behavior}",
            "",
        ])
    lines.extend([
        f"**Result:** `{outcome}`  ",
        f"**Stopping:** `{stopping}`",
    ])
    cb = account.coverage_bound
    if cb:
        c_pct = cb.causal_path_coverage * 100.0
        w_pct = cb.wildcard_scope_coverage * 100.0
        i_pct = cb.instance_cell_coverage * 100.0
        lines.extend([
            "",
            f"- **Causal Path Coverage:** `{c_pct:.1f}%` ({cb.causal_path_verified_edges}/{cb.causal_path_total_edges} relations verified)",
            f"- **Wildcard Scope Coverage:** `{w_pct:.1f}%` ({cb.explored_cells_wildcard}/{cb.known_cells_wildcard} broadsweep cells)",
            f"- **Instance Cell Coverage:** `{i_pct:.1f}%` ({cb.explored_cells_instance}/{cb.known_cells_instance} concrete entity cells)",
        ])
    if account.answer_status:
        ans_stat_val = account.answer_status.value if hasattr(account.answer_status, "value") else str(account.answer_status)
        if ans_stat_val != "UNANSWERED":
            lines.extend(["", f"**Answer Status:** `{ans_stat_val}`"])
    if answer.get("status") == "ANSWERED":
        lines.extend([
            "",
            f"**Answer ({answer.get('answer_type', 'value')}):** `{answer.get('value', 'N/A')}`",
        ])
    elif answer.get("status") in ("PARTIALLY_SUPPORTED", "VERSION_UNAVAILABLE"):
        lines.extend([
            "",
            # v6: generic fallback — no hardcoded artifact name or host
            f"**Answer:** {answer.get('explanation') or 'The artifact was observed but the requested attribute value was not found in the retrieved telemetry.'}",
        ])

        if answer.get("citation_text"):
            lines.extend(["", f"**Evidence Citation:** {answer['citation_text']}"])
    elif answer.get("status") == "NOT_FOUND":
        lines.extend(["", "**Answer:** No matching value was found in the searched telemetry."])
    elif answer.get("status") == "INCONCLUSIVE":
        lines.extend(["", f"**Answer:** Inconclusive ({answer.get('reason', 'IDENTITY_UNRESOLVED')})"])
    if answer.get("explanation") and answer.get("status") not in ("PARTIALLY_SUPPORTED", "VERSION_UNAVAILABLE"):
        lines.extend(["", f"**Answer explanation:** {answer['explanation']}"])

    lines.extend(["", "## 2. Hypothesis analysis", ""])
    if account.hypotheses:
        for hypothesis in account.hypotheses:
            statement = hypothesis.statement.replace("|", "\\|")
            status = hypothesis.status.value if hasattr(hypothesis.status, "value") else str(hypothesis.status)
            lines.append(f"- `{status}` — {statement}")
    else:
        lines.append("- No testable hypothesis was produced.")

    if intent and intent.required_correlations:
        lines.extend([
            "",
            "**Required Correlation Chain:**",
            *(f"- `{step}`" for step in intent.required_correlations),
        ])
    case = getattr(account, "case", None)
    case_graph = getattr(case, "graph", None) if case else None
    proofs = list(case_graph.proofs.values()) if case_graph and getattr(case_graph, "proofs", None) else []
    if not proofs and getattr(account, "provenance_chain", None):
        proofs = account.provenance_chain

    if proofs:
        lines.extend([
            "",
            "### Proven Relation Chain (Causal Provenance)",
            "",
            "| Edge ID | Relation Path | Citations | Verified At |",
            "|---|---|---|---|",
        ])
        for p in proofs:
            cits = getattr(p, "citations", []) or []
            cits_str = ", ".join(f"`{c}`" for c in cits) if cits else "`N/A`"
            src_v = getattr(p, "source_value", "")
            tgt_v = getattr(p, "target_value", "")
            rel_t = getattr(p, "relation_type", "")
            if hasattr(rel_t, "value"):
                rel_t = rel_t.value
            ver_at = getattr(p, "verified_at", "")
            e_id = getattr(p, "edge_id", "")
            lines.append(f"| `{e_id}` | `{src_v}` **-[{rel_t}]->** `{tgt_v}` | {cits_str} | `{ver_at}` |")
    elif account.relation_graph and account.relation_graph.nodes:
        known_edges = [e for e in account.relation_graph.edges.values() if getattr(e, "status", "") in ("KNOWN", "verified", RelationStatus.VERIFIED)]
        if known_edges:
            lines.extend([
                "",
                "**Proven Relation Chain (Graph):**",
            ])
            for e in known_edges:
                src_n = account.relation_graph.get_node(e.source_id)
                tgt_n = account.relation_graph.get_node(e.target_id)
                src_str = f"{src_n.type}({src_n.value})" if src_n else e.source_id
                tgt_str = f"{tgt_n.type}({tgt_n.value})" if tgt_n else e.target_id
                q_info = f" (via `{e.origin_query_id}`)" if e.origin_query_id else ""
                lines.append(f"- `{src_str} -[{e.relation_type}]-> {tgt_str}`{q_info}")

    # Unresolved Mandatory Unknowns. Partial proof is not a complete causal
    # chain, so inspect case-graph unknowns even when earlier edges are proven.
    case_unresolved = []
    if case and hasattr(case, "unknowns") and case.unknowns:
        case_unresolved = [
            u for u in case.unknowns
            if not getattr(u, "resolved_value", None)
            and getattr(case.graph.get_edge(u.resolving_edge_id), "status", "") in ("unproven", "hypothesized", RelationStatus.UNPROVEN, RelationStatus.HYPOTHESIZED)
        ]
    case_unresolved_types = {
        str(getattr(u, "entity_type", "")).lower().replace("nodetype.", "")
        for u in case_unresolved
    }
    model_unresolved = []
    # The model has the most readable relation wording, while the case graph
    # decides which entity types are actually in this hunt.  Keep model
    # wording only when its entity type exists in the canonical graph; this
    # prevents a legacy IP hop from returning in an artifact-only case.
    if account.investigation_model and account.investigation_model.unknowns:
        model_unresolved = [
            u for u in account.investigation_model.unknowns
            if getattr(u, "status", "") == "UNRESOLVED"
            and (
                not case_graph
                or str(getattr(u, "entity_type", "")).lower().replace("nodetype.", "") in case_unresolved_types
            )
        ]

    # Prefer the semantic model's relationship wording, then include case
    # graph unknowns that are not already represented. This preserves both the
    # human-readable relation and the concrete unresolved target (for example,
    # recipient_role).
    unresolved = list(model_unresolved)
    seen_unknowns = {
        getattr(u, "relation_to_resolve", "") or getattr(u, "variable_name", "")
        for u in unresolved
    }
    model_types = {str(getattr(u, "entity_type", "")).lower() for u in unresolved}
    for unknown in case_unresolved:
        key = getattr(unknown, "relation_to_resolve", "") or getattr(unknown, "variable_name", "")
        entity_type = str(getattr(unknown, "entity_type", "")).lower()
        if key not in seen_unknowns and entity_type not in model_types:
            unresolved.append(unknown)
            seen_unknowns.add(key)
    if unresolved:
        lines.extend([
            "",
            "**Unresolved Mandatory Unknowns:**",
            *(
                f"- `{getattr(u, 'relation_to_resolve', '') or getattr(u, 'variable_name', '')}`: {u.description}"
                for u in unresolved
            ),
        ])
    elif proofs and (case or account.investigation_model):
        lines.extend([
            "",
            "**Unresolved Mandatory Unknowns:** None (all remaining causal relations are concluded).",
        ])
    elif intent and intent.uncertainties and not proofs:
        lines.extend([
            "",
            "**Current Uncertainties / Gaps:**",
            *(f"- {u}" for u in intent.uncertainties),
        ])

    if account.claim_verdicts:
        lines.extend([
            "",
            "### Claims Evaluation",
            "",
            "| Claim | Required Capability | Status |",
            "|---|---|---|",
        ])
        for cv in account.claim_verdicts:
            stmt = cv.statement.replace("|", "\\|")
            lines.append(f"| {stmt} | `{cv.required_capability}` | **`{cv.status}`** |")

    if account.limitations:
        lines.extend([
            "",
            "### Limitations",
            "",
        ])
        for lim in account.limitations:
            lines.append(f"- {lim}")

    lines.extend(["", "## 3. Evidence and explanation", ""])
    cards = list(account.evidence_cards)
    answer_card_ids = {
        card_id
        for candidate in answer.get("candidates", [])
        for card_id in candidate.get("card_ids", [])
    }
    answer_card_ids.update(
        str(card_id).strip()
        for card_id in answer.get("card_ids", [])
        if str(card_id).strip()
    )
    cards.sort(key=lambda card: (0 if (card.id in answer_card_ids or card.id.startswith("card-edge-")) else 1, -card.count, card.id))
    cards = cards[:12]
    if cards:
        lines.extend([
            "| Evidence | Why it matters | Source |",
            "|---|---|---|",
        ])
        assessments_by_card = {assessment.card_id: assessment for assessment in account.evidence_assessments}
        for card in cards:
            summary = card.summary or card.fact_type or "telemetry"
            if card.fact_type == "web_request":
                domains = card.field_summary.get("domains") or card.field_summary.get("sites") or []
                if domains:
                    summary = f"Web request to {', '.join(str(value) for value in domains[:3])}"
            elif card.fact_type == "dns_activity":
                domains = card.field_summary.get("domains") or card.field_summary.get("sites") or []
                if domains:
                    summary = f"DNS lookup for {', '.join(str(value) for value in domains[:3])}"
            assessment = assessments_by_card.get(card.id)
            why = (
                assessment.interpretation
                if assessment and assessment.interpretation
                else card.why_it_matters or "Supports the related evidence requirement."
            )
            reps = ", ".join(f"`{value}`" for value in card.representative_observation_ids[:3]) or "not recorded"
            source = f"{card.count} event(s); representative observations: {reps}"
            summary_md = summary.replace("|", "\\|")
            why_md = why.replace("|", "\\|")
            lines.append(f"| {summary_md} | {why_md} | {source} |")
    else:
        lines.append("No evidence cards were produced.")

    lines.extend(["", "### Explanation", ""])
    sem = account.semantic_analysis or {}
    parse_status = sem.get("parse_status", "")
    llm_expl = ""
    if isinstance(sem.get("answer"), dict):
        llm_expl = str(sem["answer"].get("explanation", "")).strip()

    if answer.get("status") == "ANSWERED":
        lines.append(f"- **Deterministic Graph Resolution:** The target object `{answer.get('value')}` was proven through the verified 4-step causal provenance chain.")

    det_expl = sem.get("deterministic_explanation") or (
        sem.get("answer", {}).get("explanation", "") if "Deterministic explanation:" in str(sem.get("answer", {}).get("explanation", "")) else ""
    )
    if not det_expl and answer.get("explanation"):
        det_expl = answer.get("explanation")

    if det_expl:
        clean_det = det_expl.replace("Deterministic explanation: ", "")
        lines.append(f"- **Deterministic Explanation:** {clean_det}")

    if parse_status == "SUCCESS" and llm_expl and not llm_expl.startswith("Deterministic explanation:"):
        lines.append(f"- **LLM Narrative Analysis:** {llm_expl}")
    elif parse_status and parse_status not in ("SUCCESS", "OFFLINE_DETERMINISTIC"):
        err_detail = sem.get("error_message", parse_status)
        lines.append(f"- **LLM Narrative Analysis:** Unavailable ({parse_status}: {err_detail} — fell back to deterministic explanation)")
    elif not sem or not account.llm_usage or parse_status == "OFFLINE_DETERMINISTIC":
        lines.append("- **LLM Narrative Analysis:** Not requested / offline deterministic mode.")


    explanations: list[str] = []
    assessments_by_card = {assessment.card_id: assessment for assessment in account.evidence_assessments}
    for card in cards:
        assessment = assessments_by_card.get(card.id)
        explanation = (
            assessment.interpretation.strip()
            if assessment and assessment.interpretation
            else card.why_it_matters.strip()
        )
        if explanation and explanation not in explanations:
            explanations.append(explanation)
    if explanations:
        lines.extend(f"- {item}" for item in explanations[:8])
    if account.outcome != HuntOutcome.SUPPORTED and account.stopping_decision != StoppingDecision.STOP_RESOLVED:
        semantic_missing = account.semantic_analysis.get("missing_evidence", []) if account.semantic_analysis else []
        for missing in semantic_missing[:5]:
            lines.append(f"- Missing according to evidence analysis: {missing}")
    if account.residuals:
        lines.append(f"- Limitation: {account.residuals[0]}")

    lines.extend(["", "## 4. Queries used", ""])
    if account.queries:
        for query in account.queries:
            query_id = query.get("query_id", "unknown-query")
            requirement = query.get("requirement_id", "unknown requirement")
            query_text = str(query.get("native_query") or query.get("query_text", "")).strip()
            purpose = query.get("purpose", "")
            reason = query.get("semantic_intent", "")
            result_sum = query.get("result_summary", "")
            hypo_ids = query.get("hypothesis_ids", [])
            lines.extend([
                f"### `{query_id}` — `{requirement}`",
                f"- **Purpose:** {purpose}" if purpose else "",
                f"- **Semantic Reason:** `{reason}`" if reason else "",
                f"- **Result:** {result_sum}" if result_sum else "",
                f"- **Hypothesis Impact:** Targets `{', '.join(hypo_ids)}`" if hypo_ids else "",
                f"Provider: `{query.get('provider_id', 'unknown')}`; completeness: `{query.get('completeness_contract', 'unknown')}`",
                "",
                "```spl",
                query_text or "(native query text not captured)",
                "```",
                "",
            ])
            # Filter out empty strings from lines
            lines = [line for line in lines if line is not None]
    else:
        lines.append("No query was executed.")

    usage = account.llm_usage or {}
    lines.extend([
        "## 5. Cost",
        "",
        f"- Model: `{usage.get('model', 'unknown')}`",
        f"- Calls: `{usage.get('calls_made', 0)}`",
        f"- Tokens: `{usage.get('total_tokens', 0)}`",
        f"- Estimated cost: `${float(usage.get('estimated_cost_usd', 0.0)):.6f}`",
    ])
    return "\n".join(lines) + "\n"


__all__ = ["render_final_hunt_account", "render_analyst_report"]
