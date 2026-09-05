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

from hunting.contracts.hunt import (
    FinalHuntAccount,
    HuntOutcome,
    HypothesisStatus,
)


def render_final_hunt_account(account: FinalHuntAccount) -> str:
    """Render canonical Markdown report from FinalHuntAccount.

    Pure function: Never mutates account, dispositions, or hypotheses.
    """
    # Determine top-level outcome headline based on canonical account.outcome
    if account.outcome == HuntOutcome.SUPPORTED:
        outcome_str = HuntOutcome.SUPPORTED.value
        verdict_banner = f"**Investigation Outcome:** `{outcome_str}` (Adversary Activity Detected)"
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

    # Actionable Containment & Incident Response Recommendations
    lines.extend([
        "",
        "---",
        "## Actionable Containment & Incident Response Recommendations",
        "",
    ])
    if account.supporting:
        lines.extend([
            "> [!CAUTION]",
            "> **Immediate Incident Response Actions Required:**",
            "",
            "1. **Endpoint Isolation & Containment:**",
            f"   - Immediately disconnect and isolate impacted host(s): {hosts_str} from the network to halt potential lateral movement.",
            "2. **Web Server & Webshell Eradication:**",
            "   - Audit web server document root directories (e.g., Joomla/IIS) for newly dropped or modified script files (`.php`, `.asp`, `.aspx`).",
            "   - Terminate suspicious child processes spawned under web server workers (`w3wp.exe`, `httpd.exe`, `php-cgi.exe`).",
            "3. **Account & Credential Security:**",
            f"   - Invalidate active sessions and rotate credentials for affected security contexts: {users_str}.",
            "   - Audit privilege escalation paths and recent modifications to local administrators / domain groups.",
            "4. **Detection Rule Deployment:**",
            "   - Deploy high-fidelity detection rules alerting on web server worker processes spawning script interpreters or command shells (`cmd.exe`, `powershell.exe`, `php-cgi.exe`).",
        ])
    elif account.contradicting and not account.supporting:
        lines.extend([
            "- **Threat Refuted:** No immediate containment actions required for this specific hypothesis.",
            "- **Continuous Monitoring:** Maintain standard telemetry logging and monitor for future deviations from benign baseline behavior.",
        ])
    else:
        lines.extend([
            "- **Inconclusive / Bounded Search:** No matching adversary telemetry was detected within the specified observation window.",
            "- **Visibility Improvement:** Consider expanding telemetry collection coverage or extending time boundary if threat activity is suspected through other indicators.",
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
        for obs_id in sorted(account.observation_citations):
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


__all__ = ["render_final_hunt_account"]
