"""Command Line Interface (CLI) runner for AI Agent Hunting.

Supports:
  1. Ingest alert from JSON/YAML file (--alert <path>)
  2. Ingest alert from CLI ad-hoc flags (--host, --user, --ip, --time)
  3. Ingest alert via standard input pipe (cat alert.json | python -m hunting.cli)
  4. Interactive prompt mode (-i, --interactive)
  5. Configurable LLM provider: stub (default, deterministic offline) or api (external LLM)
  6. Human confirmation enforcement (--auto-confirm vs console prompt)
  7. Exporting Markdown investigation reports (--output <path>)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import yaml

from hunting.compiler.compiler import KnowledgeBehaviorCompiler
from hunting.contracts.entities import Account, Domain, Host, IPAddress
from hunting.contracts.hunt import HuntRequest, HuntRequestKind
from hunting.contracts.state import Alert
from hunting.controller.cost import LLMUsageTracker
from hunting.engine import HypothesisHuntEngine
from hunting.evidence.evaluator import EvidenceEvaluator
from hunting.m2_abduction.provider import (
    ApiLLMConfig,
    ApiLLMProvider,
    StubAbductionProvider,
    create_llm_caller,
)
from hunting.m5_adapter import CdbAdapter, SplunkLiveAdapter
from hunting.orchestrator import InvestigationOrchestrator
from hunting.planner.planner import CanonicalQueryPlanner
from hunting.registry.loader import load_registry


def parse_alert_from_file_or_content(content_or_path: str) -> Alert:
    """Parse Alert from file path or JSON/YAML string."""
    data: dict[str, Any]
    path = Path(content_or_path)
    if path.exists() and path.is_file():
        raw_text = path.read_text(encoding="utf-8")
        if path.suffix in {".yaml", ".yml"}:
            data = yaml.safe_load(raw_text) or {}
        else:
            data = json.loads(raw_text)
    else:
        # Try direct JSON parsing
        try:
            data = json.loads(content_or_path)
        except Exception:
            data = yaml.safe_load(content_or_path) or {}

    alert_id = str(data.get("id", "alt-cli-001"))
    source = str(data.get("source", "cli"))
    received_at = str(data.get("received_at", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")))
    raw = str(data.get("raw", data.get("title", f"Alert from {source}")))
    fields = data.get("fields", {})

    return Alert(
        id=alert_id,
        raw=raw,
        source=source,
        received_at=received_at,
        fields=fields,
    )


def create_adhoc_alert(
    host: str | None = None,
    user: str | None = None,
    ip: str | None = None,
    domain: str | None = None,
    source: str = "EDR",
    timestamp: str | None = None,
    raw: str | None = None,
) -> Alert:
    """Construct an Alert from explicit CLI parameters."""
    ts = timestamp or datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    fields: dict[str, Any] = {"timestamp": ts}
    if host:
        fields["host"] = host
    if user:
        fields["user"] = user
    if ip:
        fields["ip"] = ip
    if domain:
        fields["domain"] = domain

    raw_text = raw or f"Ad-hoc investigation on host={host or 'any'} user={user or 'any'}"
    return Alert(
        id=f"alt-adhoc-{datetime.now(timezone.utc).strftime('%H%M%S')}",
        raw=raw_text,
        source=source,
        received_at=ts,
        fields=fields,
    )


def prompt_interactive_alert() -> Alert:
    """Prompt the analyst interactively via terminal stdin."""
    print("\n--- AI Agent Hunting: Interactive Alert Setup ---")
    host = input("[?] Host name (leave empty for broad anomaly sweep): ").strip() or None
    user = input("[?] User account (leave empty if unknown): ").strip() or None
    ip = input("[?] IP address (leave empty if unknown): ").strip() or None
    domain = input("[?] Domain / FQDN (leave empty if unknown): ").strip() or None
    source = input("[?] Alert source [default: EDR]: ").strip() or "EDR"
    time_str = input("[?] Alert timestamp [default: current UTC]: ").strip() or None

    return create_adhoc_alert(
        host=host,
        user=user,
        ip=ip,
        domain=domain,
        source=source,
        timestamp=time_str,
    )


def render_terminal_summary(
    alert: Alert,
    result: Any,
    output_path: str | None,
) -> None:
    """Print an attractive summary table to stdout."""
    cb = result.account.coverage_bound
    w_pct = (cb.explored_cells_wildcard / cb.known_cells_wildcard * 100) if cb.known_cells_wildcard > 0 else 0.0
    i_pct = (cb.explored_cells_instance / cb.known_cells_instance * 100) if cb.known_cells_instance > 0 else 0.0

    print("\n" + "=" * 72)
    print("                THREAT INVESTIGATION SUMMARY")
    print("=" * 72)
    print(f" Alert ID:        {alert.id} (Source: {alert.source})")
    entities_str = ", ".join(f"{k}={v}" for k, v in alert.fields.items() if k != "timestamp")
    print(f" Alert Entities:  {entities_str or '(None - Entity-free frame)'}")
    print(f" Time Window:     {result.state.seed.window}")
    print("-" * 72)
    print(f" Terminal State:  {result.account.terminal_state.value}")
    print(f" Disposition:     {result.account.disposition.value.upper()}")
    print(f" Human Confirmed: {'YES' if result.account.human_confirmed else 'NO'}")
    if result.account.residual:
        print(f" Residual:        {result.account.residual.strip()}")
    print("-" * 72)
    print(f" Ledger Evidence: {len(result.ledger.observations)} observations ({len(result.ledger.unattributed_observations)} unattributed)")
    print(f" Queries Executed: {len(result.state.queries)} queries ({', '.join(q.id for q in result.state.queries) or 'none'})")
    print(" Coverage Bounds:")
    print(f"   * Wildcard:     {cb.explored_cells_wildcard}/{cb.known_cells_wildcard} explored ({w_pct:.1f}%)")
    print(f"   * Instance:     {cb.explored_cells_instance}/{cb.known_cells_instance} explored ({i_pct:.1f}%)")
    print("=" * 72)
    if output_path:
        print(f" Full investigation report written to: {output_path}")
def render_hunt_playbook(
    request: HuntRequest,
    objective: Any,
    hypotheses: list[Any],
    requirements: list[Any],
    time_window: str,
    output_path: str | None,
) -> None:
    """Print an offline Threat Hunting Playbook & Query Plan to stdout and file."""
    manifest_file = "configs/splunk_botsv1.yaml" if Path("configs/splunk_botsv1.yaml").exists() else None
    offline_adapter = SplunkLiveAdapter(
        splunk_url="http://offline",
        index="botsv1",
        manifest_path=manifest_file,
        verify_ssl=False,
    )

    summary_content = request.content
    if "\n" in summary_content:
        for line in summary_content.splitlines():
            clean_l = line.strip()
            if clean_l.startswith("statement:"):
                summary_content = clean_l.replace("statement:", "").strip(' "\'')
                break
        else:
            summary_content = summary_content.splitlines()[0][:70] + "..."

    entities_str = ", ".join(f"{getattr(e, 'name', getattr(e, 'username', getattr(e, 'address', 'ent')))}" for e in request.entities)

    print("\n" + "=" * 80)
    print("               THREAT HUNTING PLAYBOOK & EXECUTION PLAN (DRY-RUN)")
    print("=" * 80)
    print(f" Request Kind:    {request.kind.value}")
    print(f" Hypothesis:      {summary_content}")
    print(f" Target Entities: {entities_str or '(Population Sweep / Wildcard)'}")
    print(f" Planned Window:  {time_window}")
    print(" Telemetry Mode:  OFFLINE (No telemetry backend contacted - Pure Plan Mode)")
    print("-" * 80)
    print(" 1. COMPETING SCIENTIFIC HYPOTHESES (Ma trận giả thuyết đối trọng):")
    for h in hypotheses:
        prefix = "BENIGN (H0)" if h.hypothesis_class == "benign_baseline" else "ACTIVE (H1)"
        print(f"   * [{prefix}] {h.statement}")
    print("-" * 80)
    print(" 2. EVIDENCE REQUIREMENTS & FALSIFICATION CRITERIA (Bằng chứng & Phản nghiệm):")
    for idx, r in enumerate(requirements, 1):
        pred_str = f"{r.predicate.field} {r.predicate.op.value} {r.predicate.value or ''}".strip() if r.predicate else "None"
        print(f"   * [Req {idx}]: {r.description}")
        print(f"     - Telemetry Class: {r.evidence_type}")
        print(f"     - Detection Predicate: {pred_str}")
        print(f"     - Falsification: {r.falsification_condition}")
    print("-" * 80)
    print(" 3. GENERATED QUERY PLANS (Các câu lệnh truy vấn mẫu cho SOC / Threat Hunter):")
    first_ent = request.entities[0] if request.entities else None
    for idx, r in enumerate(requirements, 1):
        spl, _, _ = offline_adapter._build_spl(
            operation_id=r.evidence_type,
            entity=first_ent,
            window=time_window,
            predicate=r.predicate,
            limit=100,
        )
        print(f"\n   --- [Query {idx}: {r.evidence_type.upper()}] ---")
        for spl_line in spl.splitlines():
            print(f"   {spl_line}")
    print("=" * 80)

    # Markdown export
    if output_path:
        md_lines = [
            f"# Threat Hunting Playbook: {summary_content}",
            "",
            f"- **Request ID:** `{request.id}`",
            f"- **Request Kind:** `{request.kind.value}`",
            f"- **Target Entities:** `{entities_str or 'ANY'}`",
            f"- **Planned Time Window:** `{time_window}`",
            "- **Execution Mode:** `PLAN_ONLY` (Offline Pre-flight Playbook)",
            "",
            "---",
            "## 1. Competing Hypotheses Matrix",
            "",
            "| Hypothesis ID | Type | Statement |",
            "|---|---|---|",
        ]
        for h in hypotheses:
            htype = "Benign Baseline (H0)" if h.hypothesis_class == "benign_baseline" else "Active Adversary (H1)"
            md_lines.append(f"| `{h.id}` | **{htype}** | {h.statement} |")

        md_lines.extend([
            "",
            "---",
            "## 2. Evidence Requirements & Falsification Criteria",
            "",
            "| Req ID | Evidence Type | Predicate | Falsification Condition | Sources |",
            "|---|---|---|---|---|",
        ])
        for r in requirements:
            p_str = f"`{r.predicate.field} {r.predicate.op.value} {r.predicate.value or ''}`".strip() if r.predicate else "-"
            md_lines.append(f"| `{r.id}` | `{r.evidence_type}` | {p_str} | {r.falsification_condition} | {', '.join(r.source_refs)} |")

        md_lines.extend([
            "",
            "---",
            "## 3. Ready-to-Execute Parameterized Queries (SPL)",
            "",
        ])
        for idx, r in enumerate(requirements, 1):
            spl, earliest, latest = offline_adapter._build_spl(
                operation_id=r.evidence_type,
                entity=first_ent,
                window=time_window,
                predicate=r.predicate,
                limit=100,
            )
            md_lines.append(f"### 3.{idx}. Query for `{r.evidence_type}`")
            md_lines.append(f"- **Earliest Time:** `{earliest}`")
            md_lines.append(f"- **Latest Time:** `{latest}`")
            md_lines.append("```spl")
            md_lines.append(spl)
            md_lines.append("```")
            md_lines.append("")

        out_file = Path(output_path)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text("\n".join(md_lines), encoding="utf-8")
        print(f" Playbook saved to: {output_path}")
        print()


def render_hunt_terminal_summary(
    request: HuntRequest,
    result: Any,
    output_path: str | None,
) -> None:
    """Print an attractive summary table for hypothesis hunts to stdout."""
    account = result.account
    cb = account.coverage_bound
    w_pct = (cb.explored_cells_wildcard / cb.known_cells_wildcard * 100) if cb.known_cells_wildcard > 0 else 0.0
    i_pct = (cb.explored_cells_instance / cb.known_cells_instance * 100) if cb.known_cells_instance > 0 else 0.0

    print("\n" + "=" * 72)
    print("                THREAT HUNTING ACCOUNT SUMMARY")
    print("=" * 72)
    summary_content = request.content
    if "\n" in summary_content:
        for line in summary_content.splitlines():
            clean_l = line.strip()
            if clean_l.startswith("statement:"):
                summary_content = clean_l.replace("statement:", "").strip(' "\'')
                break
        else:
            summary_content = summary_content.splitlines()[0][:60] + "..."

    print(f" Hypothesis/Content:{summary_content}")
    entities_str = ", ".join(f"{getattr(e, 'name', getattr(e, 'username', getattr(e, 'address', 'ent')))}" for e in request.entities)
    print(f" Target Entities: {entities_str or '(Population Sweep / Wildcard)'}")
    print(f" Time Window:     {account.objective.time_window}")
    print("-" * 72)
    print(f" Final Outcome:   {account.outcome.value}")
    print(f" Stopping Dec:    {account.stopping_decision.value}")
    print(f" Hypotheses:      {len(account.hypotheses)} total ({len(account.supporting)} supported, {len(account.contradicting)} contradicted)")
    for h in account.hypotheses:
        print(f"   * [{h.status.value}] {h.id}: {h.statement[:55]}")
    print("-" * 72)
    print(f" Evidence Cards:  {len(account.evidence_cards)} cards")
    print(f" Ledger Events:   {len(result.ledger.observations)} observations")
    print(f" Queries Run:     {len(account.queries)} queries")
    print(f" Coverage:        Wildcard: {w_pct:.1f}%, Instance: {i_pct:.1f}%")
    llm_info = getattr(result.state, "llm_usage", {})
    if llm_info:
        calls = llm_info.get("calls_made", 0)
        tokens = llm_info.get("total_tokens", 0)
        cost = llm_info.get("estimated_cost_usd", 0.0)
        model = llm_info.get("model", "stub")
        print(f" AI Usage & Cost: {calls} calls, {tokens} tokens, ${cost:.6f} USD ({model})")
    print("=" * 72)
    if output_path:
        print(f" Full threat hunt report written to: {output_path}")
    print()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hunting",
        description="AI Agent Hunting: Deterministic Hypothesis Threat Hunting & Investigation CLI",
    )
    # Hypothesis / Threat Hunting inputs (v4)
    hunt_group = parser.add_argument_group("Hypothesis & Threat Hunting Inputs (v4)")
    hunt_group.add_argument("--hypothesis", "-H", type=str, help="Explicit hypothesis statement to test and verify (e.g. 'Attacker used webshell to execute cmd.exe')")
    hunt_group.add_argument("--hypothesis-file", type=str, help="Path to YAML/JSON file declaring custom hypothesis, requirements, and falsification conditions")
    hunt_group.add_argument("--plan-only", "--dry-run", dest="plan_only", action="store_true", help="Compile hypothesis into a structured Threat Hunt Playbook and query plans without executing queries on any backend")
    hunt_group.add_argument("--cve", type=str, help="Hunt for known CVE identifier (e.g. CVE-2024-21887)")
    hunt_group.add_argument("--ttp", type=str, help="Hunt for MITRE ATT&CK technique (e.g. T1059.001)")
    hunt_group.add_argument("--ioc", type=str, help="Hunt for observable indicator of compromise (e.g. IP/domain/hash)")
    hunt_group.add_argument("--threat-actor", type=str, help="Hunt for threat actor campaign/profile")
    hunt_group.add_argument("--campaign", type=str, help="Hunt for specific adversary campaign")
    hunt_group.add_argument("--query", "-q", type=str, help="Natural language hunting question")
    hunt_group.add_argument("--time-window", type=str, help="Explicit search time window ISO interval (e.g. 2026-02-01T00:00:00Z/P1D)")

    # Alert inputs (Legacy compatibility)
    alert_group = parser.add_argument_group("Alert Inputs (Legacy)")
    alert_group.add_argument("--alert", "-a", type=str, help="Path to alert JSON/YAML file or raw JSON string")
    alert_group.add_argument("--host", type=str, help="Host entity (e.g. DESKTOP-VICTIM1)")
    alert_group.add_argument("--user", type=str, help="User entity (e.g. CORP\\alice)")
    alert_group.add_argument("--ip", type=str, help="IP entity (e.g. 192.168.1.50)")
    alert_group.add_argument("--domain", type=str, help="Domain entity (e.g. evil-c2.corp.internal)")
    alert_group.add_argument("--source", type=str, default="EDR", help="Alert source name [default: EDR]")
    alert_group.add_argument("--time", type=str, help="Alert timestamp ISO 8601 [default: current UTC]")
    alert_group.add_argument("-i", "--interactive", action="store_true", help="Interactive prompt mode for alert setup")

    # Environment & Backend
    env_group = parser.add_argument_group("Environment & Backend")
    env_group.add_argument("--provider", choices=["auto", "cdb", "splunk"], default="auto", help="Telemetry provider: 'auto' (detect live SIEM/Splunk or fallback to CDB), 'cdb' (local SQLite), or 'splunk' (live enterprise SIEM) [default: auto]")
    env_group.add_argument("--list-indexes", action="store_true", help="List all accessible Splunk indexes with event counts and exit")
    env_group.add_argument("--splunk-url", type=str, default=os.getenv("SPLUNK_URL", "https://localhost:8089"), help="Splunk management REST API endpoint [default: https://localhost:8089]")
    env_group.add_argument("--splunk-user", type=str, default=os.getenv("SPLUNK_USER", "admin"), help="Splunk admin username [default: admin]")
    env_group.add_argument("--splunk-pass", type=str, default=os.getenv("SPLUNK_PASSWORD", "12345678"), help="Splunk password [default: 12345678]")
    env_group.add_argument("--splunk-index", type=str, default=os.getenv("SPLUNK_INDEX", "auto"), help="Target Splunk index name or 'auto' for automated discovery [default: auto]")
    env_group.add_argument("--splunk-manifest", type=str, default=None, help="Path to declarative YAML mapping manifest [default: configs/splunk_botsv1.yaml]")
    env_group.add_argument("--manifest", "-m", type=str, default="tests/fixtures/registry_cdb.yaml", help="Path to ProviderScope registry YAML")
    env_group.add_argument("--db", type=str, default="data/cdb_sample.sqlite", help="Path to SQLite CDB database")
    env_group.add_argument("--output", "-o", type=str, default="report.md", help="Path to output Markdown report file")

    # LLM & Human Loop
    loop_group = parser.add_argument_group("LLM & Human-in-the-Loop")
    loop_group.add_argument("--llm", choices=["stub", "api"], default="stub", help="LLM engine: 'stub' (offline deterministic) or 'api' (external HTTP)")
    loop_group.add_argument("--llm-model", type=str, default=None, help="LLM model name (e.g. gemini-2.5-flash, gpt-4o, 1/grok-4.6) [default: from env or config]")
    loop_group.add_argument("--llm-endpoint", type=str, default=None, help="LLM REST endpoint URL [default: from env or config]")
    loop_group.add_argument("--api-key", type=str, default=None, help="LLM API authorization key [default: from env]")
    loop_group.add_argument("--auto-confirm", dest="auto_confirm", action="store_true", default=True, help="Automatically sign-off mandatory analyst confirmation")
    loop_group.add_argument("--no-auto-confirm", dest="auto_confirm", action="store_false", help="Prompt analyst interactively on console for mandatory confirmation")

    return parser


def run_cli(args: argparse.Namespace) -> int:
    """Execute investigation or hypothesis-driven hunt workflow based on parsed arguments."""
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    # Handle index exploration
    if getattr(args, "list_indexes", False):
        adapter = SplunkLiveAdapter(
            splunk_url=args.splunk_url,
            auth=(args.splunk_user, args.splunk_pass),
            index=args.splunk_index,
            verify_ssl=False,
        )
        try:
            indexes = adapter.list_indexes()
        except Exception as e:
            print(f"[-] Error listing Splunk indexes: {e}", file=sys.stderr)
            return 1

        print("\n" + "=" * 90)
        print("                       SPLUNK INDEX TELEMETRY CATALOG")
        print("=" * 90)
        print(f" {'INDEX NAME':<20} | {'TOTAL EVENTS':>14} | {'STATUS':<8} | {'MIN TIME':<20} | {'MAX TIME':<20}")
        print("-" * 90)
        for idx in indexes:
            status = "DISABLED" if idx["disabled"] else "ACTIVE"
            min_t = idx["min_time"][:19] if idx["min_time"] else "-"
            max_t = idx["max_time"][:19] if idx["max_time"] else "-"
            print(f" {idx['name']:<20} | {idx['total_events']:>14,d} | {status:<8} | {min_t:<20} | {max_t:<20}")
        print("=" * 90)
        print(f" Total indexes discovered: {len(indexes)}")
        print()
        return 0

    # Check if hypothesis threat hunting mode is triggered
    is_hypothesis_hunt = bool(args.cve or args.ttp or args.ioc or args.threat_actor or args.campaign or args.query or args.hypothesis or args.hypothesis_file)

    # 1. Pure Plan / Dry-run Mode (Offline - No telemetry provider contacted)
    if is_hypothesis_hunt and getattr(args, "plan_only", False):
        entities = []
        if args.host:
            entities.append(Host(name=args.host))
        if args.user:
            entities.append(Account(username=args.user))
        if args.ip:
            entities.append(IPAddress(address=args.ip))
        if args.domain:
            entities.append(Domain(name=args.domain))

        if args.hypothesis_file:
            path = Path(args.hypothesis_file)
            if not path.exists():
                print(f"[-] Error: Hypothesis file not found: {path}", file=sys.stderr)
                return 1
            content = path.read_text(encoding="utf-8")
            kind = HuntRequestKind.HYPOTHESIS
            try:
                import yaml
                h_data = yaml.safe_load(content)
                if isinstance(h_data, dict) and "entities" in h_data:
                    for ent_dict in h_data["entities"]:
                        k = str(ent_dict.get("kind", "")).lower()
                        v = ent_dict.get("value")
                        if k == "host" and v and not any(isinstance(e, Host) and e.name == v for e in entities):
                            entities.append(Host(name=v))
                        elif k in ("user", "account") and v and not any(isinstance(e, Account) and e.username == v for e in entities):
                            entities.append(Account(username=v))
                        elif k == "ip" and v and not any(isinstance(e, IPAddress) and e.address == v for e in entities):
                            entities.append(IPAddress(address=v))
            except Exception:
                pass
        elif args.hypothesis:
            kind = HuntRequestKind.HYPOTHESIS
            content = args.hypothesis
        elif args.cve:
            kind = HuntRequestKind.CVE
            content = args.cve
        elif args.ttp:
            kind = HuntRequestKind.TTP
            content = args.ttp
        elif args.ioc:
            kind = HuntRequestKind.IOC
            content = args.ioc
        elif args.query:
            kind = HuntRequestKind.NL_QUESTION
            content = args.query
        else:
            kind = HuntRequestKind.HYPOTHESIS
            content = args.threat_actor or args.campaign or "Adversary Campaign"

        req = HuntRequest(
            id=f"hunt-req-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",
            kind=kind,
            content=content,
            entities=entities,
        )
        compiler = KnowledgeBehaviorCompiler()
        default_window = "2016-08-01T00:00:00Z/2016-08-29T23:59:59Z" if getattr(args, "provider", "auto") in ("splunk", "auto") else "NOW-14d/NOW"
        time_win = args.time_window or default_window
        objective, hypotheses, requirements = compiler.compile(req, time_window=time_win)
        render_hunt_playbook(req, objective, hypotheses, requirements, time_win, args.output)
        return 0

    # Determine if hypothesis threat hunting mode is triggered
    is_hypothesis_hunt = bool(args.cve or args.ttp or args.ioc or args.threat_actor or args.campaign or args.query or args.hypothesis or args.hypothesis_file)

    # Initialize Telemetry Provider Adapter with Automated Environment Audit
    selected_provider = getattr(args, "provider", "auto")
    auto_discovered_index_info: dict[str, Any] | None = None

    if selected_provider == "auto":
        if is_hypothesis_hunt:
            print("[*] [ENVIRONMENT AUDIT] Auditing available telemetry systems...")
            splunk_alive = SplunkLiveAdapter.is_available(
                splunk_url=args.splunk_url,
                auth=(args.splunk_user, args.splunk_pass),
                verify_ssl=False,
                timeout=2,
            )
            if splunk_alive:
                selected_provider = "splunk"
                print(f"[+] [ENVIRONMENT AUDIT] Detected live enterprise SIEM: Splunk at {args.splunk_url}")
            else:
                selected_provider = "cdb"
                print("[*] [ENVIRONMENT AUDIT] Splunk SIEM not reachable. Using local telemetry backend: CDB (SQLite).")
        else:
            # Legacy alert mode defaults to cdb for backwards compatibility
            selected_provider = "cdb"

    if selected_provider == "splunk":
        selected_index = args.splunk_index
        if selected_index in (None, "", "auto"):
            try:
                auto_discovered_index_info = SplunkLiveAdapter.auto_select_index(
                    splunk_url=args.splunk_url,
                    auth=(args.splunk_user, args.splunk_pass),
                    verify_ssl=False,
                )
                selected_index = auto_discovered_index_info["name"]
            except Exception:
                selected_index = "botsv1"

        manifest_file = args.splunk_manifest
        if manifest_file and manifest_file.lower() in ("none", "null", "discovery", "auto", "mode1"):
            manifest_file = None
        elif manifest_file is None:
            idx_manifest = Path(f"configs/splunk_{selected_index}.yaml")
            default_cfg = Path("configs/splunk_botsv1.yaml")
            if idx_manifest.exists():
                manifest_file = str(idx_manifest)
            elif default_cfg.exists():
                manifest_file = str(default_cfg)

        adapter = SplunkLiveAdapter(
            splunk_url=args.splunk_url,
            auth=(args.splunk_user, args.splunk_pass),
            index=selected_index,
            manifest_path=manifest_file,
            verify_ssl=False,
        )
        try:
            adapter.validate_index()
        except ValueError as ve:
            print(f"[-] Splunk Index Validation Error: {ve}", file=sys.stderr)
            return 1

        ev_count = f" ({auto_discovered_index_info['total_events']:,} events)" if auto_discovered_index_info and auto_discovered_index_info.get("name") == selected_index else ""
        print(f"[+] [ENVIRONMENT AUDIT] Selected active index: '{adapter.index}'{ev_count} (Mode: {adapter.binding_mode.upper()})")
        if adapter.discovered_sourcetypes:
            st_summary = ", ".join(f"{k} ({v:,})" for k, v in list(adapter.discovered_sourcetypes.items())[:3])
            print(f"[+] [ENVIRONMENT AUDIT] Discovered sourcetypes: {st_summary}...")
    else:
        db_path = Path(args.db)
        if not db_path.exists():
            adapter = CdbAdapter(":memory:")
        else:
            adapter = CdbAdapter(str(db_path))
        print(f"[*] Telemetry backend: Local CDB ({db_path if db_path.exists() else ':memory:'})")

    if is_hypothesis_hunt:
        entities = []
        if args.host:
            entities.append(Host(name=args.host))
        if args.user:
            entities.append(Account(username=args.user))
        if args.ip:
            entities.append(IPAddress(address=args.ip))
        if args.domain:
            entities.append(Domain(name=args.domain))

        if args.hypothesis_file:
            path = Path(args.hypothesis_file)
            if not path.exists():
                print(f"[-] Error: Hypothesis file not found: {path}", file=sys.stderr)
                return 1
            content = path.read_text(encoding="utf-8")
            kind = HuntRequestKind.HYPOTHESIS
            try:
                import yaml
                h_data = yaml.safe_load(content)
                if isinstance(h_data, dict) and "entities" in h_data:
                    for ent_dict in h_data["entities"]:
                        k = str(ent_dict.get("kind", "")).lower()
                        v = ent_dict.get("value")
                        if k == "host" and v and not any(isinstance(e, Host) and e.name == v for e in entities):
                            entities.append(Host(name=v))
                        elif k in ("user", "account") and v and not any(isinstance(e, Account) and e.username == v for e in entities):
                            entities.append(Account(username=v))
                        elif k == "ip" and v and not any(isinstance(e, IPAddress) and e.address == v for e in entities):
                            entities.append(IPAddress(address=v))
            except Exception:
                pass
        elif args.hypothesis:
            kind = HuntRequestKind.HYPOTHESIS
            content = args.hypothesis
        elif args.cve:
            kind = HuntRequestKind.CVE
            content = args.cve
        elif args.ttp:
            kind = HuntRequestKind.TTP
            content = args.ttp
        elif args.ioc:
            kind = HuntRequestKind.IOC
            content = args.ioc
        elif args.query:
            kind = HuntRequestKind.NL_QUESTION
            content = args.query
        else:
            kind = HuntRequestKind.HYPOTHESIS
            content = args.threat_actor or args.campaign or "Adversary Campaign"

        req = HuntRequest(
            id=f"hunt-req-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",
            kind=kind,
            content=content,
            entities=entities,
        )

        # Wire LLM Provider, Trackers, Compiler, Planner, and Evaluator for v4 Engine
        if args.llm == "api":
            config = ApiLLMConfig.from_env()
            if args.llm_endpoint or args.llm_model or args.api_key:
                config = ApiLLMConfig(
                    endpoint=args.llm_endpoint or config.endpoint,
                    model=args.llm_model or config.model,
                    timeout_seconds=config.timeout_seconds,
                    max_tokens=config.max_tokens,
                    api_key=args.api_key or config.api_key,
                )
            llm_provider = ApiLLMProvider(config)
            llm_tracker = LLMUsageTracker(max_calls=3, model_name=config.model)
            compiler_caller = create_llm_caller(llm_provider, llm_tracker, "compiler")
            planner_caller = create_llm_caller(llm_provider, llm_tracker, "planner")
            evaluator_caller = create_llm_caller(llm_provider, llm_tracker, "evaluator")

            compiler = KnowledgeBehaviorCompiler(llm_caller=compiler_caller)
            planner = CanonicalQueryPlanner(llm_generator=planner_caller)
            evaluator = EvidenceEvaluator(llm_caller=evaluator_caller)
            print(f"[+] [AI SUB-SYSTEM] Active ApiLLMProvider: model='{config.model}' endpoint='{config.endpoint}'")
        elif args.llm == "stub":
            llm_tracker = LLMUsageTracker(max_calls=3, model_name="stub")
            # Stub mode is deliberately non-semantic. It must not invent a
            # generic interpretation for arbitrary free text; use --llm api
            # when natural-language compilation is required.
            compiler = KnowledgeBehaviorCompiler()
            planner = CanonicalQueryPlanner()
            evaluator = EvidenceEvaluator()
            print("[+] [AI SUB-SYSTEM] Offline deterministic mode (free text requires --llm api)")
        else:
            is_free_text = (
                req.kind in (HuntRequestKind.NL_QUESTION, HuntRequestKind.HYPOTHESIS)
                and not (args.hypothesis_file and ("{" in req.content or "requirements:" in req.content))
            )
            if is_free_text:
                print(
                    "[-] Free-text hypothesis requires semantic analysis via LLM (--llm api). "
                    "Use a structured template (CVE, TTP, or YAML hypothesis) for offline deterministic execution.",
                    file=sys.stderr,
                )
            llm_tracker = LLMUsageTracker(max_calls=3, model_name="stub")
            compiler = KnowledgeBehaviorCompiler()
            planner = CanonicalQueryPlanner()
            evaluator = EvidenceEvaluator()

        engine = HypothesisHuntEngine(
            compiler=compiler,
            planner=planner,
            evaluator=evaluator,
            llm_tracker=llm_tracker,
            cdb_adapter=adapter if isinstance(adapter, CdbAdapter) else None,
        )
        default_window = "NOW-14d/NOW"
        if selected_provider == "splunk":
            if auto_discovered_index_info and auto_discovered_index_info.get("min_time") and auto_discovered_index_info.get("max_time"):
                try:
                    s_dt = datetime.fromisoformat(auto_discovered_index_info["min_time"])
                    e_dt = datetime.fromisoformat(auto_discovered_index_info["max_time"])
                    if e_dt <= s_dt:
                        e_dt = s_dt + timedelta(days=1)
                    default_window = f"{s_dt.strftime('%Y-%m-%dT%H:%M:%SZ')}/{e_dt.strftime('%Y-%m-%dT%H:%M:%SZ')}"
                except Exception:
                    default_window = "2016-08-01T00:00:00Z/2016-08-29T23:59:59Z"
            else:
                default_window = "2016-08-01T00:00:00Z/2016-08-29T23:59:59Z"

        time_win = args.time_window or default_window
        if not args.time_window and selected_provider == "splunk":
            print(f"[+] [ENVIRONMENT AUDIT] Auto-aligned hunt time window: {time_win}")
        if not entities:
            print(f"[+] [ENVIRONMENT AUDIT] Target entity unassigned -> Executing Population Sweep across '{getattr(adapter, 'index', 'telemetry')}'")

        display_content = content
        if "\n" in content:
            for l_str in content.splitlines():
                if l_str.strip().startswith("statement:"):
                    display_content = l_str.strip().replace("statement:", "").strip(' "\'')
                    break
            else:
                display_content = content.splitlines()[0][:60] + "..."

        print(f"[*] Starting hypothesis threat hunt for {kind.value}: '{display_content}'...")

        def cli_step_logger(event_type: str, data: dict[str, Any]) -> None:
            if event_type == "PHASE_START":
                phase_num = data.get("phase", 1)
                title = data.get("title", "")
                print(f"\n[*] [PHASE {phase_num}] {title}")
                if "details" in data:
                    print(f"    -> {data['details']}")
                if "hypotheses" in data:
                    for h in data["hypotheses"]:
                        print(f"    - Competing Hypothesis: \"{h}\"")
                if "requirements" in data:
                    for r in data["requirements"]:
                        print(f"    - Behavioral Requirement: \"{r}\"")

            elif event_type == "TURN_ACTION":
                turn = data.get("turn", 1)
                action = data.get("action", "")
                target = data.get("target", "")
                op = data.get("operation", "")
                pred = data.get("predicate", "")
                req = data.get("requirement", "")
                if "DISCOVER" in action:
                    print(f"\n[*] [TURN {turn}: POPULATION SWEEP] Scanning '{getattr(adapter, 'index', 'telemetry')}' on '{target}'...")
                    print(f"    -> Operation: {op} | Predicate: {pred}")
                else:
                    print(f"\n[*] [TURN {turn}: TARGETED VERIFICATION] Testing candidate '{target}'...")
                    print(f"    -> Requirement: {req} (Op: {op})")

            elif event_type == "DISCOVERY_HIT":
                hosts = data.get("discovered_hosts", [])
                ev_cnt = data.get("event_count", 0)
                print(f"[+] [DISCOVERY HIT] Turn {data.get('turn', 1)} detected {ev_cnt} event(s) across candidate host(s): {hosts}!")

            elif event_type == "EVIDENCE_CONFIRMED":
                card_id = data.get("card_id", "")
                count = data.get("count", 0)
                parent = data.get("parent", "")
                cmd = data.get("cmdline", "")
                ent = data.get("entity", "")
                print(f"[+] [EVIDENCE CONFIRMED] Card `{card_id}` validated on `{ent}` ({count} events):")
                if parent and parent != "N/A":
                    print(f"    - Parent Process: `{parent}`")
                if cmd and cmd != "N/A":
                    print(f"    - Executable / Command: `{cmd}`")

            elif event_type == "EVIDENCE_REFUTED":
                req = data.get("requirement", "")
                ent = data.get("entity", "")
                print(f"[-] [EVIDENCE REFUTED] No anomalous activity observed for '{req}' on '{ent}'.")

            elif event_type == "HUNT_CONCLUDED":
                decision = data.get("decision", "")
                supp = data.get("supported", [])
                print(f"\n[*] [INVESTIGATION CONCLUDED] Stopping Decision: `{decision}`")
                if supp:
                    print(f"[!] Active Threat Hypothesis Confirmed: \"{supp[0]}\"")

        def cli_analyst_confirm(gate_type: str, data: dict[str, Any]) -> bool:
            if args.auto_confirm:
                return True
            if gate_type == "CONFIRM_DISCOVERED_TARGETS":
                hosts = data.get("hosts", [])
                print(f"\n[?] [HUMAN DECISION GATE] Discovered candidate target(s): {hosts}")
                ans = input("[?] Authorize targeted deep-dive investigation into these hosts? [Y/n]: ").strip().lower()
                return ans in {"", "y", "yes"}
            elif gate_type == "AUTHORIZE_FINAL_REPORT":
                decision = data.get("decision", "")
                cards_count = data.get("cards_count", 0)
                print(f"\n[?] [HUMAN DECISION GATE] Investigation concluded with disposition `{decision}` ({cards_count} evidence cards).")
                ans = input("[?] Confirm disposition and authorize final report emission? [Y/n]: ").strip().lower()
                return ans in {"", "y", "yes"}
            return True

        try:
            result = engine.execute_hunt(
                req,
                adapter=adapter,
                time_window=time_win,
                step_callback=cli_step_logger,
                analyst_confirm_callback=cli_analyst_confirm,
            )
        except PermissionError as pe:
            print(f"\n[-] Investigation halted: {pe}", file=sys.stderr)
            return 2
        except Exception as e:
            print(f"[-] Threat hunt execution failed: {e}", file=sys.stderr)
            return 1

        if args.output:
            out_file = Path(args.output)
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_text(result.report, encoding="utf-8")

        render_hunt_terminal_summary(req, result, args.output)
        return 0

    # Otherwise, legacy alert investigation mode
    # 1. Determine alert
    alert: Alert
    if args.interactive:
        alert = prompt_interactive_alert()
    elif args.alert:
        alert = parse_alert_from_file_or_content(args.alert)
    elif args.host or args.user or args.ip or args.domain:
        alert = create_adhoc_alert(host=args.host, user=args.user, ip=args.ip, domain=args.domain, source=args.source, timestamp=args.time)
    elif hasattr(sys.stdin, "isatty") and not sys.stdin.isatty():
        try:
            raw_stdin = sys.stdin.read().strip()
        except (OSError, ValueError):
            raw_stdin = ""
        if raw_stdin:
            alert = parse_alert_from_file_or_content(raw_stdin)
        else:
            alert = prompt_interactive_alert()
    else:
        print("[!] No input provided. Entering interactive mode...")
        alert = prompt_interactive_alert()

    # 2. Load Manifest & Database
    manifest_path = Path(args.manifest)
    if not manifest_path.exists():
        print(f"[-] Error: Manifest file not found: {manifest_path}", file=sys.stderr)
        return 1
    registry = load_registry(manifest_path)

    # 3. Setup LLM Provider
    if args.llm == "api":
        llm_provider = ApiLLMProvider(ApiLLMConfig.from_env())
    else:
        llm_provider = StubAbductionProvider()

    scope_id = getattr(getattr(adapter, "scope", None), "scope_id", "cdb_security")
    orchestrator = InvestigationOrchestrator(
        registry=registry,
        adapters={scope_id: adapter, "cdb_security": adapter},
        llm_provider=llm_provider,
        auto_confirm_analyst=args.auto_confirm,
    )

    # 5. Run Investigation
    print(f"[*] Starting autonomous investigation for alert '{alert.id}'...")
    try:
        if not args.auto_confirm:
            try:
                result = orchestrator.investigate(alert, analyst_confirmed=False)
            except PermissionError as e:
                print(f"\n[!] {e}")
                confirm_ans = input("[?] Do you confirm this disposition and authorize report emission? [y/N]: ").strip().lower()
                if confirm_ans in {"y", "yes"}:
                    result = orchestrator.investigate(alert, analyst_confirmed=True)
                else:
                    print("[-] Investigation halted: analyst confirmation declined.", file=sys.stderr)
                    return 2
        else:
            result = orchestrator.investigate(alert, analyst_confirmed=True)

    except Exception as e:
        print(f"[-] Investigation failed with error: {e}", file=sys.stderr)
        return 1

    # 6. Save Report
    if args.output:
        out_file = Path(args.output)
        out_file.parent.mkdir(parents=True, exist_ok=True)
        out_file.write_text(result.report, encoding="utf-8")

    # 7. Render Terminal Summary
    render_terminal_summary(alert, result, args.output)
    return 0


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    sys.exit(run_cli(args))


if __name__ == "__main__":
    main()
