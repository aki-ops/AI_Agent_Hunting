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
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from hunting.contracts.entities import Account, Domain, Host, IPAddress
from hunting.contracts.hunt import HuntRequest, HuntRequestKind
from hunting.contracts.state import Alert
from hunting.engine import HypothesisHuntEngine
from hunting.m2_abduction.provider import ApiLLMConfig, ApiLLMProvider, StubAbductionProvider
from hunting.m5_adapter import CdbAdapter
from hunting.orchestrator import InvestigationOrchestrator
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
    print(f" Request ID:      {request.id} ({request.kind.value})")
    print(f" Content:         {request.content}")
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
    env_group.add_argument("--manifest", "-m", type=str, default="tests/fixtures/registry_cdb.yaml", help="Path to ProviderScope registry YAML")
    env_group.add_argument("--db", type=str, default="data/cdb_sample.sqlite", help="Path to SQLite CDB database")
    env_group.add_argument("--output", "-o", type=str, default="report.md", help="Path to output Markdown report file")

    # LLM & Human Loop
    loop_group = parser.add_argument_group("LLM & Human-in-the-Loop")
    loop_group.add_argument("--llm", choices=["stub", "api"], default="stub", help="M2 abduction engine: 'stub' (offline deterministic) or 'api' (external HTTP)")
    loop_group.add_argument("--auto-confirm", dest="auto_confirm", action="store_true", default=True, help="Automatically sign-off mandatory analyst confirmation")
    loop_group.add_argument("--no-auto-confirm", dest="auto_confirm", action="store_false", help="Prompt analyst interactively on console for mandatory confirmation")

    return parser


def run_cli(args: argparse.Namespace) -> int:
    """Execute hunting CLI with parsed arguments."""
    db_path = Path(args.db)
    if not db_path.exists():
        adapter = CdbAdapter(":memory:")
    else:
        adapter = CdbAdapter(str(db_path))

    # Check if hypothesis threat hunting mode is triggered
    is_hypothesis_hunt = bool(args.cve or args.ttp or args.ioc or args.threat_actor or args.campaign or args.query)
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

        if args.cve:
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

        engine = HypothesisHuntEngine(cdb_adapter=adapter)
        time_win = args.time_window or "NOW-14d/NOW"
        print(f"[*] Starting hypothesis threat hunt for {kind.value}: '{content}'...")
        result = engine.execute_hunt(req, adapter=adapter, time_window=time_win)

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

    # 4. Initialize Orchestrator
    orchestrator = InvestigationOrchestrator(
        registry=registry,
        adapters={"cdb_security": adapter},
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
