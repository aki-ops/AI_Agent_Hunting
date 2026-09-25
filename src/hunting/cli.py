"""Command Line Interface (CLI) runner for AI Agent Hunting.

The entry point is a free-text hypothesis (--hypothesis, --hypothesis-file, or --query).
CVE, TTP, IOC, alert, and PoC inputs are not accepted.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from hunting.compiler.compiler import KnowledgeBehaviorCompiler
from hunting.contracts.entities import Account, Domain, Host, IPAddress
from hunting.contracts.hunt import HuntRequest, HuntRequestKind, StoppingDecision
from hunting.controller.cost import LLMBudgetPolicy, LLMUsageTracker
from hunting.engine import HypothesisHuntEngine
from hunting.evidence.evaluator import EvidenceEvaluator
from hunting.m1_ledger.store import ObservationStore
from hunting.m2_abduction.provider import (
    ApiLLMConfig,
    ApiLLMProvider,
    LLMTimeoutError,
    create_llm_caller,
)
from hunting.m5_adapter import CdbAdapter, SplunkLiveAdapter
from hunting.planner.adaptive import AdaptiveOperationPlanner
from hunting.planner.planner import CanonicalQueryPlanner


def _apply_dotenv_setdefault(path: str | None = None) -> None:
    """Load `.env` into os.environ without overriding an already-set variable."""
    from hunting.m2_abduction.provider import load_dotenv

    env_path = path or os.getenv("HUNTING_DOTENV") or ".env"
    for key, value in load_dotenv(env_path).items():
        if key:
            os.environ.setdefault(key, value)


def _cli_splunk_verify_ssl(args: argparse.Namespace | None = None) -> bool:
    if args is not None and getattr(args, "splunk_insecure", False):
        return False
    raw = os.getenv("SPLUNK_VERIFY_SSL", "true").strip().lower()
    return raw not in {"0", "false", "no"}


def render_hunt_playbook(
    request: HuntRequest,
    objective: Any,
    hypotheses: list[Any],
    requirements: list[Any],
    time_window: str,
    output_path: str | None,
) -> None:
    """Print an offline Threat Hunting Playbook without contacting a provider."""
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
    print(" 3. QUERY PLANS: deferred until Prepare, sizing, and provider compilation.")
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
            "## 3. Query plans",
            "",
            "Queries are not compiled in plan-only mode. Prepare, sizing, and the provider compiler run only on a real hunt.",
            "",
        ])

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
    c_pct = cb.causal_path_coverage * 100.0

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
    print(f" Coverage:        Causal Path: {c_pct:.1f}%, Wildcard Scope: {w_pct:.1f}%, Instance: {i_pct:.1f}%")
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


def write_hunt_abort_artifact(
    request: HuntRequest,
    output_path: str | None,
    reason: str,
) -> None:
    """Replace a stale report with an explicit non-verdict failure artifact.

    A failed run must never leave the previous run's Markdown at the default
    output path. This file intentionally contains no evidence, answer, or
    disposition; it only tells the operator that the current execution did
    not produce a hunt account.
    """
    if not output_path:
        return
    out_file = Path(output_path)
    out_file.parent.mkdir(parents=True, exist_ok=True)
    safe_reason = " ".join(str(reason).split())
    content = (
        "# Hunt execution aborted\n\n"
        "**Status:** `EXECUTION_FAILED`\n\n"
        f"**Request:** {request.content}\n\n"
        f"**Reason:** {safe_reason}\n\n"
        "No telemetry evidence, answer, verdict, or cost account was produced "
        "for this run. The artifact exists to prevent a previous report from "
        "being mistaken for the current execution.\n"
    )
    out_file.write_text(content, encoding="utf-8")


def handle_show_observation(hunt_id: str | None, obs_id: str) -> int:
    """Forensic lookup: load observation from isolated artifacts and print full raw event."""
    artifacts_root = Path("artifacts")
    if not artifacts_root.exists():
        print(f"[-] No artifacts directory found at {artifacts_root.resolve()}", file=sys.stderr)
        return 1

    target_dir: Path | None = None
    if hunt_id:
        cand = artifacts_root / hunt_id
        if cand.exists():
            target_dir = cand
    else:
        hunt_dirs = [d for d in artifacts_root.iterdir() if d.is_dir()]
        if hunt_dirs:
            hunt_dirs.sort(key=lambda d: d.stat().st_mtime, reverse=True)
            target_dir = hunt_dirs[0]

    if target_dir is None:
        print(f"[-] Hunt artifact directory not found for hunt ID: {hunt_id}", file=sys.stderr)
        return 1

    obs_file = target_dir / "observations.jsonl"
    if not obs_file.exists():
        print(f"[-] observations.jsonl not found in {target_dir}", file=sys.stderr)
        return 1

    records = ObservationStore.load_jsonl(obs_file)
    target_record = None
    for r in records:
        if r.get("observation_id") == obs_id or r.get("id") == obs_id:
            target_record = r
            break

    if target_record is None:
        print(f"[-] Observation ID '{obs_id}' not found in {obs_file}", file=sys.stderr)
        return 1

    print("\n" + "=" * 80)
    print(f"                   OBSERVATION FORENSIC INSPECTION: {obs_id}")
    print("=" * 80)
    print(f"Hunt ID:        {target_dir.name}")
    print(f"Timestamp:      {target_record.get('timestamp', 'N/A')}")
    print(f"Native Type:    {target_record.get('native_type', 'N/A')}")
    print(f"Provider Scope: {target_record.get('scope_id', 'N/A')}")
    print(f"Query ID:       {target_record.get('query_id', 'N/A')}")
    print("-" * 80)
    print("MAPPED FIELDS:")
    print(json.dumps(target_record.get("fields", {}), indent=2, ensure_ascii=False))
    print("-" * 80)
    print("RAW PROVIDER EVENT (Forensic Ground Truth):")
    print(json.dumps(target_record.get("raw_event", {}), indent=2, ensure_ascii=False))
    print("=" * 80 + "\n")
    return 0


def handle_replay_query(hunt_id: str | None, query_id: str) -> int:
    """Forensic replay: load native query from artifacts and display/replay it."""
    artifacts_root = Path("artifacts")
    if not artifacts_root.exists():
        print(f"[-] No artifacts directory found at {artifacts_root.resolve()}", file=sys.stderr)
        return 1

    target_dir: Path | None = None
    if hunt_id:
        cand = artifacts_root / hunt_id
        if cand.exists():
            target_dir = cand
    else:
        hunt_dirs = [d for d in artifacts_root.iterdir() if d.is_dir()]
        if hunt_dirs:
            hunt_dirs.sort(key=lambda d: d.stat().st_mtime, reverse=True)
            target_dir = hunt_dirs[0]

    if target_dir is None:
        print(f"[-] Hunt artifact directory not found for hunt ID: {hunt_id}", file=sys.stderr)
        return 1

    queries_file = target_dir / "queries.json"
    if not queries_file.exists():
        print(f"[-] queries.json not found in {target_dir}", file=sys.stderr)
        return 1

    with open(queries_file, "r", encoding="utf-8") as f:
        queries = json.load(f)

    target_query = None
    for q in queries:
        if q.get("query_id") == query_id:
            target_query = q
            break

    if target_query is None:
        print(f"[-] Query ID '{query_id}' not found in {queries_file}", file=sys.stderr)
        return 1

    qtext = target_query.get("query_text", "")
    opid = target_query.get("operation_id", "N/A")
    pid = target_query.get("provider_id", "N/A")
    rid = target_query.get("requirement_id", "N/A")

    print("\n" + "=" * 80)
    print(f"                     QUERY FORENSIC REPLAY: {query_id}")
    print("=" * 80)
    print(f"Hunt ID:        {target_dir.name}")
    print(f"Provider:       {pid}")
    print(f"Operation:      {opid}")
    print(f"Requirement:    {rid}")
    print("-" * 80)
    print("PARAMETERS:")
    print(json.dumps(target_query.get("parameters", {}), indent=2, ensure_ascii=False))
    print("-" * 80)
    print("EXECUTABLE NATIVE QUERY STATEMENT:")
    print(qtext or "(No native query statement recorded)")
    print("=" * 80 + "\n")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hunting",
        description="AI Agent Hunting: free-text hypothesis threat hunting",
    )
    hunt_group = parser.add_argument_group("Free-text hypothesis")
    hunt_group.add_argument("--hypothesis", "-H", type=str, help="Explicit hypothesis statement to test and verify (e.g. 'Attacker used webshell to execute cmd.exe')")
    hunt_group.add_argument("--hypothesis-file", type=str, help="Path to YAML/JSON file declaring custom hypothesis, requirements, and falsification conditions")
    hunt_group.add_argument("--plan-only", "--dry-run", dest="plan_only", action="store_true", help="Compile hypothesis into a structured Threat Hunt Playbook and query plans without executing queries on any backend")
    hunt_group.add_argument("--query", "-q", type=str, help="Natural language hunting question, compiled as a free-text hypothesis")
    hunt_group.add_argument("--time-window", type=str, help="Explicit search time window ISO interval (e.g. 2026-02-01T00:00:00Z/P1D)")
    hunt_group.add_argument("--host", type=str, help="Optional host pinned on the hypothesis (e.g. DESKTOP-VICTIM1)")
    hunt_group.add_argument("--user", type=str, help="Optional account pinned on the hypothesis (e.g. CORP\\alice)")
    hunt_group.add_argument("--ip", type=str, help="Optional IP pinned on the hypothesis (e.g. 192.168.1.50)")
    hunt_group.add_argument("--domain", type=str, help="Optional domain pinned on the hypothesis (e.g. evil-c2.corp.internal)")
    hunt_group.add_argument("--hunt-plan", type=str, default=None, help="YAML/JSON Prepare overrides applied after derivation")
    hunt_group.add_argument("--skip-prepare", action="store_true", help="Bypass Prepare. The report must record that Prepare was skipped")
    hunt_group.add_argument("--prepare", action="store_true", help="On a terminal, review the derived refute threshold before execution")
    hunt_group.add_argument("--baseline-file", type=str, default=None, help="Known-benign values, one per line. A match is a citation, not a benign verdict")
    hunt_group.add_argument("--sourcetype", action="append", default=None, help="Backup analyst override: restrict Execute to these sourcetypes")

    # Environment & Backend
    env_group = parser.add_argument_group("Environment & Backend")
    env_group.add_argument("--provider", choices=["auto", "cdb", "splunk"], default="auto", help="Telemetry provider: 'auto' (detect a reachable provider), 'cdb' (explicit local SQLite test backend), or 'splunk' (live enterprise SIEM) [default: auto]")
    env_group.add_argument("--list-indexes", action="store_true", help="List all accessible Splunk indexes with event counts and exit")
    env_group.add_argument("--splunk-url", type=str, default=os.getenv("SPLUNK_URL", "https://localhost:8089"), help="Splunk management REST API endpoint [default: https://localhost:8089]")
    env_group.add_argument("--splunk-user", type=str, default=os.getenv("SPLUNK_USER", "admin"), help="Splunk admin username [default: admin]")
    env_group.add_argument("--splunk-pass", type=str, default=os.getenv("SPLUNK_PASSWORD", "12345678"), help="Splunk password [default: 12345678]")
    env_group.add_argument("--splunk-insecure", action="store_true", help="Disable TLS certificate verification for Splunk (lab/self-signed only)")
    env_group.add_argument("--splunk-index", type=str, default=os.getenv("SPLUNK_INDEX", "auto"), help="Target Splunk index name or 'auto' for automated discovery [default: auto]")
    env_group.add_argument("--splunk-manifest", type=str, default=None, help="Path to declarative YAML mapping manifest [default: configs/splunk_botsv2.yaml]")
    env_group.add_argument("--manifest", "-m", type=str, default="tests/fixtures/registry_cdb.yaml", help="Path to ProviderScope registry YAML")
    env_group.add_argument("--db", type=str, default="data/cdb_sample.sqlite", help="Path to SQLite CDB database")
    env_group.add_argument("--output", "-o", type=str, default="report.md", help="Path to output Markdown report file")

    # LLM & Human Loop
    loop_group = parser.add_argument_group("LLM & Human-in-the-Loop")
    loop_group.add_argument("--llm", choices=["stub", "api"], default="api", help="LLM engine: 'api' (default, external HTTP) or 'stub' (explicit offline test mode)")
    loop_group.add_argument(
        "--unbounded-llm",
        action="store_true",
        help="Diagnostic E2E mode: use high LLM ceilings so token optimisation does not block flow testing",
    )
    loop_group.add_argument("--llm-model", type=str, default=None, help="LLM model name (e.g. gemini-2.5-flash, gpt-4o, 1/grok-4.6) [default: from env or config]")
    loop_group.add_argument("--llm-endpoint", type=str, default=None, help="LLM REST endpoint URL [default: from env or config]")
    loop_group.add_argument("--api-key", type=str, default=None, help="LLM API authorization key [default: from env]")
    loop_group.add_argument("--auto-confirm", dest="auto_confirm", action="store_true", default=True, help="Automatically sign-off the final report disposition; ambiguous bindings still require analyst selection")
    loop_group.add_argument("--no-auto-confirm", dest="auto_confirm", action="store_false", help="Prompt analyst for final report disposition; ambiguous bindings always require selection")

    # Forensic Audit & Replay Flags
    forensic_group = parser.add_argument_group("Forensic Audit & Replay")
    forensic_group.add_argument("--hunt-id", type=str, default=None, help="Target hunt ID for artifact inspection or query replay")
    forensic_group.add_argument("--show-observation", type=str, default=None, help="Observation ID to inspect from hunt artifacts")
    forensic_group.add_argument("--observation-id", type=str, default=None, help="Observation ID to inspect")
    forensic_group.add_argument("--replay-query", type=str, default=None, help="Query ID to inspect or replay from hunt artifacts")
    forensic_group.add_argument("--query-id", type=str, default=None, help="Query ID to inspect or replay")

    # Forensic Subparsers
    subparsers = parser.add_subparsers(dest="subcommand", help="Forensic subcommands")
    obs_sub = subparsers.add_parser("show-observation", help="Inspect complete observation details including raw event")
    obs_sub.add_argument("--hunt-id", type=str, default=None, help="Target hunt ID")
    obs_sub.add_argument("--observation-id", type=str, default=None, help="Observation ID to inspect")
    obs_sub.add_argument("obs_id_pos", nargs="?", default=None, help="Positional observation ID")

    rep_sub = subparsers.add_parser("replay-query", help="Inspect or replay executable native query")
    rep_sub.add_argument("--hunt-id", type=str, default=None, help="Target hunt ID")
    rep_sub.add_argument("--query-id", type=str, default=None, help="Query ID to replay")
    rep_sub.add_argument("query_id_pos", nargs="?", default=None, help="Positional query ID")

    return parser


def _collect_facet_bucket_options(result: Any) -> list[tuple[str, str, str, list[str]]]:
    """Return winning-facet buckets instead of dumping every entity value."""
    analysis = getattr(result.account, "semantic_analysis", {}) or {}
    groups = analysis.get("candidate_groups") if isinstance(analysis, dict) else {}
    options: list[tuple[str, str, str, list[str]]] = []
    for variable_id, items in dict(groups or {}).items():
        if variable_id == "subject":
            continue
        for item in items or ():
            if not isinstance(item, dict):
                continue
            field = str(item.get("field") or "").strip()
            value = str(item.get("value") or "").strip()
            members = [str(member).strip() for member in (item.get("candidates") or ()) if str(member).strip()]
            if field and value:
                options.append((str(variable_id), field, value, members))
    return options


def _collect_semantic_candidate_options(result: Any, variable_types: dict[str, str]) -> list[tuple[str, str, str]]:
    """Return unique candidate bindings, preferring canonical CandidateSets.

    Older artifacts may not have materialized CandidateSets yet.  In that
    case the auditable binding provenance is a compatibility fallback, never
    an additional source to concatenate with the canonical set.
    """
    candidate_sets = getattr(result.state, "candidate_sets", {}) or getattr(result.account, "candidate_sets", {}) or {}
    options: list[tuple[str, str, str]] = []
    seen: set[tuple[str, str]] = set()
    for variable_id, candidate_set in candidate_sets.items():
        if variable_id == "subject":
            continue
        entity_type = getattr(candidate_set, "entity_type", None) or variable_types.get(variable_id, "entity")
        for candidate in getattr(candidate_set, "candidates", ()):
            value = str(getattr(candidate, "value", "")).strip()
            key = (str(variable_id), value)
            if not value or key in seen:
                continue
            seen.add(key)
            options.append((str(variable_id), value, str(entity_type)))
    if options:
        return options

    analysis = getattr(result.account, "semantic_analysis", {}) or {}
    provenance = analysis.get("binding_provenance", {}) if isinstance(analysis, dict) else {}
    for variable_id, entries in (provenance or {}).items():
        if variable_id == "subject":
            continue
        entity_type = variable_types.get(str(variable_id), "entity")
        for entry in entries or ():
            if not isinstance(entry, dict):
                continue
            value = str(entry.get("value", "")).strip()
            key = (str(variable_id), value)
            if not value or key in seen:
                continue
            seen.add(key)
            options.append((str(variable_id), value, str(entity_type)))
    return options


def _read_candidate_choice(prompt: str) -> str:
    """Read an analyst candidate choice; EOF/interrupt means no selection."""
    try:
        return input(prompt).strip()
    except (EOFError, KeyboardInterrupt):
        print("\n[*] No candidate selected; preserving STOP_NEEDS_USER_DECISION.")
        return ""


def _load_baseline_values(path: str | None) -> tuple[str, ...]:
    if not path:
        return ()
    file_path = Path(path)
    if not file_path.is_file():
        raise FileNotFoundError(f"Baseline file not found: {file_path}")
    return tuple(
        line.strip()
        for line in file_path.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    )


def resolve_prepare_gate(args, content: str, entities: tuple[str, ...], time_window: str):
    """Derive Prepare, then apply a user plan or a terminal edit. Runs before any provider."""
    from hunting.peak_plan import (
        PrepareError,
        apply_user_overrides,
        derive_prepare_plan,
        load_prepare_overrides,
        prompt_threshold_override,
    )

    if getattr(args, "skip_prepare", False):
        print("[!] [PREPARE] skipped (--skip-prepare); the report must record source=skipped.")
        return None, "skipped", None
    try:
        plan = derive_prepare_plan(content, time_window=time_window or "", entities=entities)
        source = "derived"
        if getattr(args, "hunt_plan", None):
            plan = apply_user_overrides(plan, load_prepare_overrides(args.hunt_plan))
            source = plan.decision_criteria.source
        if getattr(args, "sourcetype", None):
            plan = apply_user_overrides(plan, {"location_override": list(args.sourcetype)})
        elif getattr(args, "prepare", False) and sys.stdin.isatty():
            plan = prompt_threshold_override(plan, input)
            source = plan.decision_criteria.source
    except (PrepareError, OSError, ValueError) as exc:
        print(f"[-] [PREPARE] {exc}", file=sys.stderr)
        return None, "", 2
    print(
        f"[+] [PREPARE] topic={plan.topic!r} scope={plan.scope!r} "
        f"max_duration={plan.max_duration!r} "
        f"min_coverage_to_refute={plan.decision_criteria.min_coverage_to_refute} "
        f"source={source}"
    )
    return plan, source, None


def run_cli(args: argparse.Namespace) -> int:
    """Execute investigation or hypothesis-driven hunt workflow based on parsed arguments."""
    if hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass

    has_free_text = bool(
        getattr(args, "query", None)
        or getattr(args, "hypothesis", None)
        or getattr(args, "hypothesis_file", None)
    )

    # 0. Handle forensic subcommands / lookup flags
    subcmd = getattr(args, "subcommand", None)
    hunt_id = getattr(args, "hunt_id", None)

    obs_target = (
        getattr(args, "observation_id", None)
        or getattr(args, "show_observation", None)
        or getattr(args, "obs_id_pos", None)
    )
    if subcmd == "show-observation" or (obs_target and not has_free_text):
        if not obs_target:
            print("[-] Error: --observation-id is required for show-observation", file=sys.stderr)
            return 1
        return handle_show_observation(hunt_id, obs_target)

    query_target = (
        getattr(args, "query_id", None)
        or getattr(args, "replay_query", None)
        or getattr(args, "query_id_pos", None)
    )
    if subcmd == "replay-query" or (query_target and not has_free_text):
        if not query_target:
            print("[-] Error: --query-id is required for replay-query", file=sys.stderr)
            return 1
        return handle_replay_query(hunt_id, query_target)

    # Handle index exploration
    if getattr(args, "list_indexes", False):
        adapter = SplunkLiveAdapter(
            splunk_url=args.splunk_url,
            auth=(args.splunk_user, args.splunk_pass),
            index=args.splunk_index,
            verify_ssl=_cli_splunk_verify_ssl(args),
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

    if not has_free_text:
        print(
            "[-] A free-text hypothesis is required. "
            "Pass --hypothesis, --hypothesis-file, or --query.",
            file=sys.stderr,
        )
        return 2
    is_hypothesis_hunt = True
    preview_entities = tuple(
        value for value in (
            getattr(args, "host", None),
            getattr(args, "user", None),
            getattr(args, "ip", None),
            getattr(args, "domain", None),
        ) if value
    )
    if args.hypothesis:
        preview_content = str(args.hypothesis)
    elif args.query:
        preview_content = str(args.query)
    else:
        preview_path = Path(args.hypothesis_file)
        if not preview_path.exists():
            print(f"[-] Error: Hypothesis file not found: {preview_path}", file=sys.stderr)
            return 1
        preview_content = preview_path.read_text(encoding="utf-8")
    prepare_plan, prepare_source, prepare_code = resolve_prepare_gate(
        args,
        preview_content,
        preview_entities,
        getattr(args, "time_window", None) or "",
    )
    if prepare_code is not None:
        return prepare_code

    # 1. Pure Plan / Dry-run Mode (Offline - No telemetry provider contacted)
    if getattr(args, "plan_only", False):
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
        elif args.query:
            kind = HuntRequestKind.NL_QUESTION
            content = args.query
        else:
            print(
                "[-] A free-text hypothesis is required. "
                "Pass --hypothesis, --hypothesis-file, or --query.",
                file=sys.stderr,
            )
            return 2

        req = HuntRequest(
            id=f"hunt-req-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",
            kind=kind,
            content=content,
            entities=entities,
            prepare_source=prepare_source,
            prepare_plan=prepare_plan.to_dict() if prepare_plan is not None else None,
            baseline_values=_load_baseline_values(getattr(args, "baseline_file", None)),
        )
        compiler = KnowledgeBehaviorCompiler()
        default_window = ("2017-08-01T00:00:00Z/2017-08-31T23:59:59Z" if "botsv2" in str(getattr(args, "splunk_index", "")).lower() else "2016-08-01T00:00:00Z/2016-08-29T23:59:59Z") if getattr(args, "provider", "auto") in ("splunk", "auto") else "NOW-14d/NOW"
        time_win = args.time_window or default_window
        objective, hypotheses, requirements = compiler.compile(req, time_window=time_win)
        render_hunt_playbook(req, objective, hypotheses, requirements, time_win, args.output)
        return 0



    # Initialize Telemetry Provider Adapter with Automated Environment Audit
    selected_provider = getattr(args, "provider", "auto")
    auto_discovered_index_info: dict[str, Any] | None = None

    if selected_provider == "auto":
        print("[*] [ENVIRONMENT AUDIT] Auditing available telemetry systems...")
        splunk_alive = SplunkLiveAdapter.is_available(
            splunk_url=args.splunk_url,
            auth=(args.splunk_user, args.splunk_pass),
            verify_ssl=_cli_splunk_verify_ssl(args),
            timeout=2,
        )
        if splunk_alive:
            selected_provider = "splunk"
            print(f"[+] [ENVIRONMENT AUDIT] Detected live enterprise SIEM: Splunk at {args.splunk_url}")
        else:
            # A reachable provider is part of the epistemic contract.  A
            # silent in-memory SQLite fallback creates an empty, unrelated
            # data source and makes the hunt look like it executed while
            # actually searching data the user never selected.
            print(
                "[-] [ENVIRONMENT AUDIT] Splunk is not reachable. "
                "No telemetry provider was selected; use --provider cdb "
                "only for an explicit local test run.",
                file=sys.stderr,
            )
            return 2

    if selected_provider == "splunk":
        selected_index = args.splunk_index
        if selected_index in (None, "", "auto"):
            try:
                auto_discovered_index_info = SplunkLiveAdapter.auto_select_index(
                    splunk_url=args.splunk_url,
                    auth=(args.splunk_user, args.splunk_pass),
                    verify_ssl=_cli_splunk_verify_ssl(args),
                )
                selected_index = auto_discovered_index_info["name"]
            except Exception as auto_err:
                raise RuntimeError(
                    f"Auto-discovery failed: No active telemetry index could be selected on Splunk server ({auto_err}). "
                    f"Please specify --splunk-index explicitly (e.g. --splunk-index botsv2)."
                ) from auto_err

        manifest_file = args.splunk_manifest
        if manifest_file and manifest_file.lower() in ("none", "null", "discovery", "auto", "mode1"):
            manifest_file = None
        elif manifest_file is None:
            idx_manifest = Path(f"configs/splunk_{selected_index}.yaml")
            default_cfg = Path("configs/splunk_botsv2.yaml")
            if idx_manifest.exists():
                manifest_file = str(idx_manifest)
            elif default_cfg.exists():
                manifest_file = str(default_cfg)

        adapter = SplunkLiveAdapter(
            splunk_url=args.splunk_url,
            auth=(args.splunk_user, args.splunk_pass),
            index=selected_index,
            manifest_path=manifest_file,
            verify_ssl=_cli_splunk_verify_ssl(args),
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
        elif args.query:
            kind = HuntRequestKind.NL_QUESTION
            content = args.query
        else:
            print(
                "[-] A free-text hypothesis is required. "
                "Pass --hypothesis, --hypothesis-file, or --query.",
                file=sys.stderr,
            )
            return 2

        req = HuntRequest(
            id=f"hunt-req-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",
            kind=kind,
            content=content,
            entities=entities,
            prepare_source=prepare_source,
            prepare_plan=prepare_plan.to_dict() if prepare_plan is not None else None,
            baseline_values=_load_baseline_values(getattr(args, "baseline_file", None)),
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
            policy = (
                LLMBudgetPolicy.unbounded_for_testing(model_name=config.model)
                if args.unbounded_llm
                else LLMBudgetPolicy(model_name=config.model)
            )
            if args.unbounded_llm:
                print("[!] [AI SUB-SYSTEM] Diagnostic unbounded LLM budget enabled; optimise token usage after E2E validation.")
            llm_tracker = LLMUsageTracker(policy=policy)
            compiler_caller = create_llm_caller(llm_provider, llm_tracker, "compiler")
            source_profiler_caller = create_llm_caller(llm_provider, llm_tracker, "source_profiler")
            planner_caller = create_llm_caller(llm_provider, llm_tracker, "planner")
            adaptive_caller = create_llm_caller(llm_provider, llm_tracker, "adaptive_planner")
            evaluator_caller = create_llm_caller(llm_provider, llm_tracker, "evaluator")

            compiler = KnowledgeBehaviorCompiler(
                llm_caller=compiler_caller,
                require_semantic_goal_graph=True,
            )
            planner = CanonicalQueryPlanner(llm_generator=planner_caller)
            adaptive_planner = AdaptiveOperationPlanner(llm_generator=adaptive_caller, llm_tracker=llm_tracker)
            evaluator = EvidenceEvaluator(llm_caller=evaluator_caller)
            print(f"[+] [AI SUB-SYSTEM] Active ApiLLMProvider: model='{config.model}' endpoint='{config.endpoint}'")
        elif args.llm == "stub":
            policy = LLMBudgetPolicy(model_name="stub")
            llm_tracker = LLMUsageTracker(policy=policy)
            # Stub mode is deliberately non-semantic. It must not invent a
            # generic interpretation for arbitrary free text; use --llm api
            # when natural-language compilation is required.
            compiler = KnowledgeBehaviorCompiler()
            planner = CanonicalQueryPlanner()
            adaptive_planner = AdaptiveOperationPlanner()
            evaluator = EvidenceEvaluator()
            source_profiler_caller = None
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
            policy = LLMBudgetPolicy(model_name="stub")
            llm_tracker = LLMUsageTracker(policy=policy)
            compiler = KnowledgeBehaviorCompiler()
            planner = CanonicalQueryPlanner()
            adaptive_planner = AdaptiveOperationPlanner()
            evaluator = EvidenceEvaluator()
            source_profiler_caller = None

        engine = HypothesisHuntEngine(
            compiler=compiler,
            planner=planner,
            adaptive_planner=adaptive_planner,
            evaluator=evaluator,
            llm_tracker=llm_tracker,
            source_profiler_caller=source_profiler_caller,
            cdb_adapter=adapter if isinstance(adapter, CdbAdapter) else None,
        )
        default_window = "NOW-14d/NOW"
        if selected_provider == "splunk":
            is_botsv2 = "botsv2" in str(selected_index).lower()
            fallback_splunk_win = "2017-08-01T00:00:00Z/2017-08-31T23:59:59Z" if is_botsv2 else "2016-08-01T00:00:00Z/2016-08-29T23:59:59Z"
            if auto_discovered_index_info and auto_discovered_index_info.get("min_time") and auto_discovered_index_info.get("max_time"):
                try:
                    s_dt = datetime.fromisoformat(auto_discovered_index_info["min_time"])
                    e_dt = datetime.fromisoformat(auto_discovered_index_info["max_time"])
                    if e_dt <= s_dt:
                        e_dt = s_dt + timedelta(days=1)
                    default_window = f"{s_dt.strftime('%Y-%m-%dT%H:%M:%SZ')}/{e_dt.strftime('%Y-%m-%dT%H:%M:%SZ')}"
                except Exception:
                    default_window = fallback_splunk_win
            else:
                default_window = fallback_splunk_win

        time_win = args.time_window or default_window
        if not args.time_window and selected_provider == "splunk":
            print(f"[+] [ENVIRONMENT AUDIT] Auto-aligned hunt time window: {time_win}")
        if not entities and not (args.query or args.hypothesis or args.hypothesis_file):
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
                try:
                    ans = input("[?] Authorize targeted deep-dive investigation into these hosts? [Y/n]: ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    print("\n[*] No authorization received; preserving the bounded stop.")
                    return False
                return ans in {"", "y", "yes"}
            elif gate_type == "AUTHORIZE_FINAL_REPORT":
                decision = data.get("decision", "")
                cards_count = data.get("cards_count", 0)
                print(f"\n[?] [HUMAN DECISION GATE] Investigation concluded with disposition `{decision}` ({cards_count} evidence cards).")
                try:
                    ans = input("[?] Confirm disposition and authorize final report emission? [Y/n]: ").strip().lower()
                except (EOFError, KeyboardInterrupt):
                    print("\n[*] No authorization received; preserving the bounded stop.")
                    return False
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
        except (LLMTimeoutError, TimeoutError) as te:
            print(f"\n[-] Error: LLM API request timed out: {te}", file=sys.stderr)
            write_hunt_abort_artifact(req, args.output, f"LLM API timeout: {te}")
            print("[-] Threat hunt aborted. No report generated to prevent fabricated conclusions.", file=sys.stderr)
            return 1
        except PermissionError as pe:
            print(f"\n[-] Investigation halted: {pe}", file=sys.stderr)
            write_hunt_abort_artifact(req, args.output, f"Permission error: {pe}")
            return 2
        except Exception as e:
            print(f"\n[-] Threat hunt execution failed: {e}", file=sys.stderr)
            write_hunt_abort_artifact(req, args.output, f"Execution error: {e}")
            print("[-] Threat hunt aborted. No report generated to prevent fabricated conclusions.", file=sys.stderr)
            return 1

        # Semantic graph execution must pause when an upstream binding is a
        # candidate rather than a verified entity.  Present the generic
        # candidate set to the analyst; never infer a choice from ordering or
        # from an entity's name.  ``--auto-confirm`` confirms report gates but
        # deliberately does not select an ambiguous entity.
        semantic_analysis = result.account.semantic_analysis or {}
        can_prompt_for_selection = bool(getattr(sys.stdin, "isatty", lambda: False)())
        decision_rounds = 0
        while (
            result.account.stopping_decision in (
                StoppingDecision.STOP_NEEDS_USER_DECISION,
                StoppingDecision.STOP_NEEDS_CLARIFICATION,
            )
            and can_prompt_for_selection
            and decision_rounds < max(1, int(getattr(args, "max_refine", 1) or 1))
        ):
            decision_rounds += 1
            semantic_analysis = result.account.semantic_analysis or {}
            graph = result.account.semantic_goal_graph
            variable_types = {
                variable.id: variable.entity_type
                for variable in getattr(graph, "variables", ())
            }
            facet_options = _collect_facet_bucket_options(result)
            candidate_options = _collect_semantic_candidate_options(result, variable_types)

            clarification_questions = list(semantic_analysis.get("clarification_questions", []) or [])
            if graph and hasattr(graph, "validation_diagnostics"):
                for diag in graph.validation_diagnostics:
                    if "conflicting equality" in str(diag).lower() and str(diag) not in clarification_questions:
                        clarification_questions.append(str(diag))
            if clarification_questions and decision_rounds == 1:
                print("\n[?] [SEMANTIC CLARIFICATION GATE] Clarification required:")
                for q in clarification_questions:
                    print(f"    - {q}")
            if semantic_analysis.get("retrieval_incomplete") or semantic_analysis.get("continuations"):
                print("\n[*] Retrieval incomplete; groups are from the retrieved bag only.")

            resume_kwargs: dict[str, Any] = {
                "adapter": adapter,
                "time_window": time_win,
                "step_callback": cli_step_logger,
                "analyst_confirm_callback": cli_analyst_confirm,
            }
            selected = False
            if facet_options:
                print("\n[?] [SEMANTIC DECISION GATE] Pick a group (not every entity):")
                for index, (variable_id, field, value, members) in enumerate(facet_options, start=1):
                    count = len(members)
                    extra = ""
                    if count <= 3:
                        extra = " [" + ", ".join(members) + "]"
                    elif members:
                        extra = f" e.g. {members[0]} (+{count - 1} more)"
                    print(f"    {index}. {variable_id} {field}={value} ({count}){extra}")
                choice = _read_candidate_choice("[?] Select one group number to continue, or press Enter to stop: ")
                if choice.isdigit() and 1 <= int(choice) <= len(facet_options):
                    variable_id, field, value, members = facet_options[int(choice) - 1]
                    print(f"[*] [SEMANTIC DECISION] User selected {variable_id} {field}={value}")
                    if len(members) == 1:
                        resume_kwargs["initial_bindings"] = {variable_id: members[0]}
                    else:
                        resume_kwargs["facet_constraints"] = {variable_id: (field, value)}
                    selected = True
            elif candidate_options:
                print("\n[?] [SEMANTIC DECISION GATE] Candidate binding is ambiguous:")
                shown = candidate_options[:12]
                for index, (variable_id, value, entity_type) in enumerate(shown, start=1):
                    print(f"    {index}. {variable_id} ({entity_type}) = {value}")
                if len(candidate_options) > 12:
                    print(f"    … {len(candidate_options) - 12} more not listed")
                choice = _read_candidate_choice("[?] Select one candidate number to continue, or press Enter to stop: ")
                if choice.isdigit() and 1 <= int(choice) <= len(shown):
                    variable_id, value, _ = shown[int(choice) - 1]
                    print(f"[*] [SEMANTIC DECISION] User selected {variable_id}={value}; resuming graph execution...")
                    resume_kwargs["initial_bindings"] = {variable_id: value}
                    selected = True
            if not selected:
                break
            try:
                result = engine.resume_hunt(result.state, **resume_kwargs)
            except (LLMTimeoutError, TimeoutError) as te:
                print(f"\n[-] Error while resuming after analyst selection: LLM API request timed out: {te}", file=sys.stderr)
                write_hunt_abort_artifact(req, args.output, f"LLM API timeout while resuming: {te}")
                return 1
            except PermissionError as pe:
                print(f"\n[-] Investigation halted while resuming: {pe}", file=sys.stderr)
                write_hunt_abort_artifact(req, args.output, f"Permission error while resuming: {pe}")
                return 2
            except Exception as e:
                print(f"\n[-] Threat hunt resume failed: {e}", file=sys.stderr)
                write_hunt_abort_artifact(req, args.output, f"Resume execution error: {e}")
                return 1

        if args.output:
            out_file = Path(args.output)
            out_file.parent.mkdir(parents=True, exist_ok=True)
            out_file.write_text(result.report, encoding="utf-8")

        render_hunt_terminal_summary(req, result, args.output)
        for note in (result.account.semantic_analysis or {}).get("escalations") or []:
            print(f"[!] [ESCALATE] {note}")
        from hunting.act.act import commit_act
        from hunting.act_input import account_to_act_input
        act_payload = account_to_act_input(result.account, req.prepare_plan)
        commit_act(
            source=act_payload["source"],
            spls=act_payload["spls"],
            backlog=act_payload["backlog"],
            stakeholder=act_payload["stakeholder"],
            detection_tier=act_payload["detection_tier"],
            gaps=act_payload["gaps"],
            export_dir=Path("artifacts") / "act" / act_payload["source"],
        )
        return 0

def main() -> None:
    _apply_dotenv_setdefault()
    parser = build_parser()
    args = parser.parse_args()
    sys.exit(run_cli(args))


if __name__ == "__main__":
    main()
