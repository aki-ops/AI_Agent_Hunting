"""Command line for the Prepare-only workflow: ``plan``, ``verify``, ``schema``.

    python main.py plan --cve CVE-2021-44228            # public intel -> hunt plan for the Execute team
    python main.py verify --plan <dir>/plan.json --results results.json
    python main.py schema --out schemas/                # JSON Schemas of the hand-off documents

Only public sources (NVD, GitHub) are contacted. Nothing is cloned, installed or run, and no internal system is read.
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from pydantic import ValidationError

from hunting.intel import Fetcher, IntelError, digest, gather
from hunting.llm import METER, LlmUnavailable, build_llm, load_dotenv
from hunting.plan import (
    PEAK_LOCAL_CONTEXT,
    Limits,
    PlanError,
    ResultBundle,
    build_plan,
    render_verification_md,
    verify,
)
from hunting.plan.catalog import catalog_text
from hunting.plan.files import write_plan, write_schemas
from hunting.plan.schema import HuntPlan
from hunting.prepare import run_peak_texts


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="main.py", description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    a = sub.add_parser("plan", help="build a hunt plan from a public CVE / PoC repository / query")
    src = a.add_mutually_exclusive_group(required=True)
    src.add_argument("--cve", help="CVE id, e.g. CVE-2021-44228")
    src.add_argument("--repo", help="a GitHub PoC repository, owner/name")
    src.add_argument("--query", help="free-text GitHub search, e.g. 'spring4shell poc'")
    a.add_argument("--min-stars", type=int, default=50, help="minimum stars for a PoC repository to count as signal [default: 50]")
    a.add_argument("--max-repos", type=int, default=3, help="PoC repositories to read [default: 3]")
    a.add_argument("--lookback", default="14d", help="search window the Execute team should use [default: 14d]")
    a.add_argument("--max-rows", type=int, default=200, help="row cap per search [default: 200]")
    a.add_argument("--max-queries", type=int, default=30)
    a.add_argument("--max-iterations", type=int, default=3)
    a.add_argument("--env", default=".env")
    a.add_argument("--model", help="override LLM_MODEL from .env")
    a.add_argument("--no-peak", action="store_true", help="skip PEAK Assistant's ABLE/plan (faster, fewer tokens)")
    a.add_argument("--refresh", action="store_true", help="ignore cached PEAK output")
    a.add_argument("--token-budget", type=int, default=0, help="max LLM tokens for the whole run; 0 = unlimited")
    a.add_argument("--cache-dir", default="artifacts/.cache")
    a.add_argument("--out", help="output root [default: artifacts/plans]")

    v = sub.add_parser("verify", help="check executed results; accept them or produce the next round")
    v.add_argument("--plan", required=True, help="plan.json that was executed")
    v.add_argument("--results", required=True, help="results JSON from the Execute team (see result.schema.json)")
    v.add_argument("--out", help="where to write the verification [default: next to the plan]")

    s = sub.add_parser("schema", help="write plan.schema.json and result.schema.json")
    s.add_argument("--out", default="schemas")
    return p


def _plan(args: argparse.Namespace) -> int:
    METER.begin(args.token_budget or None)
    file_env = load_dotenv(args.env)  # GITHUB_TOKEN / NVD_API_KEY: process environment first, then the .env file
    fetcher = Fetcher(
        Path(args.cache_dir) / "intel",
        github_token=os.environ.get("GITHUB_TOKEN") or file_env.get("GITHUB_TOKEN", ""),
        nvd_key=os.environ.get("NVD_API_KEY") or file_env.get("NVD_API_KEY", ""),
    )
    try:
        bundle = gather(
            fetcher, cve=args.cve, repo=args.repo, query=args.query,
            min_stars=args.min_stars, max_repos=args.max_repos,
        )
    except (ValueError, IntelError) as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 2
    cve = bundle.primary_cve
    print(f"[+] intel: {len(bundle.cves)} CVE, {len(bundle.repos)} PoC repo(s), {len(bundle.indicators)} observables "
          f"({bundle.requests_made} requests, {bundle.cache_hits} cached)")
    for r in bundle.repos:
        print(f"    {r.full_name}  {r.stars:,} stars  files read: {len(r.files)}")
    for w in bundle.warnings:
        print(f"    [!] {w}", file=sys.stderr)
    label = cve.cve_id if cve else (args.repo or args.query or "plan").replace("/", "_")
    root = Path(args.out) if args.out else Path("artifacts") / "plans"
    folder = root / label.replace(" ", "_")
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "intel.json").write_text(json.dumps(bundle.to_dict(), indent=2, ensure_ascii=False), encoding="utf-8")
    (folder / "intel_digest.md").write_text(digest(bundle), encoding="utf-8")

    try:
        llm = build_llm(args.env, work_dir=folder / ".peak", model=args.model)
    except LlmUnavailable as exc:
        print(f"[i] LLM is needed to write the stages and searches and is not available ({exc}). "
              f"The public intel was saved to {folder}; configure .env and rerun.", file=sys.stderr)
        return 3
    print(f"[+] LLM via PEAK model factory: model={llm.settings.model}")
    limits = Limits(lookback=args.lookback, max_rows_per_query=args.max_rows, max_queries=args.max_queries, max_iterations=args.max_iterations)

    peak = None
    if not args.no_peak:
        hypothesis = (
            f"Assume the public exploit for {cve.cve_id if cve else label} ({(cve.description[:160] if cve else '')}) is used "
            "against our environment. Check whether any system shows evidence of exploitation or compromise."
        )
        print("[+] PEAK Assistant: ABLE table + hunt plan (a few minutes) ...")
        peak = run_peak_texts(
            hypothesis=hypothesis, research=digest(bundle, per_file=1500, max_chars=9000), data_document=catalog_text(),
            local_context=PEAK_LOCAL_CONTEXT, technique=label, llm=llm, cache_dir=Path(args.cache_dir), refresh=args.refresh,
        )
        for note in peak.notes:
            print(f"    peak: {note}")
    try:
        plan = build_plan(bundle, llm, peak=peak, limits=limits, model_name=llm.settings.model)
    except PlanError as exc:
        (folder / "planner_last_reply.txt").write_text(exc.last_reply, encoding="utf-8")
        print(f"[-] {exc}\n    the model's last reply was saved to {folder / 'planner_last_reply.txt'}", file=sys.stderr)
        return 4
    out = write_plan(plan, folder / "iter1")
    write_schemas(folder)
    snap = METER.snapshot()
    nq = sum(len(s.queries) for s in plan.stages)
    print(f"[+] plan {plan.plan_id}: {len(plan.stages)} stages, {nq} searches, {len(plan.coverage_probes)} coverage probes, "
          f"{len(plan.dropped)} dropped/notes")
    print(f"[+] LLM: {snap['calls']} calls, {snap['total_tokens']:,} tokens; models: {', '.join(snap['by_model']) or '?'}")
    print(f"[+] plan: {out / 'plan.md'}")
    return 0


def _verify(args: argparse.Namespace) -> int:
    plan_path = Path(args.plan)
    try:
        plan = HuntPlan.model_validate_json(plan_path.read_text(encoding="utf-8"))
        results = ResultBundle.model_validate_json(Path(args.results).read_text(encoding="utf-8"))
    except (OSError, ValidationError, ValueError) as exc:
        print(f"[-] cannot read plan/results: {exc}", file=sys.stderr)
        return 2
    verdict, nxt = verify(plan, results)
    out = Path(args.out) if args.out else plan_path.parent
    out.mkdir(parents=True, exist_ok=True)
    (out / "verification.json").write_text(verdict.model_dump_json(indent=2), encoding="utf-8")
    (out / "verification.md").write_text(render_verification_md(verdict, plan), encoding="utf-8")
    print(f"[+] decision: {verdict.decision} - {verdict.summary}")
    for reason in verdict.reasons:
        print(f"    - {reason}")
    for issue in verdict.protocol_issues:
        print(f"    [!] {issue}", file=sys.stderr)
    if nxt is not None:
        nxt_dir = plan_path.parent.parent / f"iter{nxt.iteration}"
        write_plan(nxt, nxt_dir)
        print(f"[+] next round: {nxt_dir / 'plan.md'}")
    print(f"[+] verification: {out / 'verification.md'}")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    if args.cmd == "plan":
        return _plan(args)
    if args.cmd == "verify":
        return _verify(args)
    write_schemas(args.out)
    print(f"[+] schemas written to {args.out}")
    return 0
