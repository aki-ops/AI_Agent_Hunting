"""Command line: run PoCs through PEAK Assistant + the deterministic hunt and print recommendations."""
from __future__ import annotations

import argparse
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

from hunting.llm import LlmUnavailable, build_llm
from hunting.peak import PrepareError
from hunting.pipeline import run_poc
from hunting.poc import poc_from_file
from hunting.report import render_summary


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="hunting",
        description="PEAK Assistant (Prepare) + deterministic hunt (Execute) -> recommendation for the hunter (Act).",
    )
    src = p.add_argument_group("PoC input")
    src.add_argument("--poc", action="append", default=[], metavar="FILE", help="PoC JSON file (repeatable)")
    src.add_argument("--poc-dir", metavar="DIR", help="run every *.json PoC in this directory")
    src.add_argument("--window", help="telemetry window 'START/END' (ISO-8601 UTC); overrides each PoC's time_window")
    prov = p.add_argument_group("telemetry provider")
    prov.add_argument("--provider", choices=["cdb", "splunk"], default="cdb")
    prov.add_argument("--db", default="data/botsv1_eval.sqlite", help="SQLite CDB path (provider cdb)")
    prov.add_argument("--splunk-url", default=os.getenv("SPLUNK_URL", "https://localhost:8089"))
    prov.add_argument("--splunk-user", default=os.getenv("SPLUNK_USER", "admin"))
    prov.add_argument("--splunk-index", default=os.getenv("SPLUNK_INDEX", "botsv1"))
    prov.add_argument("--splunk-manifest", default=None)
    llm = p.add_argument_group("PEAK Assistant / LLM")
    llm.add_argument("--env", default=".env", help="env file with LLM_ENDPOINT, LLM_API_KEY, LLM_MODEL")
    llm.add_argument("--offline", action="store_true", help="skip PEAK Assistant and every LLM call (deterministic only)")
    llm.add_argument("--research", action="store_true", help="also run PEAK's researcher team (needs MCP research servers)")
    llm.add_argument("--peak-timeout", type=int, default=420, help="seconds allowed per PEAK step [default: 420]")
    p.add_argument("--out", help="output directory [default: artifacts/runs/<UTC time>]")
    return p


def _collect(args: argparse.Namespace) -> list[Path]:
    files = [Path(f) for f in args.poc]
    if args.poc_dir:
        files += sorted(Path(args.poc_dir).glob("*.json"))
    return files


def _adapter(args: argparse.Namespace):
    if args.provider == "splunk":
        from hunting.adapters import SplunkLiveAdapter

        password = os.getenv("SPLUNK_PASSWORD", "")
        if not password:
            raise SystemExit("[-] provider splunk needs SPLUNK_PASSWORD in the environment")
        adapter = SplunkLiveAdapter(
            splunk_url=args.splunk_url, auth=(args.splunk_user, password),
            index=args.splunk_index, manifest_path=args.splunk_manifest,
        )
        return adapter, f"Splunk {args.splunk_url} index={args.splunk_index}", (
            f"# Local telemetry: Splunk index `{args.splunk_index}`\n"
            "Field names follow the declarative manifest; use index and sourcetype filters on every search."
        )
    from hunting.adapters import CdbAdapter

    db = Path(args.db)
    if not db.exists():
        raise SystemExit(f"[-] CDB database not found: {db} (build it with scripts/ingest_botsv1_eval.py)")
    adapter = CdbAdapter(str(db))
    return adapter, f"CDB {db.as_posix()}", adapter.describe_data()


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    files = _collect(args)
    if not files:
        print("[-] give at least one --poc FILE or --poc-dir DIR", file=sys.stderr)
        return 2

    out_root = Path(args.out) if args.out else Path("artifacts") / "runs" / datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    llm = None
    if not args.offline:
        try:
            llm = build_llm(args.env, work_dir=out_root / ".peak")
            print(f"[+] LLM via PEAK model factory: model={llm.settings.model}")
        except LlmUnavailable as exc:
            print(f"[!] PEAK/LLM disabled: {exc}. Running deterministic only.", file=sys.stderr)
    else:
        print("[+] offline mode: PEAK Assistant and LLM skipped")

    adapter, data_source, data_document = _adapter(args)
    rows: list[dict] = []
    failed = 0
    for path in files:
        try:
            poc = poc_from_file(path)
            window = args.window or poc.time_window
            if not window:
                raise PrepareError(f"PoC {poc.poc_id} has no time_window; pass --window START/END")
            print(f"\n=== {poc.poc_id}  window={window}")
            row = run_poc(
                poc, adapter, window=window, out_dir=out_root / poc.poc_id, llm=llm,
                data_document=data_document, data_source=data_source,
                peak_timeout=args.peak_timeout, use_research=args.research,
            )
        except (PrepareError, ValueError, OSError) as exc:
            failed += 1
            print(f"[-] {path}: {exc}", file=sys.stderr)
            continue
        rows.append(row)
        print(
            f"    verdict={row['verdict']} obs={row['observations']} -> {row['disposition']} "
            f"({row['confidence']}) | PEAK={'yes' if row['used_peak'] else 'no'}"
        )
        print(f"    report: {out_root / poc.poc_id / 'recommendation.md'}")

    if rows:
        (out_root / "summary.md").write_text(render_summary(rows), encoding="utf-8")
        (out_root / "summary.json").write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"\n[+] summary: {out_root / 'summary.md'}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
