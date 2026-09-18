"""End-to-end demo: run PoC against CDB, then judge via stub LLM.

The stub judge inspects the parent_image column to decide TP/FP:

  - parent_image contains 'OUTLOOK.EXE'  -> TRUE_POSITIVE
  - parent_image contains 'CmRcViewer'   -> FALSE_POSITIVE
  - otherwise                            -> INCONCLUSIVE

Run ``scripts/seed_cdb_judge_demo.py`` first to populate ``data/cdb_sample.sqlite``.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from hunting.m5_adapter import CdbAdapter
from hunting.poc import PocAgent, render_poc_report, get_poc


DEMO_EVENTS = [
    {
        "timestamp": "2026-09-01T09:35:10Z",
        "event_id": "4688",
        "native_type": "process_creation",
        "host": "DESKTOP-VICTIM1",
        "user": "CORP\\alice",
        "pid": 1020,
        "ppid": 800,
        "image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
        "cmdline": '"C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE"',
        "parent_image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
        "raw_ref": "outlook-001",
    },
    {
        "timestamp": "2026-09-01T10:14:30Z",
        "event_id": "4688",
        "native_type": "process_creation",
        "host": "DESKTOP-VICTIM1",
        "user": "CORP\\alice",
        "pid": 4820,
        "ppid": 1020,
        "parent_image": "C:\\Program Files\\Microsoft Office\\root\\Office16\\OUTLOOK.EXE",
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "cmdline": "powershell.exe -NoP -NonI -W Hidden -Enc JABhID0A...",
        "raw_ref": "phish-001",
    },
    {
        "timestamp": "2026-09-01T03:00:00Z",
        "event_id": "4688",
        "native_type": "process_creation",
        "host": "SCCM-SERVER",
        "user": "CORP\\svc_admin",
        "pid": 7200,
        "ppid": 600,
        "parent_image": "C:\\Program Files\\Microsoft Configuration Manager\\bin\\CmRcViewer.exe",
        "image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "cmdline": "powershell.exe -NoP -NonI -W Hidden -Enc Zm9vYmFy...",
        "raw_ref": "sccm-001",
    },
]


def _judge_from_context(prompt: str, max_tokens: int) -> str:
    """Deterministic judge: uses host/user to decide TP/FP.

    CDB does not currently persist a ``parent_image`` column, so the demo
    stub uses the next-best discriminator available in the events table:
    host + user. Interactive user on a workstation (DESKTOP-VICTIM1 /
    corp\\alice) is a phishing indicator; a service account on a
    management server (SCCM-SERVER / corp\\svc_admin) is operational.
    """
    has_alice = "DESKTOP-VICTIM1" in prompt and "CORP\\\\alice" in prompt
    has_sccm = "SCCM-SERVER" in prompt and "svc_admin" in prompt

    if has_alice and has_sccm:
        # Both present in the same brief. Mixed verdict.
        return json.dumps({
            "verdict": "INCONCLUSIVE",
            "confidence": 0.5,
            "rationale": (
                "Mixed evidence: one row from an interactive workstation "
                "(DESKTOP-VICTIM1, corp\\alice) and one row from an SCCM "
                "server. Need per-row evidence isolation before deciding."
            ),
            "notes": ["mixed_context"],
        })
    if has_alice:
        return json.dumps({
            "verdict": "TRUE_POSITIVE",
            "confidence": 0.85,
            "rationale": (
                "Encoded PowerShell ran on an interactive user workstation "
                "(DESKTOP-VICTIM1 / corp\\alice). The host + user posture is "
                "consistent with a phishing macro dropper."
            ),
            "notes": ["host=DESKTOP-VICTIM1", "user=corp\\alice"],
        })
    if has_sccm:
        return json.dumps({
            "verdict": "FALSE_POSITIVE",
            "confidence": 0.92,
            "rationale": (
                "Encoded PowerShell ran on SCCM-SERVER as the service "
                "account. This is a sanctioned baseline deployment."
            ),
            "notes": ["host=SCCM-SERVER", "user=svc_admin"],
        })
    return json.dumps({
        "verdict": "INCONCLUSIVE",
        "confidence": 0.4,
        "rationale": "Match was found but no host/user context was provided.",
        "notes": ["missing_context"],
    })


def _run(events: list, expected_label: str) -> None:
    adapter = CdbAdapter(":memory:")
    if events:
        adapter.insert_events(events)

    agent = PocAgent(
        adapter=adapter,
        ledger_dir=Path("artifacts") / "poc_hunts",
        judge_caller=_judge_from_context,
        enable_judge=True,
    )

    result = agent.run(
        "poc-phishing-powershell-enc",
        time_window="2026-09-01T00:00:00Z/2026-09-02T00:00:00Z",
    )

    poc_render = get_poc(result.poc_id).render()
    report = render_poc_report(result, poc_render)
    print(f"  Verdict  : {result.verdict}")
    if result.judgment is not None:
        print(f"  Judge    : {result.judgment.verdict} "
              f"(confidence {result.judgment.confidence:.2f})")
        print(f"  Reason   : {result.judgment.rationale}")
    print(f"  Expected : {expected_label}")
    print(f"  Matches  : {len(result.matched_step_ids)} step(s) / "
          f"{result.total_observations} row(s)")
    print(f"  LLM cost : 1 judge call, "
          f"~{result.judgment_llm_tokens} tokens")
    report_path = Path("artifacts") / "poc_hunts" / f"{result.request_id}.md"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report, encoding="utf-8")
    print(f"  Report   : {report_path}")


def main():
    print("\n" + "=" * 72)
    print("DEMO 1: TRUE_POSITIVE (phishing macro dropper)")
    print("=" * 72)
    _run([DEMO_EVENTS[1]], expected_label="TRUE_POSITIVE")

    print("\n" + "=" * 72)
    print("DEMO 2: FALSE_POSITIVE (SCCM admin script)")
    print("=" * 72)
    _run([DEMO_EVENTS[2]], expected_label="FALSE_POSITIVE")

    print("\n" + "=" * 72)
    print("DEMO 3: NO_SIGNAL (empty PoC run)")
    print("=" * 72)
    _run([], expected_label="NO_SIGNAL")


if __name__ == "__main__":
    main()
