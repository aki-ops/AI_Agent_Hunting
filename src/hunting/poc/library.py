"""Built-in PoC library.

A small, vetted catalog of PoCs that covers the common phishing-to-PowerShell
chain, an external C2 beacon, an Office macro dropper, and a credential
phishing landing page. Each PoC is fully concrete: every step has a target
field, an operator and a value that a CDB or SIEM can compile.

LLM escalation is optional and only fires after the local adapter returns
empty. This is the "PoC first, LLM only when local context is exhausted"
flow requested by the user.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

from hunting.poc.models import (
    EscalationHint,
    FieldOp,
    PocKind,
    PoC,
    TestStep,
)


POC_LIBRARY: dict[str, PoC] = {}

_OP_BY_NAME = {
    "EQUALS": FieldOp.EQUALS,
    "CONTAINS": FieldOp.CONTAINS,
    "STARTS_WITH": FieldOp.STARTS_WITH,
    "ENDS_WITH": FieldOp.ENDS_WITH,
    "MATCHES": FieldOp.MATCHES,
    "EXISTS": FieldOp.EXISTS,
}

_KIND_BY_NAME = {k.value: k for k in PocKind}


def _register(poc: PoC) -> PoC:
    POC_LIBRARY[poc.poc_id] = poc
    return poc


def get_poc(poc_id: str) -> PoC:
    if poc_id not in POC_LIBRARY:
        raise KeyError(f"Unknown PoC id: {poc_id}")
    return POC_LIBRARY[poc_id]


def list_pocs() -> list[PoC]:
    return list(POC_LIBRARY.values())


# ---------------------------------------------------------------------------
# 1) Phishing -> PowerShell encoded command (MITRE T1566 -> T1059.001)
# ---------------------------------------------------------------------------

_register(
    PoC(
        poc_id="poc-phishing-powershell-enc",
        name="Phishing email led to PowerShell encoded command",
        kind=PocKind.TTP,
        topic="phishing payload execution",
        actor="",  # unknown actor — any phish operator
        behavior="Spear-phishing attachment (T1566) leading to encoded PowerShell (T1059.001)",
        location="end-user workstations with a mail client",
        evidence="process_creation telemetry; hit = powershell.exe with -Enc and hidden window",
        research_refs=["Splunk SURGe PEAK hypothesis-driven hunting", "MITRE ATT&CK T1566 / T1059.001"],
        scope="workstation fleet in the investigation window",
        max_duration="3d",
        plan="search_text over process telemetry for powershell + encoded + hidden flags",
        summary=(
            "Detect encoded PowerShell execution on a workstation. Encoded "
            "PowerShell with -NoP/-W Hidden is a high-fidelity indicator of a "
            "phishing payload or post-exploitation activity."
        ),
        steps=[
            TestStep(
                step_id="s1-powershell-enc",
                description="Look for powershell.exe with encoded command flag",
                target_field="image",
                op=FieldOp.EQUALS,
                value="powershell.exe",
                source_kind="process",
            ),
            TestStep(
                step_id="s2-powershell-hidden",
                description="Confirm hidden window execution",
                target_field="cmdline",
                op=FieldOp.CONTAINS,
                value="-W Hidden",
                source_kind="process",
            ),
            TestStep(
                step_id="s3-powershell-encoded",
                description="Encoded command flag is the smoking gun",
                target_field="cmdline",
                op=FieldOp.CONTAINS,
                value="-Enc",
                source_kind="process",
            ),
        ],
        fallbacks=[
            TestStep(
                step_id="s1f-pwsh-enc",
                description="PowerShell 7 (pwsh) variant",
                target_field="image",
                op=FieldOp.EQUALS,
                value="pwsh.exe",
                source_kind="process",
            ),
        ],
        references=["MITRE ATT&CK T1059.001", "MITRE ATT&CK T1566"],
        expected_chain=["process_creation", "encoded_command"],
        escalation_hint=EscalationHint(
            question=(
                "If the encoded command hit was found, list the parent process "
                "image, the host, and any subsequent outbound network event "
                "in the same minute. If no hit was found, state 'no encoded "
                "PowerShell execution observed in the time window'."
            ),
            evidence_requirement="process_ancestry",
            max_tokens=2000,
        ),
    )
)


# ---------------------------------------------------------------------------
# 2) External C2 beacon (MITRE T1071.001 / T1572)
# ---------------------------------------------------------------------------

_register(
    PoC(
        poc_id="poc-c2-beacon",
        name="Outbound C2 beacon to external domain",
        kind=PocKind.BEHAVIOR,
        topic="command-and-control beaconing",
        actor="",
        behavior="Application-layer C2 beacon (T1071.001 / T1572)",
        location="egress DNS/HTTP from managed hosts",
        evidence="dns + web_request telemetry; hit = repeated outbound queries to an external domain",
        research_refs=["Splunk SURGe PEAK hypothesis-driven hunting", "MITRE ATT&CK T1071.001"],
        scope="hosts with egress DNS/HTTP in the investigation window",
        max_duration="3d",
        plan="search_text over dns and web telemetry for the external domain",
        summary=(
            "Find repeated outbound DNS or HTTP requests to an external "
            "domain. Use the connected domain as the host-side fingerprint "
            "for C2."
        ),
        steps=[
            TestStep(
                step_id="s1-dns-external",
                description="DNS query for an internal-resembling external domain",
                target_field="query",
                op=FieldOp.ENDS_WITH,
                value=".corp.internal",
                source_kind="dns",
            ),
            TestStep(
                step_id="s2-http-external",
                description="HTTP request to the same external host",
                target_field="site",
                op=FieldOp.ENDS_WITH,
                value=".corp.internal",
                source_kind="web",
            ),
        ],
        references=["MITRE ATT&CK T1071.001", "MITRE ATT&CK T1572"],
        expected_chain=["dns_query", "web_request", "process_creation"],
        escalation_hint=EscalationHint(
            question=(
                "Given the DNS/HTTP hits, list the originating process and "
                "host. If only DNS exists, infer the host from the source IP."
            ),
            evidence_requirement="network_c2_communication",
            max_tokens=2000,
        ),
    )
)


# ---------------------------------------------------------------------------
# 3) Office macro dropper (MITRE T1566.001 -> T1204.002)
# ---------------------------------------------------------------------------

_register(
    PoC(
        poc_id="poc-office-macro",
        name="Office macro dropper spawning child process",
        kind=PocKind.TTP,
        topic="malicious document execution",
        actor="",
        behavior="Malicious attachment (T1566.001) executed by user (T1204.002)",
        location="end-user workstations with Office suite",
        evidence="process_creation telemetry; hit = office parent spawning script-host child",
        research_refs=["Splunk SURGe PEAK hypothesis-driven hunting", "MITRE ATT&CK T1566.001 / T1204.002"],
        scope="workstations with Office telemetry in the investigation window",
        max_duration="3d",
        plan="search_text over process telemetry for office parent + script-host child",
        summary=(
            "Office processes (Word/Excel/PowerPoint) that spawn cmd.exe, "
            "powershell.exe, wscript.exe or mshta.exe are a strong indicator "
            "of a macro-based dropper."
        ),
        steps=[
            TestStep(
                step_id="s1-office-parent",
                description="Office app spawning child process",
                target_field="parent_image",
                op=FieldOp.MATCHES,
                value=r"(?i).*office.*\.exe",
                source_kind="process",
            ),
            TestStep(
                step_id="s2-child-script",
                description="Child process is a script host",
                target_field="image",
                op=FieldOp.MATCHES,
                value=r"(?i).*\\(?P<host>(cmd|powershell|pwsh|wscript|cscript|mshta|winword|excel|powerpnt))\.exe",
                source_kind="process",
            ),
        ],
        references=["MITRE ATT&CK T1566.001", "MITRE ATT&CK T1204.002"],
        expected_chain=["process_creation"],
        escalation_hint=EscalationHint(
            question=(
                "Given the parent/child pair, list any subsequent file "
                "creation under %TEMP% or %APPDATA% in the next 5 minutes."
            ),
            evidence_requirement="file_artifact",
            max_tokens=2000,
        ),
    )
)


# ---------------------------------------------------------------------------
# 4) Credential phishing landing page (MITRE T1566.002)
# ---------------------------------------------------------------------------

_register(
    PoC(
        poc_id="poc-credential-phish",
        name="Credential phishing landing page POST observed",
        kind=PocKind.BEHAVIOR,
        topic="credential harvesting via phishing link",
        actor="",
        behavior="Spear-phishing link (T1566.002) leading to credential submission",
        location="browser traffic from end-user workstations",
        evidence="web_request telemetry; hit = browser POST to login/verify/account URL pattern",
        research_refs=["Splunk SURGe PEAK hypothesis-driven hunting", "MITRE ATT&CK T1566.002"],
        scope="workstation browser traffic in the investigation window",
        max_duration="3d",
        plan="search_text over web telemetry for phishing URL pattern + POST + browser process",
        summary=(
            "Browser POST to a known credential-phishing URL pattern. Looks "
            "for both the URL hit and the originating browser process."
        ),
        steps=[
            TestStep(
                step_id="s1-browser-uri",
                description="Browser POST to a phishing URL",
                target_field="uri",
                op=FieldOp.MATCHES,
                value=r"(?i).*(login|verify|account).*",
                source_kind="web",
            ),
            TestStep(
                step_id="s2-http-method-post",
                description="HTTP method is POST",
                target_field="method",
                op=FieldOp.EQUALS,
                value="POST",
                source_kind="web",
            ),
            TestStep(
                step_id="s3-browser-process",
                description="Originating browser process",
                target_field="image",
                op=FieldOp.MATCHES,
                value=r"(?i).*\\(?P<host>(msedge|chrome|firefox|iexplore))\.exe",
                source_kind="process",
            ),
        ],
        references=["MITRE ATT&CK T1566.002"],
        expected_chain=["web_request", "process_creation"],
    )
)


# ---------------------------------------------------------------------------
# PoC from JSON file (analyst-authored)
# ---------------------------------------------------------------------------

def _step_from_dict(raw: dict) -> TestStep:
    op_name = str(raw.get("op", "")).upper()
    if op_name not in _OP_BY_NAME:
        raise ValueError(
            f"step.op must be one of {sorted(_OP_BY_NAME)}; got {raw.get('op')!r}"
        )
    return TestStep(
        step_id=str(raw.get("step_id", "")),
        description=str(raw.get("description", "")),
        target_field=str(raw.get("target_field", "")),
        op=_OP_BY_NAME[op_name],
        value=str(raw.get("value", "")),
        time_window_hint=raw.get("time_window_hint"),
        source_kind=str(raw.get("source_kind", "process")),
    )


def poc_from_file(path) -> PoC:
    """Load a PoC from a JSON file and register it in ``POC_LIBRARY``.

    The PoC becomes available via ``get_poc(poc_id)`` and the ``--poc``
    CLI argument for the rest of the process. JSON shape::

        {
          "poc_id": "poc-bruteforce-ssh",
          "name": "Brute force login detected",
          "kind": "behavior",
          "summary": "...",
          "steps": [
            {
              "step_id": "s1-failed-auth",
              "description": "Failed authentication",
              "target_field": "action",
              "op": "EQUALS",
              "value": "failure",
              "source_kind": "authentication"
            }
          ],
          "fallbacks": [],
          "references": ["MITRE ATT&CK T1110"],
          "expected_chain": ["authentication"]
        }

    ``kind`` is one of ``ttp``, ``cve``, ``ioc``, ``behavior``. ``op`` is
    one of ``EQUALS`` / ``CONTAINS`` / ``STARTS_WITH`` / ``ENDS_WITH`` /
    ``MATCHES`` / ``EXISTS``. ``source_kind`` is ``process`` / ``dns`` /
    ``web`` / ``file`` (defaults to ``process``). See ``docs/POC-HOW-IT-WORKS.md``.
    """
    text = Path(path).read_text(encoding="utf-8")
    data = json.loads(text)
    poc_id = str(data.get("poc_id", "")).strip()
    if not poc_id:
        raise ValueError("poc_id is required")
    if not re.match(r"^[a-zA-Z0-9_-]{3,64}$", poc_id):
        raise ValueError(
            f"poc_id must match ^[a-zA-Z0-9_-]{{3,64}}$; got {poc_id!r}"
        )

    kind_name = str(data.get("kind", "behavior")).lower()
    kind = _KIND_BY_NAME.get(kind_name)
    if kind is None:
        raise ValueError(
            f"kind must be one of {sorted(_KIND_BY_NAME)}; got {kind_name!r}"
        )

    steps = [_step_from_dict(s) for s in data.get("steps", [])]
    if not steps:
        raise ValueError("at least one step is required")
    fallbacks = [_step_from_dict(s) for s in data.get("fallbacks", [])]

    hint_raw = data.get("escalation_hint")
    hint = None
    if isinstance(hint_raw, dict):
        hint = EscalationHint(
            question=str(hint_raw.get("question", "")).strip(),
            evidence_requirement=str(hint_raw.get("evidence_requirement", "")),
            max_tokens=int(hint_raw.get("max_tokens", 2000)),
        )

    poc = PoC(
        poc_id=poc_id,
        name=str(data.get("name", poc_id)),
        kind=kind,
        summary=str(data.get("summary", "")),
        steps=steps,
        fallbacks=fallbacks,
        references=[str(r) for r in data.get("references", [])],
        escalation_hint=hint,
        expected_chain=[str(c) for c in data.get("expected_chain", [])],
        topic=str(data.get("topic", "")),
        actor=str((data.get("able") or {}).get("actor", data.get("actor", ""))),
        behavior=str((data.get("able") or {}).get("behavior", data.get("behavior", ""))),
        location=str((data.get("able") or {}).get("location", data.get("location", ""))),
        evidence=str((data.get("able") or {}).get("evidence", data.get("evidence", ""))),
        research_refs=[str(r) for r in data.get("research_refs", [])],
        scope=str(data.get("scope", "")),
        max_duration=str(data.get("max_duration", "")),
        plan=str(data.get("plan", "")),
    )
    return _register(poc)
