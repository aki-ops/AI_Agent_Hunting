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

from hunting.poc.models import (
    EscalationHint,
    FieldOp,
    PocKind,
    PoC,
    TestStep,
)


POC_LIBRARY: dict[str, PoC] = {}


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
            TestStep(
                step_id="s3-outbound-process",
                description="Process that initiated the outbound request",
                target_field="image",
                op=FieldOp.EXISTS,
                value="",
                source_kind="process",
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
