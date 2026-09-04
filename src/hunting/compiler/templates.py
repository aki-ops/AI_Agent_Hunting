"""Standard behavior templates for threat hunting categories.

Provides canonical behavior templates for:
- Process Lineage & Execution
- Remote Authentication & Lateral Movement
- Network C2 & Beaconing
- File Modification & Web Shell Drops
- Persistence Artifacts & Task Creation
"""
from __future__ import annotations

from hunting.compiler.models import BehaviorCategory, BehaviorTemplate
from hunting.contracts.expectations import FieldOp, FieldPredicate
from hunting.contracts.hunt import EvidenceRequirementV4, RequirementStatus


def build_default_templates() -> dict[str, BehaviorTemplate]:
    """Construct versioned behavior templates for the 5 core hunting categories."""
    templates: dict[str, BehaviorTemplate] = {}

    # 1. PROCESS
    templates["tmpl-proc-anomalous-lineage"] = BehaviorTemplate(
        id="tmpl-proc-anomalous-lineage",
        category=BehaviorCategory.PROCESS,
        name="Anomalous Process Lineage Execution",
        description="Detection of child process execution (sh, bash, powershell, cmd) spawned by web server or office processes.",
        requirements=[
            EvidenceRequirementV4(
                id="er-proc-lineage-01",
                description="Process creation where parent is a web server or administrative daemon",
                evidence_type="process_ancestry",
                predicate=FieldPredicate(field="parent_image", op=FieldOp.CONTAINS, value="w3wp"),
                falsification_condition="no process creation logged with matching parent under verified sensor health",
                source_refs=["MITRE-T1059", "SIGMA-proc-web-child"],
                status=RequirementStatus.VALIDATED,
            )
        ],
        required_fields=["image", "parent_image", "cmdline", "pid"],
        falsification_condition="process ancestry logs show normal administrative parents or zero matching events under verified observability",
        source_citations=["https://attack.mitre.org/techniques/T1059/"],
    )

    # 2. REMOTE AUTHENTICATION
    templates["tmpl-auth-remote-logon"] = BehaviorTemplate(
        id="tmpl-auth-remote-logon",
        category=BehaviorCategory.REMOTE_AUTHENTICATION,
        name="Anomalous Remote Authentication Activity",
        description="Detection of remote logon spikes (Type 3, Type 10) or anomalous lateral movement authentication.",
        requirements=[
            EvidenceRequirementV4(
                id="er-auth-remote-01",
                description="Authentication events with remote network logon type or anomalous user context",
                evidence_type="authentication_activity",
                predicate=FieldPredicate(field="logon_type", op=FieldOp.EQUALS, value="3"),
                falsification_condition="no network authentication logged from external or untrusted source",
                source_refs=["MITRE-T1078", "MITRE-T1021"],
                status=RequirementStatus.VALIDATED,
            )
        ],
        required_fields=["user", "source_ip", "logon_type", "status"],
        falsification_condition="authentication logs show standard service account baseline without remote anomalies",
        source_citations=["https://attack.mitre.org/techniques/T1078/"],
    )

    # 3. NETWORK
    templates["tmpl-net-c2-beacon"] = BehaviorTemplate(
        id="tmpl-net-c2-beacon",
        category=BehaviorCategory.NETWORK,
        name="Outbound C2 Connection & Beaconing",
        description="Detection of persistent or periodic network connections to external destinations or dynamic DNS.",
        requirements=[
            EvidenceRequirementV4(
                id="er-net-beacon-01",
                description="Outbound network connection initiated by untrusted host or process",
                evidence_type="network_connection",
                predicate=FieldPredicate(field="destination_port", op=FieldOp.CONTAINS, value="443"),
                falsification_condition="egress netflow shows zero connection attempts to candidate remote IP/domain",
                source_refs=["MITRE-T1071.001", "REF-THREATRAPTOR"],
                status=RequirementStatus.VALIDATED,
            )
        ],
        required_fields=["destination_ip", "destination_port", "protocol", "bytes_out"],
        falsification_condition="perimeter firewall and netflow show no outbound connections during target window",
        source_citations=["https://attack.mitre.org/techniques/T1071/001/"],
    )

    # 4. FILE
    templates["tmpl-file-webshell"] = BehaviorTemplate(
        id="tmpl-file-webshell",
        category=BehaviorCategory.FILE,
        name="Web Shell & Unauthorized File Modification",
        description="Detection of script or executable files written to public web paths or temporary execution directories.",
        requirements=[
            EvidenceRequirementV4(
                id="er-file-webshell-01",
                description="File write event creating script or executable artifact in web directory",
                evidence_type="file_modification",
                predicate=FieldPredicate(field="file_path", op=FieldOp.CONTAINS, value="web"),
                falsification_condition="filesystem change records confirm zero file writes matching extension/path",
                source_refs=["MITRE-T1505.003", "CISA-AA24-010A"],
                status=RequirementStatus.VALIDATED,
            )
        ],
        required_fields=["file_path", "action", "file_hash", "process_id"],
        falsification_condition="filesystem audit logs confirm no new files written to target directory tree",
        source_citations=["https://attack.mitre.org/techniques/T1505/003/"],
    )

    # 5. PERSISTENCE
    templates["tmpl-pers-scheduled-task"] = BehaviorTemplate(
        id="tmpl-pers-scheduled-task",
        category=BehaviorCategory.PERSISTENCE,
        name="Persistence via Scheduled Task or Service",
        description="Detection of scheduled tasks or system service installation configured with commandline payload.",
        requirements=[
            EvidenceRequirementV4(
                id="er-pers-task-01",
                description="Scheduled task or service creation event with program execution argument",
                evidence_type="persistence_change",
                predicate=FieldPredicate(field="task_name", op=FieldOp.EXISTS),
                falsification_condition="task scheduler registry and event logs verify zero task creation records",
                source_refs=["MITRE-T1053.005", "SIGMA-task-creation"],
                status=RequirementStatus.VALIDATED,
            )
        ],
        required_fields=["task_name", "action_payload", "user", "trigger"],
        falsification_condition="scheduler logs and persistence registry keys reflect clean configuration without additions",
        source_citations=["https://attack.mitre.org/techniques/T1053/005/"],
    )

    return templates


__all__ = ["build_default_templates"]
