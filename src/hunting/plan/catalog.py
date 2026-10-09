"""Generic description of the telemetry categories a plan may ask for.

This is deliberately platform-neutral and says nothing about any real environment: the executing team maps each
``{{INDEX_*}}`` placeholder to its own index. Field names follow the Splunk Common Information Model (CIM) so the
same search can be bound to different deployments.
"""
from __future__ import annotations

CATALOG: dict[str, dict[str, object]] = {
    "web": {
        "placeholder": "{{INDEX_WEB}}",
        "what": "web server / reverse proxy access logs",
        "fields": ["src", "dest", "http_method", "uri_path", "uri_query", "url", "status", "http_user_agent", "http_referrer", "bytes_out"],
    },
    "proxy": {
        "placeholder": "{{INDEX_PROXY}}",
        "what": "forward proxy / secure web gateway logs (outbound)",
        "fields": ["src", "dest", "url", "uri_path", "http_method", "status", "http_user_agent", "bytes_out", "category"],
    },
    "endpoint": {
        "placeholder": "{{INDEX_ENDPOINT}}",
        "what": "process creation, file and registry telemetry (Sysmon / EDR)",
        "fields": ["dest", "user", "process", "process_name", "parent_process", "parent_process_name", "process_id", "file_path", "file_name"],
    },
    "network": {
        "placeholder": "{{INDEX_NETWORK}}",
        "what": "firewall / flow / IDS connection logs",
        "fields": ["src", "src_port", "dest", "dest_port", "transport", "action", "bytes_out", "bytes_in"],
    },
    "dns": {
        "placeholder": "{{INDEX_DNS}}",
        "what": "DNS queries and answers",
        "fields": ["src", "query", "query_type", "answer"],
    },
    "auth": {
        "placeholder": "{{INDEX_AUTH}}",
        "what": "authentication events (directory, SSH, VPN)",
        "fields": ["user", "src", "dest", "action", "app"],
    },
    "app": {
        "placeholder": "{{INDEX_APP}}",
        "what": "application / framework logs (free text in _raw)",
        "fields": ["_raw", "host", "source", "sourcetype"],
    },
}

PLACEHOLDERS = {str(v["placeholder"]) for v in CATALOG.values()}
TIME_PLACEHOLDERS = ("{{EARLIEST}}", "{{LATEST}}", "{{MAX_ROWS}}")

PHASES = (
    "reconnaissance", "initial_access", "execution", "persistence", "privilege_escalation", "defense_evasion",
    "credential_access", "discovery", "lateral_movement", "command_and_control", "exfiltration", "impact",
)


def catalog_text() -> str:
    lines = []
    for name, spec in CATALOG.items():
        lines.append(f"- {name}: {spec['what']}. index={spec['placeholder']}. Fields: {', '.join(spec['fields'])}")  # type: ignore[arg-type]
    return "\n".join(lines)
