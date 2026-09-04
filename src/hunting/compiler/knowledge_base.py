"""Trusted Threat Knowledge Base with versioning and source citations.

Stores authoritative knowledge records for:
- CVEs with 5-phase decomposition (exposure, preconditions, exploitation, post-exploitation, gaps)
- MITRE ATT&CK TTPs
- Threat Actor Campaign Indicators
"""
from __future__ import annotations

from hunting.compiler.models import CVEPhases, KnowledgeRecord


def build_default_knowledge_base() -> dict[str, KnowledgeRecord]:
    """Construct versioned knowledge records with verifiable citations."""
    records: dict[str, KnowledgeRecord] = {}

    # CVE-2024-21887: Ivanti Connect Secure / Policy Secure Command Injection
    records["CVE-2024-21887"] = KnowledgeRecord(
        id="CVE-2024-21887",
        version="2024.1.0",
        kind="cve",
        title="Ivanti Connect Secure and Policy Secure Web Command Injection",
        description="A command injection vulnerability in web components of Ivanti Connect Secure allows an authenticated administrator or pre-auth chained adversary to execute arbitrary commands.",
        source_citations=(
            "https://nvd.nist.gov/vuln/detail/CVE-2024-21887",
            "https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-010a",
            "https://forums.ivanti.com/s/article/KB-CVE-2023-46805-Auth-Bypass-and-CVE-2024-21887-Command-Injection",
        ),
        phases=CVEPhases(
            exposure=(
                "Ivanti Connect Secure (ICS) versions 9.x, 22.x with web interface exposed on 443/TCP",
                "Appliance management endpoints reachable via perimeter gateway",
            ),
            preconditions=(
                "Network reachability to web management or SAML endpoints (/api/v1/cav/client/status)",
                "Chained authentication bypass (CVE-2023-46805) or administrative access",
            ),
            exploitation_indicators=(
                "POST request containing command injection tokens in /api/v1/cav/client/status/path parameter",
                "Execution of python/sh subprocesses by web server daemons",
            ),
            post_exploitation=(
                "Web shell written into /home/etc/manifest/ or static web paths",
                "Outbound TLS connection to adversary C2 infrastructure",
                "Tampering with internal integrity checker tool (ICT)",
            ),
            gaps=(
                "Appliance encrypted filesystem may prevent live disk forensics",
                "Volatile command execution may not persist across appliance reboots",
            ),
        ),
    )

    # CVE-2023-34362: Progress MOVEit Transfer SQL Injection
    records["CVE-2023-34362"] = KnowledgeRecord(
        id="CVE-2023-34362",
        version="2023.2.0",
        kind="cve",
        title="MOVEit Transfer Web Application SQL Injection Vulnerability",
        description="SQL injection vulnerability in the MOVEit Transfer web application allowing unauthenticated attacker to gain access to the database and execute arbitrary SQL.",
        source_citations=(
            "https://nvd.nist.gov/vuln/detail/CVE-2023-34362",
            "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-158a",
        ),
        phases=CVEPhases(
            exposure=(
                "MOVEit Transfer web applications exposed on HTTPS (port 443)",
                "Versions prior to 2021.0.6, 2021.1.5, 2022.0.4, 2022.1.5, 2023.0.1",
            ),
            preconditions=(
                "Direct HTTP/HTTPS access to guestaccess.aspx or moveitisapi endpoints",
            ),
            exploitation_indicators=(
                "SQL injection payload in HTTP header (X-Forwarded-For or session variables)",
                "Unexpected database queries extracting active user sessions",
            ),
            post_exploitation=(
                "Web shell dropped as human2.aspx in MOVEit wwwroot directory",
                "Automated mass exfiltration of sensitive organizational files",
            ),
            gaps=(
                "IIS access logs may not log request body containing SQL injection string",
            ),
        ),
    )

    # T1059.001: PowerShell Command and Scripting Interpreter
    records["T1059.001"] = KnowledgeRecord(
        id="T1059.001",
        version="14.1",
        kind="ttp",
        title="Command and Scripting Interpreter: PowerShell",
        description="Adversaries may abuse PowerShell commands and scripts for execution and automation.",
        source_citations=(
            "https://attack.mitre.org/techniques/T1059/001/",
        ),
    )

    # T1053.005: Scheduled Task
    records["T1053.005"] = KnowledgeRecord(
        id="T1053.005",
        version="14.1",
        kind="ttp",
        title="Scheduled Task/Job: Scheduled Task",
        description="Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code.",
        source_citations=(
            "https://attack.mitre.org/techniques/T1053/005/",
        ),
    )

    # T1071.001: Web Protocols C2
    records["T1071.001"] = KnowledgeRecord(
        id="T1071.001",
        version="14.1",
        kind="ttp",
        title="Application Layer Protocol: Web Protocols",
        description="Adversaries may communicate using application layer protocols (HTTP/HTTPS) to avoid detection through firewalls and proxies.",
        source_citations=(
            "https://attack.mitre.org/techniques/T1071/001/",
        ),
    )

    return records


__all__ = ["build_default_knowledge_base"]
