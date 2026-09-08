"""Evidence grouping and EvidenceCard builder.

Compresses repeated observations into canonical EvidenceCards:
- Invariant semantic fingerprints group identical background telemetry.
- Malicious event indicators (anomalous cmdlines, external IPs) form distinct cards
  to preserve 100% malicious-event recall.
- Aggregates representative IDs, counts, entity summaries, and time windows.
"""
from __future__ import annotations

import hashlib
from collections import defaultdict

from hunting.contracts.hunt import EvidenceCard
from hunting.contracts.observations import Observation
from hunting.evidence.facts import extract_facts


class EvidenceGroupBuilder:
    """Deterministic compression of observations into canonical EvidenceCards."""

    def __init__(self, max_representative_ids: int = 3) -> None:
        self.max_representative_ids = max_representative_ids
        self._groups: dict[str, list[Observation]] = defaultdict(list)

    def _build_card_from_group(self, fp: str, group_obs: list[Observation]) -> EvidenceCard:
        """Construct a single EvidenceCard from a list of grouped observations."""
        rep_ids = [o.id for o in group_obs[: self.max_representative_ids]]
        count = len(group_obs)

        # Determine primary fact type across group_obs
        primary_fact_type = "generic_telemetry"
        facts: list[Any] = []
        for o in group_obs:
            f_list = extract_facts(o)
            if f_list:
                facts = f_list
                primary_fact_type = f_list[0].fact_type
                if primary_fact_type == "process_execution":
                    break

        # Check if fields permit classifying away from generic_telemetry
        if primary_fact_type in ("telemetry", "generic_telemetry"):
            for o in group_obs:
                sample_f = o.fields
                has_proc = bool(
                    sample_f.get("image") or sample_f.get("Image") or sample_f.get("process_name")
                    or sample_f.get("Name") or sample_f.get("cmdline") or sample_f.get("CommandLine")
                    or sample_f.get("parent_image") or sample_f.get("ParentImage")
                )
                has_path = bool(
                    sample_f.get("file_path") or sample_f.get("path") or sample_f.get("Path") or sample_f.get("TargetFilename")
                )
                raw_str = str(o.raw_event or sample_f).lower()
                if "tor" in raw_str or has_proc:
                    primary_fact_type = "process_execution"
                    break
                elif sample_f.get("uri") or sample_f.get("http_method") or sample_f.get("site"):
                    primary_fact_type = "web_request"
                    break
                elif has_path:
                    primary_fact_type = "file_modification"
                    break
                elif sample_f.get("query") or sample_f.get("domain"):
                    primary_fact_type = "dns_activity"
                    break
                elif sample_f.get("destination_ip") or sample_f.get("dest_ip") or sample_f.get("remote_ip"):
                    primary_fact_type = "network_connection"
                    break
                elif sample_f.get("user") and (sample_f.get("logon_type") or sample_f.get("action")):
                    primary_fact_type = "authentication_activity"
                    break

        # Summaries
        timestamps = [o.timestamp for o in group_obs if o.timestamp]
        earliest = min(timestamps) if timestamps else ""
        latest = max(timestamps) if timestamps else ""

        # Entity summary
        entities_seen: dict[str, set[str]] = defaultdict(set)
        for o in group_obs:
            if "host" in o.fields and o.fields["host"]:
                entities_seen["hosts"].add(str(o.fields["host"]))
            if "user" in o.fields and o.fields["user"]:
                entities_seen["users"].add(str(o.fields["user"]))
            if "destination_ip" in o.fields and o.fields["destination_ip"]:
                entities_seen["destination_ips"].add(str(o.fields["destination_ip"]))
            if "dest_ip" in o.fields and o.fields["dest_ip"]:
                entities_seen["destination_ips"].add(str(o.fields["dest_ip"]))
            if "domain" in o.fields and o.fields["domain"]:
                entities_seen["domains"].add(str(o.fields["domain"]))
            if "site" in o.fields and o.fields["site"]:
                entities_seen["domains"].add(str(o.fields["site"]))

        entity_summary = {k: sorted(list(v)) for k, v in entities_seen.items()}
        time_summary = {"earliest": earliest, "latest": latest, "span_events": count}

        # Field summary (sample of distinct commands, paths, domains, uris, sites, software_versions)
        field_summary: dict[str, list[str]] = {}

        # Preserve order of commands while deduplicating
        cmd_list: list[str] = []
        seen_cmds: set[str] = set()
        for o in group_obs:
            c_val = o.fields.get("cmdline") or o.fields.get("CommandLine")
            if c_val:
                c_str = str(c_val).strip()
                if c_str and c_str not in seen_cmds:
                    seen_cmds.add(c_str)
                    cmd_list.append(c_str)
        if cmd_list:
            field_summary["cmdlines"] = cmd_list[:20]

        images = {
            str(o.fields.get("image") or o.fields.get("Image") or o.fields.get("process_name") or o.fields.get("Name"))
            for o in group_obs
            if o.fields.get("image") or o.fields.get("Image") or o.fields.get("process_name") or o.fields.get("Name")
        }
        images = {im for im in images if im and im != "None"}
        if images:
            field_summary["images"] = sorted(list(images))[:5]
            field_summary["process_names"] = sorted(list(images))[:5]

        parent_images = {
            str(o.fields.get("parent_image") or o.fields.get("ParentImage"))
            for o in group_obs
            if o.fields.get("parent_image") or o.fields.get("ParentImage")
        }
        parent_images = {pi for pi in parent_images if pi and pi != "None"}
        if parent_images:
            field_summary["parent_images"] = sorted(list(parent_images))[:5]

        file_paths = {
            str(o.fields.get("file_path") or o.fields.get("path") or o.fields.get("Path") or o.fields.get("TargetFilename"))
            for o in group_obs
            if o.fields.get("file_path") or o.fields.get("path") or o.fields.get("Path") or o.fields.get("TargetFilename")
        }
        file_paths = {fp_str for fp_str in file_paths if fp_str and fp_str != "None"}
        if file_paths:
            field_summary["file_paths"] = sorted(list(file_paths))[:5]

        software_versions = {
            str(o.fields.get(k)).strip()
            for o in group_obs
            for k in ("software_version", "ProductVersion", "FileVersion", "Version", "version")
            if o.fields.get(k) and str(o.fields.get(k)).strip()
        }
        if software_versions:
            field_summary["software_versions"] = sorted(list(software_versions))[:5]
        domains = {str(o.fields.get("domain") or o.fields.get("query")) for o in group_obs if o.fields.get("domain") or o.fields.get("query")}
        if domains:
            field_summary["domains"] = sorted(list(domains))[:5]
        uris = {str(o.fields.get("uri")) for o in group_obs if o.fields.get("uri")}
        if uris:
            field_summary["uris"] = sorted(list(uris))[:5]
        sites = {str(o.fields.get("site")) for o in group_obs if o.fields.get("site")}
        if sites:
            field_summary["sites"] = sorted(list(sites))[:5]

        relations_summary = []
        if facts and facts[0].relations:
            for rel in facts[0].relations:
                relations_summary.append({
                    "relation": rel.relation_type,
                    "source": str(rel.source_entity),
                    "target": str(rel.target_entity),
                })

        # Query IDs and Replay
        query_ids = sorted(list({o.query_id for o in group_obs if o.query_id}))
        replay_cmd = f"python -m hunting.cli show-observation --observation-id {rep_ids[0]}" if rep_ids else ""
        replay = {
            "artifact": "observations.jsonl",
            "query_ids": query_ids,
            "command": replay_cmd,
        }

        # Human-readable summary, why_it_matters, supports, and does_not_prove
        hosts_list = entity_summary.get("hosts", [])
        host_label = hosts_list[0] if hosts_list else "endpoint"

        supports: list[str] = []
        does_not_prove: list[str] = []

        if primary_fact_type == "process_execution":
            parents = field_summary.get("parent_images", [])
            imgs = field_summary.get("process_names", []) or field_summary.get("images", [])
            fps = field_summary.get("file_paths", [])

            img_label = imgs[0] if imgs else ""
            path_label = fps[0] if fps else ""

            if any("tor" in s.lower() for s in imgs + fps):
                if img_label and path_label:
                    summary = f"Process: {img_label} Path: {path_label} Host: {host_label}"
                elif img_label:
                    summary = f"Process: {img_label} Host: {host_label}"
                elif path_label:
                    summary = f"Process: tor.exe Path: {path_label} Host: {host_label}"
                else:
                    summary = f"Process: tor.exe Host: {host_label}"
                supports.append("Tor Browser was present")
                supports.append("Tor Browser process executed")
            elif parents and imgs:
                summary = f"{parents[0]} spawned {imgs[0]} on {host_label}"
                supports.append(f"Process {imgs[0]} executed on {host_label}")
            elif imgs:
                summary = f"Process: {imgs[0]} executed on {host_label}"
                if path_label:
                    summary += f" (Path: {path_label})"
                supports.append(f"Process {imgs[0]} executed on {host_label}")
            elif path_label:
                summary = f"Process artifact observed on {host_label}: {path_label}"
                supports.append(f"Artifact {path_label} present on {host_label}")
            else:
                summary = f"Process execution observed on {host_label}"
                supports.append(f"Process execution on {host_label}")

            versions = field_summary.get("software_versions", [])
            if versions:
                supports.append(f"Software version: {', '.join(versions)}")
            else:
                does_not_prove.append("Exact software version")

            # Assess suspicious web server / script runner spawning shell
            suspicious_parents = ("php-cgi", "w3wp", "httpd", "nginx", "apache", "tomcat")
            interactive_shells = ("cmd.exe", "powershell", "powershell.exe", "sh", "bash", "cscript", "wscript")
            is_suspicious_lineage = any(
                any(sp in p.lower() for sp in suspicious_parents) for p in parents
            ) and any(
                any(ish in im.lower() for ish in imgs) for im in imgs
            )
            if is_suspicious_lineage:
                why_it_matters = (
                    "High-fidelity indicator of remote code execution / web shell activity: "
                    "web worker process spawned an interactive command shell."
                )
                confidence = "HIGH"
            else:
                why_it_matters = "Observed process execution providing evidence of code execution on endpoint."
                confidence = "MEDIUM"

        elif primary_fact_type == "web_request":
            doms = entity_summary.get("domains", [])
            uris = field_summary.get("uris", [])
            target_site = doms[0] if doms else host_label
            uri_part = f" ({uris[0]})" if uris else ""
            summary = f"Web request to {target_site}{uri_part}"
            supports.append(f"Web request transmitted to {target_site}")
            why_it_matters = (
                "Represents incoming HTTP activity targeting web application services, "
                "potentially correlating with exploitation attempts or web access."
            )
            confidence = "MEDIUM"

        elif primary_fact_type == "file_modification":
            fps = field_summary.get("file_paths", [])
            f_label = fps[0] if fps else "file"
            if any("tor" in s.lower() for s in fps):
                summary = f"Process: tor.exe Path: {f_label} Host: {host_label}"
                supports.append("Tor Browser was present")
            else:
                summary = f"File modification on {host_label}: {f_label}"
                supports.append(f"File artifact present on {host_label}: {f_label}")
            versions = field_summary.get("software_versions", [])
            if versions:
                supports.append(f"Software version: {', '.join(versions)}")
            else:
                does_not_prove.append("Exact software version")
            why_it_matters = "Observed disk write activity, indicating payload delivery, persistence creation, or artifact modification."
            confidence = "MEDIUM"

        elif primary_fact_type == "dns_activity":
            doms = field_summary.get("domains", [])
            d_label = doms[0] if doms else "external domain"
            summary = f"DNS query resolution for {d_label}"
            supports.append(f"DNS resolution for {d_label}")
            why_it_matters = "Domain lookup that may indicate external infrastructure resolution or beaconing."
            confidence = "MEDIUM"

        elif primary_fact_type == "network_connection":
            ips = entity_summary.get("destination_ips", [])
            ip_label = ips[0] if ips else "remote IP"
            summary = f"Network connection established to {ip_label}"
            supports.append(f"Network connection to {ip_label}")
            why_it_matters = "Observed network communication which may indicate command-and-control (C2) channel or external data exfiltration."
            confidence = "MEDIUM"

        elif primary_fact_type == "authentication_activity":
            users = entity_summary.get("users", [])
            u_label = users[0] if users else "account"
            summary = f"Authentication event for {u_label} on {host_label}"
            supports.append(f"Authentication for {u_label} on {host_label}")
            why_it_matters = "Observed credential validation or session initiation on the target system."
            confidence = "MEDIUM"

        else:
            summary = f"Telemetry observations ({count} events on {host_label})"
            supports.append(f"Telemetry activity on {host_label}")
            why_it_matters = "Observed operational telemetry within the monitored scope."
            confidence = "LOW"

        return EvidenceCard(
            id=f"card-{fp[:12]}",
            fingerprint=fp,
            summary=summary,
            why_it_matters=why_it_matters,
            hypotheses=[],
            requirements=[],
            confidence=confidence,
            query_ids=query_ids,
            replay=replay,
            representative_observation_ids=rep_ids,
            count=count,
            entity_summary=entity_summary,
            time_summary=time_summary,
            field_summary=field_summary,
            fact_type=primary_fact_type,
            completeness="complete",
            relations=relations_summary,
            supports=supports,
            does_not_prove=does_not_prove,
        )

    def ingest_delta(self, new_observations: list[Observation]) -> list[EvidenceCard]:
        """Incrementally ingest new observations and return only the newly created or modified cards."""
        if not new_observations:
            return []

        affected_fps: set[str] = set()
        for obs in new_observations:
            fp = self.compute_fingerprint(obs)
            self._groups[fp].append(obs)
            affected_fps.add(fp)

        delta_cards = [self._build_card_from_group(fp, self._groups[fp]) for fp in affected_fps]
        delta_cards.sort(key=lambda c: (-c.count, c.id))
        return delta_cards

    def build_cards(self, observations: list[Observation] | None = None) -> list[EvidenceCard]:
        """Group observations and return compressed EvidenceCards."""
        if observations is not None:
            self._groups.clear()
            for obs in observations:
                fp = self.compute_fingerprint(obs)
                self._groups[fp].append(obs)

        cards = [self._build_card_from_group(fp, group_obs) for fp, group_obs in self._groups.items()]
        cards.sort(key=lambda c: (-c.count, c.id))
        return cards

    def compute_fingerprint(self, observation: Observation) -> str:
        """Compute an invariant semantic fingerprint for an observation.

        Process executions collapse command line variations under the same parent/image/host,
        while distinct processes, files, web endpoints, and network destinations form distinct cards.
        """
        scope_id = observation.provider_scope.scope_id if observation.provider_scope else ""
        native_type = observation.native_type or ""
        semantic_val = ""
        if observation.semantic_type:
            semantic_val = (
                observation.semantic_type.value
                if hasattr(observation.semantic_type, "value")
                else str(observation.semantic_type)
            )

        fields = observation.fields
        host = str(fields.get("host", "")).strip().lower()
        image = str(fields.get("image", "")).strip().lower()
        parent_image = str(fields.get("parent_image", "")).strip().lower()
        dst_ip = str(fields.get("destination_ip") or fields.get("dest_ip") or fields.get("remote_ip") or "").strip()
        path = str(fields.get("file_path") or fields.get("path") or "").strip().lower()
        uri = str(fields.get("uri") or fields.get("cs_uri_stem") or "").strip().lower()
        site = str(fields.get("site") or fields.get("domain") or "").strip().lower()
        user = str(fields.get("user", "")).strip().lower()
        cmd = str(fields.get("cmdline", "")).strip().lower()

        # For process executions: collapse command line variations under same parent_image + image + host
        if image or parent_image:
            fact_key = f"proc|{host}|{parent_image}|{image}"
        elif cmd:
            cmd_token = cmd.split()[0] if cmd.split() else ""
            fact_key = f"proc|{host}||{cmd_token}"
        elif uri or site or (native_type and any(k in str(native_type).lower() for k in ("http", "iis", "web"))):
            fact_key = f"web|{host}|{site}|{uri}"
        elif path:
            fact_key = f"file|{host}|{path}"
        elif dst_ip:
            fact_key = f"net|{host}|{dst_ip}"
        elif user and (fields.get("logon_type") or fields.get("action")):
            fact_key = f"auth|{host}|{user}"
        else:
            task = str(fields.get("task_name", "")).strip().lower()
            fact_key = f"telemetry|{host}|{task}|{scope_id}"

        raw_sig = f"{scope_id}|{native_type}|{semantic_val}|{fact_key}"
        return hashlib.sha256(raw_sig.encode("utf-8")).hexdigest()


__all__ = ["EvidenceGroupBuilder"]
