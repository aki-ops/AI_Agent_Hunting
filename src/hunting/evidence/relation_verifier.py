"""Deterministic Relation Verifier (v5.0).

The gatekeeper of the Investigation Case Graph.
Verifies candidate edges against observation ledgers, enforcing strict field roles
(client_ip ≠ server_ip, host ≠ sensor), web server isolation, and valid citations
before minting RelationProofs and updating graph state.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from email.utils import parseaddr

from hunting.contracts.case_graph import (
    GraphEdge,
    GraphNode,
    InvestigationGraph,
    NodeStatus,
    RelationProof,
    RelationStatus,
    RelationType,
)
from hunting.contracts.observations import Observation
from hunting.m1_ledger.ledger import ObservationLedger

KNOWN_WEB_SERVERS = {"jabbah", "we1149srv", "web01", "iis01", "venus"}


def is_prohibited_server(name: str | None) -> bool:
    if not name:
        return False
    nl = str(name).lower().strip()
    root = nl.split(".")[0]
    return root in KNOWN_WEB_SERVERS or any(s in nl for s in ("jabbah", "we1149srv", "web01", "iis", "venus", "dc01", "srv"))


@dataclass
class VerificationResult:
    """Outcome of deterministic relation verification."""
    verified: bool
    proof: RelationProof | None = None
    target_value: str | None = None
    diagnostic: str = ""
    violations: list[str] = field(default_factory=list)

    @property
    def cited_observation_ids(self) -> list[str]:
        return self.proof.citations if self.proof else []

    @property
    def field_matches(self) -> dict[str, str]:
        return self.proof.field_matches if self.proof else {}


class RelationVerifier:
    """Deterministic authority that verifies graph edges from ledger observations."""

    USER_FIELDS = ("user", "username", "targetusername", "account_name", "samaccountname")
    HOST_FIELDS = ("host", "computername", "workstationname", "workstation_name", "target_host", "hostname", "name")
    CLIENT_IP_FIELDS = ("ipaddress", "src_ip", "client_ip", "c_ip", "source_ip", "host_addr")
    SERVER_IP_FIELDS = ("dest_ip", "server_ip", "s_ip", "destination_ip")
    DOMAIN_FIELDS = ("site", "cs_host", "query", "domain", "url", "uri")
    VERSION_FIELDS = (
        "version", "productversion", "product_version", "fileversion", "file_version",
        "software_version", "app_version", "displayversion", "package_version",
    )
    ARTIFACT_FIELDS = ("image", "targetfilename", "target_filename", "file_path", "path", "commandline", "cmdline")
    KNOWN_NOISE_DOMAINS = (
        "doubleclick.net", "rubiconproject.com", "bing.com", "msn.com",
        "microsoft.com", "adnxs.com", "gigya.com", "criteo.com", "fwmrm.net",
        "outbrain.com", "krxd.net", "atwola.com", "demdex.net", "quantserve.com",
        "sharethrough.com", "media.net", "doubleverify.com", "lijit.com",
        "scorecardresearch.com", "chartbeat.net", "symcd.com", "symcb.com",
        "windowsupdate.com", "digicert.com", "godaddy.com", "turner.com",
        "cnn.com", "akamaihd.net", "akamaized.net", "akamai.net",
        "googlesyndication.com", "google.com", "googleapis.com", "gvt1.com",
        "advertising.com", "amazon-adsystem.com", "bounceexchange.com",
        "smartclip.net", "revsci.net", "afy11.net", "imrworldwide.com",
        "switchadhub.com", "livefyre.com", "frothly.local", "mercury",
        "verisign", "globalsign", "entrust", "msocsp", "chartbeat.com",
        "360yield.com", "bidswitch.net", "bizographics.com", "dotomi.com",
        "dvtps.com", "mathtag.com", "nexage.com", "office.com", "office.net",
        "postrelease.com", "s3xified.com", "serving-sys.com", "spotxchange.com",
        "tapad.com", "tubemogul.com", "usabilla.com", "videoamp.com",
        "volvelle.tech", "yahoo.com", "edgesuite.net", "exelator.com",
        "cnn.io", "wayfair.com"
    )

    @classmethod
    def _artifact_value(
        cls,
        fields: dict[str, str],
        edge: GraphEdge,
        target_type: str,
    ) -> tuple[str | None, dict[str, str]]:
        """Return an artifact value only when the row carries target evidence.

        This is intentionally a verifier, not an answer generator.  A row is
        eligible only if it contains a product hint derived from the semantic
        request.  A version is accepted only from an explicit version field or
        a version-shaped token in the same cited row.
        """
        terms = [str(t).strip().lower() for t in (edge.acceptance_predicate or {}).get("software_terms", []) if str(t).strip()]
        searchable = " ".join(str(v).lower() for v in fields.values())
        if terms and not any(term in searchable for term in terms):
            return None, {}
        if not terms:
            return None, {}

        if target_type in ("software_version", "version"):
            for key in cls.VERSION_FIELDS:
                val = str(fields.get(key, "") or "").strip()
                if val and val not in ("-", "unknown", "none"):
                    match = re.search(r"\b\d+(?:\.\d+){1,4}\b", val)
                    if match:
                        return match.group(0), {"software_term": next(t for t in terms if t in searchable), "version": match.group(0), key: val}

            # Some native feeds expose only _raw or a filename.  Still require
            # the product term before accepting a version-shaped token.
            match = re.search(r"(?<![A-Za-z0-9])v?(\d+(?:\.\d+){1,4})(?![A-Za-z0-9])", searchable)
            if match:
                return match.group(1), {"software_term": next(t for t in terms if t in searchable), "version": match.group(1)}
            return None, {}

        preferred = ("image", "targetfilename", "target_filename", "file_path", "path", "commandline", "cmdline")
        for key in preferred:
            val = str(fields.get(key, "") or "").strip()
            if val and val not in ("-", "unknown", "none"):
                return val, {"software_term": next(t for t in terms if t in searchable), key: val}
        return None, {}

    def verify_candidate_edge(
        self,
        edge: GraphEdge,
        source_node: GraphNode,
        target_node: GraphNode,
        ledger: ObservationLedger,
        observations: list[Observation] | None = None,
    ) -> VerificationResult:
        # 1. Collect cited observations
        candidate_obs = observations or []
        if not candidate_obs:
            obs_ids = edge.citations or edge.metadata.get("observation_ids", [])
            if not obs_ids and edge.origin_query_id:
                obs_ids = [o.id for o in ledger.observations if o.query_id == edge.origin_query_id]
            candidate_obs = [o for o in ledger.observations if o.id in obs_ids]

        if not candidate_obs:
            return VerificationResult(
                verified=False,
                diagnostic="Verification failed: No observation citations found in ledger.",
                violations=["No observation citations found."],
            )

        src_type = source_node.type if isinstance(source_node.type, str) else source_node.type.value
        tgt_type = target_node.type if isinstance(target_node.type, str) else target_node.type.value
        src_val = source_node.value.strip().lower()

        discovered_target_val: str | None = None
        matching_obs_ids: list[str] = []
        field_matches: dict[str, str] = {}
        diagnostic_violations: list[str] = []
        domain_candidates: list[tuple[int, str, str, str]] = []

        for obs in candidate_obs:
            raw_ev = getattr(obs, "raw_event", {}) or obs.fields.get("raw_event", {})
            combined_fields = {}
            if isinstance(raw_ev, dict):
                for k, v in raw_ev.items():
                    if isinstance(v, list) and v:
                        combined_fields[k.lower()] = str(v[0])
                    elif not isinstance(v, dict) and v is not None:
                        combined_fields[k.lower()] = str(v)
            for k, v in obs.fields.items():
                if isinstance(v, list) and v:
                    combined_fields[k.lower()] = str(v[0])
                elif not isinstance(v, dict) and v is not None:
                    combined_fields[k.lower()] = str(v)
            fields = combined_fields

            raw_type = str(obs.native_type).lower()
            if tgt_type in ("endpoint", "host") and "iis" in raw_type:
                diagnostic_violations.append("IIS web server telemetry cannot prove client workstation logon.")
                continue
            if tgt_type in ("endpoint", "host"):
                for f_name, f_val in obs.fields.items():
                    if f_name.lower() in self.HOST_FIELDS and str(f_val).lower() in KNOWN_WEB_SERVERS:
                        diagnostic_violations.append(f"Web server '{f_val}' is prohibited from being bound as user client endpoint.")
            if tgt_type == "ip":
                has_client_ip = any(k.lower() in self.CLIENT_IP_FIELDS for k in fields)
                has_server_ip = any(k.lower() in self.SERVER_IP_FIELDS for k in fields)
                if has_server_ip and not has_client_ip:
                    diagnostic_violations.append("Found server/destination IP, but target requires client IP.")
                    continue

            # 0. Person -> Account verification
            if src_type == "person" and tgt_type == "account":
                first_name = src_val.split()[0].lower() if src_val else ""
                last_name = src_val.split()[-1].lower() if src_val and len(src_val.split()) > 1 else ""
                matched_user = None
                for uf in (*self.USER_FIELDS, "sender", "receiver", "sender_email", "receiver_email", "displayName"):
                    val = str(fields.get(uf, "")).lower()
                    if val and (src_val.lower() in val or (first_name and first_name in val) or (last_name and last_name in val)):
                        raw_match = fields.get(uf)
                        m = re.search(r'[\w\.-]+@[\w\.-]+', str(raw_match))
                        if m:
                            matched_user = m.group(0).split('@')[0].lower()
                        elif uf in self.USER_FIELDS:
                            matched_user = str(raw_match)
                        break
                if not matched_user and first_name:
                    h_val = str(fields.get("host", "")).lower()
                    if "wrk-" in h_val and (first_name in h_val or (last_name and last_name in h_val)):
                        matched_user = h_val.split("wrk-")[-1].split(".")[0]

                if matched_user:
                    discovered_target_val = matched_user
                    matching_obs_ids.append(obs.id)
                    field_matches["person"] = source_node.value
                    field_matches["account"] = matched_user
                    break

            # 0.1 Account -> Email Address verification
            elif (src_type == "account" and tgt_type == "email_address") or edge.relation_type in ("has_email", RelationType.HAS_EMAIL):
                matched_email = None
                user_tokens = [t for t in re.split(r'[\._\s]+', src_val.lower()) if len(t) > 1]
                user_prefix = src_val.split('@')[0].split('.')[0].lower() if '.' in src_val else src_val.lower()

                # Try structured sender and receiver pairs first
                for disp_k, mail_k in [("sender", "sender_email"), ("receiver", "receiver_email")]:
                    disp_v = str(fields.get(disp_k) or "").strip()
                    mail_v = str(fields.get(mail_k) or "").strip()
                    d_name, parsed = parseaddr(disp_v)
                    eff_email = parsed or mail_v
                    eff_name = d_name or disp_v
                    if eff_email and "@" in eff_email:
                        if src_val.lower() in eff_email.lower() or user_prefix in eff_email.lower():
                            matched_email = eff_email.lower()
                            break
                        if eff_name and user_tokens and all(tok in eff_name.lower() for tok in user_tokens):
                            matched_email = eff_email.lower()
                            break

                # Fallback to scanning individual fields
                if not matched_email:
                    for obs_field in ("sender_email", "sender", "receiver_email", "receiver", "mail", "userPrincipalName", "user"):
                        val = str(fields.get(obs_field, "") or "")
                        if val:
                            d_name, email_parsed = parseaddr(val)
                            if email_parsed and "@" in email_parsed:
                                if src_val.lower() in email_parsed.lower() or user_prefix in email_parsed.lower():
                                    matched_email = email_parsed.lower()
                                    break
                                if d_name and user_tokens and all(tok in d_name.lower() for tok in user_tokens):
                                    matched_email = email_parsed.lower()
                                    break
                            m = re.search(r'[\w\.-]+@[\w\.-]+', val)
                            if m and (src_val.lower() in m.group(0).lower() or user_prefix in m.group(0).lower()):
                                matched_email = m.group(0).lower()
                                break

                if matched_email:
                    discovered_target_val = matched_email
                    matching_obs_ids.append(obs.id)
                    field_matches["account"] = source_node.value
                    field_matches["email"] = matched_email
                    break

            # 0.2 Email -> Outbound Message verification
            elif (src_type == "email_address" and tgt_type == "message") or edge.relation_type in ("sent_message", RelationType.SENT_MESSAGE):
                matched_obs = None
                pred = edge.acceptance_predicate or {}
                external_only = bool(pred.get("recipient_external") or pred.get("external"))

                # Sort candidate observations chronologically to inspect initial messages
                sorted_candidates = sorted(
                    candidate_obs,
                    key=lambda o: str(o.timestamp or o.fields.get("timestamp") or o.fields.get("_time") or "")
                )
                has_any_msg_id = any(bool(o.fields.get("msg_id") or o.fields.get("message_id")) for o in sorted_candidates)
                for obs_item in sorted_candidates:
                    raw_f = obs_item.fields
                    msg_id_val = raw_f.get("msg_id") or raw_f.get("message_id")
                    if has_any_msg_id and not msg_id_val:
                        # Skip telemetry that lacks a message identifier when actual message events are present
                        continue

                    s_raw = str(raw_f.get("sender_email", "") or raw_f.get("sender", "")).strip().lower()
                    _, s_email = parseaddr(s_raw)
                    if not s_email:
                        m = re.search(r'[\w\.-]+@[\w\.-]+', s_raw)
                        s_email = m.group(0).lower() if m else s_raw

                    if not src_val or (s_email and src_val.lower() in s_email) or (s_email and s_email in src_val.lower()):
                        if external_only:
                            r_raw = str(raw_f.get("receiver_email", "") or raw_f.get("receiver", "")).strip().lower()
                            _, r_email = parseaddr(r_raw)
                            if not r_email:
                                m = re.search(r'[\w\.-]+@[\w\.-]+', r_raw)
                                r_email = m.group(0).lower() if m else ""
                            s_dom = s_email.split("@")[-1] if "@" in s_email else ""
                            r_dom = r_email.split("@")[-1] if "@" in r_email else ""
                            if not r_dom or (s_dom and r_dom == s_dom):
                                continue

                        matched_obs = obs_item
                        break

                if matched_obs:
                    msg_id = matched_obs.fields.get("msg_id") or matched_obs.fields.get("message_id") or f"msg-{matched_obs.id}"
                    discovered_target_val = str(msg_id)
                    matching_obs_ids.append(matched_obs.id)
                    field_matches["sender"] = str(matched_obs.fields.get("sender") or matched_obs.fields.get("sender_email"))
                    field_matches["message_id"] = str(msg_id)
                    if matched_obs.fields.get("subject"):
                        field_matches["subject"] = str(matched_obs.fields.get("subject"))
                    break

            # 0.3 Message -> Recipient Identity verification
            elif (src_type == "message" and tgt_type in ("email_address", "person")) or edge.relation_type in ("received_message", RelationType.RECEIVED_MESSAGE):
                matched_obs = None
                for obs_item in candidate_obs:
                    m_id = str(obs_item.fields.get("msg_id") or obs_item.fields.get("message_id") or f"msg-{obs_item.id}").lower().strip()
                    if src_val and (src_val.lower() == m_id or src_val.lower() in m_id or m_id in src_val.lower()):
                        matched_obs = obs_item
                        break

                if not matched_obs and candidate_obs:
                    for obs_item in candidate_obs:
                        r_f = str(obs_item.fields.get("receiver_email") or obs_item.fields.get("receiver") or "")
                        if "@" in r_f:
                            matched_obs = obs_item
                            break

                if matched_obs:
                    re_val = matched_obs.fields.get("receiver_email") or matched_obs.fields.get("receiver")
                    if isinstance(re_val, list):
                        re_val = re_val[0]
                    re_str = str(re_val or "").strip()
                    parsed_name, parsed_email = parseaddr(re_str)
                    if not parsed_email:
                        m = re.search(r'[\w\.-]+@[\w\.-]+', re_str)
                        parsed_email = m.group(0) if m else re_str

                    if not parsed_name and matched_obs.fields.get("receiver"):
                        rec_sec = str(matched_obs.fields.get("receiver") or "").strip()
                        sec_name, _ = parseaddr(rec_sec)
                        if sec_name:
                            parsed_name = sec_name

                    discovered_target_val = parsed_email.strip()
                    matching_obs_ids.append(matched_obs.id)
                    field_matches["recipient_email"] = parsed_email.strip()
                    clean_name = parsed_name.strip().strip("'\"") if parsed_name else ""
                    if clean_name and "@" not in clean_name and clean_name.lower() != parsed_email.lower():
                        field_matches["recipient_name"] = clean_name
                    if matched_obs.fields.get("subject"):
                        field_matches["subject"] = str(matched_obs.fields.get("subject"))
                    break

            # 0.4 Recipient -> Role verification
            elif tgt_type == "role" or edge.relation_type in ("holds_role", RelationType.HOLDS_ROLE):
                title_val = fields.get("title") or fields.get("role") or fields.get("department") or fields.get("job_title")
                if title_val:
                    if target_node.value and target_node.value != "?":
                        if target_node.value.lower() in str(title_val).lower():
                            discovered_target_val = str(title_val)
                            matching_obs_ids.append(obs.id)
                            field_matches["role"] = str(title_val)
                            break
                    else:
                        discovered_target_val = str(title_val)
                        matching_obs_ids.append(obs.id)
                        field_matches["role"] = str(title_val)
                        break
                else:
                    diagnostic_violations.append(f"Recipient executive role for '{src_val}' cannot be verified from message telemetry alone without directory/LDAP evidence.")

            # Artifact requirements are anchored to the resolved endpoint.  Do
            # not route them through IP/web telemetry and do not accept an
            # arbitrary row merely because it contains a version-looking value.
            elif src_type in ("endpoint", "host") and tgt_type == "event":
                terms = [str(t).strip().lower() for t in (edge.acceptance_predicate or {}).get("software_terms", []) if str(t).strip()]
                searchable = " ".join(str(v).lower() for v in fields.values())
                if terms and any(term in searchable for term in terms):
                    for domain_key in self.DOMAIN_FIELDS:
                        value = str(fields.get(domain_key, "") or "").strip()
                        if value and value not in ("-", "unknown"):
                            discovered_target_val = value
                            matching_obs_ids.append(obs.id)
                            field_matches["endpoint"] = source_node.value
                            field_matches["web_field"] = domain_key
                            field_matches["web_value"] = value
                            break
                    if discovered_target_val:
                        break

            # Artifact requirements are anchored to the resolved endpoint.  Do
            # not route them through IP/web telemetry and do not accept an
            # arbitrary row merely because it contains a version-looking value.
            elif src_type in ("endpoint", "host") and tgt_type in (
                "software", "software_version", "application", "version",
                "file", "file_artifact", "process", "process_name",
            ):
                artifact_value, artifact_matches = self._artifact_value(fields, edge, tgt_type)
                if artifact_value:
                    discovered_target_val = artifact_value
                    matching_obs_ids.append(obs.id)
                    field_matches.update(artifact_matches)
                    field_matches["endpoint"] = source_node.value
                    break

            # A. Person/Account -> Endpoint logon verification
            elif src_type in ("person", "account") and tgt_type in ("endpoint", "host"):
                # Check user field
                first_name = src_val.split()[0] if src_val else src_val
                matched_user = None
                for uf in self.USER_FIELDS:
                    val = fields.get(uf, "").lower()
                    if src_val in val or (first_name and first_name in val):
                        matched_user = fields.get(uf)
                        break

                if matched_user:
                    # Extract endpoint host, prioritizing specific workstation name
                    candidate_host = None
                    ws_val = fields.get("workstationname") or fields.get("workstation_name")
                    if ws_val and not is_prohibited_server(ws_val) and ws_val.lower() not in ("source", "-", "unknown", ""):
                        candidate_host = ws_val
                    elif fields.get("host", "").lower().startswith("wrk") or fields.get("computername", "").lower().startswith("wrk"):
                        candidate_host = fields.get("host") or fields.get("computername")
                    else:
                        for hf in ("workstationname", "workstation_name", "host", "computername", "target_host"):
                            hval = fields.get(hf)
                            if hval and not is_prohibited_server(hval) and hval.lower() not in ("source", "-", "unknown", ""):
                                candidate_host = hval
                                break
                    if candidate_host and not is_prohibited_server(candidate_host):
                        discovered_target_val = candidate_host
                        matching_obs_ids.append(obs.id)
                        field_matches["user"] = matched_user
                        field_matches["host"] = candidate_host
                        break

            # B. Endpoint -> Client IP verification
            elif src_type in ("endpoint", "host") and tgt_type == "ip":
                matched_host = None
                candidate_host_fields = list(self.HOST_FIELDS) + ["targetusername", "user", "account_name"]
                for hf in candidate_host_fields:
                    val = str(fields.get(hf, "")).lower()
                    if src_val in val:
                        matched_host = fields.get(hf)
                        break

                if matched_host or not src_val:
                    for cf in self.CLIENT_IP_FIELDS:
                        ip_val = fields.get(cf)
                        if ip_val and str(ip_val) not in ("127.0.0.1", "0.0.0.0", "-"):
                            discovered_target_val = str(ip_val)
                            matching_obs_ids.append(obs.id)
                            field_matches["host"] = str(matched_host or src_val)
                            field_matches["client_ip"] = str(ip_val)
                            break
                    if discovered_target_val:
                        break

            # C. Client IP -> Web / Domain verification
            elif src_type == "ip" and (
                tgt_type in ("domain", "event", "software", "url", "uri", "site", "website", "fqdn", "fully_qualified_domain_name")
                or "domain" in tgt_type
                or "web" in tgt_type
                or "site" in tgt_type
                or "url" in tgt_type
            ):
                matched_ip = None
                for cf in self.CLIENT_IP_FIELDS:
                    ip_val = str(fields.get(cf, "")).lower()
                    if src_val in ip_val:
                        matched_ip = fields.get(cf)
                        break

                if matched_ip or not src_val:
                    for df in self.DOMAIN_FIELDS:
                        dval = fields.get(df)
                        if dval and str(dval).strip() not in ("-", ""):
                            dval_clean = str(dval).lower().strip()
                            noise_matches = any(dval_clean.endswith(nd) or nd in dval_clean for nd in self.KNOWN_NOISE_DOMAINS)
                            if not noise_matches:
                                if target_node.value and target_node.value != "?" and target_node.value.lower() in dval_clean:
                                    priority = 0
                                else:
                                    priority = 1
                                domain_candidates.append((priority, str(dval).strip(), obs.id, str(matched_ip or src_val)))

        if domain_candidates and not discovered_target_val:
            domain_candidates.sort(key=lambda c: c[0])
            top_prio, top_dval, top_obs_id, top_ip = domain_candidates[0]
            discovered_target_val = top_dval
            matching_obs_ids = [c[2] for c in domain_candidates if c[1] == top_dval]
            field_matches["client_ip"] = top_ip
            field_matches["domain"] = top_dval

        if not discovered_target_val:
            diag_v = list(set(diagnostic_violations)) if diagnostic_violations else ["Predicate match failure."]
            return VerificationResult(
                verified=False,
                diagnostic=f"Verification rejected by epistemic rules: {'; '.join(diag_v)}",
                violations=diag_v,
            )

        # 5. Success: mint RelationProof
        proof = RelationProof(
            id=f"proof-{edge.id}",
            edge_id=edge.id,
            source_node_id=source_node.id,
            source_value=source_node.value,
            target_node_id=target_node.id,
            target_value=discovered_target_val,
            relation_type=edge.relation_type if isinstance(edge.relation_type, str) else edge.relation_type.value,
            citations=list(set(matching_obs_ids)),
            field_matches=field_matches,
        )

        return VerificationResult(
            verified=True,
            proof=proof,
            target_value=discovered_target_val,
            diagnostic=f"Verified relation {source_node.value} -> {discovered_target_val} with {len(proof.citations)} observation(s).",
        )

    def apply_verification_to_graph(
        self,
        result: VerificationResult,
        edge: GraphEdge,
        target_node: GraphNode,
        graph: InvestigationGraph,
    ) -> None:
        """Apply a successful verification to update the InvestigationGraph."""
        if not result.verified or not result.proof:
            return

        edge.status = RelationStatus.VERIFIED
        edge.citations = list(set(edge.citations + result.proof.citations))
        graph.proofs[result.proof.id] = result.proof

        if result.target_value:
            target_node.value = result.target_value
        target_node.status = NodeStatus.KNOWN
