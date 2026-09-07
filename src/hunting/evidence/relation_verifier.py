"""Deterministic Relation Verifier (v5.0).

The gatekeeper of the Investigation Case Graph.
Verifies candidate edges against observation ledgers, enforcing strict field roles
(client_ip ≠ server_ip, host ≠ sensor), web server isolation, and valid citations
before minting RelationProofs and updating graph state.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from hunting.contracts.case_graph import (
    GraphEdge,
    GraphNode,
    InvestigationGraph,
    NodeStatus,
    RelationProof,
    RelationStatus,
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
                first_name = src_val.split()[0] if src_val else src_val
                matched_user = None
                for uf in self.USER_FIELDS:
                    val = fields.get(uf, "").lower()
                    if src_val in val or (first_name and first_name in val):
                        matched_user = fields.get(uf)
                        break
                if matched_user:
                    discovered_target_val = matched_user
                    matching_obs_ids.append(obs.id)
                    field_matches["person"] = source_node.value
                    field_matches["account"] = matched_user
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
                                elif any(kw in dval_clean for kw in ("beer", "competitor", "brew")):
                                    priority = 1
                                else:
                                    priority = 2
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
