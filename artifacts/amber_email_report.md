# Hunt Report

## 1. Hypothesis / Question

> Amber sent an email to the competitor's CEO. What is the recipient's name and email address?

- **Subject:** `user`: `Amber`
- **Requested Object:** `recipient_identity_record` (role: `answer`)
- **Behavior:** User Amber sent an outbound email to the CEO of a competitor organization.

**Result:** `SUPPORTED_WITH_LIMITATIONS`  
**Stopping:** `STOP_RESOLVED`

- **Causal Path Coverage:** `80.0%` (4/5 relations verified)
- **Wildcard Scope Coverage:** `0.0%` (0/1 broadsweep cells)
- **Instance Cell Coverage:** `100.0%` (5/5 concrete entity cells)

**Answer Status:** `PARTIALLY_ANSWERED`

**Answer (recipient_identity_record):** `{'recipient_name': 'Martin Berk', 'recipient_email': 'mberk@berkbeer.com'}`

**Answer explanation:** Based on the verified causal provenance subgraph and card-edge-message-received-by (citing obs-207), the outbound message sent by Amber (via aturing@froth.ly) with ID <SN1PR18MB058947DF30988EF32297D445D4890@SN1PR18MB0589.namprd18.prod.outlook.com> was received by Martin Berk at the email address mberk@berkbeer.com.

## 2. Hypothesis analysis

- `LIVE` — Amber intentionally transmitted sensitive or proprietary information to an external competitor's leadership.
- `LIVE` — An unauthorized party compromised Amber's credentials and used her account to contact an external executive.
- `LIVE` — The email communication represents routine, approved business correspondence or personal recruiting dialogue rather than malicious activity.

### Proven Relation Chain (Causal Provenance)

| Edge ID | Relation Path | Citations | Verified At |
|---|---|---|---|
| `edge-person-owns-account` | `Amber` **-[owns]->** `aturing` | `obs-1` | `2026-09-07T15:41:53.846703` |
| `edge-account-has-email` | `aturing` **-[has_email]->** `aturing@froth.ly` | `obs-101` | `2026-09-07T15:41:54.853428` |
| `edge-email-sent-message` | `aturing@froth.ly` **-[sent_message]->** `<SN1PR18MB058947DF30988EF32297D445D4890@SN1PR18MB0589.namprd18.prod.outlook.com>` | `obs-204` | `2026-09-07T15:41:55.847111` |
| `edge-message-received-by` | `<SN1PR18MB058947DF30988EF32297D445D4890@SN1PR18MB0589.namprd18.prod.outlook.com>` **-[received_message]->** `mberk@berkbeer.com` | `obs-207` | `2026-09-07T15:41:56.648695` |

**Unresolved Mandatory Unknowns:** None (all causal relations verified).

### Claims Evaluation

| Claim | Required Capability | Status |
|---|---|---|
| Email sent from aturing | `outbound_message_metadata` | **`SUPPORTED`** |
| Recipient email is mberk@berkbeer.com | `recipient_identity` | **`SUPPORTED`** |
| The recipient was the competitor's CEO | `role_identity` | **`UNKNOWN`** |

### Limitations

- Chưa chứng minh được người nhận là CEO từ dữ liệu telemetry.
- Chưa có bằng chứng đủ mạnh về việc email thực sự do đối tượng trực tiếp soạn thảo.

## 3. Evidence and explanation

| Evidence | Why it matters | Source |
|---|---|---|
| Verified relation <SN1PR18MB058947DF30988EF32297D445D4890@SN1PR18MB0589.namprd18.prod.outlook.com> -[RelationType.RECEIVED_MESSAGE]-> mberk@berkbeer.com | Directly identifies the recipient of Amber's outbound message as Martin Berk (mberk@berkbeer.com) with the subject 'Amber from Froth.ly'. | 1 event(s); representative observations: `obs-207` |
| Network connection established to 172.31.38.181 | Documents network connections between host matar and IP 172.31.38.181; does not provide recipient identity information. | 111 event(s); representative observations: `obs-17`, `obs-65`, `obs-70` |
| Telemetry observations (90 events on wrk-aturing) | Provides workstation telemetry on wrk-aturing linking Amber to the account aturing. | 90 event(s); representative observations: `obs-1`, `obs-2`, `obs-3` |
| Network connection established to 10.0.1.100 | Documents network connections between host jupiter and IP 10.0.1.100; does not reveal recipient identity. | 3 event(s); representative observations: `obs-28`, `obs-88`, `obs-89` |
| Telemetry observations (3 events on mercury) | Telemetry on host mercury for user amber.turing; corroborates user identity across hosts but does not identify the email recipient. | 3 event(s); representative observations: `obs-27`, `obs-86`, `obs-87` |

### Explanation

- **Deterministic Graph Resolution:** The target object `{'recipient_name': 'Martin Berk', 'recipient_email': 'mberk@berkbeer.com'}` was proven through the verified 4-step causal provenance chain.
- **LLM Narrative Analysis:** Based on the verified causal provenance subgraph and card-edge-message-received-by (citing obs-207), the outbound message sent by Amber (via aturing@froth.ly) with ID <SN1PR18MB058947DF30988EF32297D445D4890@SN1PR18MB0589.namprd18.prod.outlook.com> was received by Martin Berk at the email address mberk@berkbeer.com.
- Directly identifies the recipient of Amber's outbound message as Martin Berk (mberk@berkbeer.com) with the subject 'Amber from Froth.ly'.
- Documents network connections between host matar and IP 172.31.38.181; does not provide recipient identity information.
- Provides workstation telemetry on wrk-aturing linking Amber to the account aturing.
- Documents network connections between host jupiter and IP 10.0.1.100; does not reveal recipient identity.
- Telemetry on host mercury for user amber.turing; corroborates user identity across hosts but does not identify the email recipient.
- Limitation: No definitive adversary presence or refutation established in searched frame.

## 4. Queries used

### `qp-v5-1-resolve_person_to_account` — `edge-person-owns-account`
- **Purpose:** resolve_person_to_account

- **Result:** 100 rows returned; complete=True
- **Hypothesis Impact:** Targets `hypo-1`
Provider: `splunk`; completeness: `complete`

```spl
search index="botsv2" (sourcetype="stream:smtp" OR sourcetype="stream:ldap" OR sourcetype="*security*" OR sourcetype="WinEventLog:Security" OR sourcetype="wineventlog:security") ("Amber" OR "Amber" OR TargetUserName="*Amber*" OR "*aturing*") | rex field=_raw "New Logon:[\s\S]*?Account Name:\s*(?<TargetUserName>[^\r\n\s]+)" | rex field=_raw "Account Name:\s*(?<user>[^\r\n\s]+)" | head 101 | table _time, host, ComputerName, TargetUserName, user, sender, sender_email, receiver, receiver_email, IpAddress, WorkstationName, LogonType, _raw
```

### `qp-v5-2-resolve_account_to_email` — `edge-account-has-email`
- **Purpose:** resolve_account_to_email

- **Result:** 100 rows returned; complete=True
- **Hypothesis Impact:** Targets `hypo-1`
Provider: `splunk`; completeness: `complete`

```spl
search index="botsv2" sourcetype="stream:smtp" ("aturing" OR "aturing*@*" OR "*aturing*") | head 101 | table _time, host, TargetUserName, user, sender, sender_email, receiver, receiver_email, _raw
```

### `qp-v5-3-find_outbound_message_metadata` — `edge-email-sent-message`
- **Purpose:** find_outbound_message_metadata

- **Result:** 4 rows returned; complete=True
- **Hypothesis Impact:** Targets `hypo-1`
Provider: `splunk`; completeness: `complete`

```spl
search index="botsv2" sourcetype="stream:smtp" ("aturing@froth.ly" OR "*amber*" OR "*aturing*") ("berkbeer" OR "ceo" OR "competitor" OR "external" OR "Amber from Froth.ly") | head 101 | table _time, host, sender, sender_email, receiver, receiver_email, subject, msg_id, src_ip, dest_ip, _raw
```

### `qp-v5-4-resolve_recipient_identity` — `edge-message-received-by`
- **Purpose:** resolve_recipient_identity

- **Result:** 3 rows returned; complete=True
- **Hypothesis Impact:** Targets `hypo-1`
Provider: `splunk`; completeness: `complete`

```spl
search index="botsv2" sourcetype="stream:smtp" ("<SN1PR18MB058947DF30988EF32297D445D4890@SN1PR18MB0589.namprd18.prod.outlook.com>" OR "mberk@berkbeer.com" OR "Amber from Froth.ly") | head 101 | table _time, host, sender, sender_email, receiver, receiver_email, subject, msg_id, _raw
```

### `qp-v5-5-resolve_role_identity` — `edge-recipient-holds-role`
- **Purpose:** resolve_role_identity

- **Result:** 9 rows returned; complete=True
- **Hypothesis Impact:** Targets `hypo-1`
Provider: `splunk`; completeness: `complete`

```spl
search index="botsv2" (sourcetype="stream:smtp" OR sourcetype="*active_directory*" OR sourcetype="*ldap*") ("mberk@berkbeer.com" OR "CEO" OR "chief executive") | head 101 | table _time, host, sender, receiver, subject, title, role, department, _raw
```

## 5. Cost

- Model: `1/gemini-flash-3.8-high-omni`
- Calls: `2`
- Tokens: `8865`
- Estimated cost: `$0.001105`
