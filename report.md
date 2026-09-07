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
- **Instance Cell Coverage:** `60.0%` (3/5 concrete entity cells)

**Answer Status:** `PARTIALLY_ANSWERED`

**Answer (recipient_email):** `mberk@berkbeer.com`

## 2. Hypothesis analysis

- `LIVE` — Amber intentionally transmitted sensitive or proprietary information to an external competitor's leadership.
- `LIVE` — An unauthorized party compromised Amber's credentials and used her account to contact an external executive.
- `LIVE` — The email communication represents routine, approved business correspondence or personal recruiting dialogue rather than malicious activity.

### Proven Relation Chain (Causal Provenance)

| Edge ID | Relation Path | Citations | Verified At |
|---|---|---|---|
| `edge-person-owns-account` | `Amber` **-[owns]->** `amber.turing` | `obs-1` | `2026-09-07T17:02:41.284350` |
| `edge-account-has-email` | `amber.turing` **-[has_email]->** `aturing@froth.ly` | `obs-101` | `2026-09-07T17:02:42.086687` |
| `edge-email-sent-message` | `aturing@froth.ly` **-[sent_message]->** `<SN1PR18MB058947DF30988EF32297D445D4890@SN1PR18MB0589.namprd18.prod.outlook.com>` | `obs-470` | `2026-09-07T17:02:43.071666` |
| `edge-message-received-by` | `<SN1PR18MB058947DF30988EF32297D445D4890@SN1PR18MB0589.namprd18.prod.outlook.com>` **-[received_message]->** `mberk@berkbeer.com` | `obs-702` | `2026-09-07T17:02:43.278323` |

**Unresolved Mandatory Unknowns:** None (all causal relations verified).

### Claims Evaluation

| Claim | Required Capability | Status |
|---|---|---|
| Email sent from amber.turing | `outbound_message_metadata` | **`SUPPORTED`** |
| Recipient email is mberk@berkbeer.com | `recipient_identity` | **`SUPPORTED`** |
| The recipient was the competitor's CEO | `role_identity` | **`UNKNOWN`** |

### Limitations

- Chưa chứng minh được người nhận là CEO từ dữ liệu telemetry.
- Chưa có bằng chứng đủ mạnh về việc email thực sự do đối tượng trực tiếp soạn thảo.

## 3. Evidence and explanation

| Evidence | Why it matters | Source |
|---|---|---|
| Verified relation <SN1PR18MB058947DF30988EF32297D445D4890@SN1PR18MB0589.namprd18.prod.outlook.com> -[RelationType.RECEIVED_MESSAGE]-> mberk@berkbeer.com | Verified relation establishing that message <SN1PR18MB058947DF30988EF32297D445D4890@SN1PR18MB0589.namprd18.prod.outlook.com> with subject 'Amber from Froth.ly' was received by mberk@berkbeer.com. Provides recipient email, but lacks recipient full name and role. | 1 event(s); representative observations: `obs-702` |
| Telemetry observations (608 events on matar) | Telemetry on host matar showing message transmissions involving surveys@vindale.com and aturing@froth.ly. Unrelated to the outbound communication to mberk@berkbeer.com. | 608 event(s); representative observations: `obs-6`, `obs-14`, `obs-25` |
| Telemetry observations (40 events on wrk-aturing) | Telemetry observations on host wrk-aturing confirming account activity for amber.turing between 2017-08-31T13:31:34Z and 2017-08-31T22:30:41Z, corroborating Amber's ownership of the workstation account. | 40 event(s); representative observations: `obs-1`, `obs-3`, `obs-4` |
| Telemetry observations (36 events on mercury) | Telemetry observations on mercury for user amber.turing across 36 events. Indicates domain activity but provides no details regarding outbound emails or recipient identities. | 36 event(s); representative observations: `obs-2`, `obs-5`, `obs-10` |
| Telemetry observations (18 events on venus) | Telemetry observations on venus for user amber.turing across 18 events. Demonstrates user activity across internal hosts but provides no recipient identity information. | 18 event(s); representative observations: `obs-9`, `obs-12`, `obs-23` |

### Explanation

- **Deterministic Graph Resolution:** The target object `mberk@berkbeer.com` was proven through the verified 4-step causal provenance chain.
- **LLM Narrative Analysis:** The verified provenance subgraph and observation obs-702 (card-edge-message-received-by) establish that an email from Amber (amber.turing / aturing@froth.ly) was received by mberk@berkbeer.com with subject 'Amber from Froth.ly'. However, the bounded evidence does not contain the recipient's full name, nor does it confirm the recipient's status as a competitor CEO. Consequently, while the recipient email address is verified as mberk@berkbeer.com, the recipient's name remains unverified in the provided evidence.
- Verified relation establishing that message <SN1PR18MB058947DF30988EF32297D445D4890@SN1PR18MB0589.namprd18.prod.outlook.com> with subject 'Amber from Froth.ly' was received by mberk@berkbeer.com. Provides recipient email, but lacks recipient full name and role.
- Telemetry on host matar showing message transmissions involving surveys@vindale.com and aturing@froth.ly. Unrelated to the outbound communication to mberk@berkbeer.com.
- Telemetry observations on host wrk-aturing confirming account activity for amber.turing between 2017-08-31T13:31:34Z and 2017-08-31T22:30:41Z, corroborating Amber's ownership of the workstation account.
- Telemetry observations on mercury for user amber.turing across 36 events. Indicates domain activity but provides no details regarding outbound emails or recipient identities.
- Telemetry observations on venus for user amber.turing across 18 events. Demonstrates user activity across internal hosts but provides no recipient identity information.
- Limitation: No definitive adversary presence or refutation established in searched frame.

## 4. Queries used

### `qp-v5-1-resolve_person_to_account` — `edge-person-owns-account`
- **Purpose:** resolve_person_to_account

- **Result:** 100 rows returned; complete=False
- **Hypothesis Impact:** Targets `hypo-1`
Provider: `splunk`; completeness: `complete`

```spl
search index="botsv2" (sourcetype="stream:smtp" OR sourcetype="stream:ldap" OR sourcetype="*security*" OR sourcetype="WinEventLog:Security" OR sourcetype="wineventlog:security") ("Amber" OR "Amber" OR TargetUserName="*Amber*") | rex field=_raw "New Logon:[\s\S]*?Account Name:\s*(?<TargetUserName>[^\r\n\s]+)" | rex field=_raw "Account Name:\s*(?<user>[^\r\n\s]+)" | head 101 | table _time, host, ComputerName, TargetUserName, user, sender, sender_email, receiver, receiver_email, IpAddress, WorkstationName, LogonType, _raw
```

### `qp-v5-2-resolve_account_to_email` — `edge-account-has-email`
- **Purpose:** resolve_account_to_email

- **Result:** 100 rows returned; complete=False
- **Hypothesis Impact:** Targets `hypo-1`
Provider: `splunk`; completeness: `complete`

```spl
search index="botsv2" sourcetype="stream:smtp" ("amber.turing" OR "amber*@*" OR "*amber.turing*") | head 101 | table _time, host, TargetUserName, user, sender, sender_email, receiver, receiver_email, _raw
```

### `qp-v5-3-find_outbound_message_metadata` — `edge-email-sent-message`
- **Purpose:** find_outbound_message_metadata

- **Result:** 500 rows returned; complete=True
- **Hypothesis Impact:** Targets `hypo-1`
Provider: `splunk`; completeness: `complete`

```spl
search index="botsv2" sourcetype="stream:smtp" (sender="*aturing@froth.ly*" OR sender_email="*aturing@froth.ly*" OR "aturing@froth.ly") | head 500 | table _time, host, sender, sender_email, receiver, receiver_email, subject, msg_id, src_ip, dest_ip, _raw
```

### `qp-v5-4-resolve_recipient_identity` — `edge-message-received-by`
- **Purpose:** resolve_recipient_identity

- **Result:** 2 rows returned; complete=True
- **Hypothesis Impact:** Targets `hypo-1`
Provider: `splunk`; completeness: `complete`

```spl
search index="botsv2" sourcetype="stream:smtp" (msg_id="<SN1PR18MB058947DF30988EF32297D445D4890@SN1PR18MB0589.namprd18.prod.outlook.com>" OR message_id="<SN1PR18MB058947DF30988EF32297D445D4890@SN1PR18MB0589.namprd18.prod.outlook.com>" OR "<SN1PR18MB058947DF30988EF32297D445D4890@SN1PR18MB0589.namprd18.prod.outlook.com>") | head 101 | table _time, host, sender, sender_email, receiver, receiver_email, subject, msg_id, _raw
```

### `qp-v5-5-resolve_role_identity` — `edge-recipient-holds-role`
- **Purpose:** resolve_role_identity

- **Result:** 0 rows returned; complete=True
- **Hypothesis Impact:** Targets `hypo-1`
Provider: `splunk`; completeness: `complete`

```spl
search index="botsv2" (sourcetype="*active_directory*" OR sourcetype="*ldap*" OR sourcetype="stream:ldap") ("mberk@berkbeer.com") | head 101 | table _time, host, sender, receiver, subject, title, role, department, _raw
```

## 5. Cost

- Model: `1/gemini-flash-3.8-high-omni`
- Calls: `2`
- Tokens: `9055`
- Estimated cost: `$0.001172`
