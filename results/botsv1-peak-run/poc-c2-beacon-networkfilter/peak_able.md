# PEAK ABLE Table: HTTP Command-and-Control Beaconing to ad.networkfilter.co

*Hypothesis: C2 beacon to ad.networkfilter.co (BOTS v1 known IOC). Outbound HTTP request to ad.networkfilter.co, the ad-fraud beacon seen in BOTS v1.*

| ABLE Element | |
|---|---|
| Actor | Ad-fraud/C2 operator associated with the BOTS v1 known IOC ad.networkfilter.co. No named APT or individual actor is specified in the hypothesis or research document. |
| Behavior | Outbound HTTP command-and-control beaconing to ad.networkfilter.co. The expected behavior is a web request to the known C2 host, potentially using a GET request to the /banner/ path. MITRE ATT&CK T1071.001: Application Layer Protocol: Web. Expected observable chain: web_request, process_creation. |
| Location | Network perimeter/egress web traffic and internal endpoints that generate outbound HTTP requests. Examine web/proxy telemetry for outbound requests from internal hosts, and endpoint process creation on hosts that may launch beaconing processes. In local telemetry, the relevant tables are web_request and process_creation. |
| Evidence | Data sources: web_request and process_creation. In web_request, the site is stored in domain and the text site=<host> uri=<path> is stored in cmdline. Candidate literal predicates: web_request.domain EQUALS ad.networkfilter.co; web_request.cmdline CONTAINS ad.networkfilter.co; web_request.cmdline CONTAINS /banner/; process_creation.cmdline CONTAINS ad.networkfilter.co; process_creation.cmdline CONTAINS /banner/. Pivot on host, user, ip, and timestamp to scope beaconing. Optional DNS pivot if ad.networkfilter.co appears in dns.domain, but the expected observable chain is web_request and process_creation. |

## Notes
- ad.networkfilter.co is a known BOTS v1 IOC; its presence should be treated as high-signal but still verified with host, user, and timing context.
- Field matching in the local executor is literal and case-insensitive for EQUALS, CONTAINS, STARTS_WITH, and ENDS_WITH.
- Web requests store the host in domain and site=<host> uri=<path> in cmdline; the available columns do not include full HTTP headers, response codes, or complete URI beyond what is in cmdline.
- The available data can show individual web requests but cannot by itself prove periodic beaconing without time-series analysis across host, ip, and timestamp.
- process_creation may not capture browser-driven or script-driven beaconing; absence in process_creation does not rule out web_request evidence.
- The dns table exists, but the expected observable chain does not include DNS. DNS pivots are optional if ad.networkfilter.co appears in dns.domain.
- Equivalent detection draft: search web_request where domain EQUALS ad.networkfilter.co OR cmdline CONTAINS ad.networkfilter.co OR cmdline CONTAINS /banner/; then pivot to process_creation by host and time.
