# Deployment guide

What an operator needs before putting this pack in front of production traffic. The rule-level facts are in
[RULES.md](RULES.md), the measured false-positive profile in [docs/fp-report.md](docs/fp-report.md).

## Before operational use

Trial the pack in an internal test environment or a limited, non-blocking deployment before using it for operational
alerts or response. Include normal traffic, approved security tests and automation. Verify field mappings, false
positives, alert volume, resource use and service impact. Alert-only deployment can still overload log processing or
alert queues. Keep blocking and anomaly scoring opt-in, with per-rule approval and a tested rollback.

## What a match means

A match is a fingerprint of a known tool (User-Agent, path, title, cookie name, tool-function name, short marker)
or an automation shape (burst, 404 rate, path count). It does not establish that an LLM was involved, that the
actor was malicious, that the activity was unauthorised, or that anything succeeded. Tool-specific rules identify the
software; generic rules describe behaviour that ordinary scanners, monitors and batch jobs also produce. A sanctioned
assessment that uses one of these tools matches exactly like an attacker; the pack cannot tell them apart.

## Observation points and blind spots

| point | evidence | what it needs | what it cannot see |
|---|---|---|---|
| A target-facing HTTP | `suricata/aipt-target-facing.rules`, `sigma/web/`, `sigma/correlation/`, `modsecurity/`, `analytics/` | the original client address (trusted real-IP extraction), request headers, status codes, timestamps with sub-second precision for the correlations | the attacker's LLM calls, tool console or processes; anything inside TLS a WAF or IDS does not terminate |
| B operator egress | `suricata/aipt-operator-egress.rules`, `sigma/proxy/`, `sigma/zeek/` | a TLS-inspecting forward proxy or request-level proxy logs; DNS/SNI gives host contact only | an operator outside your network |
| C exposed console | `suricata/aipt-exposed-console.rules`, Sigma console rules, ModSecurity 9590400-9590499 | the console or API traffic to pass the sensor; `xbits` chains need both directions on one sensor | consoles bound to loopback (PentAGI, MetasploitMCP and msfrpcd default to 127.0.0.1) |
| D endpoint telemetry | `sigma/process_creation/`, `sigma/file_event/`, `sigma/network_connection/`, `yara/` | an EDR or auditd feed from the host that runs the tool; YARA on seized files or process memory | hosts you do not manage |
| E LLM side | `suricata/aipt-llm-side.rules`, `sigma/proxy/proxy_generic_llm_api_client.yml` | cleartext LLM API bodies: a TLS-terminating egress proxy, an LLM gateway or relay, a local model server; large body limits | hosted providers reached over TLS you do not terminate |

A target-side WAF or IDS sees point A only. Deploy each file where its evidence exists and nowhere else.

## Observe-only defaults and enforcement opt-in

- **Suricata**: every rule ships as `alert`. Conversion to `drop` is a per-sensor decision on sids from
  `suricata/aipt-block-eligible.sids` only, after the baseline below. The five ARTEX conversation-marker sids
  (9500032, 9500033, 9500034, 9500071, 9500072) are drop candidates on an egress proxy only, never on an LLM gateway
  or chat proxy, where a conversation about the tool reproduces the indicator. Sid 9500060 (console asset by
  `filemd5`) is listed as deferred: the internal validation summary has no positive file-replay fixture, so its drop behaviour is
  unvalidated and it stays alert-only until you validate it on a capture of your own. Rollback: reload the alert
  version.
- **ModSecurity** (`modsecurity/aipt-config.conf`, `aipt-before.conf` in the CRS plugins directory, loaded after
  `crs-setup.conf` and before `rules/*.conf`): as shipped the plugin is observe-only. Every rule is `pass,log`, no
  rule adds an anomaly score, and the plugin never contributes to a CRS block whatever `SecRuleEngine` and the CRS
  thresholds of the host are. Enforcement is opt-in per direction: switch 9590015 lets the five product User-Agent
  rules add the CRS critical inbound score (a single match then blocks at paranoia level 1), switch 9590013 does the
  same outbound for the ARTEX console response 9590401. Both are commented-out `SecAction`s in `aipt-config.conf`;
  commenting them out again is the rollback. Do not set the host WAF to `DetectionOnly` or raise CRS thresholds for
  this pack; it does not need either. Verify in your test environment that an independent CRS-positive request stays
  blocked with the plugin observe-only, including when it carries an AIPT User-Agent.
- **Sigma / SIEM**: `level` is a tier label, not an action. The base selectors `sigma/web/web_aipt_*_base.yml` are
  inputs of the correlations only; registered as stand-alone alerts they fire on most requests.
- **YARA**: file rules and `*_Mem` rules are never mixed in one scan; `-s` would print transcript secrets.

## Noise you will see

Generic rules (Go-http-client, Headless Chromium, manifest probe, generic MCP, scanner User-Agents, the LLM API client
rule until `llm_approved_clients` is filled, the correlations) fire on monitoring, batch jobs, gateways, crawlers,
QA automation and logged-in users behind NAT. The README "Noisy rules" table gives the corpus counts. Route these to
hunting or an allow-listed queue, not to paging or automatic blocking. The correlations count requests that carry a
cookie like any other (a cookie is not server-validated authentication); where your web server logs a validated user
or session id, group by it instead of the address.

## Telemetry requirements

- **Client address**: take it from a real-IP header only from proxies you trust (`set_real_ip_from` / `SET_REAL_IP_FROM`
  limited to those hops); otherwise the correlations group on the proxy address. One NAT or CGNAT address is many
  users; do not treat it as one actor, allow-list known NAT ranges in `approved_assessment_sources` only when they are
  an assessment source.
- **Field mapping**: Sigma webserver names (`c-ip`, `cs-uri-stem`, `cs-user-agent`, `sc-status`) and proxy names
  (`src_ip`, `cs-host`, `c-uri-stem`, `c-useragent`); `cs-content-type` and, for Sentinel ASIM, `c-uri-stem` need a
  manual mapping (README, backend caveats). Missing User-Agents must arrive as empty or absent, not as the string
  `null`.
- **Timestamps**: the correlations need event times with at least second precision and events in time order per
  client; run them with a lookback that covers the longest window (10 min) plus ingestion delay, and deduplicate
  alerts on (correlation, client) with a suppression of at least one window.
- **Duplicates**: a request logged twice (load balancer and origin) doubles every count; feed one tier.

## Approved assessments and other exemptions

The placeholders `approved_assessment_sources` and `approved_assessment_user_agents` (Sigma), the threshold template
`suricata/approved-assessment-suppress.threshold.template` (Suricata) and switch 9590012 with
`aipt-approved-assessment-sources.txt` (ModSecurity) suppress generic rules only:

- Sigma: `web_generic_*` (Go-http-client, Headless Chromium, manifest probe, Nmap NSE, scanner User-Agents), the five
  base selectors and therefore the correlations, and `proxy_generic_llm_api_client`.
- Suricata: 9500006, 9500007, 9500008, 9500010, 9500110, 9500280-9500283, 9500290-9500295, 9500297, 9500299.
- ModSecurity: 9590300-9590399.

Every tool-specific rule stays active for an approved source: a sanctioned engagement that runs ARTEX still raises the
ARTEX rules, and should. A source is exempt only when its address matches; a User-Agent alone never exempts. Give
every exemption an owner, a scope and an expiry.

## Rollout checklist

Each step produces evidence; there is no waiting period that makes enforcement safe by itself.

1. **Telemetry**: confirm the client address, field names, status codes, timestamps and a single log tier for each
   observation point. Run syntax, conversion and load checks with the engine versions you intend to deploy; the
   public repository does not include a test runner.
2. **Observe**: deploy observe-only (defaults) and collect a period that contains normal peaks, batch windows,
   synthetic monitoring, development and QA activity, and at least one authorised assessment or scan.
3. **Review**: for every block-eligible rule, list the sources that matched; each must be an identified tool use (a
   finding) or an identified exemption. Any unexplained match keeps that rule at alert.
4. **Regressions**: use your own authorised test cases to check positive and benign matches, assessment exemptions,
   correlation boundaries and observe-only/scoring behaviour. Preserve existing CRS protections. Treat the corpus
   figures in `docs/fp-report.md` as historical reference, not as a production false-positive rate.
5. **Cost**: measure sensor CPU and memory with the LLM-side body limits, and SIEM query time for the correlations
   at your peak event rate before scheduling them.
6. **Enforce per rule**: convert one sid or switch at a time, per sensor, with the rollback (alert version or
   switch commented out) tested first, and re-review after each change.

## Validation scope

This is the public rules-only edition. Internal Python tools, fixtures, corpus generators, replay services, execution
logs and CI are not distributed. The README "Validation" table and [false-positive report](docs/fp-report.md) describe
author-reported internal work, not tests a public checkout can run. No engine rerun was performed for this packaging
change.

Kusto language-service checks and functional emulator runs are separate evidence; neither measures query cost at your
peak load. The Elasticsearch equivalents of three correlations use fixed buckets (`analytics/correlations.esql.md`),
which can miss a burst that straddles a bucket edge. Validate the backend and telemetry you actually deploy.

## If you deployed a pre-release copy

1.0.0 is the first public release, but copies of the pack circulated during review. Compared with those:

- ModSecurity is observe-only as shipped. A pre-release copy added the CRS critical inbound score on the five product
  User-Agent rules; that is now switch 9590015 (and 9590013 outbound), both commented out in `aipt-config.conf`.
- The correlation base selector no longer exempts cookie-bearing requests; the request burst, distinct paths and
  identical request correlations are `informational`. The SPL, ES|QL and KQL equivalents changed with it.
- Proxy rules use the Sigma proxy taxonomy name `c-useragent` (was `cs-user-agent`); regenerate converted rules and
  check your field mapping. `cs-content-type` still needs a manual mapping.
- Removed: Suricata 9500232 and 9500243 and ModSecurity 9590222 (indicators on loopback-only ports), Sigma
  `web_pentagi_graphql_api_request` and `net_connection_lnx_strix_caido_sidecar`. The sids are in
  `suricata/retired.rules` and are not reused. Suricata 9500036 and 9500225 are `alert` tier (were block-eligible);
  9500209 was narrowed and 9500047 added.
- Kusto conversions of the approved-source placeholders now emit `<name>_v4` and `<name>_v6` lists
  (`sigma/pipelines/aipt-cidr-kusto.yaml`); define both, an empty list exempts nothing.
