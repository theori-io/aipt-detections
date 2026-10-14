# AIPT detection pack

Detection rules for LLM-driven autonomous penetration-testing tools: ARTEX (`Autumn-27/ARTEX` v0.3.15, commit
`e6ec569`) and CyberStrikeAI, HexStrike-AI, PentAGI, Strix, Shannon, MetasploitMCP, PentestGPT, Decepticon and
Villager. Formats: Suricata, Sigma, YARA, ModSecurity (OWASP CRS v4 plugin), KQL and SPL. Rule index with per-rule
source, tier and observation point: [RULES.md](RULES.md). 한국어: [README.ko.md](README.ko.md).

Everything is fingerprint level: User-Agents, URL paths, ports, header names, TLS fields, process and file names, LLM
tool-function names and a few short markers. The pack does not inspect attack payloads, does not say what an agent did
with a vulnerability, and cannot tell a sanctioned assessment from an attack on its own. A tool that changes its
User-Agent and runs over TLS you cannot inspect leaves only the behavioural shapes (bursts, 404 rates, path counts),
which also match ordinary scanners.

## Public release scope

This repository contains detection rules, Sigma conversion settings, KQL/SPL queries and documentation. Internal
Python utilities, test suites, fixture generators, replay services, execution logs and CI workflows are not distributed.
The published [false-positive report](docs/fp-report.md) retains the method and aggregate results, not a runnable test
suite.

## Deployment safety

Before operational use, trial the rules in an internal test environment or a limited, non-blocking deployment.
Include normal traffic, authorised assessments and automation; check field mappings, false positives, alert volume,
resource use and service impact. Alert-only rules can still increase logging and processing load. Do not enable
blocking or anomaly scoring in bulk; approve changes per rule and test rollback first.

- A match identifies a tool fingerprint or an automation shape, not AI involvement, intent, authorisation or success.
- Everything ships observe-only: Suricata rules are `alert`, the ModSecurity plugin adds no anomaly score until the
  opt-in switches 9590015 (inbound) or 9590013 (outbound) are set, Sigma `level` is a label. Rollback is the alert
  version or the switch commented out.
- `block-eligible` is a candidate for local policy review, never a list to convert wholesale. The 0-hit figure is a
  measurement on the synthetic corpus below, not a production false-positive rate.
- Each file belongs to one observation point; a target-side WAF sees none of the attacker's LLM calls or processes.
- Generic rules and the correlations fire on ordinary automation; the base selectors `web_aipt_*_base` are never
  stand-alone alerts. Correlations need a trusted client address and deduplicated, time-ordered events.
- Observation points, telemetry requirements, exemption scope and the rollout checklist: [DEPLOYMENT.md](DEPLOYMENT.md).

## Layout by observation point

| | where the evidence is | files |
|---|---|---|
| A | own web server, WAF and reverse-proxy logs | `suricata/aipt-target-facing.rules`, `sigma/web/`, `sigma/correlation/`, `modsecurity/`, `analytics/` |
| B | egress, proxy, DNS and firewall logs | `suricata/aipt-operator-egress.rules`, `sigma/proxy/`, `sigma/zeek/` |
| C | perimeter sensors and threat intelligence: a tool console or API exposed on a network | `suricata/aipt-exposed-console.rules`, Sigma console rules, ModSecurity 9590400-9590499 |
| D | compromised or seized hosts | `sigma/process_creation/`, `sigma/file_event/`, `sigma/network_connection/`, `yara/` |
| E | LLM provider and relay proxy (cleartext LLM API bodies only) | `suricata/aipt-llm-side.rules`, `sigma/proxy/proxy_generic_llm_api_client.yml` |

## Format notes

- **Suricata** 7/8. One file per sensor position; load only what the sensor can see. `aipt-exposed-console.rules`
  chains client rules on `xbits` set by console response fingerprints (same IP pair, one sensor) and needs
  `artex-ui-assets.md5` plus `force-hash: [md5]` for sid 9500060. `aipt-llm-side.rules` needs large request and
  response body limits. `retired.rules` is documentation, never load it. Sids 9500070-9500072 are the JSON
  `\uXXXX`-escaped twins of the three non-ASCII markers (Python relays escape them, ARTEX's Go encoder does not).
- **Sigma**. Convert with `sigma/pipelines/aipt-placeholders.yaml` (pySigma rejects empty placeholder lists) and,
  for CIDR-aware approved-source lists, the backend pipeline `aipt-cidr-{splunk,kusto,esql}.yaml`. The five base
  selectors `sigma/web/web_aipt_*_base.yml` are correlation inputs only, never stand-alone alerts.
  `proc_creation_lnx_artex_tool_env_proxy_injection` uses the non-taxonomy field `Environment`. sigma-cli 3.1.0
  cannot convert the correlations as a set: deploy `analytics/correlations.{spl,kql}` and `correlations.esql.md`
  instead ([sigma/correlation/README.md](sigma/correlation/README.md)).
- **YARA** 4.x. `aipt_artex.yar` and `aipt_family.yar` are file rules (`filesize`, executable header) and never match a
  live process; `aipt_memory.yar` holds the strings-only `*_Mem` variants for process scans. Do not mix the two in one
  scan. Leave `-s` out: matched strings can contain secrets from transcripts.
- **ModSecurity** CRS v4 plugin (`aipt-config.conf`, `aipt-before.conf`, ids 9590000-9590999). As shipped it is
  observe-only: every rule is `pass,log` and nothing adds an anomaly score, so the plugin never contributes to a CRS
  block. Scoring is opt-in per direction: switch 9590015 lets the product User-Agent rules 9590101, 9590103, 9590201,
  9590211 and 9590221 add the CRS critical inbound score; switch 9590013 does the same outbound for 9590401 (ARTEX
  console response). Response fingerprints need `SecResponseBodyAccess On` and
  `application/json` in `SecResponseBodyMimeType`; generic rules 9590301-9590304 run from paranoia level 2. The 404
  and no-User-Agent counters (switch 9590011) are idle-timeout accumulators, not windows, need a persistent collection
  backend and ship off. The block 9590000-9590999 is free in the CRS plugin registry but not yet registered there (registration is a
  pull request to `coreruleset/plugin-registry`); renumber if a later registrant takes it.
- **KQL / SPL** (`analytics/artex_behavior.*`): triage queries with fixed bins; the sliding-window alerts are
  `analytics/correlations.*`. Idle gap: with a hosted model (GLM-5.3, lab runs 01-03, LLM latency p50 6-20 s) `T`=30 s
  found 4-7 think-act cycles per 20-minute run and `T`=5 s 10-19; a CPU-bound local model makes every gap minutes
  long. Burst size and path or User-Agent counts depend on the tool mix and on the tools the model chooses.

Backend caveats found on real engines: Splunk lookups must be visible to the searching app (a private lookup silently
exempts nothing) and `proxy_villager_pypi_download` needs `c-uri-stem` mapped to a name without `-`; Elasticsearch
needs `ip`-typed address fields, keyword matching is case-sensitive, and ES|QL drops rows where a converted `not`
condition is null (use the Lucene output or the hand-written ES|QL). Kusto was checked with the language service and the
hand-written KQL plus the generated allowlist construct were reported as executed on Microsoft's Kusto emulator during internal testing;
malformed allowlist entries are reported as a data-quality row and ignored in `correlations.kql`; on the engine an
unparsable list entry does not change the verdict of the other entries, while the bare `ipv4_is_in_any_range` still
drops IPv6, missing and malformed client addresses (null), which the null-safe construct keeps.
The proxy rules use the taxonomy name `c-useragent`, which `splunk_cim`, `sentinel_asim` and `ecs_zeek_beats` map
(internal conversion tests); `cs-content-type` in `proxy_generic_llm_api_client` has no taxonomy equivalent and needs
a manual field mapping (Splunk CIM `http_content_type`, ASIM `HttpContentType`, ECS `http.request.mime_type`) before
that rule converts; `sentinel_asim` also lacks `c-uri-stem`. The web rules keep the SigmaHQ webserver field names
(`c-ip`, `cs-method`, `cs-uri-stem`, `cs-user-agent`, `sc-status`), which none of the three pipelines maps; for Sentinel
convert them with the plain `kusto` backend and `sigma/pipelines/aipt-webserver-asim.yaml` (ASIM WebSession column names,
output is the predicate to put after `imWebSession | where`). Internal testing covered generated User-Agent and path
predicates on the Kusto emulator. This adapter only renames fields: before using path rules, map `cs-uri-stem` to a column containing
only the request path, without the scheme, host or query string. Raw ASIM `Url` is not necessarily path-only, including
for WebServerSession and ApiRequest events. `web_artex_console_session_cookie` uses the optional `HttpCookie` field;
use it only where the header is already collected.

## Policy

Every rule carries one tier, measured on a 510,680-request synthetic benign corpus and the lab captures
([docs/fp-report.md](docs/fp-report.md)):

- `block-eligible`: product-specific indicator, 0 benign hits on the corpus; a candidate for local policy review, not
  a recommendation to convert the list. Suricata `metadata: policy`, listed in
  `suricata/aipt-block-eligible.sids` (36); Sigma `level: high`; the ModSecurity rules that score once switch 9590015
  or 9590013 is on. May be converted to drop
  after an observe-mode baseline on your own traffic; ships as alert. The five ARTEX conversation-marker sids
  (9500032, 9500033, 9500034, 9500071, 9500072) may be converted on an egress proxy only, never on an LLM gateway or
  chat proxy sensor: a conversation about the tool reproduces the indicator.
- `alert`: useful, needs context, never blocks. Residual benign sources are fixed and nameable (monitoring, partner
  pollers, batch jobs, gateways, crawlers): allow-list them.
- `informational`: inventory, hunting, correlation input.

Sanctioned assessments are exempted from the generic rules only, never from tool-specific ones: Sigma placeholders
`approved_assessment_sources` and `approved_assessment_user_agents` (source must match; a User-Agent alone never
exempts), the Suricata `threshold.config` template, and ModSecurity switch 9590012 with
`aipt-approved-assessment-sources.txt`. Nothing ships pre-filled.

## Noisy rules

Measured on the synthetic benign corpus (510,680 requests over 4 hours, [docs/fp-report.md](docs/fp-report.md)).
These rules fire on ordinary traffic by design; keep them out of the alert queue until the listed sources are
allow-listed or the placeholders are filled.

| rule | fires on | corpus hits |
|---|---|---|
| Sigma base selectors `web_aipt_*_base` | every request (correlation inputs) | 323,000-500,000 |
| Go-http-client User-Agent: `web_generic_go_http_client_user_agent`, ModSecurity 9590303, Suricata 9500010 | every Go client: batch jobs, monitoring, gateways, internal services | 29,004 (Suricata 517, throttled) |
| Headless Chromium: `web_generic_headless_chromium_user_agent`, 9590302, 9500007 | synthetic browser checks, Lighthouse, QA automation | 6,743 (Suricata 184) |
| `proxy_generic_llm_api_client` | every LLM API call until `llm_approved_clients` is filled | 3,447 |
| port-keyed MetasploitMCP SSE rules: `web_metasploitmcp_sse_or_msfrpcd_request`, 9590231, 9500267 (8085) | any FastMCP SSE server on 8085; MetasploitMCP binds 127.0.0.1 by default, so only exposed instances are visible | 522 |
| manifest probe: `web_generic_manifest_probe_no_referer`, 9590301, 9500006 | browsers on no-referrer sites, crawlers, PWA refreshes | 1,972 / 756 / 76 |
| generic MCP: 9500280-9500283, 9590304 | every developer MCP client, internal MCP servers | 854 (ModSecurity), 391 (Suricata) |
| `proc_creation_lnx_generic_playwright_mcp_headless` | QA automation hosts | 122 of 8,344 host events |
| correlations: identical request, distinct paths, request burst (informational: a cookie no longer exempts, so NAT offices and CGNAT reach the thresholds), 404 burst (alert) | partner pollers, batch jobs, crawlers, gateways, NAT offices, misconfigured clients | 373 / 382 / 219 / 160 windows |
| ModSecurity counters 9590312, 9590314 (off by default) | pollers without a User-Agent: an alert every 20 polls | - |

Everything in the table is `informational` or `alert` tier. Tool-specific `block-eligible` rules produced 0 hits on
the corpus.

## Validation

The table below summarises author-reported development checks. This public edition does not include the harnesses,
fixtures, corpora, execution logs or test CI, so these checks are not reproducible from a public checkout alone.
Publishing the rules separately does not add validation or change the scope of the previous results.

| evidence | reported scope | limits |
|---|---|---|
| rule-engine checks | Suricata 8.0.7 fixtures and synthetic corpus; OWASP CRS 4.30.0 nginx load, policy and header replay; YARA file and memory fixtures; syntax and conversion checks | internal tooling and logs are not distributed |
| custom Python matcher | 54 Sigma rules and 8 correlations over fixtures and the synthetic corpus | not a SIEM engine |
| Python emulation | think-act analytics and CIDR allowlist semantics | distinct from engine execution |
| development engine runs, not repeated for 1.0.0 | Splunk 10.6, Elasticsearch 8.19 and ModSecurity 2.9 persistent collections | historical results; backend and window differences are documented in `analytics/` and `sigma/correlation/README.md` |
| lab-capture replay with the 1.0.0 rules | ARTEX and CyberStrikeAI with GLM-5.3, benign browsing and a ZAP baseline | [method and aggregate results](docs/fp-report.md); captures and replay harness are not distributed |
| Kusto emulator | correlation regression, CIDR constructs and generated web predicates; Kusto language-service checks were separate | functional testing only; query cost under peak load was not measured |

Tool-specific target-facing signatures did not appear in every lab run. In the hosted-model ARTEX runs the model used
curl and Python commands rather than the built-in skills that emit those fingerprints. A ZAP baseline raised generic
scanner-shape rules without identifying an AI tool. Rules for HexStrike-AI, PentAGI, Strix, Shannon, MetasploitMCP,
PentestGPT, Decepticon and Villager were fixture-tested, not exercised in those lab runs.

The internal fixture set had positive cases for 49 of 82 Suricata sids, including 35 of 36 block-eligible sids.
Sid 9500060 (`filemd5`) had none and remains deferred in `suricata/aipt-block-eligible.sids`. Coverage is listed in
[RULES.md](RULES.md); it is not proof of safe blocking in another environment.

TP in the lab results means a hit from the attacker role's address, not identification of the specific tool.
Tiers, confidence and YARA scores are author judgements. Follow [DEPLOYMENT.md](DEPLOYMENT.md) before operational use.

## Contributing

Open a pull request and we review it. Bring the upstream source line or a sanitised capture excerpt, a positive and
a near-miss example, and a sentence on what the indicator does on ordinary traffic; the rest is in
[CONTRIBUTING.md](CONTRIBUTING.md). Conventions: Emerging Threats Open layout and `suricata-check` for Suricata,
SigmaHQ validators for Sigma, signature-base layout and `yaraQA` for YARA, CRS v4 plugin conventions for
ModSecurity. Include your validation commands, engine versions and results in the pull request; this public edition
has no bundled test runner or test CI.

## Ids and contact

Suricata sids 9500001-9500299 (ARTEX 00xx, CyberStrikeAI 20x, HexStrike-AI 22x, PentAGI 23x, Strix 24x, Shannon
25x, Villager 26x, MetasploitMCP 265-279, generic MCP 28x, scanner shapes 29x); ModSecurity 9590000-9590999;
Sigma uuid4 ids; YARA `AIPT_<Tool>_<What>`. Ids are never reused. The Suricata block overlaps no range listed at
sidallocation.org (nearest: 9555000, Wybot) and the Sigma ids, Sigma names and YARA rule names collide with nothing in
SigmaHQ and signature-base; the ModSecurity block collides with no registered CRS plugin.

Contributions: [CONTRIBUTING.md](CONTRIBUTING.md). False positives and evasions: [SECURITY.md](SECURITY.md), contact@xint.io.
Upstream commits read: ARTEX `e6ec569` (original repository removed; line references point to a mirror at the same
commit), CyberStrikeAI `edec607`, HexStrike-AI `d689933`, PentAGI `b611fbe`, Strix `4695290`, Shannon `2468b67`,
MetasploitMCP `afc792d`. Tool names identify the software the rules detect; this project is not affiliated with any
of them.
