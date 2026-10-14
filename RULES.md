# Rule index

Index of the published rule files. Keep it consistent when changing rules. The internal index generator and test CI are not distributed.

## Counts

| format | rules | notes |
|---|---|---|
| Suricata | 82 | sids in `suricata/aipt-*.rules`; retired sids are listed in [suricata/retired.rules](suricata/retired.rules) |
| Sigma | 54 | detection rules (14 informational base or supporting rules) |
| Sigma correlation | 8 | Sigma v2 correlations, `generate: false` on the base rules |
| YARA | 19 | public rules: 13 file rules (aipt_artex.yar, aipt_family.yar) and 6 memory-scan variants `*_Mem` (aipt_memory.yar) |
| ModSecurity | 24 | alerting rules; plus 13 plugin-control and counter rules and 6 switches that ship commented out (all listed below) |

## How to read this index

- **Blocking policy** (measured false-positive profile in `docs/fp-report.md`): `block-eligible` = a product-specific indicator with 0 hits on the benign corpus; a candidate for local policy review, which an operator may convert to drop/deny only after the observe-mode baseline of DEPLOYMENT.md (Suricata list: `suricata/aipt-block-eligible.sids`; ModSecurity: observe-only as shipped, the product User-Agent rules score only with switch 9590015, the ARTEX console response only with switch 9590013). `alert` = useful, needs context, never blocks. `informational` = inventory, hunting or correlation input. Sigma derives it from `level`.
- **Correlation base selectors**: the Sigma rules `web_aipt_*_base` are inputs of the correlations only. Never deploy them as stand-alone alerts (README, Format notes).
- **YARA scope**: the file rules use `filesize` (some also an executable header at offset 0) and match files and memory dumps saved as files, never a live process scan; the `*_Mem` rules in `yara/aipt_memory.yar` are the strings-only variants for live process scans.
- **How to read TP/FP** in the validation results (`docs/fp-report.md`): TP means the hit came from the address of the attacker role in that lab run, not that the rule identified the specific tool correctly; FP means a hit on the benign-browsing or other non-attacker traffic. Generic scanner-shape rules firing on the ZAP baseline are expected and labelled `scanner-shape (generic)`, not counted as FP. Levels, confidence and YARA scores are author judgements, not measured precision.

## Blocking policy

Rules per format and policy tier (alerting rules only; YARA is not tiered).

| format | block-eligible | alert | informational |
|---|---|---|---|
| Suricata | 36 | 36 | 10 |
| Sigma | 17 | 23 | 14 |
| Sigma correlation | 0 | 4 | 4 |
| ModSecurity | 6 | 13 | 5 |

## Coverage by tool

Number of rules per tool and format. `Generic` covers scanner-shape, behavioural and shared-component rules (go-mitmproxy, generic MCP, LLM API clients) that are not specific to one tool.

| tool | Suricata | Sigma | Sigma correlation | YARA | ModSecurity | total |
|---|---|---|---|---|---|---|
| ARTEX | 33 | 16 | - | 12 | 6 | 67 |
| CyberStrikeAI | 9 | 5 | - | 4 | 4 | 22 |
| HexStrike-AI | 7 | 3 | - | - | 3 | 13 |
| PentAGI | 4 | 3 | - | - | 2 | 9 |
| Strix | 2 | 3 | - | - | - | 5 |
| Shannon | 2 | 3 | - | - | - | 5 |
| MetasploitMCP | 5 | 4 | - | - | 1 | 10 |
| PentestGPT | - | 1 | - | - | - | 1 |
| Decepticon | - | 1 | - | - | - | 1 |
| Villager | 1 | 2 | - | - | - | 3 |
| Generic | 19 | 13 | 8 | 3 | 8 | 51 |
| **total** | 82 | 54 | 8 | 19 | 24 | 187 |

## Coverage by tool and log source

Number of rules per tool and deployment position (all formats; a correlation counts once per position of its base rules).

| tool | A. target web / WAF | B. egress / proxy / DNS | C. exposed console | D. operator host | E. LLM provider / relay |
|---|---|---|---|---|---|
| ARTEX | 9 | 7 | 17 | 20 | 14 |
| CyberStrikeAI | 3 | 3 | 9 | 6 | 1 |
| HexStrike-AI | 4 | - | 7 | 1 | 1 |
| PentAGI | 2 | 3 | 2 | 1 | 1 |
| Strix | - | 2 | - | 2 | 1 |
| Shannon | - | 2 | - | 2 | 1 |
| MetasploitMCP | - | - | 6 | 3 | 1 |
| PentestGPT | - | - | - | 1 | - |
| Decepticon | - | - | - | 1 | - |
| Villager | - | 2 | - | 1 | - |
| Generic | 38 | 4 | 5 | 4 | 1 |

## Rules by observation point

The five observation points of the whitepaper (chapter 5). A rule is listed where its evidence is collected; a correlation is listed under every point of its base rules. Format, id or name, policy tier.

### A. own web server, WAF and reverse-proxy logs

- Suricata `9500001`: AIPT ARTEX Enrichment Prober User-Agent (artex-enrich) (ARTEX; block-eligible)
- Suricata `9500002`: AIPT ARTEX Norma SDK WebFetch User-Agent (norma) (ARTEX; alert)
- Suricata `9500004`: AIPT ARTEX api-recon Skill Script User-Agent (spa-api-recon) (ARTEX; block-eligible)
- Suricata `9500006`: AIPT Generic Web App Manifest Probe Without Referer (Generic; informational)
- Suricata `9500007`: AIPT Generic Headless Chromium User-Agent (browser automation) (Generic; informational)
- Suricata `9500008`: AIPT Generic HTTP 404 Burst to Single Client (path enumeration) (Generic; alert)
- Suricata `9500010`: AIPT Generic Go-http-client Default User-Agent (Go agent tooling) (Generic; informational)
- Suricata `9500110`: AIPT Scanner Nmap Scripting Engine User-Agent (Generic; alert)
- Suricata `9500207`: AIPT CyberStrikeAI WebShell Manager User-Agent (CyberStrikeAI; block-eligible)
- Suricata `9500223`: AIPT HexStrike-AI HTTP Framework User-Agent (HexStrike-AI; block-eligible)
- Suricata `9500224`: AIPT HexStrike-AI Exploit Helper User-Agent (Compatible Exploit) (HexStrike-AI; block-eligible)
- Suricata `9500290`: AIPT Scanner nuclei Default User-Agent (Chrome/87.0.4280.88) (Generic; alert)
- Suricata `9500291`: AIPT Scanner nuclei Project User-Agent (Generic; alert)
- Suricata `9500292`: AIPT Scanner ffuf User-Agent (Fuzz Faster U Fool) (Generic; alert)
- Suricata `9500293`: AIPT Scanner sqlmap User-Agent (Generic; alert)
- Suricata `9500294`: AIPT Scanner gobuster User-Agent (Generic; alert)
- Suricata `9500295`: AIPT Scanner Nikto User-Agent (Generic; alert)
- Suricata `9500297`: AIPT Scanner Burst of Requests With Empty User-Agent (Generic; alert)
- Suricata `9500299`: AIPT Scanner Burst of Requests Without User-Agent Header (Generic; alert)
- Sigma `web_aipt_empty_user_agent_base`: HTTP Request Without User-Agent Base Rule for AIPT Correlations (Generic; informational)
- Sigma `web_aipt_http_404_base`: HTTP 404 Response Base Rule for AIPT Correlations (Generic; informational)
- Sigma `web_aipt_http_request_anonymous_base`: Anonymous HTTP Request to a Non-Static Path Base Rule for AIPT Correlations (Generic; informational)
- Sigma `web_aipt_http_request_base`: HTTP Request Base Rule for AIPT Correlations (Generic; informational)
- Sigma `web_aipt_http_request_non_static_base`: HTTP Request to a Non-Static Path Base Rule for AIPT Correlations (Generic; informational)
- Sigma `web_artex_api_recon_user_agent`: ARTEX API Recon Skill Script User-Agent (ARTEX; block-eligible)
- Sigma `web_artex_enrich_user_agent`: ARTEX Asset Enrichment Prober User-Agent (ARTEX; block-eligible)
- Sigma `web_artex_norma_webfetch_user_agent`: ARTEX Norma SDK WebFetch User-Agent (ARTEX; alert)
- Sigma `web_cyberstrikeai_user_agent`: CyberStrikeAI Client or WebShell Manager User-Agent (CyberStrikeAI; block-eligible)
- Sigma `web_generic_go_http_client_user_agent`: Go Default HTTP Client User-Agent (Generic; informational)
- Sigma `web_generic_headless_chromium_user_agent`: Headless Chromium User-Agent (Generic; informational)
- Sigma `web_generic_manifest_probe_no_referer`: Web App Manifest Requested Without Referer (Generic; informational)
- Sigma `web_generic_nmap_nse_user_agent`: Nmap Scripting Engine User-Agent (Generic; alert)
- Sigma `web_generic_scanner_user_agents`: Web Scanner User-Agents Used by AI Pentest Tools (Generic; alert)
- Sigma `web_hexstrike_user_agent`: HexStrike-AI HTTP Framework or Exploit User-Agent (HexStrike-AI; block-eligible)
- Sigma `web_pentagi_searcher_user_agent`: PentAGI Searcher User-Agent (PentAGI; block-eligible)
- Sigma correlation `correlation_aipt_distinct_paths_per_minute`: Many Distinct Non-Static URL Paths From a Single Client Per Minute (Generic; informational)
- Sigma correlation `correlation_aipt_empty_user_agent_burst`: Burst of Requests Without User-Agent From a Single Client (Generic; alert)
- Sigma correlation `correlation_aipt_http_404_burst`: HTTP 404 Burst From a Single Client (Generic; alert)
- Sigma correlation `correlation_aipt_identical_request_repeat`: Identical HTTP Request Repeated by a Single Client (Generic; informational)
- Sigma correlation `correlation_aipt_llm_call_then_target_requests`: LLM API Call Followed by a Request Burst From the Same Host (Generic; alert)
- Sigma correlation `correlation_aipt_request_burst`: HTTP Request Burst From a Single Client (Generic; informational)
- Sigma correlation `correlation_aipt_user_agent_diversity`: Several User-Agents Receiving 404 From a Single Client Within 10 Minutes (Generic; informational)
- Sigma correlation `correlation_aipt_user_agent_rotation`: Scanner-Grade User-Agent Rotation Among 404 Responses From a Single Client (Generic; alert)
- ModSecurity `9590101`: ARTEX enrichment prober User-Agent (ARTEX; block-eligible)
- ModSecurity `9590102`: ARTEX norma SDK WebFetch User-Agent (ARTEX; alert)
- ModSecurity `9590103`: ARTEX api-recon skill script User-Agent (ARTEX; block-eligible)
- ModSecurity `9590201`: CyberStrikeAI client or WebShell manager User-Agent (CyberStrikeAI; block-eligible)
- ModSecurity `9590211`: HexStrike-AI User-Agent (HexStrike-AI; block-eligible)
- ModSecurity `9590221`: PentAGI searcher User-Agent (PentAGI; block-eligible)
- ModSecurity `9590301`: Generic web app manifest probe without Referer (Generic; informational)
- ModSecurity `9590302`: Generic headless Chromium User-Agent (Generic; informational)
- ModSecurity `9590303`: Generic Go-http-client default User-Agent (Generic; informational)
- ModSecurity `9590305`: Scanner nuclei default User-Agent (Generic; alert)
- ModSecurity `9590306`: Scanner User-Agent (nuclei, ffuf, sqlmap, gobuster, Nikto) (Generic; alert)
- ModSecurity `9590312`: Generic 404 accumulation from one client (idle-timeout counter, path enumeration) (Generic; alert)
- ModSecurity `9590314`: Scanner accumulation of requests without User-Agent (idle-timeout counter) (Generic; alert)

### B. egress, proxy, DNS and firewall logs

- Suricata `9500020`: AIPT ARTEX Self-Update User-Agent (artex-selfupdate) (ARTEX; block-eligible)
- Suricata `9500021`: AIPT ARTEX Self-Update GitHub Release Check (ARTEX; block-eligible)
- Suricata `9500022`: AIPT ARTEX Self-Update Release Asset Download (ARTEX; alert)
- Suricata `9500038`: AIPT Generic go-mitmproxy Leaf Certificate (Generic; informational)
- Suricata `9500042`: AIPT ARTEX Norma web_search DuckDuckGo HTML Scrape (ARTEX; alert)
- Suricata `9500045`: AIPT ARTEX ScopeSentry MCP API Key Header (ssk_) (ARTEX; alert)
- Suricata `9500206`: AIPT CyberStrikeAI Client User-Agent (CyberStrikeAI; block-eligible)
- Suricata `9500212`: AIPT CyberStrikeAI HITL Judge Backend TLS SNI (api .typesafe .ai) (CyberStrikeAI; alert)
- Suricata `9500230`: AIPT PentAGI Searcher User-Agent (PentAGI; block-eligible)
- Suricata `9500233`: AIPT PentAGI Container Image Pull (vxcontrol) (PentAGI; alert)
- Suricata `9500241`: AIPT Strix Sandbox Image Pull (usestrix/strix-sandbox) (Strix; alert)
- Suricata `9500253`: AIPT Shannon Worker Image Pull (keygraph/shannon) (Shannon; alert)
- Suricata `9500260`: AIPT Villager PyPI Package Download (Villager; alert)
- Sigma `proxy_artex_norma_duckduckgo_html_scrape`: ARTEX Norma web_search DuckDuckGo HTML Scrape (ARTEX; informational)
- Sigma `proxy_artex_selfupdate_github`: ARTEX Self-Update Check or Release Download (ARTEX; block-eligible)
- Sigma `proxy_cyberstrikeai_operator_egress`: CyberStrikeAI Client User-Agent or TypeSafe Judge API Request (CyberStrikeAI; alert)
- Sigma `proxy_generic_llm_api_client`: LLM API Request From a Host Not Approved for LLM Use (Generic; informational)
- Sigma `proxy_pentagi_searcher_or_image_pull`: PentAGI Searcher User-Agent or Sandbox Image Pull (PentAGI; alert)
- Sigma `proxy_shannon_package_or_image_fetch`: Shannon CLI Package or Worker Image Fetch (Shannon; alert)
- Sigma `proxy_strix_sandbox_image_pull`: Strix Sandbox Image Pull (Strix; alert)
- Sigma `proxy_villager_pypi_download`: Villager PyPI Package Download (Villager; alert)
- Sigma `zeek_generic_go_mitmproxy_certificate`: TLS Certificate Issued by a Mitmproxy CA (Generic; informational)
- Sigma correlation `correlation_aipt_llm_call_then_target_requests`: LLM API Call Followed by a Request Burst From the Same Host (Generic; alert)

### C. perimeter sensors and threat intelligence (tool consoles and APIs exposed on a network)

- Suricata `9500050`: AIPT ARTEX Control Plane Health Response (service artex) (ARTEX; block-eligible)
- Suricata `9500051`: AIPT ARTEX Control Plane Auth Status Response (initialized flag, known console) (ARTEX; alert)
- Suricata `9500052`: AIPT ARTEX Control Plane 401 Error Body (ARTEX; alert)
- Suricata `9500053`: AIPT ARTEX Web Console HTML Title (ARTEX; block-eligible)
- Suricata `9500055`: AIPT ARTEX Console Session Cookie (artex_token) (ARTEX; block-eligible)
- Suricata `9500056`: AIPT ARTEX Console JWT With Subject ARTEX (ARTEX; block-eligible)
- Suricata `9500057`: AIPT ARTEX Console First-Run Initialisation (POST /api/auth/init) (ARTEX; alert)
- Suricata `9500058`: AIPT ARTEX Console API Use (exploration, intercept, sync routes) (ARTEX; alert)
- Suricata `9500059`: AIPT ARTEX Server Log Line in HTTP Response (backend listening on) (ARTEX; block-eligible)
- Suricata `9500060`: AIPT ARTEX Web Console Static Asset by MD5 (favicon or logo) (ARTEX; block-eligible)
- Suricata `9500061`: AIPT ARTEX Console Login With Fixed Username ARTEX (ARTEX; block-eligible)
- Suricata `9500103`: AIPT CyberStrikeAI Console API Use (agent, HITL, WebShell, CnC routes) (CyberStrikeAI; alert)
- Suricata `9500200`: AIPT CyberStrikeAI Console HTML Title (CyberStrikeAI; block-eligible)
- Suricata `9500201`: AIPT CyberStrikeAI API Docs Page Title (CyberStrikeAI; block-eligible)
- Suricata `9500202`: AIPT CyberStrikeAI OpenAPI Spec Title (CyberStrikeAI; block-eligible)
- Suricata `9500208`: AIPT CyberStrikeAI MCP Server Auth Header (X-MCP-Token) (CyberStrikeAI; alert)
- Suricata `9500220`: AIPT HexStrike-AI API Server Health Response (HexStrike-AI; block-eligible)
- Suricata `9500221`: AIPT HexStrike-AI Command or File API Request (8888) (HexStrike-AI; alert)
- Suricata `9500222`: AIPT HexStrike-AI Tool Wrapper API Request (8888) (HexStrike-AI; alert)
- Suricata `9500225`: AIPT HexStrike-AI MCP Server Name in JSON-RPC Response (HexStrike-AI; alert)
- Suricata `9500231`: AIPT PentAGI Web UI HTML Title (PentAGI; block-eligible)
- Suricata `9500265`: AIPT MetasploitMCP msfrpcd RPC Over Plaintext HTTP (55553) (MetasploitMCP; alert)
- Suricata `9500266`: AIPT MetasploitMCP Default msfrpcd Password in RPC Login (MetasploitMCP; block-eligible)
- Suricata `9500267`: AIPT MetasploitMCP MCP SSE Endpoint Request (8085) (MetasploitMCP; informational)
- Suricata `9500268`: AIPT MetasploitMCP MCP tools/call of a Metasploit Tool (MetasploitMCP; block-eligible)
- Suricata `9500280`: AIPT Generic MCP JSON-RPC tools/call Over HTTP (non-standard port) (Generic; informational)
- Suricata `9500281`: AIPT Generic MCP JSON-RPC tools/list Over HTTP (non-standard port) (Generic; informational)
- Suricata `9500282`: AIPT Generic MCP Streamable-HTTP Session Headers (non-standard port) (Generic; informational)
- Suricata `9500283`: AIPT Generic MCP SSE Endpoint Event (Generic; informational)
- Sigma `web_artex_console_auth_endpoints`: ARTEX Console Auth Status or First-Run Init Request (ARTEX; informational)
- Sigma `web_artex_console_routes`: ARTEX Console-Specific API or UI Route Access (ARTEX; alert)
- Sigma `web_artex_console_session_cookie`: ARTEX Console Session Cookie Presented (ARTEX; block-eligible)
- Sigma `web_cyberstrikeai_console_routes`: CyberStrikeAI Console API Route Access (CyberStrikeAI; alert)
- Sigma `web_hexstrike_api_server_request`: HexStrike-AI Unauthenticated API Server Request (HexStrike-AI; alert)
- Sigma `web_metasploitmcp_sse_or_msfrpcd_request`: MetasploitMCP SSE Transport or Metasploit RPC Request (MetasploitMCP; alert)
- ModSecurity `9590104`: ARTEX console session cookie (ARTEX; alert)
- ModSecurity `9590105`: ARTEX console JWT with subject ARTEX (ARTEX; alert)
- ModSecurity `9590202`: CyberStrikeAI console API route (CyberStrikeAI; alert)
- ModSecurity `9590203`: CyberStrikeAI MCP auth header X-MCP-Token (CyberStrikeAI; alert)
- ModSecurity `9590212`: HexStrike-AI command, file or tool API request on 8888 (HexStrike-AI; alert)
- ModSecurity `9590231`: MetasploitMCP SSE endpoint request on 8085 (MetasploitMCP; informational)
- ModSecurity `9590304`: Generic MCP Streamable-HTTP header (Generic; informational)
- ModSecurity `9590401`: ARTEX console served behind this WAF (health response) (ARTEX; block-eligible)
- ModSecurity `9590402`: CyberStrikeAI console served behind this WAF (CyberStrikeAI; alert)
- ModSecurity `9590403`: HexStrike-AI API server behind this WAF (HexStrike-AI; alert)
- ModSecurity `9590404`: PentAGI UI served behind this WAF (PentAGI; alert)

### D. compromised or seized hosts

- Sigma `file_event_lnx_artex_cmd_output_spill`: ARTEX Worker Command Output Spill File (ARTEX; block-eligible)
- Sigma `file_event_lnx_artex_jwt_key`: ARTEX Console JWT Signing Key Created (ARTEX; alert)
- Sigma `file_event_lnx_artex_recording_proxy_ca`: ARTEX Recording Proxy CA or Traffic Index Written (ARTEX; alert)
- Sigma `file_event_lnx_artex_selfupdate_staging`: ARTEX Self-Update Staging Files Written (ARTEX; block-eligible)
- Sigma `file_event_lnx_artex_transcript_files`: ARTEX Agent Transcript File Written (ARTEX; block-eligible)
- Sigma `file_event_lnx_cyberstrikeai_lock_or_c2_artefact`: CyberStrikeAI Cgroup Lock File or C2 Artefact Written (CyberStrikeAI; block-eligible)
- Sigma `file_event_lnx_metasploitmcp_payload_dir`: MetasploitMCP Payload Written to Default Save Directory (MetasploitMCP; informational)
- Sigma `file_event_lnx_shannon_home_directory`: Shannon Configuration or Workspace File Written (Shannon; alert)
- Sigma `file_event_lnx_strix_run_directory`: Strix Run Directory Written (Strix; alert)
- Sigma `net_connection_lnx_metasploitmcp_msfrpcd`: Python Process Connecting to Metasploit RPC Port 55553 (MetasploitMCP; alert)
- Sigma `proc_creation_lnx_artex_child_process`: Shell or Attack Tool Spawned by ARTEX (ARTEX; block-eligible)
- Sigma `proc_creation_lnx_artex_server_binary`: ARTEX Server Binary Execution (ARTEX; block-eligible)
- Sigma `proc_creation_lnx_artex_tool_env_proxy_injection`: ARTEX Recording Proxy and CA Bundle Injected Into Tool Environment (ARTEX; block-eligible)
- Sigma `proc_creation_lnx_cyberstrikeai_server_or_child`: CyberStrikeAI Server Binary or Its Tool Children (CyberStrikeAI; block-eligible)
- Sigma `proc_creation_lnx_decepticon_mcp_server`: Decepticon MCP Server or Docker Network (Decepticon; alert)
- Sigma `proc_creation_lnx_generic_playwright_mcp_headless`: Playwright MCP Server or Playwright CLI Started Headless (Generic; informational)
- Sigma `proc_creation_lnx_hexstrike_server_or_mcp`: HexStrike-AI Server or MCP Client Started (HexStrike-AI; block-eligible)
- Sigma `proc_creation_lnx_metasploitmcp_server`: MetasploitMCP Server or Metasploit RPC Daemon With Default Password (MetasploitMCP; block-eligible)
- Sigma `proc_creation_lnx_pentagi_docker_image`: PentAGI Image or Container on the Docker CLI (PentAGI; alert)
- Sigma `proc_creation_lnx_pentestgpt_cli`: PentestGPT CLI Execution (PentestGPT; alert)
- Sigma `proc_creation_lnx_shannon_components`: Shannon Temporal Container, Worker or CLI (Shannon; alert)
- Sigma `proc_creation_lnx_strix_cli_or_sandbox`: Strix CLI or Sandbox Image (Strix; alert)
- Sigma `proc_creation_lnx_villager_pip_install`: Villager Package Installed With Pip (Villager; alert)
- YARA `AIPT_ARTEX_Go_Binary`: Detects the ARTEX backend Go binary (module github.com/Autumn-27/artex) by its enrichment and self-update User-Agents, release URL, session-id formats and listen banner (ARTEX; score 85)
- YARA `AIPT_ARTEX_Embedded_WebUI`: Detects the ARTEX web console (embedded in the binary or as the exported Next.js site) by its HTML title, meta description, login and disclaimer strings and session cookie name (ARTEX; score 75)
- YARA `AIPT_ARTEX_LLM_Prompt_Markers`: Detects short fixed markers that ARTEX writes into its LLM conversations (guard block tag, worker chat marker, intent block header, goals decomposer role, connection test, output contract heading) in transcripts, LLM record dumps, relay logs or the binary; raw UTF-8 or JSON \\uXXXX-escaped (ARTEX; score 70)
- YARA `AIPT_ARTEX_LLM_Tool_Schema`: Detects the ARTEX planner and worker tool names serialised as an LLM function schema, plain or JSON-escaped inside a record (LLM request records, relay logs, transcripts), compact or with up to four whitespace characters after the colon, or present together in the binary. Names written as \\uXXXX escapes are not matched (ARTEX; score 70)
- YARA `AIPT_ARTEX_Transcript_File`: Detects ARTEX agent transcripts and LLM record exports: JSON lines whose session_id has an ARTEX session name (exp<N>-worker-i<M>, -planner, -main, -main-s<K>, -goals, -compactor, -btw-<id>, or conv-<N>; the same list as the Sigma file rule file_event_lnx_artex_transcript_files) together with an ARTEX tool name (ARTEX; score 80)
- YARA `AIPT_ARTEX_ApiRecon_Skill_Scripts`: Detects the reference scripts of the ARTEX api-recon skill (harvest_static.py, spider_mpa.py, preload.js, runtime_harvest.js) by their User-Agent constants or preload globals (ARTEX; score 75)
- YARA `AIPT_ARTEX_Supervisor_Script`: Detects the ARTEX start.sh supervisor that relaunches the binary after a self-update (exit code 75) (ARTEX; score 65)
- YARA `AIPT_Norma_SDK_Go_Binary`: Detects a Go binary built on the norma agent SDK (github.com/Autumn-27/norma), which ARTEX uses; any other norma-based agent matches too (ARTEX; score 50)
- YARA `AIPT_GoMitmproxy_Embedded_Recorder`: Detects a Go binary embedding go-mitmproxy together with its CA file names, as the ARTEX traffic recorder does; every go-mitmproxy consumer matches (Generic; score 40)
- YARA `AIPT_GoMitmproxy_CA_Certificate_PEM`: Detects a PEM certificate whose DER name is O=mitmproxy, CN=mitmproxy encoded as PrintableString, the CA that go-mitmproxy generates (ARTEX writes it to data/traffic/_ca/). Matches the base64 body at all three alignments and across PEM line breaks; standalone go-mitmproxy CAs match too (Generic; score 40)
- YARA `AIPT_CyberStrikeAI_Go_Binary`: Detects the CyberStrikeAI server binary by its module path, client and WebShell-manager User-Agents, cgroup lock name, MCP auth header and the Eino agent framework (CyberStrikeAI; score 85)
- YARA `AIPT_CyberStrikeAI_Prompt_Strings`: Detects the CyberStrikeAI authorization-suppression block of its default agent prompt in the binary, agent definition files or exported conversations (both short fragments required, raw UTF-8 or both JSON \\uXXXX-escaped) (CyberStrikeAI; score 60)
- YARA `AIPT_Generic_LLM_Agent_Go_Binary`: Hunting rule for Go binaries that call an LLM API with function tools (chat-completions or messages path, provider header, tool-call fields); matches ARTEX, CyberStrikeAI and many benign LLM clients (Generic; score 30)
- YARA `AIPT_ARTEX_Go_Binary_Mem`: Memory-safe variant of AIPT_ARTEX_Go_Binary (strings only, no filesize or header check) for live process scans. Detects the ARTEX backend Go binary (module github.com/Autumn-27/artex) by its enrichment and self-update User-Agents, release URL, session-id formats and listen banner (ARTEX; score 75)
- YARA `AIPT_ARTEX_LLM_Tool_Schema_Mem`: Memory-safe variant of AIPT_ARTEX_LLM_Tool_Schema (strings only, no filesize or header check) for live process scans. Detects the ARTEX planner and worker tool names serialised as an LLM function schema, plain or JSON-escaped inside a record (LLM request records, relay logs, transcripts), compact or with up to four whitespace characters after the colon, or present together in the binary. Names written as \\uXXXX escapes are not matched (ARTEX; score 60)
- YARA `AIPT_ARTEX_LLM_Prompt_Markers_Mem`: Memory-safe variant of AIPT_ARTEX_LLM_Prompt_Markers (strings only, no filesize or header check) for live process scans. Detects short fixed markers that ARTEX writes into its LLM conversations (guard block tag, worker chat marker, intent block header, goals decomposer role, connection test, output contract heading) in transcripts, LLM record dumps, relay logs or the binary (ARTEX; score 60)
- YARA `AIPT_Norma_SDK_Go_Binary_Mem`: Memory-safe variant of AIPT_Norma_SDK_Go_Binary (strings only, no filesize or header check) for live process scans. Detects a Go binary built on the norma agent SDK (github.com/Autumn-27/norma), which ARTEX uses; any other norma-based agent matches too (ARTEX; score 40)
- YARA `AIPT_CyberStrikeAI_Go_Binary_Mem`: Memory-safe variant of AIPT_CyberStrikeAI_Go_Binary (strings only, no filesize or header check) for live process scans. Detects the CyberStrikeAI server binary by its module path, client and WebShell-manager User-Agents, cgroup lock name, MCP auth header and the Eino agent framework (CyberStrikeAI; score 75)
- YARA `AIPT_CyberStrikeAI_Prompt_Strings_Mem`: Memory-safe variant of AIPT_CyberStrikeAI_Prompt_Strings (strings only, no filesize or header check) for live process scans. Detects the CyberStrikeAI authorization-suppression block of its default agent prompt in the binary, agent definition files or exported conversations (both short fragments required) (CyberStrikeAI; score 50)

### E. LLM provider and relay proxy

- Suricata `9500023`: AIPT ARTEX Planner LLM Request (graph_overview, add_intent, prove_goal tools) (ARTEX; block-eligible)
- Suricata `9500024`: AIPT ARTEX Worker LLM Request (record_fact, report_finding, insert_assets tools) (ARTEX; block-eligible)
- Suricata `9500025`: AIPT ARTEX LLM Request With Traffic Recorder Tools (traffic_search, traffic_get, traffic_blob) (ARTEX; block-eligible)
- Suricata `9500026`: AIPT ARTEX Goals Decomposer LLM Request (set_goals, set_constraints, add_task_scope tools) (ARTEX; block-eligible)
- Suricata `9500030`: AIPT ARTEX LLM Profile Connection Test Request (ARTEX; alert)
- Suricata `9500032`: AIPT ARTEX Guard Block Marker in LLM Request (ARTEX; block-eligible)
- Suricata `9500033`: AIPT ARTEX Worker Chat Marker in LLM Request (ARTEX_WORKER_CHAT) (ARTEX; block-eligible)
- Suricata `9500034`: AIPT ARTEX Worker Intent Block Header in LLM Request (ARTEX; block-eligible)
- Suricata `9500035`: AIPT ARTEX Norma SDK Agent LLM Request (SearchExtraTools, ExecuteExtraTool) (ARTEX; alert)
- Suricata `9500036`: AIPT ARTEX Tool Call in LLM Response (OpenAI tool_calls) (ARTEX; alert)
- Suricata `9500037`: AIPT Generic Go LLM Agent chat/completions Request With Function Tools (Generic; informational)
- Suricata `9500047`: AIPT ARTEX Tool Call in LLM Response (Anthropic tool_use) (ARTEX; alert)
- Suricata `9500070`: AIPT ARTEX LLM Profile Connection Test Request (JSON unicode-escaped) (ARTEX; alert)
- Suricata `9500071`: AIPT ARTEX Guard Block Marker in LLM Request (JSON unicode-escaped) (ARTEX; block-eligible)
- Suricata `9500072`: AIPT ARTEX Worker Intent Block Header in LLM Request (JSON unicode-escaped) (ARTEX; block-eligible)
- Suricata `9500209`: AIPT CyberStrikeAI LLM Request (tool_search with built-in tool set) (CyberStrikeAI; block-eligible)
- Suricata `9500226`: AIPT HexStrike-AI MCP Tool Set in LLM Request (HexStrike-AI; alert)
- Suricata `9500234`: AIPT PentAGI Agent Tool Set in LLM Request (PentAGI; block-eligible)
- Suricata `9500242`: AIPT Strix Agent Tool Set in LLM Request (Strix; block-eligible)
- Suricata `9500252`: AIPT Shannon Pipeline Collector Tool in LLM Request (Shannon; alert)
- Suricata `9500269`: AIPT MetasploitMCP Tool Set in LLM Request (MetasploitMCP; block-eligible)

## Reported internal Suricata fixture coverage

Author-reported coverage of the internal synthetic HTTP fixture set. The fixtures, generator and execution logs are not distributed, so this public tree cannot reproduce the checks. A sid without a positive case has no coverage from that fixture set; lab captures and the false-positive corpus are separate evidence.

- 49 of 82 sids have a positive pcap fixture (84 cases); block-eligible: 35 of 36.
- Without one: `9500002`, `9500007`, `9500008`, `9500010`, `9500022`, `9500038`, `9500045`, `9500052`, `9500057`, `9500058`, `9500060` (block-eligible), `9500103`, `9500110`, `9500208`, `9500212`, `9500221`, `9500222`, `9500226`, `9500233`, `9500241`, `9500252`, `9500253`, `9500260`, `9500280`, `9500281`, `9500282`, `9500283`, `9500290`, `9500291`, `9500292`, `9500293`, `9500294`, `9500295`.
- Not coverable by the pcap generator (HTTP only): TLS rules and `filemd5` rules. A block-eligible sid without a positive fixture is listed as deferred in `suricata/aipt-block-eligible.sids` and is not converted to drop until validated.

## Suricata

Confidence and `signature_severity` come from each rule's `metadata`.

| sid | msg | tool | log source | confidence / severity | policy | file |
|---|---|---|---|---|---|---|
| 9500001 | AIPT ARTEX Enrichment Prober User-Agent (artex-enrich) | ARTEX | target web / WAF (http) | High / Major | block-eligible | [suricata/aipt-target-facing.rules](suricata/aipt-target-facing.rules) |
| 9500002 | AIPT ARTEX Norma SDK WebFetch User-Agent (norma) | ARTEX | target web / WAF (http) | Medium / Minor | alert | [suricata/aipt-target-facing.rules](suricata/aipt-target-facing.rules) |
| 9500004 | AIPT ARTEX api-recon Skill Script User-Agent (spa-api-recon) | ARTEX | target web / WAF (http) | High / Major | block-eligible | [suricata/aipt-target-facing.rules](suricata/aipt-target-facing.rules) |
| 9500006 | AIPT Generic Web App Manifest Probe Without Referer | Generic | target web / WAF (http) | Low / Informational | informational | [suricata/aipt-target-facing.rules](suricata/aipt-target-facing.rules) |
| 9500007 | AIPT Generic Headless Chromium User-Agent (browser automation) | Generic | target web / WAF (http) | Low / Informational | informational | [suricata/aipt-target-facing.rules](suricata/aipt-target-facing.rules) |
| 9500008 | AIPT Generic HTTP 404 Burst to Single Client (path enumeration) | Generic | target web / WAF (http) | Medium / Minor | alert | [suricata/aipt-target-facing.rules](suricata/aipt-target-facing.rules) |
| 9500010 | AIPT Generic Go-http-client Default User-Agent (Go agent tooling) | Generic | target web / WAF (http) | Low / Informational | informational | [suricata/aipt-target-facing.rules](suricata/aipt-target-facing.rules) |
| 9500020 | AIPT ARTEX Self-Update User-Agent (artex-selfupdate) | ARTEX | egress / proxy / DNS (http) | High / Major | block-eligible | [suricata/aipt-operator-egress.rules](suricata/aipt-operator-egress.rules) |
| 9500021 | AIPT ARTEX Self-Update GitHub Release Check | ARTEX | egress / proxy / DNS (http) | High / Major | block-eligible | [suricata/aipt-operator-egress.rules](suricata/aipt-operator-egress.rules) |
| 9500022 | AIPT ARTEX Self-Update Release Asset Download | ARTEX | egress / proxy / DNS (http) | Medium / Minor | alert | [suricata/aipt-operator-egress.rules](suricata/aipt-operator-egress.rules) |
| 9500023 | AIPT ARTEX Planner LLM Request (graph_overview, add_intent, prove_goal tools) | ARTEX | LLM provider / relay (http) | High / Major | block-eligible | [suricata/aipt-llm-side.rules](suricata/aipt-llm-side.rules) |
| 9500024 | AIPT ARTEX Worker LLM Request (record_fact, report_finding, insert_assets tools) | ARTEX | LLM provider / relay (http) | High / Major | block-eligible | [suricata/aipt-llm-side.rules](suricata/aipt-llm-side.rules) |
| 9500025 | AIPT ARTEX LLM Request With Traffic Recorder Tools (traffic_search, traffic_get, traffic_blob) | ARTEX | LLM provider / relay (http) | High / Major | block-eligible | [suricata/aipt-llm-side.rules](suricata/aipt-llm-side.rules) |
| 9500026 | AIPT ARTEX Goals Decomposer LLM Request (set_goals, set_constraints, add_task_scope tools) | ARTEX | LLM provider / relay (http) | High / Major | block-eligible | [suricata/aipt-llm-side.rules](suricata/aipt-llm-side.rules) |
| 9500030 | AIPT ARTEX LLM Profile Connection Test Request | ARTEX | LLM provider / relay (http) | Medium / Minor | alert | [suricata/aipt-llm-side.rules](suricata/aipt-llm-side.rules) |
| 9500032 | AIPT ARTEX Guard Block Marker in LLM Request | ARTEX | LLM provider / relay (http) | High / Major | block-eligible | [suricata/aipt-llm-side.rules](suricata/aipt-llm-side.rules) |
| 9500033 | AIPT ARTEX Worker Chat Marker in LLM Request (ARTEX_WORKER_CHAT) | ARTEX | LLM provider / relay (http) | High / Major | block-eligible | [suricata/aipt-llm-side.rules](suricata/aipt-llm-side.rules) |
| 9500034 | AIPT ARTEX Worker Intent Block Header in LLM Request | ARTEX | LLM provider / relay (http) | High / Major | block-eligible | [suricata/aipt-llm-side.rules](suricata/aipt-llm-side.rules) |
| 9500035 | AIPT ARTEX Norma SDK Agent LLM Request (SearchExtraTools, ExecuteExtraTool) | ARTEX | LLM provider / relay (http) | Medium / Minor | alert | [suricata/aipt-llm-side.rules](suricata/aipt-llm-side.rules) |
| 9500036 | AIPT ARTEX Tool Call in LLM Response (OpenAI tool_calls) | ARTEX | LLM provider / relay (http) | High / Major | alert | [suricata/aipt-llm-side.rules](suricata/aipt-llm-side.rules) |
| 9500037 | AIPT Generic Go LLM Agent chat/completions Request With Function Tools | Generic | LLM provider / relay (http) | Low / Informational | informational | [suricata/aipt-llm-side.rules](suricata/aipt-llm-side.rules) |
| 9500038 | AIPT Generic go-mitmproxy Leaf Certificate | Generic | egress / proxy / DNS (tls) | Medium / Minor | informational | [suricata/aipt-operator-egress.rules](suricata/aipt-operator-egress.rules) |
| 9500042 | AIPT ARTEX Norma web_search DuckDuckGo HTML Scrape | ARTEX | egress / proxy / DNS (http) | Medium / Minor | alert | [suricata/aipt-operator-egress.rules](suricata/aipt-operator-egress.rules) |
| 9500045 | AIPT ARTEX ScopeSentry MCP API Key Header (ssk_) | ARTEX | egress / proxy / DNS (http) | Medium / Minor | alert | [suricata/aipt-operator-egress.rules](suricata/aipt-operator-egress.rules) |
| 9500047 | AIPT ARTEX Tool Call in LLM Response (Anthropic tool_use) | ARTEX | LLM provider / relay (http) | High / Major | alert | [suricata/aipt-llm-side.rules](suricata/aipt-llm-side.rules) |
| 9500050 | AIPT ARTEX Control Plane Health Response (service artex) | ARTEX | exposed console (http) | High / Major | block-eligible | [suricata/aipt-exposed-console.rules](suricata/aipt-exposed-console.rules) |
| 9500051 | AIPT ARTEX Control Plane Auth Status Response (initialized flag, known console) | ARTEX | exposed console (http) | High / Minor | alert | [suricata/aipt-exposed-console.rules](suricata/aipt-exposed-console.rules) |
| 9500052 | AIPT ARTEX Control Plane 401 Error Body | ARTEX | exposed console (http) | Low / Informational | alert | [suricata/aipt-exposed-console.rules](suricata/aipt-exposed-console.rules) |
| 9500053 | AIPT ARTEX Web Console HTML Title | ARTEX | exposed console (http) | High / Major | block-eligible | [suricata/aipt-exposed-console.rules](suricata/aipt-exposed-console.rules) |
| 9500055 | AIPT ARTEX Console Session Cookie (artex_token) | ARTEX | exposed console (http) | High / Major | block-eligible | [suricata/aipt-exposed-console.rules](suricata/aipt-exposed-console.rules) |
| 9500056 | AIPT ARTEX Console JWT With Subject ARTEX | ARTEX | exposed console (http) | High / Major | block-eligible | [suricata/aipt-exposed-console.rules](suricata/aipt-exposed-console.rules) |
| 9500057 | AIPT ARTEX Console First-Run Initialisation (POST /api/auth/init) | ARTEX | exposed console (http) | High / Major | alert | [suricata/aipt-exposed-console.rules](suricata/aipt-exposed-console.rules) |
| 9500058 | AIPT ARTEX Console API Use (exploration, intercept, sync routes) | ARTEX | exposed console (http) | High / Major | alert | [suricata/aipt-exposed-console.rules](suricata/aipt-exposed-console.rules) |
| 9500059 | AIPT ARTEX Server Log Line in HTTP Response (backend listening on) | ARTEX | exposed console (http) | High / Major | block-eligible | [suricata/aipt-exposed-console.rules](suricata/aipt-exposed-console.rules) |
| 9500060 | AIPT ARTEX Web Console Static Asset by MD5 (favicon or logo) | ARTEX | exposed console (http) | High / Major | block-eligible | [suricata/aipt-exposed-console.rules](suricata/aipt-exposed-console.rules) |
| 9500061 | AIPT ARTEX Console Login With Fixed Username ARTEX | ARTEX | exposed console (http) | High / Major | block-eligible | [suricata/aipt-exposed-console.rules](suricata/aipt-exposed-console.rules) |
| 9500070 | AIPT ARTEX LLM Profile Connection Test Request (JSON unicode-escaped) | ARTEX | LLM provider / relay (http) | Medium / Minor | alert | [suricata/aipt-llm-side.rules](suricata/aipt-llm-side.rules) |
| 9500071 | AIPT ARTEX Guard Block Marker in LLM Request (JSON unicode-escaped) | ARTEX | LLM provider / relay (http) | High / Major | block-eligible | [suricata/aipt-llm-side.rules](suricata/aipt-llm-side.rules) |
| 9500072 | AIPT ARTEX Worker Intent Block Header in LLM Request (JSON unicode-escaped) | ARTEX | LLM provider / relay (http) | High / Major | block-eligible | [suricata/aipt-llm-side.rules](suricata/aipt-llm-side.rules) |
| 9500103 | AIPT CyberStrikeAI Console API Use (agent, HITL, WebShell, CnC routes) | CyberStrikeAI | exposed console (http) | High / Major | alert | [suricata/aipt-exposed-console.rules](suricata/aipt-exposed-console.rules) |
| 9500110 | AIPT Scanner Nmap Scripting Engine User-Agent | Generic | target web / WAF (http) | High / Minor | alert | [suricata/aipt-target-facing.rules](suricata/aipt-target-facing.rules) |
| 9500200 | AIPT CyberStrikeAI Console HTML Title | CyberStrikeAI | exposed console (http) | High / Major | block-eligible | [suricata/aipt-exposed-console.rules](suricata/aipt-exposed-console.rules) |
| 9500201 | AIPT CyberStrikeAI API Docs Page Title | CyberStrikeAI | exposed console (http) | High / Major | block-eligible | [suricata/aipt-exposed-console.rules](suricata/aipt-exposed-console.rules) |
| 9500202 | AIPT CyberStrikeAI OpenAPI Spec Title | CyberStrikeAI | exposed console (http) | High / Major | block-eligible | [suricata/aipt-exposed-console.rules](suricata/aipt-exposed-console.rules) |
| 9500206 | AIPT CyberStrikeAI Client User-Agent | CyberStrikeAI | egress / proxy / DNS (http) | High / Major | block-eligible | [suricata/aipt-operator-egress.rules](suricata/aipt-operator-egress.rules) |
| 9500207 | AIPT CyberStrikeAI WebShell Manager User-Agent | CyberStrikeAI | target web / WAF (http) | High / Major | block-eligible | [suricata/aipt-target-facing.rules](suricata/aipt-target-facing.rules) |
| 9500208 | AIPT CyberStrikeAI MCP Server Auth Header (X-MCP-Token) | CyberStrikeAI | exposed console (http) | Medium / Minor | alert | [suricata/aipt-exposed-console.rules](suricata/aipt-exposed-console.rules) |
| 9500209 | AIPT CyberStrikeAI LLM Request (tool_search with built-in tool set) | CyberStrikeAI | LLM provider / relay (http) | High / Major | block-eligible | [suricata/aipt-llm-side.rules](suricata/aipt-llm-side.rules) |
| 9500212 | AIPT CyberStrikeAI HITL Judge Backend TLS SNI (api .typesafe .ai) | CyberStrikeAI | egress / proxy / DNS (tls) | Low / Informational | alert | [suricata/aipt-operator-egress.rules](suricata/aipt-operator-egress.rules) |
| 9500220 | AIPT HexStrike-AI API Server Health Response | HexStrike-AI | exposed console (http) | High / Major | block-eligible | [suricata/aipt-exposed-console.rules](suricata/aipt-exposed-console.rules) |
| 9500221 | AIPT HexStrike-AI Command or File API Request (8888) | HexStrike-AI | exposed console (http) | Medium / Major | alert | [suricata/aipt-exposed-console.rules](suricata/aipt-exposed-console.rules) |
| 9500222 | AIPT HexStrike-AI Tool Wrapper API Request (8888) | HexStrike-AI | exposed console (http) | Low / Minor | alert | [suricata/aipt-exposed-console.rules](suricata/aipt-exposed-console.rules) |
| 9500223 | AIPT HexStrike-AI HTTP Framework User-Agent | HexStrike-AI | target web / WAF (http) | High / Major | block-eligible | [suricata/aipt-target-facing.rules](suricata/aipt-target-facing.rules) |
| 9500224 | AIPT HexStrike-AI Exploit Helper User-Agent (Compatible Exploit) | HexStrike-AI | target web / WAF (http) | High / Major | block-eligible | [suricata/aipt-target-facing.rules](suricata/aipt-target-facing.rules) |
| 9500225 | AIPT HexStrike-AI MCP Server Name in JSON-RPC Response | HexStrike-AI | exposed console (http) | High / Major | alert | [suricata/aipt-exposed-console.rules](suricata/aipt-exposed-console.rules) |
| 9500226 | AIPT HexStrike-AI MCP Tool Set in LLM Request | HexStrike-AI | LLM provider / relay (http) | Medium / Minor | alert | [suricata/aipt-llm-side.rules](suricata/aipt-llm-side.rules) |
| 9500230 | AIPT PentAGI Searcher User-Agent | PentAGI | egress / proxy / DNS (http) | High / Major | block-eligible | [suricata/aipt-operator-egress.rules](suricata/aipt-operator-egress.rules) |
| 9500231 | AIPT PentAGI Web UI HTML Title | PentAGI | exposed console (http) | High / Major | block-eligible | [suricata/aipt-exposed-console.rules](suricata/aipt-exposed-console.rules) |
| 9500233 | AIPT PentAGI Container Image Pull (vxcontrol) | PentAGI | egress / proxy / DNS (http) | Medium / Minor | alert | [suricata/aipt-operator-egress.rules](suricata/aipt-operator-egress.rules) |
| 9500234 | AIPT PentAGI Agent Tool Set in LLM Request | PentAGI | LLM provider / relay (http) | High / Major | block-eligible | [suricata/aipt-llm-side.rules](suricata/aipt-llm-side.rules) |
| 9500241 | AIPT Strix Sandbox Image Pull (usestrix/strix-sandbox) | Strix | egress / proxy / DNS (http) | Medium / Minor | alert | [suricata/aipt-operator-egress.rules](suricata/aipt-operator-egress.rules) |
| 9500242 | AIPT Strix Agent Tool Set in LLM Request | Strix | LLM provider / relay (http) | High / Major | block-eligible | [suricata/aipt-llm-side.rules](suricata/aipt-llm-side.rules) |
| 9500252 | AIPT Shannon Pipeline Collector Tool in LLM Request | Shannon | LLM provider / relay (http) | Medium / Minor | alert | [suricata/aipt-llm-side.rules](suricata/aipt-llm-side.rules) |
| 9500253 | AIPT Shannon Worker Image Pull (keygraph/shannon) | Shannon | egress / proxy / DNS (http) | Medium / Minor | alert | [suricata/aipt-operator-egress.rules](suricata/aipt-operator-egress.rules) |
| 9500260 | AIPT Villager PyPI Package Download | Villager | egress / proxy / DNS (http) | Low / Informational | alert | [suricata/aipt-operator-egress.rules](suricata/aipt-operator-egress.rules) |
| 9500265 | AIPT MetasploitMCP msfrpcd RPC Over Plaintext HTTP (55553) | MetasploitMCP | exposed console (http) | Low / Minor | alert | [suricata/aipt-exposed-console.rules](suricata/aipt-exposed-console.rules) |
| 9500266 | AIPT MetasploitMCP Default msfrpcd Password in RPC Login | MetasploitMCP | exposed console (http) | High / Major | block-eligible | [suricata/aipt-exposed-console.rules](suricata/aipt-exposed-console.rules) |
| 9500267 | AIPT MetasploitMCP MCP SSE Endpoint Request (8085) | MetasploitMCP | exposed console (http) | Low / Minor | informational | [suricata/aipt-exposed-console.rules](suricata/aipt-exposed-console.rules) |
| 9500268 | AIPT MetasploitMCP MCP tools/call of a Metasploit Tool | MetasploitMCP | exposed console (http) | High / Major | block-eligible | [suricata/aipt-exposed-console.rules](suricata/aipt-exposed-console.rules) |
| 9500269 | AIPT MetasploitMCP Tool Set in LLM Request | MetasploitMCP | LLM provider / relay (http) | High / Major | block-eligible | [suricata/aipt-llm-side.rules](suricata/aipt-llm-side.rules) |
| 9500280 | AIPT Generic MCP JSON-RPC tools/call Over HTTP (non-standard port) | Generic | exposed console (http) | Low / Informational | informational | [suricata/aipt-exposed-console.rules](suricata/aipt-exposed-console.rules) |
| 9500281 | AIPT Generic MCP JSON-RPC tools/list Over HTTP (non-standard port) | Generic | exposed console (http) | Low / Informational | informational | [suricata/aipt-exposed-console.rules](suricata/aipt-exposed-console.rules) |
| 9500282 | AIPT Generic MCP Streamable-HTTP Session Headers (non-standard port) | Generic | exposed console (http) | Low / Informational | informational | [suricata/aipt-exposed-console.rules](suricata/aipt-exposed-console.rules) |
| 9500283 | AIPT Generic MCP SSE Endpoint Event | Generic | exposed console (http) | Low / Informational | informational | [suricata/aipt-exposed-console.rules](suricata/aipt-exposed-console.rules) |
| 9500290 | AIPT Scanner nuclei Default User-Agent (Chrome/87.0.4280.88) | Generic | target web / WAF (http) | Medium / Minor | alert | [suricata/aipt-target-facing.rules](suricata/aipt-target-facing.rules) |
| 9500291 | AIPT Scanner nuclei Project User-Agent | Generic | target web / WAF (http) | High / Minor | alert | [suricata/aipt-target-facing.rules](suricata/aipt-target-facing.rules) |
| 9500292 | AIPT Scanner ffuf User-Agent (Fuzz Faster U Fool) | Generic | target web / WAF (http) | High / Minor | alert | [suricata/aipt-target-facing.rules](suricata/aipt-target-facing.rules) |
| 9500293 | AIPT Scanner sqlmap User-Agent | Generic | target web / WAF (http) | High / Minor | alert | [suricata/aipt-target-facing.rules](suricata/aipt-target-facing.rules) |
| 9500294 | AIPT Scanner gobuster User-Agent | Generic | target web / WAF (http) | High / Minor | alert | [suricata/aipt-target-facing.rules](suricata/aipt-target-facing.rules) |
| 9500295 | AIPT Scanner Nikto User-Agent | Generic | target web / WAF (http) | High / Minor | alert | [suricata/aipt-target-facing.rules](suricata/aipt-target-facing.rules) |
| 9500297 | AIPT Scanner Burst of Requests With Empty User-Agent | Generic | target web / WAF (http) | Low / Minor | alert | [suricata/aipt-target-facing.rules](suricata/aipt-target-facing.rules) |
| 9500299 | AIPT Scanner Burst of Requests Without User-Agent Header | Generic | target web / WAF (http) | Low / Minor | alert | [suricata/aipt-target-facing.rules](suricata/aipt-target-facing.rules) |

## Sigma

| id | title | tool | log source | level | policy | file |
|---|---|---|---|---|---|---|
| bf806994-5ad1-4f90-9cfe-265c6bb4b0f9 | ARTEX Worker Command Output Spill File | ARTEX | operator host (linux/file_event) | high | block-eligible | [sigma/file_event/file_event_lnx_artex_cmd_output_spill.yml](sigma/file_event/file_event_lnx_artex_cmd_output_spill.yml) |
| dc673faa-3b16-402b-a1e8-d018de955b47 | ARTEX Console JWT Signing Key Created | ARTEX | operator host (linux/file_event) | low | alert | [sigma/file_event/file_event_lnx_artex_jwt_key.yml](sigma/file_event/file_event_lnx_artex_jwt_key.yml) |
| cd1a33aa-c789-43ab-9c66-a286367e62b3 | ARTEX Recording Proxy CA or Traffic Index Written | ARTEX | operator host (linux/file_event) | medium | alert | [sigma/file_event/file_event_lnx_artex_recording_proxy_ca.yml](sigma/file_event/file_event_lnx_artex_recording_proxy_ca.yml) |
| 9cc3e72a-d62a-4a06-989f-004c03f9d3a5 | ARTEX Self-Update Staging Files Written | ARTEX | operator host (linux/file_event) | high | block-eligible | [sigma/file_event/file_event_lnx_artex_selfupdate_staging.yml](sigma/file_event/file_event_lnx_artex_selfupdate_staging.yml) |
| 34a3e655-8ce7-4938-9fb9-da887d91002c | ARTEX Agent Transcript File Written | ARTEX | operator host (linux/file_event) | high | block-eligible | [sigma/file_event/file_event_lnx_artex_transcript_files.yml](sigma/file_event/file_event_lnx_artex_transcript_files.yml) |
| 2353b0e9-ff2d-486b-b8e0-abdc60beaade | CyberStrikeAI Cgroup Lock File or C2 Artefact Written | CyberStrikeAI | operator host (linux/file_event) | high | block-eligible | [sigma/file_event/file_event_lnx_cyberstrikeai_lock_or_c2_artefact.yml](sigma/file_event/file_event_lnx_cyberstrikeai_lock_or_c2_artefact.yml) |
| 74b47db4-5377-4e11-82cf-fde984da6dd3 | MetasploitMCP Payload Written to Default Save Directory | MetasploitMCP | operator host (linux/file_event) | informational | informational | [sigma/file_event/file_event_lnx_metasploitmcp_payload_dir.yml](sigma/file_event/file_event_lnx_metasploitmcp_payload_dir.yml) |
| 65f02339-b935-44e3-8bbe-4f9a30b35adc | Shannon Configuration or Workspace File Written | Shannon | operator host (linux/file_event) | low | alert | [sigma/file_event/file_event_lnx_shannon_home_directory.yml](sigma/file_event/file_event_lnx_shannon_home_directory.yml) |
| 3fc3ed93-6831-4d7d-ac87-a701e4b2c156 | Strix Run Directory Written | Strix | operator host (linux/file_event) | medium | alert | [sigma/file_event/file_event_lnx_strix_run_directory.yml](sigma/file_event/file_event_lnx_strix_run_directory.yml) |
| eb7379c4-5a8e-4313-a013-a5a601576c03 | Python Process Connecting to Metasploit RPC Port 55553 | MetasploitMCP | operator host (linux/network_connection) | medium | alert | [sigma/network_connection/net_connection_lnx_metasploitmcp_msfrpcd.yml](sigma/network_connection/net_connection_lnx_metasploitmcp_msfrpcd.yml) |
| 2a25c7e1-18bc-4141-878f-7c99e5c2bc33 | Shell or Attack Tool Spawned by ARTEX | ARTEX | operator host (linux/process_creation) | high | block-eligible | [sigma/process_creation/proc_creation_lnx_artex_child_process.yml](sigma/process_creation/proc_creation_lnx_artex_child_process.yml) |
| 8cffa640-61d7-4aed-9114-5c8cca3b2119 | ARTEX Server Binary Execution | ARTEX | operator host (linux/process_creation) | high | block-eligible | [sigma/process_creation/proc_creation_lnx_artex_server_binary.yml](sigma/process_creation/proc_creation_lnx_artex_server_binary.yml) |
| d65a7721-a07b-42a1-9f69-131539c18e00 | ARTEX Recording Proxy and CA Bundle Injected Into Tool Environment | ARTEX | operator host (linux/process_creation) | high | block-eligible | [sigma/process_creation/proc_creation_lnx_artex_tool_env_proxy_injection.yml](sigma/process_creation/proc_creation_lnx_artex_tool_env_proxy_injection.yml) |
| 27e85058-a499-46b4-9ff1-339db5883a4f | CyberStrikeAI Server Binary or Its Tool Children | CyberStrikeAI | operator host (linux/process_creation) | high | block-eligible | [sigma/process_creation/proc_creation_lnx_cyberstrikeai_server_or_child.yml](sigma/process_creation/proc_creation_lnx_cyberstrikeai_server_or_child.yml) |
| 044f6c20-5ef4-4975-8178-b7489c6766d6 | Decepticon MCP Server or Docker Network | Decepticon | operator host (linux/process_creation) | low | alert | [sigma/process_creation/proc_creation_lnx_decepticon_mcp_server.yml](sigma/process_creation/proc_creation_lnx_decepticon_mcp_server.yml) |
| 404887ed-2da9-434f-81e8-0d7ebb1ea5ee | Playwright MCP Server or Playwright CLI Started Headless | Generic | operator host (linux/process_creation) | informational | informational | [sigma/process_creation/proc_creation_lnx_generic_playwright_mcp_headless.yml](sigma/process_creation/proc_creation_lnx_generic_playwright_mcp_headless.yml) |
| cdda796e-0543-48fb-91ac-0eb8277fdeb2 | HexStrike-AI Server or MCP Client Started | HexStrike-AI | operator host (linux/process_creation) | high | block-eligible | [sigma/process_creation/proc_creation_lnx_hexstrike_server_or_mcp.yml](sigma/process_creation/proc_creation_lnx_hexstrike_server_or_mcp.yml) |
| 953b4923-4ff0-4045-a367-f87cae344fdb | MetasploitMCP Server or Metasploit RPC Daemon With Default Password | MetasploitMCP | operator host (linux/process_creation) | high | block-eligible | [sigma/process_creation/proc_creation_lnx_metasploitmcp_server.yml](sigma/process_creation/proc_creation_lnx_metasploitmcp_server.yml) |
| e94a96c7-2cd2-4612-905f-d18bd8bb4fff | PentAGI Image or Container on the Docker CLI | PentAGI | operator host (linux/process_creation) | medium | alert | [sigma/process_creation/proc_creation_lnx_pentagi_docker_image.yml](sigma/process_creation/proc_creation_lnx_pentagi_docker_image.yml) |
| 33357311-edbc-4d3b-a8f2-00cd03d12e24 | PentestGPT CLI Execution | PentestGPT | operator host (linux/process_creation) | low | alert | [sigma/process_creation/proc_creation_lnx_pentestgpt_cli.yml](sigma/process_creation/proc_creation_lnx_pentestgpt_cli.yml) |
| 5c393799-a356-47fa-a08a-c2f7e921671f | Shannon Temporal Container, Worker or CLI | Shannon | operator host (linux/process_creation) | medium | alert | [sigma/process_creation/proc_creation_lnx_shannon_components.yml](sigma/process_creation/proc_creation_lnx_shannon_components.yml) |
| a165e12d-77cd-4ad5-8fa8-86f00b6c3f6a | Strix CLI or Sandbox Image | Strix | operator host (linux/process_creation) | medium | alert | [sigma/process_creation/proc_creation_lnx_strix_cli_or_sandbox.yml](sigma/process_creation/proc_creation_lnx_strix_cli_or_sandbox.yml) |
| c24e8605-d472-4519-a0aa-e7527afae3dd | Villager Package Installed With Pip | Villager | operator host (linux/process_creation) | low | alert | [sigma/process_creation/proc_creation_lnx_villager_pip_install.yml](sigma/process_creation/proc_creation_lnx_villager_pip_install.yml) |
| af2a4fe3-6124-4533-a415-4110e800eecf | ARTEX Norma web_search DuckDuckGo HTML Scrape | ARTEX | egress / proxy / DNS (proxy) | informational | informational | [sigma/proxy/proxy_artex_norma_duckduckgo_html_scrape.yml](sigma/proxy/proxy_artex_norma_duckduckgo_html_scrape.yml) |
| 350f64c4-a7f1-4d99-80b4-3708c59f87a8 | ARTEX Self-Update Check or Release Download | ARTEX | egress / proxy / DNS (proxy) | high | block-eligible | [sigma/proxy/proxy_artex_selfupdate_github.yml](sigma/proxy/proxy_artex_selfupdate_github.yml) |
| 3c8ae62c-7294-4c44-ac49-25358ad14a13 | CyberStrikeAI Client User-Agent or TypeSafe Judge API Request | CyberStrikeAI | egress / proxy / DNS (proxy) | medium | alert | [sigma/proxy/proxy_cyberstrikeai_operator_egress.yml](sigma/proxy/proxy_cyberstrikeai_operator_egress.yml) |
| 4d76d11a-310d-4281-ab3c-ebaa6a1934b2 | LLM API Request From a Host Not Approved for LLM Use | Generic | egress / proxy / DNS (proxy) | informational | informational | [sigma/proxy/proxy_generic_llm_api_client.yml](sigma/proxy/proxy_generic_llm_api_client.yml) |
| 9f7401b7-2bc3-4d21-8d14-5c0655289f91 | PentAGI Searcher User-Agent or Sandbox Image Pull | PentAGI | egress / proxy / DNS (proxy) | medium | alert | [sigma/proxy/proxy_pentagi_searcher_or_image_pull.yml](sigma/proxy/proxy_pentagi_searcher_or_image_pull.yml) |
| d06cadb5-8d4c-47d4-8c0b-b84d622dc310 | Shannon CLI Package or Worker Image Fetch | Shannon | egress / proxy / DNS (proxy) | medium | alert | [sigma/proxy/proxy_shannon_package_or_image_fetch.yml](sigma/proxy/proxy_shannon_package_or_image_fetch.yml) |
| 5c0e3e33-8fbd-4c2d-b7da-96895e0d46f2 | Strix Sandbox Image Pull | Strix | egress / proxy / DNS (proxy) | medium | alert | [sigma/proxy/proxy_strix_sandbox_image_pull.yml](sigma/proxy/proxy_strix_sandbox_image_pull.yml) |
| 3165cf4d-35bb-4750-9aa4-bfad53aab954 | Villager PyPI Package Download | Villager | egress / proxy / DNS (proxy) | low | alert | [sigma/proxy/proxy_villager_pypi_download.yml](sigma/proxy/proxy_villager_pypi_download.yml) |
| 6ca41916-e292-47aa-829b-886fedb6f9c3 | HTTP Request Without User-Agent Base Rule for AIPT Correlations | Generic | target web / WAF (webserver) | informational | informational | [sigma/web/web_aipt_empty_user_agent_base.yml](sigma/web/web_aipt_empty_user_agent_base.yml) |
| d34dc9e3-aba4-4832-acae-22d932d93676 | HTTP 404 Response Base Rule for AIPT Correlations | Generic | target web / WAF (webserver) | informational | informational | [sigma/web/web_aipt_http_404_base.yml](sigma/web/web_aipt_http_404_base.yml) |
| abe41beb-a479-4b6e-bf67-0c5587cc9e90 | Anonymous HTTP Request to a Non-Static Path Base Rule for AIPT Correlations | Generic | target web / WAF (webserver) | informational | informational | [sigma/web/web_aipt_http_request_anonymous_base.yml](sigma/web/web_aipt_http_request_anonymous_base.yml) |
| 4fe0f0c0-a94a-40f3-8848-7fdf72b0192b | HTTP Request Base Rule for AIPT Correlations | Generic | target web / WAF (webserver) | informational | informational | [sigma/web/web_aipt_http_request_base.yml](sigma/web/web_aipt_http_request_base.yml) |
| a55e4fba-e3b6-44c4-afa9-c1fd6540a335 | HTTP Request to a Non-Static Path Base Rule for AIPT Correlations | Generic | target web / WAF (webserver) | informational | informational | [sigma/web/web_aipt_http_request_non_static_base.yml](sigma/web/web_aipt_http_request_non_static_base.yml) |
| 00dc4078-e4c5-4b49-a53d-3ef6f5c5bba3 | ARTEX API Recon Skill Script User-Agent | ARTEX | target web / WAF (webserver) | high | block-eligible | [sigma/web/web_artex_api_recon_user_agent.yml](sigma/web/web_artex_api_recon_user_agent.yml) |
| d970003a-63f2-4981-85ae-7137869b9ab4 | ARTEX Console Auth Status or First-Run Init Request | ARTEX | exposed console (webserver) | informational | informational | [sigma/web/web_artex_console_auth_endpoints.yml](sigma/web/web_artex_console_auth_endpoints.yml) |
| 89b93481-c7af-419e-9bae-6dfd1892e437 | ARTEX Console-Specific API or UI Route Access | ARTEX | exposed console (webserver) | medium | alert | [sigma/web/web_artex_console_routes.yml](sigma/web/web_artex_console_routes.yml) |
| f0720560-640f-41b0-9f5c-bfc066f5f314 | ARTEX Console Session Cookie Presented | ARTEX | exposed console (webserver) | high | block-eligible | [sigma/web/web_artex_console_session_cookie.yml](sigma/web/web_artex_console_session_cookie.yml) |
| 06c3b971-d488-486b-9ff5-ad628a2bf3f4 | ARTEX Asset Enrichment Prober User-Agent | ARTEX | target web / WAF (webserver) | high | block-eligible | [sigma/web/web_artex_enrich_user_agent.yml](sigma/web/web_artex_enrich_user_agent.yml) |
| b27c0488-676f-4c85-a5d9-2ca68e594fa0 | ARTEX Norma SDK WebFetch User-Agent | ARTEX | target web / WAF (webserver) | medium | alert | [sigma/web/web_artex_norma_webfetch_user_agent.yml](sigma/web/web_artex_norma_webfetch_user_agent.yml) |
| 748b7564-74e6-4d83-baa5-8f9f40419e13 | CyberStrikeAI Console API Route Access | CyberStrikeAI | exposed console (webserver) | low | alert | [sigma/web/web_cyberstrikeai_console_routes.yml](sigma/web/web_cyberstrikeai_console_routes.yml) |
| ca3370bd-f355-49f2-9f0b-e9a44a2c1339 | CyberStrikeAI Client or WebShell Manager User-Agent | CyberStrikeAI | target web / WAF (webserver) | high | block-eligible | [sigma/web/web_cyberstrikeai_user_agent.yml](sigma/web/web_cyberstrikeai_user_agent.yml) |
| eb4a1aa0-f729-4669-9c7d-eb1eb2de0363 | Go Default HTTP Client User-Agent | Generic | target web / WAF (webserver) | informational | informational | [sigma/web/web_generic_go_http_client_user_agent.yml](sigma/web/web_generic_go_http_client_user_agent.yml) |
| 31461d3c-a5b3-4d8a-834f-329785c61a96 | Headless Chromium User-Agent | Generic | target web / WAF (webserver) | informational | informational | [sigma/web/web_generic_headless_chromium_user_agent.yml](sigma/web/web_generic_headless_chromium_user_agent.yml) |
| a03347e3-e7b9-498a-a4ad-8195c8c50c26 | Web App Manifest Requested Without Referer | Generic | target web / WAF (webserver) | informational | informational | [sigma/web/web_generic_manifest_probe_no_referer.yml](sigma/web/web_generic_manifest_probe_no_referer.yml) |
| 22453e58-ff76-4b42-8ce3-9d427faa8922 | Nmap Scripting Engine User-Agent | Generic | target web / WAF (webserver) | low | alert | [sigma/web/web_generic_nmap_nse_user_agent.yml](sigma/web/web_generic_nmap_nse_user_agent.yml) |
| b39a5b4e-b75d-49e3-b834-8e2fe58c37e7 | Web Scanner User-Agents Used by AI Pentest Tools | Generic | target web / WAF (webserver) | low | alert | [sigma/web/web_generic_scanner_user_agents.yml](sigma/web/web_generic_scanner_user_agents.yml) |
| 4d1a0295-af2d-43c6-9159-65b9ae3061ed | HexStrike-AI Unauthenticated API Server Request | HexStrike-AI | exposed console (webserver) | medium | alert | [sigma/web/web_hexstrike_api_server_request.yml](sigma/web/web_hexstrike_api_server_request.yml) |
| 593d3131-7735-46dc-9509-ffe3553c26d2 | HexStrike-AI HTTP Framework or Exploit User-Agent | HexStrike-AI | target web / WAF (webserver) | high | block-eligible | [sigma/web/web_hexstrike_user_agent.yml](sigma/web/web_hexstrike_user_agent.yml) |
| 34a32b7b-4aa1-4f0c-83fe-aa1f13a45443 | MetasploitMCP SSE Transport or Metasploit RPC Request | MetasploitMCP | exposed console (webserver) | low | alert | [sigma/web/web_metasploitmcp_sse_or_msfrpcd_request.yml](sigma/web/web_metasploitmcp_sse_or_msfrpcd_request.yml) |
| 6b5c55ab-5750-4d0c-8481-5027007462c0 | PentAGI Searcher User-Agent | PentAGI | target web / WAF (webserver) | high | block-eligible | [sigma/web/web_pentagi_searcher_user_agent.yml](sigma/web/web_pentagi_searcher_user_agent.yml) |
| 719406fe-5f30-4ba5-a822-b617b107b865 | TLS Certificate Issued by a Mitmproxy CA | Generic | egress / proxy / DNS (zeek/x509) | informational | informational | [sigma/zeek/zeek_generic_go_mitmproxy_certificate.yml](sigma/zeek/zeek_generic_go_mitmproxy_certificate.yml) |

## Sigma correlations

| id | title | tool | log source | level | policy | file |
|---|---|---|---|---|---|---|
| 376ac24f-ffa6-4b2c-993b-045b17e681f4 | Many Distinct Non-Static URL Paths From a Single Client Per Minute | Generic | target web / WAF (webserver; value_count over web_aipt_http_request_anonymous_base) | informational | informational | [sigma/correlation/correlation_aipt_distinct_paths_per_minute.yml](sigma/correlation/correlation_aipt_distinct_paths_per_minute.yml) |
| 54ff969a-30f3-4381-85df-ffa8d6299b83 | Burst of Requests Without User-Agent From a Single Client | Generic | target web / WAF (webserver; event_count over web_aipt_empty_user_agent_base) | low | alert | [sigma/correlation/correlation_aipt_empty_user_agent_burst.yml](sigma/correlation/correlation_aipt_empty_user_agent_burst.yml) |
| 53e38a64-a6ee-4c53-b1f6-467a5ae06044 | HTTP 404 Burst From a Single Client | Generic | target web / WAF (webserver; event_count over web_aipt_http_404_base) | low | alert | [sigma/correlation/correlation_aipt_http_404_burst.yml](sigma/correlation/correlation_aipt_http_404_burst.yml) |
| d4328981-5339-4842-bce2-2e55e7771e2b | Identical HTTP Request Repeated by a Single Client | Generic | target web / WAF (webserver; event_count over web_aipt_http_request_anonymous_base) | informational | informational | [sigma/correlation/correlation_aipt_identical_request_repeat.yml](sigma/correlation/correlation_aipt_identical_request_repeat.yml) |
| 79303e1c-0b24-4575-aae2-a2fb09963151 | LLM API Call Followed by a Request Burst From the Same Host | Generic | target web / WAF, egress / proxy / DNS (proxy, webserver; temporal_ordered over proxy_generic_llm_api_client, correlation_aipt_request_burst) | low | alert | [sigma/correlation/correlation_aipt_llm_call_then_target_requests.yml](sigma/correlation/correlation_aipt_llm_call_then_target_requests.yml) |
| c834ec7a-f73f-4818-8a0a-052a8714401a | HTTP Request Burst From a Single Client | Generic | target web / WAF (webserver; event_count over web_aipt_http_request_anonymous_base) | informational | informational | [sigma/correlation/correlation_aipt_request_burst.yml](sigma/correlation/correlation_aipt_request_burst.yml) |
| 147134aa-3760-4911-bbfb-d0a9f6d64a44 | Several User-Agents Receiving 404 From a Single Client Within 10 Minutes | Generic | target web / WAF (webserver; value_count over web_aipt_http_404_base) | informational | informational | [sigma/correlation/correlation_aipt_user_agent_diversity.yml](sigma/correlation/correlation_aipt_user_agent_diversity.yml) |
| 7c15f6c6-f824-4f5b-9e84-a4a69ef0ffa2 | Scanner-Grade User-Agent Rotation Among 404 Responses From a Single Client | Generic | target web / WAF (webserver; value_count over web_aipt_http_404_base) | low | alert | [sigma/correlation/correlation_aipt_user_agent_rotation.yml](sigma/correlation/correlation_aipt_user_agent_rotation.yml) |

## YARA

Scores follow the signature-base convention (85 tool binary, 30-40 generic components, below 50 hunting only).

| rule | description | tool | log source | score | policy | file |
|---|---|---|---|---|---|---|
| AIPT_ARTEX_Go_Binary | Detects the ARTEX backend Go binary (module github.com/Autumn-27/artex) by its enrichment and self-update User-Agents, release URL, session-id formats and listen banner | ARTEX | operator host (files, memory dumps saved as files, exported data) | score 85 | n/a | [yara/aipt_artex.yar](yara/aipt_artex.yar) |
| AIPT_ARTEX_Embedded_WebUI | Detects the ARTEX web console (embedded in the binary or as the exported Next.js site) by its HTML title, meta description, login and disclaimer strings and session cookie name | ARTEX | operator host (files, memory dumps saved as files, exported data) | score 75 | n/a | [yara/aipt_artex.yar](yara/aipt_artex.yar) |
| AIPT_ARTEX_LLM_Prompt_Markers | Detects short fixed markers that ARTEX writes into its LLM conversations (guard block tag, worker chat marker, intent block header, goals decomposer role, connection test, output contract heading) in transcripts, LLM record dumps, relay logs or the binary; raw UTF-8 or JSON \\uXXXX-escaped | ARTEX | operator host (files, memory dumps saved as files, exported data) | score 70 | n/a | [yara/aipt_artex.yar](yara/aipt_artex.yar) |
| AIPT_ARTEX_LLM_Tool_Schema | Detects the ARTEX planner and worker tool names serialised as an LLM function schema, plain or JSON-escaped inside a record (LLM request records, relay logs, transcripts), compact or with up to four whitespace characters after the colon, or present together in the binary. Names written as \\uXXXX escapes are not matched | ARTEX | operator host (files, memory dumps saved as files, exported data) | score 70 | n/a | [yara/aipt_artex.yar](yara/aipt_artex.yar) |
| AIPT_ARTEX_Transcript_File | Detects ARTEX agent transcripts and LLM record exports: JSON lines whose session_id has an ARTEX session name (exp<N>-worker-i<M>, -planner, -main, -main-s<K>, -goals, -compactor, -btw-<id>, or conv-<N>; the same list as the Sigma file rule file_event_lnx_artex_transcript_files) together with an ARTEX tool name | ARTEX | operator host (files, memory dumps saved as files, exported data) | score 80 | n/a | [yara/aipt_artex.yar](yara/aipt_artex.yar) |
| AIPT_ARTEX_ApiRecon_Skill_Scripts | Detects the reference scripts of the ARTEX api-recon skill (harvest_static.py, spider_mpa.py, preload.js, runtime_harvest.js) by their User-Agent constants or preload globals | ARTEX | operator host (files, memory dumps saved as files, exported data) | score 75 | n/a | [yara/aipt_artex.yar](yara/aipt_artex.yar) |
| AIPT_ARTEX_Supervisor_Script | Detects the ARTEX start.sh supervisor that relaunches the binary after a self-update (exit code 75) | ARTEX | operator host (files, memory dumps saved as files, exported data) | score 65 | n/a | [yara/aipt_artex.yar](yara/aipt_artex.yar) |
| AIPT_Norma_SDK_Go_Binary | Detects a Go binary built on the norma agent SDK (github.com/Autumn-27/norma), which ARTEX uses; any other norma-based agent matches too | ARTEX | operator host (files, memory dumps saved as files, exported data) | score 50 | n/a | [yara/aipt_artex.yar](yara/aipt_artex.yar) |
| AIPT_GoMitmproxy_Embedded_Recorder | Detects a Go binary embedding go-mitmproxy together with its CA file names, as the ARTEX traffic recorder does; every go-mitmproxy consumer matches | Generic | operator host (files, memory dumps saved as files, exported data) | score 40 | n/a | [yara/aipt_artex.yar](yara/aipt_artex.yar) |
| AIPT_GoMitmproxy_CA_Certificate_PEM | Detects a PEM certificate whose DER name is O=mitmproxy, CN=mitmproxy encoded as PrintableString, the CA that go-mitmproxy generates (ARTEX writes it to data/traffic/_ca/). Matches the base64 body at all three alignments and across PEM line breaks; standalone go-mitmproxy CAs match too | Generic | operator host (files, memory dumps saved as files, exported data) | score 40 | n/a | [yara/aipt_artex.yar](yara/aipt_artex.yar) |
| AIPT_CyberStrikeAI_Go_Binary | Detects the CyberStrikeAI server binary by its module path, client and WebShell-manager User-Agents, cgroup lock name, MCP auth header and the Eino agent framework | CyberStrikeAI | operator host (files, memory dumps saved as files, exported data) | score 85 | n/a | [yara/aipt_family.yar](yara/aipt_family.yar) |
| AIPT_CyberStrikeAI_Prompt_Strings | Detects the CyberStrikeAI authorization-suppression block of its default agent prompt in the binary, agent definition files or exported conversations (both short fragments required, raw UTF-8 or both JSON \\uXXXX-escaped) | CyberStrikeAI | operator host (files, memory dumps saved as files, exported data) | score 60 | n/a | [yara/aipt_family.yar](yara/aipt_family.yar) |
| AIPT_Generic_LLM_Agent_Go_Binary | Hunting rule for Go binaries that call an LLM API with function tools (chat-completions or messages path, provider header, tool-call fields); matches ARTEX, CyberStrikeAI and many benign LLM clients | Generic | operator host (files, memory dumps saved as files, exported data) | score 30 | n/a | [yara/aipt_family.yar](yara/aipt_family.yar) |
| AIPT_ARTEX_Go_Binary_Mem | Memory-safe variant of AIPT_ARTEX_Go_Binary (strings only, no filesize or header check) for live process scans. Detects the ARTEX backend Go binary (module github.com/Autumn-27/artex) by its enrichment and self-update User-Agents, release URL, session-id formats and listen banner | ARTEX | operator host (live process memory) | score 75 | n/a | [yara/aipt_memory.yar](yara/aipt_memory.yar) |
| AIPT_ARTEX_LLM_Tool_Schema_Mem | Memory-safe variant of AIPT_ARTEX_LLM_Tool_Schema (strings only, no filesize or header check) for live process scans. Detects the ARTEX planner and worker tool names serialised as an LLM function schema, plain or JSON-escaped inside a record (LLM request records, relay logs, transcripts), compact or with up to four whitespace characters after the colon, or present together in the binary. Names written as \\uXXXX escapes are not matched | ARTEX | operator host (live process memory) | score 60 | n/a | [yara/aipt_memory.yar](yara/aipt_memory.yar) |
| AIPT_ARTEX_LLM_Prompt_Markers_Mem | Memory-safe variant of AIPT_ARTEX_LLM_Prompt_Markers (strings only, no filesize or header check) for live process scans. Detects short fixed markers that ARTEX writes into its LLM conversations (guard block tag, worker chat marker, intent block header, goals decomposer role, connection test, output contract heading) in transcripts, LLM record dumps, relay logs or the binary | ARTEX | operator host (live process memory) | score 60 | n/a | [yara/aipt_memory.yar](yara/aipt_memory.yar) |
| AIPT_Norma_SDK_Go_Binary_Mem | Memory-safe variant of AIPT_Norma_SDK_Go_Binary (strings only, no filesize or header check) for live process scans. Detects a Go binary built on the norma agent SDK (github.com/Autumn-27/norma), which ARTEX uses; any other norma-based agent matches too | ARTEX | operator host (live process memory) | score 40 | n/a | [yara/aipt_memory.yar](yara/aipt_memory.yar) |
| AIPT_CyberStrikeAI_Go_Binary_Mem | Memory-safe variant of AIPT_CyberStrikeAI_Go_Binary (strings only, no filesize or header check) for live process scans. Detects the CyberStrikeAI server binary by its module path, client and WebShell-manager User-Agents, cgroup lock name, MCP auth header and the Eino agent framework | CyberStrikeAI | operator host (live process memory) | score 75 | n/a | [yara/aipt_memory.yar](yara/aipt_memory.yar) |
| AIPT_CyberStrikeAI_Prompt_Strings_Mem | Memory-safe variant of AIPT_CyberStrikeAI_Prompt_Strings (strings only, no filesize or header check) for live process scans. Detects the CyberStrikeAI authorization-suppression block of its default agent prompt in the binary, agent definition files or exported conversations (both short fragments required) | CyberStrikeAI | operator host (live process memory) | score 50 | n/a | [yara/aipt_memory.yar](yara/aipt_memory.yar) |

## ModSecurity (CRS plugin)

Severity and paranoia level (PL) from each rule's actions. Plugin-control and configuration entries do not alert.

| id | msg | tool | log source | severity / PL | policy | file |
|---|---|---|---|---|---|---|
| 9590010 | plugin configuration switch (ships commented out) | - | plugin (phase 1) | - | - | [modsecurity/aipt-config.conf](modsecurity/aipt-config.conf) |
| 9590011 | plugin configuration switch (ships commented out) | - | plugin (phase 1) | - | - | [modsecurity/aipt-config.conf](modsecurity/aipt-config.conf) |
| 9590012 | plugin configuration switch (ships commented out) | - | plugin (phase 1) | - | - | [modsecurity/aipt-config.conf](modsecurity/aipt-config.conf) |
| 9590013 | plugin configuration switch (ships commented out) | - | plugin (phase 1) | - | - | [modsecurity/aipt-config.conf](modsecurity/aipt-config.conf) |
| 9590014 | plugin configuration switch (ships commented out) | - | plugin (phase 1) | - | - | [modsecurity/aipt-config.conf](modsecurity/aipt-config.conf) |
| 9590015 | plugin configuration switch (ships commented out) | - | plugin (phase 1) | - | - | [modsecurity/aipt-config.conf](modsecurity/aipt-config.conf) |
| 9590020 | plugin control (no alert) | - | plugin (phase 1) | - | - | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
| 9590021 | plugin control (no alert) | - | plugin (phase 1) | - | - | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
| 9590022 | plugin control (no alert) | - | plugin (phase 1) | - | - | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
| 9590023 | plugin control (no alert) | - | plugin (phase 1) | - | - | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
| 9590024 | plugin control (no alert) | - | plugin (phase 1) | - | - | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
| 9590025 | plugin control (no alert) | - | plugin (phase 1) | - | - | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
| 9590090 | plugin control (no alert) | - | plugin (phase 2) | - | - | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
| 9590091 | plugin control (no alert) | - | plugin (phase 4) | - | - | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
| 9590099 | plugin control (no alert) | - | plugin (phase 1) | - | - | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
| 9590101 | ARTEX enrichment prober User-Agent | ARTEX | target web / WAF (phase 1) | CRITICAL / PL1 | block-eligible | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
| 9590102 | ARTEX norma SDK WebFetch User-Agent | ARTEX | target web / WAF (phase 1) | WARNING / PL1 | alert | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
| 9590103 | ARTEX api-recon skill script User-Agent | ARTEX | target web / WAF (phase 1) | CRITICAL / PL1 | block-eligible | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
| 9590104 | ARTEX console session cookie | ARTEX | exposed console (phase 1) | WARNING / PL1 | alert | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
| 9590105 | ARTEX console JWT with subject ARTEX | ARTEX | exposed console (phase 1) | WARNING / PL1 | alert | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
| 9590201 | CyberStrikeAI client or WebShell manager User-Agent | CyberStrikeAI | target web / WAF (phase 1) | CRITICAL / PL1 | block-eligible | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
| 9590202 | CyberStrikeAI console API route | CyberStrikeAI | exposed console (phase 1) | NOTICE / PL1 | alert | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
| 9590203 | CyberStrikeAI MCP auth header X-MCP-Token | CyberStrikeAI | exposed console (phase 1) | NOTICE / PL1 | alert | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
| 9590211 | HexStrike-AI User-Agent | HexStrike-AI | target web / WAF (phase 1) | CRITICAL / PL1 | block-eligible | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
| 9590212 | HexStrike-AI command, file or tool API request on 8888 | HexStrike-AI | exposed console (phase 1) | WARNING / PL1 | alert | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
| 9590221 | PentAGI searcher User-Agent | PentAGI | target web / WAF (phase 1) | CRITICAL / PL1 | block-eligible | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
| 9590231 | MetasploitMCP SSE endpoint request on 8085 | MetasploitMCP | exposed console (phase 1) | WARNING / PL1 | informational | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
| 9590301 | Generic web app manifest probe without Referer | Generic | target web / WAF (phase 1) | NOTICE / PL2 | informational | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
| 9590302 | Generic headless Chromium User-Agent | Generic | target web / WAF (phase 1) | NOTICE / PL2 | informational | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
| 9590303 | Generic Go-http-client default User-Agent | Generic | target web / WAF (phase 1) | NOTICE / PL2 | informational | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
| 9590304 | Generic MCP Streamable-HTTP header | Generic | exposed console (phase 1) | NOTICE / PL2 | informational | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
| 9590305 | Scanner nuclei default User-Agent | Generic | target web / WAF (phase 1) | WARNING / PL1 | alert | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
| 9590306 | Scanner User-Agent (nuclei, ffuf, sqlmap, gobuster, Nikto) | Generic | target web / WAF (phase 1) | WARNING / PL1 | alert | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
| 9590310 | plugin control (no alert) | - | plugin (phase 1) | - | - | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
| 9590311 | plugin control (no alert) | - | plugin (phase 5) | - | - | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
| 9590312 | Generic 404 accumulation from one client (idle-timeout counter, path enumeration) | Generic | target web / WAF (phase 1) | WARNING / PL1 | alert | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
| 9590313 | plugin control (no alert) | - | plugin (phase 1) | - | - | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
| 9590314 | Scanner accumulation of requests without User-Agent (idle-timeout counter) | Generic | target web / WAF (phase 1) | WARNING / PL1 | alert | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
| 9590315 | plugin control (no alert) | - | plugin (phase 1) | - | - | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
| 9590401 | ARTEX console served behind this WAF (health response) | ARTEX | exposed console (phase 4) | WARNING / PL1 | block-eligible | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
| 9590402 | CyberStrikeAI console served behind this WAF | CyberStrikeAI | exposed console (phase 4) | WARNING / PL1 | alert | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
| 9590403 | HexStrike-AI API server behind this WAF | HexStrike-AI | exposed console (phase 4) | WARNING / PL1 | alert | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
| 9590404 | PentAGI UI served behind this WAF | PentAGI | exposed console (phase 4) | WARNING / PL1 | alert | [modsecurity/aipt-before.conf](modsecurity/aipt-before.conf) |
