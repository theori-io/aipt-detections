# AIPT correlations on Elasticsearch (EQL and ES|QL)

AIPT detection pack v1.0.0 (2026-10-12), DRL 1.1. Maintained Elasticsearch equivalents of the eight Sigma correlations
in `sigma/correlation/` (sigma-cli 3.1.0 cannot convert all of them: see `sigma/correlation/README.md`). Every query
below was run on Elasticsearch 8.19.23 (single node, offline container) over internal fixtures and anonymised
lab captures (an earlier local-model ARTEX run and runs 04/05) and compared with an internal Python Sigma matcher per correlation and client during development (engine harness not in this repository).

## Semantics

| correlation | form here | window | agreement with the evaluator (sliding) |
|---|---|---|---|
| 1 request burst (>= 30 / 10 s) | EQL `sequence ... with runs=30` | sliding | same clients on all 6 datasets |
| 2 distinct anonymous paths (>= 30 / 60 s) | ES\|QL `count_distinct` per 60 s bucket | fixed bins | missed the earlier local-model ARTEX client (its 30 paths straddle a bucket edge); can miss any burst that does |
| 3 404 burst (>= 15 / 60 s) | EQL `sequence ... with runs=15` | sliding | same clients on all 6 datasets |
| 4 identical request (>= 20 / 60 s) | EQL `sequence by c-ip, cs-host, cs-method, cs-uri-stem` | sliding | same groups except one group of the earlier local-model ARTEX run of requests without a Host header (null join key, see notes) |
| 5 requests without User-Agent (>= 40 / 60 s) | EQL `sequence ... with runs=40` | sliding | same clients on all 6 datasets |
| 6 UA diversity among 404 responses (>= 2 / 10 min) | ES\|QL `count_distinct` per 10 min bucket | fixed bins | same clients here; can miss across a bucket edge |
| 7 UA rotation among 404 responses (>= 50 / 10 min) | ES\|QL `count_distinct` per 10 min bucket | fixed bins | missed the fixture client (50 UAs over 490 s split across a bucket edge) |
| 8 LLM call, then request burst (5 min, ordered) | two stages: query 1 writes burst alerts (client, time of the 30th request), then an EQL sequence over the proxy index and those alerts | sliding | same clients (fixture and lab run 02) |

Overall 43 of 46 (correlation, dataset) results agree with the evaluator (query 8 runs only where proxy data exists). EQL cannot count distinct values, so 2, 6 and 7 use ES|QL buckets (the same fixed-bin semantics as the sigma-cli
ES|QL output). Run them as Kibana ES|QL rules, or schedule them every bucket length with a look-back of two buckets.

## Field mapping and prerequisites

- Field names are the Sigma webserver/proxy names (`c-ip`, `cs-method`, `cs-uri-stem`, `cs-host`, `cs-user-agent`,
  `sc-status`; proxy `src_ip`, `cs-host`, `c-uri-stem`, `cs-content-type`, `c-useragent`). For ECS replace them by
  `source.ip`, `http.request.method`, `url.path`, `url.domain`, `user_agent.original`, `http.response.status_code`,
  `http.request.mime_type`. Backtick-quote names that contain `-` (EQL and ES|QL both require it).
- `c-ip` and `src_ip` must be mapped as `ip` (CIDR matching; ES\|QL rejects comparing an ip field with a CIDR string).
- Every field an ES|QL query names must exist in the index mapping, or the query fails with `Unknown column`.
- Keyword fields are case-sensitive in EQL `:`/`==`, ES|QL `==`/`like` and Lucene `query_string`; Sigma matching is
  case-insensitive. The queries below use `in~` / `like~` where it matters; for converted rules see the README.
- `@timestamp` is the event time.
- Approved-assessment exemption (sigma/placeholders.yaml semantics): replace `"0.0.0.0/32"` (never matches) with your
  addresses or CIDRs and `"aipt-unset-placeholder"` with the approved User-Agents (`*` wildcards allowed: EQL
  `like~` is case-insensitive, ES|QL `LIKE` case-sensitive). A source is exempt when it matches
  AND (its UA matches OR it sends none); query 5 exempts by source alone.

## Queries

The index patterns `web-*` and `proxy-*` stand for your web-server and proxy indices.

### 1. correlation_aipt_request_burst (EQL; base web_aipt_http_request_anonymous_base)

```eql id=1 index=web-*
sequence by `c-ip` with maxspan=10s
  [any where `cs-method` in~ ("GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH")
     and not `cs-uri-stem` like~ ("*.js", "*.css", "*.png", "*.jpg", "*.jpeg", "*.gif", "*.svg", "*.ico", "*.webp", "*.woff",
                                  "*.woff2", "*.ttf", "*.map", "*/static/*", "*/assets/*")
     and not (`cs-method` : "OPTIONS" and `cs-uri-stem` == "/")
     and not (cidrmatch(`c-ip`, "0.0.0.0/32") and (`cs-user-agent` like~ ("aipt-unset-placeholder") or ?`cs-user-agent` == null))] with runs=30
```

### 2. correlation_aipt_distinct_paths_per_minute (ES|QL, fixed 60 s buckets; anonymous base)

```esql id=2 index=web-*
FROM web-*
| WHERE `cs-method` IN ("GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH")
    AND NOT (ends_with(`cs-uri-stem`, ".js") OR ends_with(`cs-uri-stem`, ".css") OR ends_with(`cs-uri-stem`, ".png")
             OR ends_with(`cs-uri-stem`, ".jpg") OR ends_with(`cs-uri-stem`, ".jpeg") OR ends_with(`cs-uri-stem`, ".gif")
             OR ends_with(`cs-uri-stem`, ".svg") OR ends_with(`cs-uri-stem`, ".ico") OR ends_with(`cs-uri-stem`, ".webp")
             OR ends_with(`cs-uri-stem`, ".woff") OR ends_with(`cs-uri-stem`, ".woff2") OR ends_with(`cs-uri-stem`, ".ttf")
             OR ends_with(`cs-uri-stem`, ".map") OR `cs-uri-stem` LIKE "*/static/*" OR `cs-uri-stem` LIKE "*/assets/*")
    AND NOT (`cs-method` == "OPTIONS" AND `cs-uri-stem` == "/")
    AND NOT (cidr_match(`c-ip`, "0.0.0.0/32") AND (`cs-user-agent` LIKE "aipt-unset-placeholder" OR `cs-user-agent` IS NULL))
| EVAL bucket = date_trunc(60 seconds, @timestamp)
| STATS n = count_distinct(`cs-uri-stem`) BY bucket, `c-ip`
| WHERE n >= 30
| STATS first_bucket = min(bucket), max_in_bucket = max(n) BY `c-ip`
```

### 3. correlation_aipt_http_404_burst (EQL)

```eql id=3 index=web-*
sequence by `c-ip` with maxspan=60s
  [any where `sc-status` == 404
     and not (cidrmatch(`c-ip`, "0.0.0.0/32") and (`cs-user-agent` like~ ("aipt-unset-placeholder") or ?`cs-user-agent` == null))] with runs=15
```

### 4. correlation_aipt_identical_request_repeat (EQL; anonymous base, >= 20)

```eql id=4 index=web-*
sequence by `c-ip`, `cs-host`, `cs-method`, `cs-uri-stem` with maxspan=60s
  [any where `cs-method` in~ ("GET", "POST", "HEAD", "OPTIONS", "PUT", "DELETE", "PATCH")
     and not `cs-uri-stem` like~ ("*.js", "*.css", "*.png", "*.jpg", "*.jpeg", "*.gif", "*.svg", "*.ico", "*.webp", "*.woff",
                                  "*.woff2", "*.ttf", "*.map", "*/static/*", "*/assets/*")
     and not (`cs-method` : "OPTIONS" and `cs-uri-stem` == "/")
     and not (cidrmatch(`c-ip`, "0.0.0.0/32") and (`cs-user-agent` like~ ("aipt-unset-placeholder") or ?`cs-user-agent` == null))] with runs=20
```

### 5. correlation_aipt_empty_user_agent_burst (EQL; >= 40, health paths excluded)

```eql id=5 index=web-*
sequence by `c-ip` with maxspan=60s
  [any where (?`cs-user-agent` == null or `cs-user-agent` in ("", "-"))
     and not `cs-uri-stem` in~ ("/health", "/healthz", "/readyz", "/livez", "/status", "/metrics", "/ping", "/api/health")
     and not `cs-uri-stem` like~ "/actuator/*" and not (`cs-method` : "OPTIONS" and `cs-uri-stem` == "/")
     and not cidrmatch(`c-ip`, "0.0.0.0/32")] with runs=40
```

### 6. correlation_aipt_user_agent_diversity (ES|QL, fixed 10 min buckets; UAs among 404 responses, >= 2)

```esql id=6 index=web-*
FROM web-*
| WHERE `sc-status` == 404
    AND NOT (cidr_match(`c-ip`, "0.0.0.0/32") AND (`cs-user-agent` LIKE "aipt-unset-placeholder" OR `cs-user-agent` IS NULL))
| EVAL bucket = date_trunc(10 minutes, @timestamp), ua = coalesce(`cs-user-agent`, "(none)")
| STATS n = count_distinct(ua) BY bucket, `c-ip`
| WHERE n >= 2
| STATS first_bucket = min(bucket), max_in_bucket = max(n) BY `c-ip`
```

### 7. correlation_aipt_user_agent_rotation (ES|QL, fixed 10 min buckets; UAs among 404 responses, >= 50)

```esql id=7 index=web-*
FROM web-*
| WHERE `sc-status` == 404
    AND NOT (cidr_match(`c-ip`, "0.0.0.0/32") AND (`cs-user-agent` LIKE "aipt-unset-placeholder" OR `cs-user-agent` IS NULL))
| EVAL bucket = date_trunc(10 minutes, @timestamp), ua = coalesce(`cs-user-agent`, "(none)")
| STATS n = count_distinct(ua) BY bucket, `c-ip`
| WHERE n >= 50
| STATS first_bucket = min(bucket), max_in_bucket = max(n) BY `c-ip`
```

### 8. correlation_aipt_llm_call_then_target_requests (two stages)

Stage 1 is query 1 run as a detection rule whose alerts carry the client address in `client` (ip) and `@timestamp` =
the time of the 30th request of the burst (the last event of the EQL sequence), written to an alerts index (pattern
`aipt-burst-alerts-*` here; in Kibana, the rule's alerts index with `client` taken from `c-ip`). Stage 2 joins LLM API
requests from the proxy logs (same selector as proxy_generic_llm_api_client: a POST to a provider host with an
API path or a JSON body, or a POST with a JSON body and a non-browser UA to a local API path) to those alerts:

```eql id=8 index=proxy-*,aipt-burst-alerts-*
sequence with maxspan=5m
  [any where `cs-method` == "POST"
     and (((`cs-host` in~ ("api.anthropic.com", "api.openai.com", "dashscope.aliyuncs.com", "dashscope-intl.aliyuncs.com",
                              "api.deepseek.com", "api.moonshot.ai", "api.moonshot.cn", "api.z.ai",
                              "open.bigmodel.cn", "generativelanguage.googleapis.com", "openrouter.ai", "api.groq.com",
                              "api.mistral.ai", "api.together.xyz", "api.x.ai", "api.minimax.chat",
                              "ark.cn-beijing.volces.com", "api.cohere.com", "api.fireworks.ai", "api.perplexity.ai",
                              "api.cerebras.ai", "api.siliconflow.cn")
            or `cs-host` like~ "*.openai.azure.com" or `cs-host` like~ "bedrock-runtime.*.amazonaws.com"
            or `cs-host` like~ "*-aiplatform.googleapis.com")
           and (`c-uri-stem` like~ ("*/chat/completions*", "*/messages*", "*/responses*", "*/completions*", "*:generateContent*", "*:streamGenerateContent*", "*/chatcompletion*", "*/services/aigc/*")
                or `cs-content-type` like~ "*json*"))
          or (`c-uri-stem` like~ ("*/chat/completions", "*/v1/messages", "*/v1/responses", "*/api/chat", "*/api/generate")
              and `cs-content-type` like~ "*json*" and not `c-useragent` like~ "Mozilla/*"))
     and not cidrmatch(src_ip, "0.0.0.0/32")
     and not (cidrmatch(src_ip, "0.0.0.0/32") and (`c-useragent` like~ ("aipt-unset-placeholder") or ?`c-useragent` == null))] by src_ip
  [any where stream == "burst_alert"] by client
```

The first `cidrmatch(src_ip, ...)` is `llm_approved_clients`, the second `approved_assessment_sources`. NAT can join
different users behind one address.

## Notes from the engine run

- EQL `maxspan` includes both ends (15 404s whose first and last are exactly 60.000 s apart match), like the evaluator;
  Splunk's `streamstats time_window` excludes the far end.
- EQL drops events whose join key is null: requests without a Host header never reach query 4 (the evaluator and
  `analytics/correlations.spl` count them under an empty host). Map a missing `cs-host` to a constant at ingest (an
  ingest pipeline `set` with `override: false`) if raw probes without Host matter to you.
- ES|QL drops rows where a `NOT` condition evaluates to null (three-valued logic): a converted Sigma filter such as
  `not cs-referer like "*://*"` silently removes every request WITHOUT a Referer. Write such filters null-safe
  (`cs-referer IS NULL OR NOT cs-referer LIKE "*://*"`); EQL needs the same care
  (`?field == null or not field like~ ...`).
