# Sigma correlations: conversion status and maintained equivalents

AIPT detection pack v1.0.0 (2026-10-12). The eight correlation rules in this directory are the reference definitions
(Sigma v2 correlation format, tested internally with a Python sliding-window matcher). **sigma-cli 3.1.0 cannot
convert them as a set for any backend, and cannot convert some of them at all.** Deploy the maintained, engine-tested
equivalents instead:

| backend | file | window semantics | tested on |
|---|---|---|---|
| Splunk SPL | [`analytics/correlations.spl`](../../analytics/correlations.spl) | sliding (`streamstats time_window`) | Splunk Enterprise 10.6.0.5: 46 of 48 (correlation, dataset) results equal the evaluator; the 2 others are the exact-boundary case below |
| Elasticsearch EQL / ES\|QL | [`analytics/correlations.esql.md`](../../analytics/correlations.esql.md) | sliding (EQL sequences) for 1, 3, 4, 5, 8; fixed buckets (ES\|QL) for the distinct-count correlations 2, 6, 7 | Elasticsearch 8.19.23: 43 of 46 equal (query 8 needs proxy data); 2 bucket-edge misses (UA rotation fixture, distinct paths of an earlier local-model lab run), 1 group with a null join key |
| Microsoft Sentinel / ADX KQL | [`analytics/correlations.kql`](../../analytics/correlations.kql) | sliding (pre-filter + self-join over (t - span, t]) | author-reported language-service checks and a functional Kusto emulator regression run; the internal harness is not distributed and peak-load cost was not measured |

The engine runs were made during development. All harnesses and fixtures are internal; the public repository cannot reproduce these reported comparisons on its own.

## What sigma-cli 3.1.0 does with these files (pySigma 1.5.1; backends splunk 2.1.0, elasticsearch 2.1.1, kusto 1.0.1)

| case | result |
|---|---|
| correlation file and its base rules given as separate path arguments (`sigma convert ... sigma/web sigma/correlation/x.yml`) | fails for every correlation: `Rule 'web_aipt_http_request_base' not found in rule collection`. pySigma resolves references per path argument (`load_ruleset` calls `resolve_rule_references` before sigma-cli merges the collections) |
| one directory holding the correlation and the four base rules | `Conversion result not available in rule ...` for 5 of the 7 single-stream correlations (Splunk, ES\|QL, EQL); the same rules converted in a fixed order (next row) succeed, so the failure depends on the order in which the files are read |
| one ordered multi-document YAML on stdin (base rule first, `sigma convert -t <target> -`) | converts the 7 single-stream correlations for `splunk`, `esql` and `eql` |
| `correlation_aipt_llm_call_then_target_requests` (`temporal_ordered`, aliases) | not convertible: Splunk `Correlation type 'temporal_ordered' is not supported`, ES\|QL/EQL `Correlation field normalization is not supported` |
| `kusto`, `lucene` | `Backend does not support correlation rules` |
| the whole `sigma/` directory | aborts on the first unsupported correlation, with no partial output |

Where the conversion succeeds, the output is still not equivalent:

- Splunk and ES\|QL output use fixed bins (`bin _time span=...`, `date_trunc(...)`). On Splunk 10.6 the sigma-cli
  output misses fixture and lab bursts that straddle a bin edge (distinct paths, identical requests, empty UA, UA
  rotation), and the chained correlation is absent.
- The ES\|QL output compares the IP placeholder with `==`; on an `ip` field Elasticsearch rejects the query
  (`Cannot convert string [0.0.0.0/32] to [IP]`) unless `sigma/pipelines/aipt-cidr-esql.yaml` is used.
- The EQL output leaves hyphenated field names bare (`sequence by c-ip`: `Unsupported join key`), applies `:` to an
  `ip` field, and renders `value_count` as a join on the counted field (`by cs-user-agent with runs=3`, i.e. the same
  UA three times), which is a different rule.

## Window boundaries

The evaluator and EQL `maxspan` include both ends of the timespan; Splunk `streamstats time_window` (and the KQL
equivalent, written to the same semantics) excludes an event exactly one timespan earlier. Results differ only when a
group's first and last events are exactly one timespan apart to the millisecond (`boundary` dataset of the engine test).
