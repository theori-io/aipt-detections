# Changelog

Rule ids are never changed or reused; a changed Suricata rule bumps its `rev`, a changed Sigma or YARA rule its
`modified` date.

## Unreleased

- Public packaging: exclude internal Python utilities, tests, generators, replay configuration, logs, Makefile and test CI.
- Retain the false-positive methodology and aggregate tables in `docs/fp-report.md`, with the limits of public reproducibility stated.
- Add internal-trial and staged-enforcement warnings, including text for the report body.
- Update references after removing internal tools. Detection expressions, thresholds and enforcement defaults are unchanged.

## 1.0.0 - initial release - 2026-10-12

- Suricata: 82 sids in four files split by sensor position (`aipt-target-facing`, `aipt-exposed-console`,
  `aipt-operator-egress`, `aipt-llm-side`), every action `alert`, the `artex-ui-assets.md5` list for sid 9500060, a
  threshold.config template for sanctioned assessments and `aipt-block-eligible.sids` (36 sids that are candidates
  for a per-sensor drop conversion after the observe-mode baseline of DEPLOYMENT.md). Console client rules depend on
  an `xbits` flag set by a console response fingerprint on the same IP pair. Sids reserved for indicators that
  matched ordinary traffic or that a network sensor cannot see are listed in `suricata/retired.rules` and never
  reused.
- Sigma: 54 detection rules and 8 Sigma v2 correlations (SigmaHQ file names and conventions, proxy taxonomy field
  names), five correlation base selectors that are never deployed stand-alone, `placeholders.yaml`,
  the conversion pipeline `pipelines/aipt-placeholders.yaml`, CIDR-aware pipelines for Splunk,
  Kusto and ES|QL, and `pipelines/aipt-webserver-asim.yaml` (webserver field names to ASIM WebSession columns for
  Sentinel). Correlations count cookie-bearing requests like any other.
- YARA: 13 file rules in `aipt_artex.yar` and `aipt_family.yar` and 6 strings-only `*_Mem` variants in
  `aipt_memory.yar` for live process scans.
- ModSecurity: OWASP CRS v4 plugin (`aipt-config.conf`, `aipt-before.conf`) in the id range 9590000-9590999 with
  24 alerting rules, observe-only as shipped: anomaly scoring is opt-in per direction (switch 9590015 inbound for the
  five product User-Agent rules, 9590013 outbound for the ARTEX console response).
- Analytics: KQL and SPL hunting queries, sliding-window equivalents of the eight correlations for Splunk,
  Elasticsearch and Sentinel (IPv6-aware, null-safe allowlists and time-bounded joins in KQL). Internal behavioural
  feature extraction and regression tooling are not distributed in this public edition.
- Blocking policy tiers `block-eligible` / `alert` / `informational` on every rule, measured on the synthetic benign
  corpus (`docs/fp-report.md`); DEPLOYMENT.md for observation points, telemetry requirements, exemptions and the
  rollout checklist.
- Internal validation included static checks, Sigma/YARA/Suricata fixtures, backend mapping and policy checks,
  synthetic false-positive measurements and functional Kusto emulator cases. The tools and logs are not part of the
  public edition; README.md records the reported validation scope.
