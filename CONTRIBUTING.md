# Contributing

Open a pull request with the rule's source, a positive and a near-miss example, and a note on ordinary traffic. False-positive reports
with a sanitised log line are as welcome as new rules. Contact: contact@xint.io.

Contributions of new rules, fixes and false-positive reports are welcome. This repository publishes detection content
only: fingerprints that identify a tool, never attack payloads, exploit code, wordlists or prompt text beyond a few
fixed words. Pull requests that add such material are closed. Internal test code, generators, fixtures, execution
logs and replay infrastructure are not part of this public edition.

## Evidence requirement

Every rule needs a source a reviewer can check:

- **Upstream code**: a commit-pinned URL with file and line (`.../blob/<commit>/path#L123`). Tag or branch links are
  not accepted because they move.
- **Observed traffic or artefacts**: describe the capture or host (tool version, commit, how it was run, which test
  target) and attach a sanitised excerpt: header names and values, paths, process or file names. Run tools only
  against systems you own or are authorised to test, in an isolated network.
- **Documentation only** (README, package metadata): allowed, but the rule must say so in its description and use
  `status: experimental` / `confidence Low`.

State why the indicator does not occur in ordinary traffic. If it can (a common library User-Agent, a generic path, a
well-known port), the rule is generic: mark it as such and keep its severity low.

## Naming and metadata

| format | file | identifier | required metadata |
|---|---|---|---|
| Suricata | `suricata/aipt-<position>.rules` (target-facing, exposed-console, operator-egress, llm-side) | next free sid in the tool's range (README, "Ids, license, contact"); never reuse a retired sid | `msg:"AIPT <Tool> <What>"`, standard `classtype`, `reference:url,`, `sid`, `rev`, `metadata:` affected_product, attack_target, confidence, created_at, deployment, signature_severity, tag ai_pentest, updated_at; one `# source:` comment line above the rule |
| Sigma | `sigma/<logsource dir>/<prefix>_<tool>_<what>.yml` (SigmaHQ prefixes: `web_`, `proxy_`, `zeek_`, `proc_creation_lnx_`, `file_event_lnx_`, `net_connection_lnx_`, `correlation_`) | new uuid4 `id`, unique `name` | Title Case `title` (110 characters max), `status`, one-paragraph `description`, commit-pinned `references`, `author`, `date`, `modified`, ATT&CK `tags`, standard taxonomy fields, `falsepositives`, `level`; generic rules carry the approved-assessment filter (see `sigma/placeholders.yaml`) |
| YARA | `yara/aipt_artex.yar` or `yara/aipt_family.yar` | `AIPT_<Tool>_<What>` | `description`, `author`, `reference`, `date`, `modified`, `score`, `hash` of a sample where one exists, `license`; `$x*` high-confidence and `$s*` supporting strings, a file-size cap, no rule that fires on one generic string |
| ModSecurity | `modsecurity/aipt-before.conf` | next free id in the plugin sub-range (9590100-9590999) | `msg:'AIPT: ...'`, `tag:'aipt'`, `tag:'aipt/<tool>'`, `tag:'paranoia-level/N'`, `ver:'aipt-plugin/<version>'`, CRS `severity`; phase 1 for request headers, phase 4 for response bodies; no hard `deny` |

Changing an existing rule: keep its id, bump Suricata `rev` / Sigma `modified` / YARA `modified`, and record the reason
in the pull request. Retiring a Suricata sid: move it to `suricata/retired.rules` with the reason; never reuse it.

## Validation evidence

Include sanitised positive and near-miss examples in the pull request, together with the exact engine or backend
version, validation commands, expected result and actual result. Use synthetic addresses, example hosts and
placeholder credentials. Do not commit internal test suites, captures, corpora, logs or customer data.

For correlations, cover the grouping keys, window boundaries and assessment exemptions. For ModSecurity, verify that
observe-only matches do not add an AIPT score, unrelated CRS-positive requests still block, and explicit scoring opt-in
has the documented effect. YARA changes need file or process-memory checks according to the rule's scope.

## Quality bar

This public edition has no Makefile or test CI. Contributors must provide their own validation evidence; an unavailable
engine is a pending check, not a pass.

| format | validation evidence |
|---|---|
| Suricata | syntax/load check on the target version, positive replay and benign near miss; retain `alert` defaults |
| Sigma | schema validation and conversion with the intended backend and field mappings; execute representative positive and negative cases |
| YARA | compilation and positive/negative checks in the intended file or memory scope |
| ModSecurity | plugin load, observe-only behaviour, existing CRS protection and explicit scoring opt-in |
| all | unique IDs, matching `RULES.md` entries, documented false-positive sources and no undocumented enforcement changes |

## Publication boundary

Keep internal validation assets in a private development copy. The public tree contains rules, conversion settings,
queries and documentation only. `.gitignore` prevents untracked files from being added normally; it does not remove
tracked files or previous commits. Publish a clean rules-only snapshot rather than pushing private development
history. Do not commit release patches: deletion diffs contain the removed internal code.

## Pull request checklist

- [ ] Source is commit-pinned or the capture is described; indicator is fingerprint level, no payload or prompt text.
- [ ] File name, id range, `msg`/`title` and metadata follow the table above; no retired id reused.
- [ ] Generic rules are marked generic, low severity, and honour the approved-assessment exemption.
- [ ] Sanitised positive and near-miss examples, engine versions, commands and results included in the pull request.
- [ ] Applicable engine checks completed or explicitly marked pending; `RULES.md` updated.
- [ ] No internal code, captures, logs, addresses, host names, credentials or local paths in the public tree.
- [ ] `CHANGELOG.md` updated under `[Unreleased]`.

By contributing you agree that your contribution is licensed under the Detection Rule License 1.1 (see `LICENSE`).
