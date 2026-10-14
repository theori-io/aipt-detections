# Security policy

## Scope

This repository publishes detection content only: Suricata, Sigma, YARA and ModSecurity rules, conversion settings,
hunting queries and documentation. Internal test scripts and execution data are not distributed. It contains no exploit code and runs no service. The tools it detects are third-party
projects; vulnerabilities in those tools should be reported to their maintainers.

In scope:

- **False positives**: a rule that fires on legitimate software or traffic.
- **Evasions**: a way for a covered tool to avoid a rule that claims to detect it, for example a changed User-Agent,
  path or file name in a newer release.
- **Unsafe content**: anything in the repository that goes beyond fingerprints (payloads, credentials, internal
  addresses).
- **Unsafe deployment behaviour**: unexpected scoring, blocking or query behaviour in the published rules and configuration.

## Reporting privately

Evasion reports and anything that would help an attacker avoid detection should not be filed as public issues.
Use e-mail contact@xint.io. Include:

- the rule id (sid, Sigma `id`, YARA rule name or ModSecurity id) and the release version;
- the tool or software and its exact version or commit;
- a sanitised description of the evidence: header names and values, paths, process or file names, the log line that
  did or did not match. Do not send payloads, captured credentials or customer data.

Ordinary false positives with no evasion value can be reported as public issues with the same information.

We aim to acknowledge reports within five working days and to ship a fix or a documented limitation in the next
release. Reporters are credited in `CHANGELOG.md` unless they ask otherwise.
