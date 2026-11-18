# Changelog

All notable changes are documented here. The format follows Keep a Changelog,
and the project uses semantic versioning.

## Unreleased

### Added

- SARIF 2.1.0 report output (`--format sarif`), suitable for GitHub code
  scanning and other SARIF viewers, with deduplicated rule metadata, ATT&CK
  tags, stable fingerprints and bounded evidence locations.

## [0.1.0] - 2026-11-15

### Added

- Streaming detection engine for Linux logs with bounded, per-group
  correlation state.
- Parsers for OpenSSH auth logs, RFC 3164 and RFC 5424 syslog, JSON-lines and
  Linux auditd records, with automatic format detection and a forced-parser
  option.
- 36 bundled Sigma-inspired rules with severity, documented false positives
  and ATT&CK tags, covering 48 techniques across 12 tactics.
- Sliding-window thresholds, distinct-value thresholds and two-stage
  fail-then-success sequences.
- Rule loader, schema validation, semantic linting and ATT&CK coverage checks.
- `scan`, `rules list`, `rules show`, `rules lint`, `rules validate`,
  `explain`, `attack-matrix` and `version` commands.
- Console, JSON-lines, Markdown and standalone HTML reports, plus an HTML
  ATT&CK matrix.
- Suppression windows from the command line or a YAML file.
- `--since`, `--until`, severity filtering, evidence sampling, statistics and
  deterministic exit codes for CI.
- Benign and attack corpora with a reproducible incident scenario.
- Test suite covering parsers, matchers, conditions, correlation, reports,
  CLI behaviour and the packaged rule pack.
- MIT licence, security policy, contribution guide and CI workflow.

[0.1.0]: https://github.com/dev-rudran/argus-detect/releases/tag/v0.1.0
