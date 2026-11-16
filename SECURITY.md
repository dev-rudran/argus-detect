# Security policy

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x | Yes |

`argus` is pre-1.0 software. Security fixes are made on the latest release and
on `main`.

## Reporting a vulnerability

Do not open a public issue for a vulnerability. Report it privately through the
repository's GitHub Security Advisory page, or email
`rudraking2404@gmail.com` with:

- the affected version or commit,
- the input that triggers the problem,
- the expected and observed behaviour,
- any relevant rule or log sample.

You should receive an acknowledgement within a few days. Please allow time for
a fix and a coordinated disclosure before publishing details.

## Scope

`argus` parses untrusted log files. The security-relevant surface is:

- parser handling of malformed, oversized or adversarial log lines,
- regular expressions and globs loaded from rule files,
- HTML escaping and Markdown fence/table handling in reports,
- suppression files and rule files supplied by a user,
- resource use while correlating high-cardinality groups.

The following are not vulnerabilities in `argus` itself:

- a detection rule failing to fire on a log format it does not claim to parse,
- a rule producing a false positive that is documented in its
  `falsepositives` field,
- running with `--rules` pointed at untrusted content, which is equivalent to
  running untrusted code in the same account,
- a report containing the sensitive log lines that were explicitly scanned.

## Operational guidance

- Treat reports as sensitive. They include raw evidence lines.
- Run `argus` with the least privilege needed to read the target logs. It does
  not need root when the files are readable by the service account.
- Review custom rules before use. A pathological regular expression can slow a
  scan; rule loading validates syntax but cannot prove a regex is cheap.
- Keep rules and suppression files in version control and review changes.
- `argus` makes no network connections and does not execute log content.
