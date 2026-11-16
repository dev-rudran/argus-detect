# Detection catalogue

The bundled pack contains 36 rules. They cover 48 techniques across 12 ATT&CK
tactics, and every catalogued technique has at least one rule.

```console
$ argus rules validate
36 rules valid
$ argus rules lint

36 rules checked, 0 error(s), 0 warning(s)
$ argus attack-matrix
argus 0.1.0 ATT&CK coverage
36 rules cover 48/48 catalogued techniques (100.0%)
```

Coverage is a statement about the rule pack, not about a specific host. Tune
thresholds against your own baseline before enabling `--fail-on` in a
production pipeline.

## Rule index

| ID | Rule | Severity | Logsource | Primary signal | ATT&CK |
|---|---|---|---|---|---|
| ARGUS-0001 | SSH brute force from a single source | high | linux/sshd | 6 or more failed SSH authentications from one address in 2 minutes | T1110, T1110.001 |
| ARGUS-0002 | Distributed SSH brute force against one account | high | linux/sshd | 10 or more failures for one account across sources in 5 minutes | T1110, T1110.001 |
| ARGUS-0003 | SSH password spray across many accounts | high | linux/sshd | Failures from one address against 6 or more distinct users in 5 minutes | T1110, T1110.003 |
| ARGUS-0004 | SSH login succeeds after repeated failures | critical | linux/sshd | 3 or more failures followed by a success from one address in 10 minutes | T1078, T1110.001, T1021, T1021.004 |
| ARGUS-0005 | Direct SSH login as root | high | linux/sshd | Successful SSH authentication as root | T1078, T1021, T1021.004 |
| ARGUS-0006 | New local user account created | medium | linux/auth | `useradd`, `adduser` or equivalent account creation | T1136, T1136.001 |
| ARGUS-0007 | Privileged group membership changed | high | linux/auth | Membership change in sudo, wheel, adm, docker, disk, shadow or root | T1098 |
| ARGUS-0008 | Sudo used to spawn a shell | high | linux/auth | Sudo command that launches an interactive shell | T1548, T1548.003 |
| ARGUS-0009 | Sudoers configuration modified | high | linux/auth | Write or edit under `/etc/sudoers` or `/etc/sudoers.d` | T1548, T1548.003 |
| ARGUS-0010 | Cron persistence installed | high | linux/auth | Crontab or cron directory changed | T1053, T1053.003 |
| ARGUS-0011 | Suspicious command in a scheduled job | medium | linux/cron | Cron command that downloads, decodes or executes a remote payload | T1053, T1053.003 |
| ARGUS-0012 | Systemd service persistence | high | linux/systemd | New or enabled systemd service unit | T1543, T1543.002 |
| ARGUS-0013 | Systemd timer persistence | medium | linux/systemd | New or enabled systemd timer unit | T1053, T1053.006 |
| ARGUS-0014 | System log clearing or truncation | high | linux/auth | `truncate`, `journalctl --vacuum` or direct log deletion | T1070, T1070.002 |
| ARGUS-0015 | Audit daemon or audit rules tampered with | high | linux/auditd | Audit service stop, disable or rules reload | T1562, T1562.001 |
| ARGUS-0016 | Host firewall disabled or flushed | high | linux/auth | `ufw disable`, `iptables -F` or nftables flush | T1562, T1562.004 |
| ARGUS-0017 | SUID or SGID bit set on a file | high | linux/auth | `chmod` that adds the SUID or SGID bit | T1222, T1222.002 |
| ARGUS-0018 | Shadow password file accessed | critical | linux/auditd | Read or write of `/etc/shadow` | T1003, T1552.001 |
| ARGUS-0019 | SSH authorized_keys modified | high | linux/auth | Write to an SSH `authorized_keys` file | T1098, T1098.004 |
| ARGUS-0020 | Reverse shell command executed | critical | linux/auth | Shell, netcat or socat reverse-shell construction | T1059, T1059.004 |
| ARGUS-0021 | Periodic C2 beacon pattern over HTTP | high | nginx/http | 6 or more small POST requests to one public host and path in 10 minutes | T1071, T1071.001 |
| ARGUS-0022 | Large outbound HTTP transfer | high | nginx/http | 50 MB or more in a single outbound request | T1041 |
| ARGUS-0023 | Outbound connection to an unusual port | medium | linux/network | Connection to a public address on a non-standard port | T1571 |
| ARGUS-0024 | Network service discovery from one host | medium | linux/network | 15 or more distinct destination ports from one source in 2 minutes | T1046 |
| ARGUS-0025 | Suspicious tool download over HTTP | medium | nginx/http | Download of `.sh`, `.py`, `.elf`, `.bin`, archive or similar payload | T1105 |
| ARGUS-0026 | Kernel module loaded | medium | linux/auth | `insmod`, `modprobe` or module load record | T1547, T1547.006, T1014 |
| ARGUS-0027 | Package installation through a privileged command | medium | linux/auth | Package manager invoked through sudo or a privileged context | T1195, T1195.002 |
| ARGUS-0028 | Security service stopped | high | linux/systemd | Stop of SSH, audit, firewall, AppArmor, fail2ban or journald | T1489, T1562.001 |
| ARGUS-0029 | System shutdown or reboot initiated | low | linux/systemd | Shutdown, reboot or halt request | T1529 |
| ARGUS-0030 | USB mass storage device connected | low | linux/kernel | USB mass-storage enumeration | T1200 |
| ARGUS-0031 | Credential file read | high | linux/auth | Access to a credential or secret file | T1552, T1552.001 |
| ARGUS-0032 | PAM authentication configuration modified | high | linux/auth | Write to PAM configuration | T1556 |
| ARGUS-0033 | Shell history or data integrity tampering | medium | linux/auth | History file deletion or shell history manipulation | T1070.003, T1565 |
| ARGUS-0034 | Bulk mailbox access | medium | mail/mailbox | 3 or more mailbox reads by one account in 5 minutes | T1114 |
| ARGUS-0035 | Resource hijacking process started | high | linux/process | Known miner process names starting | T1496 |
| ARGUS-0036 | Interactive su to root | low | linux/auth | Successful `su` to root | T1548, T1548.003 |

The ATT&CK column lists techniques and sub-techniques. Tactic membership is
derived from the built-in catalogue and is shown by `argus attack-matrix`.

## Coverage by tactic

| Tactic | Covered | Techniques in catalogue |
|---|---:|---:|
| Initial Access | 4 | 4 |
| Execution | 5 | 5 |
| Persistence | 13 | 13 |
| Privilege Escalation | 12 | 12 |
| Defense Evasion | 13 | 13 |
| Credential Access | 7 | 7 |
| Discovery | 1 | 1 |
| Lateral Movement | 2 | 2 |
| Collection | 1 | 1 |
| Command and Control | 4 | 4 |
| Exfiltration | 1 | 1 |
| Impact | 4 | 4 |

Techniques can belong to more than one tactic, so the tactic totals are larger
than the 48 unique techniques in the catalogue.

## Example corpus

`examples/logs/attack/` is a single-host intrusion story: external brute force,
a successful login, privileged discovery, credential access, persistence,
defense evasion and a reverse shell. A scan of the directory fires all 36 rules
and produces 43 alerts because several rules fire for more than one group.

```console
$ argus scan examples/logs/attack --format jsonl --min-severity informational --year 2026 | wc -l
43
```

The exact critical findings and the full story are in
[../examples/scenario-breach.md](../examples/scenario-breach.md).

`examples/logs/benign/` contains normal logins, sudo administration, cron
maintenance, package updates and application traffic. It produces no alerts at
or above medium:

```console
$ argus scan examples/logs/benign --min-severity medium --year 2026
argus 0.1.0  detection report
rules 36  |  events 88  |  files 3  |  malformed 0
window 2026-11-03 03:00:01 .. 2026-11-06 17:30:11 UTC

No alerts at or above medium.
Summary
  no alerts
```

## Tuning notes

- Rules that correlate on `user` or `host` can be noisy on shared jump hosts.
  Group on a more specific field or add a suppression for the known source.
- ARGUS-0005 (direct root login) is high by design. If your policy permits root
  SSH from a bastion, suppress that group rather than lowering the rule.
- ARGUS-0021 depends on HTTP logs carrying `bytes_out`, `dest_host` and `path`.
  Confirm the shipper populates those fields before relying on it.
- ARGUS-0023 has an allow-list filter for common outbound ports. Extend the
  filter for your environment instead of disabling the rule.
- ARGUS-0030 is low severity because USB storage is legitimate on many
  workstations. Escalate it only in contexts where removable media is banned.
