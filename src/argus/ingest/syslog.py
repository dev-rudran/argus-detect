"""Syslog parsing and semantic classification.

The parser understands RFC 3164 (with an optional year), RFC 5424 and modern
ISO-8601-prefixed syslog lines. Daemon messages are normalized into an
``action`` list plus fields used by detection rules.
"""

from __future__ import annotations

import re
from datetime import datetime

from argus.ingest.base import BaseParser
from argus.models import Event
from argus.util.timeparse import UTC, TimeParseError, YearResolver, parse_timestamp

_MONTHS = {
    "jan": 1,
    "feb": 2,
    "mar": 3,
    "apr": 4,
    "may": 5,
    "jun": 6,
    "jul": 7,
    "aug": 8,
    "sep": 9,
    "oct": 10,
    "nov": 11,
    "dec": 12,
}

_RFC5424_RE = re.compile(
    r"^(?:<(?P<pri>\d{1,3})>)?(?P<version>1) (?P<ts>\S+) (?P<host>\S+) "
    r"(?P<app>\S+) (?P<proc>\S+) (?P<msgid>\S+) (?P<sd>-|\[[^\]]*\])"
    r"(?: (?P<msg>.*))?$"
)
_ISO_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?"
    r"(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<host>\S+)\s+(?P<rest>.*)$"
)
_RFC3164_WITH_YEAR_RE = re.compile(
    r"^(?P<year>\d{4})\s+(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})(?P<frac>\.\d+)?\s+(?P<host>\S+)\s+(?P<rest>.*)$"
)
_RFC3164_RE = re.compile(
    r"^(?P<mon>[A-Za-z]{3})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})(?P<frac>\.\d+)?\s+(?P<host>\S+)\s+(?P<rest>.*)$"
)
_PROGRAM_RE = re.compile(
    r"^(?P<program>[A-Za-z0-9_./@-]+)(?:\[(?P<pid>\d+)\])?:\s?(?P<message>.*)$"
)
_PRI_RE = re.compile(r"^<(?P<pri>\d{1,3})>")

_SSH_FAILED_RE = re.compile(
    r"Failed (?P<method>password|publickey|keyboard-interactive(?:/pam)?|none) for "
    r"(?P<invalid>invalid user )?(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_SSH_INVALID_RE = re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>\S+)")
_SSH_ACCEPTED_RE = re.compile(
    r"Accepted (?P<method>password|publickey|keyboard-interactive(?:/pam)?|gssapi-with-mic) for "
    r"(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)(?: ssh2)?"
    r"(?:: (?P<key_type>[A-Za-z0-9-]+) (?P<fingerprint>\S+))?"
)
_SSH_MAX_RE = re.compile(
    r"(?:error: )?maximum authentication attempts exceeded for "
    r"(?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_SSH_SESSION_RE = re.compile(r"session (?P<state>opened|closed) for user (?P<user>\S+)")
_SSH_DISCONNECT_RE = re.compile(
    r"(?:Disconnected from|Connection closed by|Received disconnect from) "
    r"(?:authenticating user )?(?P<user>\S+) (?P<ip>\S+) port (?P<port>\d+)"
)
_SSH_DISCONNECT_IP_RE = re.compile(
    r"(?:Connection closed by|Received disconnect from) (?P<ip>\S+) port (?P<port>\d+)"
)

_SUDO_RE = re.compile(
    r"^(?P<user>[^\s:]+)\s+:\s+TTY=(?P<tty>\S+)\s*;\s*PWD=(?P<pwd>.*?)\s*;\s*"
    r"USER=(?P<target>\S+)\s*;\s*COMMAND=(?P<command>.*)$"
)
_SU_BY_RE = re.compile(r"(?P<state>Successful|FAILED) su for (?P<target>\S+) by (?P<user>[^\s(]+)")
_SU_PAM_RE = re.compile(
    r"pam_unix\(su(?:-l)?:(?:session|auth)\): .*?(?:user=(?P<target>\S+))?"
    r"(?:.*?by (?P<user>[^\s(]+))?"
)
_CRON_RE = re.compile(r"^\((?P<user>[^)]+)\)\s+CMD\s+\((?P<command>.*)\)$")
_UNIT = r"(?P<unit>[\w@:.-]+\.(?:service|socket|timer|target|mount|automount|path|slice|scope))"
_SYSTEMD_STARTED_RE = re.compile(r"^Started " + _UNIT + r"\.?$")
_SYSTEMD_STOPPING_RE = re.compile(r"^Stopping " + _UNIT + r"\.{0,3}$")
_SYSTEMD_STOPPED_RE = re.compile(r"^Stopped " + _UNIT + r"\.?$")
_SYSTEMD_STARTING_RE = re.compile(r"^Starting " + _UNIT + r"\.{0,3}$")
_SYSTEMD_RELOAD_RE = re.compile(r"^Reloading " + _UNIT + r"\.{0,3}$")
_SYSTEMD_FAILED_RE = re.compile(r"^Failed to start " + _UNIT + r"\.?$")
_USERADD_RE = re.compile(r"new user: name=(?P<user>[^,\s]+)")
_USERMOD_GROUP_RE = re.compile(r"add '(?P<user>[^']+)' to group '(?P<group>[^']+)'")
_GROUPADD_RE = re.compile(r"group added to /etc/group: name=(?P<group>[^,\s]+)")
_PASSWD_RE = re.compile(r"password changed for (?P<user>\S+)")
_USBDEL_RE = re.compile(r"delete user '(?P<user>[^']+)'")

_PACKAGE_RE = re.compile(
    r"\b(?:apt(?:-get)?|aptitude)\s+(?:install|reinstall)\b|\bdpkg\s+-i\b|"
    r"\b(?:yum|dnf)\s+install\b|\bpip3?\s+install\b|\bnpm\s+(?:install|i)\s+-g\b|"
    r"\bsnap\s+install\b|\bpacman\s+-S\b"
)
_SUID_RE = re.compile(r"\bchmod\s+(?:[ugoa]*\+s|[0-7]?[4-7][0-7]{2})\b|\bsetcap\s+cap_setuid")
_REVERSE_SHELL_RE = re.compile(
    r"/dev/tcp/|\bnc(?:at)?\b[^;&|]*\s-e\s|\bsocat\b[^;&|]*\bexec\b|"
    r"\b(?:bash|sh|zsh)\s+-i\b|\bpython[0-9.]*\s+-c\b[^;&|]*(?:socket|pty\.spawn)|"
    r"\bperl\s+-e\b[^;&|]*(?:socket|IO::Socket)|mkfifo\b[^;&|]*\bnc\b"
)
_LOG_CLEAR_RE = re.compile(
    r"\brm\s+[^;&|]*?/var/log|\btruncate\s+[^;&|]*?/var/log|"
    r"\bshred\s+[^;&|]*?/var/log|>\s*/var/log|journalctl\s+--vacuum|"
    r"\bdmesg\s+-c\b|find\s+/var/log[^;&|]*-delete|\brm\s+-rf\s+/var/log"
)
_LOG_READ = (
    r"\b(?:cat|less|more|head|tail|cp|scp|rsync|strings|xxd|base64|grep|awk|sed|sort|uniq)\b"
)
_SHADOW_RE = re.compile(_LOG_READ + r"[^;&|]*/etc/(?:g?shadow|security/opasswd)")
_SECRET_RE = re.compile(
    _LOG_READ + r"[^;&|]*(?:\.aws/credentials|\.ssh/id_(?:rsa|dsa|ecdsa|ed25519)|"
    r"\.docker/config\.json|\.kube/config|\.netrc|\.pgpass|\.env(?:\b|/))"
)
_SSH_KEY_RE = re.compile(r"authorized_keys|\.ssh/authorized_keys2")
_HISTORY_RE = re.compile(
    r"\bhistory\s+-c\b|unset\s+HISTFILE|\.bash_history|HISTSIZE=0|HISTFILESIZE=0"
)
_PAM_RE = re.compile(r"/etc/pam\.d|pam-auth-update|authconfig|/etc/security/pwquality")
_AUDIT_TAMPER_RE = re.compile(
    r"auditctl\s+-(?:d|e\s*0)|/etc/audit/|systemctl\s+(?:stop|disable|mask)\s+auditd|"
    r"service\s+auditd\s+stop|auditd\s+-s\s+disable"
)
_FIREWALL_RE = re.compile(
    r"\bufw\s+disable\b|\bip6?tables\s+-f\b|\bnft\s+flush\b|"
    r"systemctl\s+(?:stop|disable|mask)\s+(?:firewalld|ufw|nftables)|"
    r"service\s+(?:firewalld|ufw)\s+stop"
)
_MODULE_RE = re.compile(r"\b(?:insmod|modprobe)\s+\S+")
_SHELL_RE = re.compile(r"(?:^|[/\s])(?:bash|sh|zsh|dash|ksh)(?:\s|$)")
_TMP_TRANSFER_RE = re.compile(
    r"\b(?:curl|wget)\b[^;&|]*(?:https?://)[^;&|]*(?:/tmp/|\.sh\b|\.elf\b|\.bin\b)"
)
_SHUTDOWN_RE = re.compile(r"\b(?:shutdown|reboot|halt|poweroff)\b")
_GROUP_ADD_CMD_RE = re.compile(
    r"usermod\s+[^;&|]*-aG\s+(?P<group>[^\s]+)|gpasswd\s+-a\s+\S+\s+(?P<group2>[^\s]+)"
)
_SYSTEMCTL_STOP_RE = re.compile(
    r"systemctl\s+(?:stop|disable|mask)\s+(?:--now\s+)?(?P<unit>[\w@.:-]+)"
)
_SERVICE_STOP_RE = re.compile(r"service\s+(?P<unit>[\w@.:-]+)\s+stop")
_SYSTEMCTL_ENABLE_RE = re.compile(
    r"systemctl\s+(?:enable|reenable|link)\s+(?:--now\s+)?(?P<unit>[\w@.:-]+)"
)
_SYSTEMD_UNIT_WRITE_RE = re.compile(r"/etc/systemd/system/[^\s;&|]+\.(?P<kind>service|timer)")


def _add(actions: list[str], *values: str) -> None:
    for value in values:
        if value and value not in actions:
            actions.append(value)


def _normalize_unit(value: str) -> str:
    unit = value.strip().strip("'\"")
    if not unit:
        return unit
    suffixes = (".service", ".socket", ".timer", ".target", ".mount", ".path", ".slice", ".scope")
    if not unit.endswith(suffixes):
        unit += ".service"
    return unit


def derive_command_actions(command: str) -> list[str]:
    """Derive semantic actions from a sudo or shell command line."""
    actions: list[str] = []
    text = command or ""
    lower = text.lower()

    if re.search(r"/etc/sudoers|visudo", lower):
        _add(actions, "sudoers_change")
    if _AUDIT_TAMPER_RE.search(lower):
        _add(actions, "audit_tamper")
    if _FIREWALL_RE.search(lower):
        _add(actions, "firewall_disabled")
    if _LOG_CLEAR_RE.search(lower):
        _add(actions, "log_cleared")
    if re.search(r"crontab\s+(?:-e|-r\b)|/etc/cron|/var/spool/cron", lower):
        _add(actions, "cron_persistence")
    match = _SYSTEMD_UNIT_WRITE_RE.search(lower) or _SYSTEMCTL_ENABLE_RE.search(lower)
    if match is not None:
        if match.groupdict().get("kind"):
            kind = match.group("kind")
        else:
            unit = _normalize_unit(match.group("unit"))
            kind = "timer" if unit.endswith(".timer") else "service"
        _add(actions, "systemd_timer_persistence" if kind == "timer" else "systemd_persistence")
    if _SSH_KEY_RE.search(lower):
        _add(actions, "ssh_key_added")
    if _SHADOW_RE.search(lower):
        _add(actions, "shadow_access")
    if _SECRET_RE.search(lower):
        _add(actions, "secret_file_access")
    if _SUID_RE.search(lower):
        _add(actions, "suid_change")
    if _MODULE_RE.search(lower):
        _add(actions, "module_load")
    if _PACKAGE_RE.search(lower):
        _add(actions, "package_install")
    if _REVERSE_SHELL_RE.search(lower):
        _add(actions, "reverse_shell")
    if _HISTORY_RE.search(lower):
        _add(actions, "history_cleared")
    if _PAM_RE.search(lower):
        _add(actions, "pam_change")
    if _TMP_TRANSFER_RE.search(lower):
        _add(actions, "tool_transfer")
    if _SHUTDOWN_RE.search(lower):
        _add(actions, "system_shutdown")
    group_match = _GROUP_ADD_CMD_RE.search(text)
    if group_match:
        _add(actions, "group_member_added")
    if re.search(r"\b(?:useradd|adduser)\b", lower):
        _add(actions, "user_created")

    unit_match = _SYSTEMCTL_STOP_RE.search(lower) or _SERVICE_STOP_RE.search(lower)
    if unit_match:
        _add(actions, "service_stopped")

    # Shell escalation. Interactive shells and shell -c commands both qualify;
    # rules that care about reverse shells filter those out explicitly.
    first = text.strip().split()[0] if text.strip() else ""
    if (
        _SHELL_RE.search(first)
        and re.search(r"(?:^|[/\s])(?:bash|sh|zsh|dash|ksh)\s+(?:-[-a-z]*[ci]|$)", lower)
    ) or re.search(r"(?:^|\s)su\s+-\s*$", lower):
        _add(actions, "sudo_shell")
    return actions


def _extract_unit(command: str) -> str:
    match = _SYSTEMCTL_STOP_RE.search(command) or _SERVICE_STOP_RE.search(command)
    return _normalize_unit(match.group("unit")) if match else ""


class SyslogParser(BaseParser):
    """RFC 3164/5424/ISO syslog parser with daemon-specific normalization."""

    log_type = "syslog"

    def __init__(
        self,
        year: int | None = None,
        default_timestamp: datetime | None = None,
        log_type: str = "syslog",
    ) -> None:
        super().__init__(year=year, default_timestamp=default_timestamp)
        self.log_type = log_type
        self.resolver = YearResolver(year=year)

    def parse_line(self, line: str, line_no: int, source: str) -> Event | None:
        text = self.clean(line)
        if not text.strip():
            return None
        priority: int | None = None
        pri_match = _PRI_RE.match(text)
        if pri_match:
            priority = int(pri_match.group("pri"))
            if priority > 191:
                return None
            text = text[pri_match.end() :].lstrip()

        parsed = self._parse_prefix(text)
        if parsed is None:
            return None
        timestamp, host, rest, rfc5424 = parsed
        if timestamp is None:
            return None

        program = ""
        pid = ""
        message = rest
        rfc_match = _RFC5424_RE.match(text)
        if rfc_match:
            program = "" if rfc_match.group("app") == "-" else rfc_match.group("app")
            pid = "" if rfc_match.group("proc") == "-" else rfc_match.group("proc")
            message = rfc_match.group("msg") or ""
        else:
            program_match = _PROGRAM_RE.match(rest)
            if program_match:
                program = program_match.group("program")
                pid = program_match.group("pid") or ""
                message = program_match.group("message")

        fields: dict[str, object] = {
            "host": "" if host in {"-", ""} else host,
            "program": program,
            "pid": pid,
            "message": message,
        }
        if priority is not None:
            fields["syslog_priority"] = priority
            fields["syslog_facility"] = priority // 8
            fields["syslog_severity"] = priority % 8
        if rfc5424:
            fields["message_id"] = rfc_match.group("msgid") if rfc_match else ""

        actions: list[str] = []
        self._classify(program, message, fields, actions)
        if not actions:
            _add(actions, "syslog_message")
        fields["action"] = actions
        # Normalize common aliases once so rules can stay simple.
        if "target_user" in fields and "user" not in fields:
            fields["user"] = fields["target_user"]
        for key in ("user", "src_ip", "command", "unit"):
            value = fields.get(key)
            if isinstance(value, str) and value in {"-", "unknown"}:
                fields[key] = ""
        return Event(
            timestamp=timestamp,
            fields=fields,
            raw=self.clean(line),
            source=source,
            line_no=line_no,
            log_type=self.log_type,
        )

    def _parse_prefix(self, text: str) -> tuple[datetime | None, str, str, bool] | None:
        rfc_match = _RFC5424_RE.match(text)
        if rfc_match:
            try:
                timestamp = parse_timestamp(rfc_match.group("ts"))
            except TimeParseError:
                return None
            return timestamp, rfc_match.group("host"), "", True

        iso_match = _ISO_RE.match(text)
        if iso_match:
            raw_ts = iso_match.group("ts").replace(",", ".")
            try:
                timestamp = parse_timestamp(raw_ts)
            except TimeParseError:
                return None
            rest = iso_match.group("rest")
            return timestamp, iso_match.group("host"), rest, False

        year_match = _RFC3164_WITH_YEAR_RE.match(text)
        if year_match:
            timestamp = self._build_syslog_datetime(
                int(year_match.group("year")),
                year_match.group("mon"),
                int(year_match.group("day")),
                year_match.group("time"),
                year_match.group("frac"),
                explicit_year=True,
            )
            return timestamp, year_match.group("host"), year_match.group("rest"), False

        legacy_match = _RFC3164_RE.match(text)
        if legacy_match:
            timestamp = self._build_syslog_datetime(
                None,
                legacy_match.group("mon"),
                int(legacy_match.group("day")),
                legacy_match.group("time"),
                legacy_match.group("frac"),
                explicit_year=False,
            )
            return timestamp, legacy_match.group("host"), legacy_match.group("rest"), False
        return None

    def _build_syslog_datetime(
        self,
        year: int | None,
        month_name: str,
        day: int,
        time_text: str,
        fraction: str | None,
        *,
        explicit_year: bool,
    ) -> datetime | None:
        month = _MONTHS.get(month_name.lower())
        if month is None:
            return None
        hour, minute, second = (int(part) for part in time_text.split(":"))
        try:
            if explicit_year and year is not None:
                timestamp = datetime(
                    year,
                    month,
                    day,
                    hour,
                    minute,
                    second,
                    microsecond=int(float(fraction or 0) * 1_000_000),
                    tzinfo=UTC,
                )
                self.resolver._last = timestamp
            else:
                timestamp = self.resolver.resolve(month, day, hour, minute, second)
                timestamp = timestamp.replace(microsecond=int(float(fraction or 0) * 1_000_000))
        except (ValueError, TimeParseError):
            return None
        return timestamp

    def _classify(
        self,
        program: str,
        message: str,
        fields: dict[str, object],
        actions: list[str],
    ) -> None:
        program_lower = program.lower()
        if program_lower.startswith("sshd") or any(
            marker in message
            for marker in ("Failed password for", "Accepted publickey for", "Invalid user ")
        ):
            self._classify_ssh(message, fields, actions)
        if program_lower == "sudo" or message.startswith("sudo:"):
            self._classify_sudo(message, fields, actions)
        if program_lower in {"su", "su-l"} or message.startswith("su:"):
            self._classify_su(message, fields, actions)
        if program_lower in {"cron", "crond", "anacron"}:
            self._classify_cron(message, fields, actions)
        if program_lower.startswith("systemd") or program_lower == "systemd-logind":
            self._classify_systemd(program_lower, message, fields, actions)
        if program_lower in {
            "useradd",
            "usermod",
            "groupadd",
            "groupmod",
            "userdel",
            "passwd",
            "chage",
            "gpasswd",
        }:
            self._classify_accounts(program_lower, message, fields, actions)
        if program_lower == "kernel":
            self._classify_kernel(message, fields, actions)

    def _classify_ssh(self, message: str, fields: dict[str, object], actions: list[str]) -> None:
        match = _SSH_FAILED_RE.search(message)
        if match:
            _add(actions, "ssh_auth_failed")
            fields["user"] = match.group("user")
            fields["src_ip"] = match.group("ip")
            fields["src_port"] = int(match.group("port"))
            fields["auth_method"] = match.group("method")
            fields["invalid_user"] = bool(match.group("invalid"))
            return
        match = _SSH_INVALID_RE.search(message)
        if match:
            _add(actions, "ssh_invalid_user")
            fields["user"] = match.group("user")
            fields["src_ip"] = match.group("ip")
            fields["invalid_user"] = True
            return
        match = _SSH_ACCEPTED_RE.search(message)
        if match:
            _add(actions, "ssh_auth_success")
            fields["user"] = match.group("user")
            fields["src_ip"] = match.group("ip")
            fields["src_port"] = int(match.group("port"))
            fields["auth_method"] = match.group("method")
            if match.group("key_type"):
                fields["key_type"] = match.group("key_type")
            if match.group("fingerprint"):
                fields["fingerprint"] = match.group("fingerprint")
            return
        match = _SSH_MAX_RE.search(message)
        if match:
            _add(actions, "ssh_auth_failed", "ssh_max_auth")
            fields["user"] = match.group("user")
            fields["src_ip"] = match.group("ip")
            fields["src_port"] = int(match.group("port"))
            return
        match = _SSH_SESSION_RE.search(message)
        if match:
            _add(
                actions,
                "ssh_session_opened" if match.group("state") == "opened" else "ssh_session_closed",
            )
            fields["user"] = match.group("user")
            return
        match = _SSH_DISCONNECT_RE.search(message)
        if match:
            _add(actions, "ssh_disconnected")
            value = match.group("user")
            if (value and value[0].isdigit()) or ":" in value:
                fields["src_ip"] = value
                if match.group("ip"):
                    fields["src_ip"] = match.group("ip")
            else:
                fields["user"] = value
                fields["src_ip"] = match.group("ip")
            return
        match = _SSH_DISCONNECT_IP_RE.search(message)
        if match:
            _add(actions, "ssh_disconnected")
            fields["src_ip"] = match.group("ip")

    def _classify_sudo(self, message: str, fields: dict[str, object], actions: list[str]) -> None:
        text = message[5:].lstrip() if message.startswith("sudo:") else message
        match = _SUDO_RE.match(text)
        if match:
            command = match.group("command")
            _add(actions, "sudo_command")
            fields["user"] = match.group("user")
            fields["target_user"] = match.group("target")
            fields["command"] = command
            fields["tty"] = match.group("tty")
            fields["pwd"] = match.group("pwd")
            unit = _extract_unit(command)
            if unit:
                fields["unit"] = unit
            for action in derive_command_actions(command):
                _add(actions, action)
            return
        if "session opened" in message:
            _add(actions, "sudo_session")

    def _classify_su(self, message: str, fields: dict[str, object], actions: list[str]) -> None:
        match = _SU_BY_RE.search(message)
        if match:
            _add(actions, "su_success" if match.group("state") == "Successful" else "su_failed")
            fields["target_user"] = match.group("target")
            fields["user"] = match.group("user")
            return
        if "session opened" in message:
            _add(actions, "su_session")
        elif "authentication failure" in message:
            _add(actions, "su_failed")
        target = re.search(r"user=(?P<user>\S+)", message)
        if target:
            fields["target_user"] = target.group("user")

    def _classify_cron(self, message: str, fields: dict[str, object], actions: list[str]) -> None:
        match = _CRON_RE.match(message)
        if match:
            user = match.group("user")
            if user.lower() == "cron":
                _add(actions, "cron_info")
            else:
                _add(actions, "cron_command")
                fields["user"] = user
                fields["command"] = match.group("command")
            return
        if "session opened" in message:
            _add(actions, "cron_session")

    def _classify_systemd(
        self,
        program: str,
        message: str,
        fields: dict[str, object],
        actions: list[str],
    ) -> None:
        if (
            "System is rebooting" in message
            or "System is powering down" in message
            or message == "Shutting down."
        ):
            _add(actions, "system_shutdown")
        for regex, action in (
            (_SYSTEMD_STARTED_RE, "service_started"),
            (_SYSTEMD_STOPPING_RE, "service_stopping"),
            (_SYSTEMD_STOPPED_RE, "service_stopped"),
            (_SYSTEMD_STARTING_RE, "service_starting"),
            (_SYSTEMD_RELOAD_RE, "service_reloaded"),
            (_SYSTEMD_FAILED_RE, "service_failed"),
        ):
            match = regex.match(message)
            if match:
                unit = match.group("unit")
                fields["unit"] = unit
                _add(actions, action)
                if unit == "auditd.service" and action in {"service_stopping", "service_stopped"}:
                    _add(actions, "audit_tamper")
                if action in {"service_stopped", "service_stopping"} and unit in {
                    "firewalld.service",
                    "ufw.service",
                    "nftables.service",
                }:
                    _add(actions, "firewall_disabled")
                break

    def _classify_accounts(
        self,
        program: str,
        message: str,
        fields: dict[str, object],
        actions: list[str],
    ) -> None:
        match = _USERADD_RE.search(message)
        if match:
            _add(actions, "user_created")
            fields["user"] = match.group("user")
            return
        match = _USERMOD_GROUP_RE.search(message)
        if match:
            _add(actions, "group_member_added")
            fields["user"] = match.group("user")
            fields["group"] = match.group("group")
            return
        match = _GROUPADD_RE.search(message)
        if match:
            _add(actions, "group_created")
            fields["group"] = match.group("group")
            return
        match = _PASSWD_RE.search(message)
        if match:
            _add(actions, "password_changed")
            fields["user"] = match.group("user")
            return
        match = _USBDEL_RE.search(message)
        if match:
            _add(actions, "user_deleted")
            fields["user"] = match.group("user")
            return

    def _classify_kernel(self, message: str, fields: dict[str, object], actions: list[str]) -> None:
        lower = message.lower()
        if "usb mass storage device detected" in lower or re.search(
            r"usb \S+: new (?:high|full|super|low)-speed", lower
        ):
            _add(actions, "usb_storage")
        if "module verification failed" in lower or "tainting kernel" in lower:
            fields["kernel_tainted"] = True
