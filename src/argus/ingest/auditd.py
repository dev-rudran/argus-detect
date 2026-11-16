"""Linux auditd parser.

auditd emits one ``type=... msg=audit(epoch:serial):`` record per line. Records
for a syscall share a serial but are parsed independently; the fields needed by
detection rules (executable, path, key, syscall) are present on the relevant
record.
"""

from __future__ import annotations

import re
from datetime import datetime
from typing import Any

from argus.ingest.base import BaseParser
from argus.ingest.syslog import derive_command_actions
from argus.models import Event
from argus.util.timeparse import UTC

_HEADER_RE = re.compile(
    r"^(?:node=(?P<node>\S+)\s+)?type=(?P<type>[A-Z0-9_]+)\s+"
    r"msg=audit\((?P<ts>\d+(?:\.\d+)?):(?P<id>\d+)\):\s*(?P<body>.*)$"
)
_KV_RE = re.compile(r"(?P<key>[A-Za-z0-9_]+)=(?P<value>\"(?:\\.|[^\"])*\"|\S+)")

_KEY_ACTIONS = {
    "log_tamper": "audit_tamper",
    "audit_tamper": "audit_tamper",
    "suid_change": "suid_change",
    "suid": "suid_change",
    "module_load": "module_load",
    "module": "module_load",
    "ssh_key": "ssh_key_added",
    "authorized_keys": "ssh_key_added",
    "firewall": "firewall_disabled",
    "firewall_disable": "firewall_disabled",
    "package": "package_install",
    "package_install": "package_install",
    "cron": "cron_persistence",
    "secret": "secret_file_access",  # nosec B105 - action label, not a credential
    "credential": "shadow_access",
    "shadow": "shadow_access",
    "pam": "pam_change",
    "reverse_shell": "reverse_shell",
    "user_add": "user_created",
    "group_change": "group_member_added",
}


def _unescape(value: str) -> str:
    if value.startswith('"') and value.endswith('"') and len(value) >= 2:
        inner = value[1:-1]
        return inner.replace('\\"', '"').replace("\\\\", "\\")
    return value


def _decode_path(value: str) -> str:
    text = _unescape(value)
    if text in {"(null)", "?", ""}:
        return ""
    if text.startswith("/") or not re.fullmatch(r"[0-9A-Fa-f]+", text):
        return text
    if len(text) >= 4 and len(text) % 2 == 0:
        try:
            decoded = bytes.fromhex(text).decode("utf-8", "replace")
        except ValueError:
            return text
        # Only accept complete, printable ASCII decodings. Short values such as
        # chmod mode arguments (``75b4``) are hexadecimal, not encoded paths,
        # and would otherwise decode to mojibake.
        if decoded.isascii() and decoded.isprintable():
            return decoded
    return text


class AuditdParser(BaseParser):
    """Parse auditd key=value records."""

    log_type = "auditd"

    def parse_line(self, line: str, line_no: int, source: str) -> Event | None:
        text = self.clean(line)
        if not text.strip():
            return None
        match = _HEADER_RE.match(text)
        if not match:
            return None
        try:
            timestamp = datetime.fromtimestamp(float(match.group("ts")), tz=UTC)
        except (ValueError, OSError, OverflowError):
            return None
        body = match.group("body")
        values: dict[str, Any] = {}
        for kv in _KV_RE.finditer(body):
            values[kv.group("key")] = _unescape(kv.group("value"))

        fields: dict[str, Any] = {
            "host": match.group("node") or "",
            "audit_type": match.group("type"),
            "audit_id": match.group("id"),
            "message": body,
        }
        for key in (
            "syscall",
            "success",
            "exit",
            "uid",
            "auid",
            "gid",
            "euid",
            "pid",
            "ppid",
            "comm",
            "exe",
            "key",
            "argc",
            "proctitle",
        ):
            if key in values and values[key] != "":
                fields[key] = values[key]
        path = ""
        for candidate in ("name", "path", "cwd"):
            if values.get(candidate):
                path = _decode_path(values[candidate])
                if path:
                    break
        if path:
            fields["path"] = path

        args: list[str] = []
        index = 0
        while f"a{index}" in values:
            args.append(_decode_path(values[f"a{index}"]))
            index += 1
        if args:
            fields["command"] = " ".join(args)
        proctitle = fields.get("proctitle")
        if isinstance(proctitle, str) and proctitle:
            fields["proctitle"] = _decode_path(proctitle)
            if not fields.get("command"):
                fields["command"] = fields["proctitle"]
        if fields.get("comm") and not fields.get("process"):
            fields["process"] = fields["comm"]
        if fields.get("uid") not in (None, "-1", "4294967295"):
            fields["user"] = fields["uid"]

        actions: list[str] = []
        key = str(fields.get("key", "")).lower()
        for token in re.split(r"[,| ]+", key):
            if token in _KEY_ACTIONS:
                self._append(actions, _KEY_ACTIONS[token])
        if "audit" in path and "/etc/audit" in path:
            self._append(actions, "audit_tamper")
        if path == "/etc/shadow" or path == "/etc/gshadow":
            self._append(actions, "shadow_access")
        if path.endswith("authorized_keys"):
            self._append(actions, "ssh_key_added")
        if "/etc/pam.d" in path:
            self._append(actions, "pam_change")
        if path == "/etc/sudoers" or "/etc/sudoers.d" in path:
            self._append(actions, "sudoers_change")

        command = str(fields.get("command", ""))
        if match.group("type") in {"EXECVE", "SYSCALL"} and command:
            for action in derive_command_actions(command):
                self._append(actions, action)
        lowered = body.lower()
        if (
            fields.get("audit_type") == "DAEMON"
            and "audit" in lowered
            and any(word in lowered for word in ("stopping", "disabled", "shutdown"))
        ):
            self._append(actions, "audit_tamper")
        if not actions:
            self._append(actions, "audit_event")
        fields["action"] = actions
        return Event(
            timestamp=timestamp,
            fields=fields,
            raw=self.clean(line),
            source=source,
            line_no=line_no,
            log_type=self.log_type,
        )

    @staticmethod
    def _append(actions: list[str], value: str) -> None:
        if value not in actions:
            actions.append(value)
