"""JSON-lines parser with schema normalization for generic application logs."""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from argus.ingest.base import BaseParser
from argus.models import Event
from argus.util.net import dest_scope
from argus.util.timeparse import TimeParseError, parse_timestamp

TIMESTAMP_KEYS = ("@timestamp", "timestamp", "time", "ts", "event.created", "datetime", "date")
SRC_KEYS = (
    "src_ip",
    "source.ip",
    "source_ip",
    "client_ip",
    "remote_addr",
    "remote_ip",
    "srcip",
    "ip",
)
DST_KEYS = ("dest_ip", "destination.ip", "dst_ip", "destination_ip", "server_ip", "target_ip")
USER_KEYS = ("user", "user.name", "username", "account", "principal", "actor")
HOST_KEYS = ("host", "host.name", "hostname", "agent.hostname")
MESSAGE_KEYS = ("message", "event.original", "msg", "log", "event.message")
ACTION_KEYS = ("event.action", "action", "event.type", "type")
BYTES_OUT_KEYS = (
    "bytes_out",
    "body_bytes_sent",
    "sent_bytes",
    "sc_bytes",
    "out_bytes",
    "response_bytes",
    "egress_bytes",
)
BYTES_IN_KEYS = ("bytes_in", "request_length", "received_bytes", "cs_bytes", "ingress_bytes")
HTTP_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT"}
_REQUEST_RE = re.compile(r"^(?P<method>[A-Z]+) (?P<path>\S+) (?P<protocol>HTTP/\d(?:\.\d)?)$")


def flatten_json(
    value: dict[str, Any], prefix: str = "", out: dict[str, Any] | None = None
) -> dict[str, Any]:
    """Flatten nested mappings into dotted field names."""
    if out is None:
        out = {}
    for key, item in value.items():
        name = f"{prefix}{key}"
        if isinstance(item, dict):
            flatten_json(item, f"{name}.", out)
        elif isinstance(item, list):
            if item and all(isinstance(entry, dict) for entry in item):
                out[name] = json.dumps(item, separators=(",", ":"), sort_keys=True)
            else:
                out[name] = item
        else:
            out[name] = item
    return out


def _first(flat: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        if key in flat and flat[key] not in (None, ""):
            return flat[key]
    return None


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if item not in (None, "")]
    return [str(value)]


def _to_int(value: Any) -> int | None:
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return int(value)
    text = str(value).strip().replace(",", "")
    match = re.match(r"^[+-]?\d+(?:\.\d+)?", text)
    if not match:
        return None
    try:
        return int(float(match.group(0)))
    except ValueError:
        return None


class JsonlParser(BaseParser):
    """Parse one JSON object per line and normalize common security fields."""

    log_type = "jsonl"

    def parse_line(self, line: str, line_no: int, source: str) -> Event | None:
        text = self.clean(line)
        if not text.strip():
            return None
        try:
            data = json.loads(text)
        except json.JSONDecodeError:
            return None
        if not isinstance(data, dict):
            return None
        flat = flatten_json(data)
        timestamp_value = _first(flat, TIMESTAMP_KEYS)
        timestamp: datetime | None = None
        timestamp_source = "event"
        if timestamp_value is not None:
            try:
                timestamp = parse_timestamp(timestamp_value)
            except TimeParseError:
                return None
        if timestamp is None:
            timestamp = self.default_timestamp
            timestamp_source = "file_mtime"

        fields: dict[str, Any] = dict(flat)
        user = _first(flat, USER_KEYS)
        host = _first(flat, HOST_KEYS)
        src_ip = _first(flat, SRC_KEYS)
        dest_ip = _first(flat, DST_KEYS)
        message = _first(flat, MESSAGE_KEYS)
        if user is not None:
            fields["user"] = str(user)
        if host is not None:
            fields["host"] = str(host)
        if src_ip is not None:
            fields["src_ip"] = str(src_ip)
        if dest_ip is not None:
            fields["dest_ip"] = str(dest_ip)
            fields["dest_scope"] = dest_scope(dest_ip)
        if message is not None:
            fields["message"] = str(message)
        fields["timestamp_source"] = timestamp_source

        action_values = _as_list(_first(flat, ACTION_KEYS))
        request = _first(flat, ("request", "http.request"))
        method = _first(flat, ("method", "http.method", "request.method"))
        path = _first(flat, ("path", "uri", "request_uri", "http.target", "url.path"))
        protocol = _first(flat, ("protocol", "http.version", "server_protocol"))
        url = _first(flat, ("url", "http.url", "request.url"))
        if isinstance(request, str):
            match = _REQUEST_RE.match(request)
            if match:
                method = method or match.group("method")
                path = path or match.group("path")
                protocol = protocol or match.group("protocol")
        if isinstance(url, str) and not path:
            parsed = urlsplit(url)
            path = parsed.path or path
            if parsed.hostname and not _first(flat, ("dest_host", "server_name", "http.host")):
                fields["dest_host"] = parsed.hostname
                fields.setdefault("url_scheme", parsed.scheme)
        for name, value in (
            ("method", method),
            ("path", path),
            ("protocol", protocol),
            ("url", url),
            (
                "status",
                _first(
                    flat, ("status", "status_code", "http.response.status_code", "response.status")
                ),
            ),
            (
                "user_agent",
                _first(flat, ("user_agent", "http.user_agent", "agent", "http_user_agent")),
            ),
        ):
            if value is not None:
                fields[name] = value
        if "method" in fields:
            fields["method"] = str(fields["method"]).upper()
        for key in ("status",):
            if key in fields:
                numeric = _to_int(fields[key])
                if numeric is not None:
                    fields[key] = numeric
        dest_host = _first(flat, ("dest_host", "server_name", "http.host"))
        if dest_host is not None:
            fields["dest_host"] = str(dest_host)
        host_header = fields.get("dest_host")
        if isinstance(host_header, str) and ":" in host_header and host_header.count(":") == 1:
            fields["dest_host"] = host_header.split(":", 1)[0]

        dest_port = _first(
            flat, ("dest_port", "destination.port", "dst_port", "server_port", "port")
        )
        if dest_port is not None:
            numeric = _to_int(dest_port)
            if numeric is not None:
                fields["dest_port"] = numeric

        bytes_out = _first(flat, BYTES_OUT_KEYS)
        bytes_in = _first(flat, BYTES_IN_KEYS)
        if bytes_out is not None:
            numeric = _to_int(bytes_out)
            if numeric is not None:
                fields["bytes_out"] = numeric
        if bytes_in is not None:
            numeric = _to_int(bytes_in)
            if numeric is not None:
                fields["bytes_in"] = numeric

        process = data.get("process")
        if isinstance(process, dict):
            if process.get("name"):
                fields["process"] = str(process["name"])
            if process.get("executable"):
                fields["exe"] = str(process["executable"])
            if process.get("command_line") and "command" not in fields:
                fields["command"] = str(process["command_line"])
        elif isinstance(process, str):
            fields["process"] = process
        for name, value in (
            ("exe", _first(flat, ("exe", "process.executable", "executable"))),
            ("command", _first(flat, ("command", "cmd", "process.command_line", "process.args"))),
            ("process", _first(flat, ("process.name", "process_name"))),
        ):
            if value is not None and not fields.get(name):
                if isinstance(value, list):
                    value = " ".join(str(item) for item in value)
                fields[name] = value

        if not action_values:
            action_values = [self._infer_action(fields)]
        fields["action"] = action_values

        for key in ("user", "host", "src_ip", "dest_ip", "message"):
            if isinstance(fields.get(key), str) and not fields[key].strip():
                fields.pop(key, None)
        return Event(
            timestamp=timestamp,
            fields=fields,
            raw=self.clean(line),
            source=source,
            line_no=line_no,
            log_type=self.log_type,
        )

    @staticmethod
    def _infer_action(fields: dict[str, Any]) -> str:
        if "method" in fields or "path" in fields or "status" in fields:
            return "http_request"
        if "dest_port" in fields or "dest_ip" in fields:
            return "network_connection"
        if "process" in fields or "exe" in fields:
            return "process_start"
        return "log_event"
