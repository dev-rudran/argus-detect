"""MITRE ATT&CK technique metadata and rule coverage calculations."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

from argus.models import Rule

BASE_URL = "https://attack.mitre.org/techniques"

# Ordered tactics used by the matrix and report.
TACTICS: tuple[tuple[str, str], ...] = (
    ("reconnaissance", "Reconnaissance"),
    ("resource-development", "Resource Development"),
    ("initial-access", "Initial Access"),
    ("execution", "Execution"),
    ("persistence", "Persistence"),
    ("privilege-escalation", "Privilege Escalation"),
    ("defense-evasion", "Defense Evasion"),
    ("credential-access", "Credential Access"),
    ("discovery", "Discovery"),
    ("lateral-movement", "Lateral Movement"),
    ("collection", "Collection"),
    ("command-and-control", "Command and Control"),
    ("exfiltration", "Exfiltration"),
    ("impact", "Impact"),
)
TACTIC_NAMES = {tactic for tactic, _ in TACTICS}
TACTIC_LABELS = dict(TACTICS)


@dataclass(frozen=True)
class Technique:
    id: str
    name: str
    tactics: tuple[str, ...]
    description: str = ""

    @property
    def url(self) -> str:
        return f"{BASE_URL}/{self.id.replace('.', '/')}"

    @property
    def is_subtechnique(self) -> bool:
        return "." in self.id


def _tech(identifier: str, name: str, tactics: str, description: str) -> Technique:
    return Technique(
        id=identifier,
        name=name,
        tactics=tuple(part.strip() for part in tactics.split(",")),
        description=description,
    )


TECHNIQUES: dict[str, Technique] = {
    item.id: item
    for item in (
        _tech(
            "T1110",
            "Brute Force",
            "credential-access",
            "Repeated authentication attempts against an account.",
        ),
        _tech(
            "T1110.001",
            "Password Guessing",
            "credential-access",
            "Guessing passwords against one or more known accounts.",
        ),
        _tech(
            "T1110.003",
            "Password Spraying",
            "credential-access",
            "Trying a small set of passwords across many accounts.",
        ),
        _tech(
            "T1078",
            "Valid Accounts",
            "defense-evasion,persistence,privilege-escalation,initial-access",
            "Use of legitimate credentials to access a system.",
        ),
        _tech(
            "T1548",
            "Abuse Elevation Control Mechanism",
            "privilege-escalation,defense-evasion",
            "Circumventing mechanisms designed to control privilege elevation.",
        ),
        _tech(
            "T1548.003",
            "Sudo and Sudo Caching",
            "privilege-escalation,defense-evasion",
            "Abusing sudo or sudo credential caching to execute commands as another user.",
        ),
        _tech(
            "T1136", "Create Account", "persistence", "Creating an account for persistent access."
        ),
        _tech(
            "T1136.001",
            "Local Account",
            "persistence",
            "Creating a local operating system account.",
        ),
        _tech(
            "T1098",
            "Account Manipulation",
            "persistence,privilege-escalation",
            "Modifying accounts or their authentication material.",
        ),
        _tech(
            "T1098.004",
            "SSH Authorized Keys",
            "persistence,privilege-escalation",
            "Adding an SSH key to authorized_keys for persistent access.",
        ),
        _tech(
            "T1053",
            "Scheduled Task/Job",
            "execution,persistence,privilege-escalation",
            "Scheduling code to run automatically.",
        ),
        _tech(
            "T1053.003",
            "Cron",
            "execution,persistence,privilege-escalation",
            "Using cron to persist or execute code.",
        ),
        _tech(
            "T1053.006",
            "Systemd Timers",
            "execution,persistence,privilege-escalation",
            "Using systemd timers to persist or execute code.",
        ),
        _tech(
            "T1070",
            "Indicator Removal",
            "defense-evasion",
            "Deleting or altering artifacts that might reveal activity.",
        ),
        _tech(
            "T1070.002",
            "Clear Linux or Mac System Logs",
            "defense-evasion",
            "Clearing system logs to remove evidence.",
        ),
        _tech(
            "T1070.003",
            "Clear Command History",
            "defense-evasion",
            "Clearing shell history to remove evidence of executed commands.",
        ),
        _tech(
            "T1222",
            "File and Directory Permissions Modification",
            "defense-evasion",
            "Changing permissions to access or hide files.",
        ),
        _tech(
            "T1222.002",
            "Linux and Mac File and Directory Permissions Modification",
            "defense-evasion",
            "Changing Linux file permissions, including setting setuid or setgid bits.",
        ),
        _tech(
            "T1543",
            "Create or Modify System Process",
            "persistence,privilege-escalation",
            "Creating or modifying system services for persistence.",
        ),
        _tech(
            "T1543.002",
            "Systemd Service",
            "persistence,privilege-escalation",
            "Creating or modifying a systemd service.",
        ),
        _tech(
            "T1021",
            "Remote Services",
            "lateral-movement",
            "Using remote services to move laterally.",
        ),
        _tech(
            "T1021.004",
            "SSH",
            "lateral-movement",
            "Using SSH for remote access or lateral movement.",
        ),
        _tech(
            "T1046",
            "Network Service Discovery",
            "discovery",
            "Enumerating services on remote hosts.",
        ),
        _tech(
            "T1105",
            "Ingress Tool Transfer",
            "command-and-control",
            "Transferring tools or payloads into an environment.",
        ),
        _tech(
            "T1059",
            "Command and Scripting Interpreter",
            "execution",
            "Executing commands through an interpreter.",
        ),
        _tech("T1059.004", "Unix Shell", "execution", "Executing commands through a Unix shell."),
        _tech(
            "T1003",
            "OS Credential Dumping",
            "credential-access",
            "Extracting credential material from the operating system.",
        ),
        _tech(
            "T1114",
            "Email Collection",
            "collection",
            "Collecting email from local or remote mailboxes.",
        ),
        _tech(
            "T1562",
            "Impair Defenses",
            "defense-evasion",
            "Disabling or modifying security controls.",
        ),
        _tech(
            "T1562.001",
            "Disable or Modify Tools",
            "defense-evasion",
            "Disabling or modifying security tools such as auditd.",
        ),
        _tech(
            "T1562.004",
            "Disable or Modify System Firewall",
            "defense-evasion",
            "Disabling or modifying host or network firewalls.",
        ),
        _tech(
            "T1071",
            "Application Layer Protocol",
            "command-and-control",
            "Using application protocols for command and control.",
        ),
        _tech(
            "T1071.001",
            "Web Protocols",
            "command-and-control",
            "Using HTTP or HTTPS for command and control.",
        ),
        _tech(
            "T1496",
            "Resource Hijacking",
            "impact",
            "Using compromised resources for cryptocurrency mining or similar work.",
        ),
        _tech(
            "T1489",
            "Service Stop",
            "impact",
            "Stopping services to disrupt operations or security controls.",
        ),
        _tech("T1529", "System Shutdown/Reboot", "impact", "Shutting down or rebooting a system."),
        _tech(
            "T1200",
            "Hardware Additions",
            "initial-access",
            "Introducing hardware into a system or network.",
        ),
        _tech(
            "T1552",
            "Unsecured Credentials",
            "credential-access",
            "Finding credentials stored in insecure locations.",
        ),
        _tech(
            "T1552.001",
            "Credentials In Files",
            "credential-access",
            "Reading credentials from files on disk.",
        ),
        _tech(
            "T1556",
            "Modify Authentication Process",
            "defense-evasion,persistence,credential-access",
            "Modifying authentication components such as PAM.",
        ),
        _tech(
            "T1565", "Data Manipulation", "impact", "Altering data or evidence to affect integrity."
        ),
        _tech(
            "T1195",
            "Supply Chain Compromise",
            "initial-access",
            "Compromising software or its distribution path.",
        ),
        _tech(
            "T1195.002",
            "Compromise Software Supply Chain",
            "initial-access",
            "Compromising software before delivery, including package installation paths.",
        ),
        _tech(
            "T1571",
            "Non-Standard Port",
            "command-and-control",
            "Using a non-standard port for command and control.",
        ),
        _tech(
            "T1041",
            "Exfiltration Over C2 Channel",
            "exfiltration",
            "Sending data out over an existing command channel.",
        ),
        _tech(
            "T1547",
            "Boot or Logon Autostart Execution",
            "persistence,privilege-escalation",
            "Configuring code to run automatically at boot or logon.",
        ),
        _tech(
            "T1547.006",
            "Kernel Modules and Extensions",
            "persistence,privilege-escalation",
            "Loading kernel modules to persist or subvert the kernel.",
        ),
        _tech(
            "T1014",
            "Rootkit",
            "defense-evasion",
            "Hiding activity using kernel or user-mode rootkit techniques.",
        ),
    )
}


def technique(identifier: str) -> Technique | None:
    """Look up a technique by ID, case-insensitively."""
    return TECHNIQUES.get(str(identifier).upper())


def techniques_for_tags(tags: Iterable[str]) -> list[Technique]:
    """Return known techniques referenced by rule tags, in tag order."""
    found: list[Technique] = []
    seen: set[str] = set()
    for tag in tags:
        lower = str(tag).lower()
        if not lower.startswith("attack.t"):
            continue
        item = technique(lower.split(".", 1)[1])
        if item is not None and item.id not in seen:
            seen.add(item.id)
            found.append(item)
    return found


def techniques_for_rule(rule: Rule) -> list[Technique]:
    return techniques_for_tags(rule.tags)


@dataclass
class Coverage:
    """ATT&CK coverage derived from the loaded rule set."""

    rule_ids_by_technique: dict[str, list[str]]
    catalog: dict[str, Technique]

    @property
    def covered_techniques(self) -> list[str]:
        return sorted(self.rule_ids_by_technique)

    @property
    def covered_count(self) -> int:
        return len(self.rule_ids_by_technique)

    @property
    def catalog_count(self) -> int:
        return len(self.catalog)

    @property
    def percent(self) -> float:
        if not self.catalog:
            return 0.0
        return 100.0 * self.covered_count / self.catalog_count

    def tactic_ids(self, tactic: str) -> list[str]:
        return sorted(item.id for item in self.catalog.values() if tactic in item.tactics)

    def tactic_covered(self, tactic: str) -> list[str]:
        return [item for item in self.tactic_ids(tactic) if item in self.rule_ids_by_technique]

    def tactic_percent(self, tactic: str) -> float:
        total = self.tactic_ids(tactic)
        if not total:
            return 0.0
        return 100.0 * len(self.tactic_covered(tactic)) / len(total)

    def heat(self, technique_id: str) -> int:
        return len(self.rule_ids_by_technique.get(technique_id, []))

    def rows(self) -> list[dict[str, object]]:
        rows: list[dict[str, object]] = []
        for tactic, label in TACTICS:
            ids = self.tactic_ids(tactic)
            covered = self.tactic_covered(tactic)
            rows.append(
                {
                    "tactic": tactic,
                    "label": label,
                    "total": len(ids),
                    "covered": len(covered),
                    "percent": self.tactic_percent(tactic),
                    "techniques": [
                        {
                            "id": item_id,
                            "name": self.catalog[item_id].name,
                            "rules": self.rule_ids_by_technique.get(item_id, []),
                        }
                        for item_id in ids
                    ],
                }
            )
        return rows


def coverage(rules: Iterable[Rule]) -> Coverage:
    """Calculate technique and tactic coverage for *rules*."""
    mapping: dict[str, list[str]] = {}
    for rule in rules:
        for item in techniques_for_rule(rule):
            mapping.setdefault(item.id, []).append(rule.id)
    for rule_ids in mapping.values():
        rule_ids.sort()
    return Coverage(rule_ids_by_technique=mapping, catalog=dict(TECHNIQUES))


def tactic_label(tactic: str) -> str:
    normalized = tactic.replace("_", "-")
    return TACTIC_LABELS.get(normalized, normalized.replace("-", " ").title())
