"""Compare two sets of servers and say what a change means for risk, not just that it changed."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from agentaudit.audit import audit
from agentaudit.capabilities import tag_server
from agentaudit.models import Finding, Server, Severity
from agentaudit.rules.builtin import _CRED_FLAG, _CRED_URL

_URL_PASSWORD = re.compile(r"(://[^/@\s:]+:)[^/@\s]+(@)")


def mask_args(args: list[str]) -> list[str]:
    """Hide credential-looking values before they are shown anywhere."""
    masked, hide_next = [], False
    for arg in args:
        if hide_next and not arg.startswith("-"):
            masked.append("***")
        elif _CRED_FLAG.match(arg) and "=" in arg:
            masked.append(arg.split("=", 1)[0] + "=***")
        elif _CRED_URL.search(arg):
            masked.append(_URL_PASSWORD.sub(r"\1***\2", arg))
        else:
            masked.append(arg)
        hide_next = bool(_CRED_FLAG.match(arg)) and "=" not in arg
    return masked


def launch_line(server: Server) -> str:
    if server.url:
        return server.url.split("?")[0].split("@")[-1]
    return " ".join(filter(None, [server.command, *mask_args(server.args)]))


@dataclass
class ServerChange:
    server: str
    details: list[str]


@dataclass
class CapabilityChange:
    server: str
    gained: dict[str, str] = field(default_factory=dict)
    lost: dict[str, str] = field(default_factory=dict)


@dataclass
class ToolChange:
    server: str
    tool: str
    kind: str  # added | removed | changed
    before: str = ""
    after: str = ""


@dataclass
class TrifectaChange:
    config: str
    kind: str  # new | widened | resolved
    servers: list[str]
    added_servers: list[str] = field(default_factory=list)


@dataclass
class Diff:
    added: list[Server]
    removed: list[Server]
    changed: list[ServerChange]
    capabilities: list[CapabilityChange]
    tools: list[ToolChange]
    new_findings: list[Finding]
    resolved_findings: list[Finding]
    trifectas: list[TrifectaChange]

    @property
    def is_empty(self) -> bool:
        return not (
            self.added
            or self.removed
            or self.changed
            or self.capabilities
            or self.tools
            or self.new_findings
            or self.resolved_findings
            or self.trifectas
        )

    def introduces_risk(self, fail_on: Severity) -> bool:
        """True if the change adds a failing finding or creates or widens a trifecta."""
        if any(t.kind in ("new", "widened") for t in self.trifectas):
            return True
        return any(not f.advisory and f.severity.rank >= fail_on.rank for f in self.new_findings)


def _key(finding: Finding) -> tuple:
    return (finding.rule_id, finding.server, finding.tool, finding.message)


def _config_name(finding: Finding, root: Path) -> str:
    if finding.source is None:
        return "?"
    try:
        return finding.source.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return finding.source.name


def _server_details(old: Server, new: Server) -> list[str]:
    details = []
    if old.command != new.command:
        details.append(f"command: {old.command} -> {new.command}")
    if old.args != new.args:
        details.append(f"args: {' '.join(mask_args(old.args))} -> {' '.join(mask_args(new.args))}")
    if old.url != new.url:
        details.append(f"url: {launch_line(old) or '-'} -> {launch_line(new) or '-'}")
    old_env, new_env = set(old.env), set(new.env)
    if added := sorted(new_env - old_env):
        details.append("env vars added: " + ", ".join(added))
    if removed := sorted(old_env - new_env):
        details.append("env vars removed: " + ", ".join(removed))
    return details


def _trifectas(
    base: list[Finding], head: list[Finding], base_root: Path, head_root: Path
) -> list[TrifectaChange]:
    def collect(findings: list[Finding], root: Path) -> dict[str, set[str]]:
        found: dict[str, set[str]] = {}
        for f in findings:
            if f.rule_id == "AA100":
                found.setdefault(_config_name(f, root), set()).update(f.server.split(", "))
        return found

    old, new = collect(base, base_root), collect(head, head_root)
    changes = []
    for config in sorted(new):
        if config not in old:
            changes.append(TrifectaChange(config, "new", sorted(new[config])))
        elif grown := new[config] - old[config]:
            changes.append(TrifectaChange(config, "widened", sorted(new[config]), sorted(grown)))
    for config in sorted(old.keys() - new.keys()):
        changes.append(TrifectaChange(config, "resolved", sorted(old[config])))
    return changes


def compute_diff(base: list[Server], head: list[Server], base_root: Path, head_root: Path) -> Diff:
    old = {s.id: s for s in base}
    new = {s.id: s for s in head}
    changed, capabilities, tools = [], [], []
    for sid in sorted(old.keys() & new.keys()):
        if details := _server_details(old[sid], new[sid]):
            changed.append(ServerChange(sid, details))
        before, after = tag_server(old[sid]), tag_server(new[sid])
        gained = {c.value: kw for c, kw in after.items() if c not in before}
        lost = {c.value: kw for c, kw in before.items() if c not in after}
        if gained or lost:
            capabilities.append(CapabilityChange(sid, gained, lost))
        old_tools = {t.name: t for t in old[sid].tools}
        new_tools = {t.name: t for t in new[sid].tools}
        for name in sorted(new_tools.keys() - old_tools.keys()):
            tools.append(ToolChange(sid, name, "added", after=new_tools[name].description))
        for name in sorted(old_tools.keys() - new_tools.keys()):
            tools.append(ToolChange(sid, name, "removed", before=old_tools[name].description))
        for name in sorted(old_tools.keys() & new_tools.keys()):
            a, b = old_tools[name], new_tools[name]
            if (a.description, a.input_schema) != (b.description, b.input_schema):
                tools.append(ToolChange(sid, name, "changed", a.description, b.description))

    base_findings, head_findings = audit(base), audit(head)
    base_keys = {_key(f) for f in base_findings if f.rule_id != "AA100"}
    head_keys = {_key(f) for f in head_findings if f.rule_id != "AA100"}
    return Diff(
        added=[new[sid] for sid in sorted(new.keys() - old.keys())],
        removed=[old[sid] for sid in sorted(old.keys() - new.keys())],
        changed=changed,
        capabilities=capabilities,
        tools=tools,
        new_findings=[
            f for f in head_findings if f.rule_id != "AA100" and _key(f) not in base_keys
        ],
        resolved_findings=[
            f for f in base_findings if f.rule_id != "AA100" and _key(f) not in head_keys
        ],
        trifectas=_trifectas(base_findings, head_findings, base_root, head_root),
    )
