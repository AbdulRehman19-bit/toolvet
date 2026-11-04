"""Compare two sets of servers and say what a change means for risk, not just that it changed."""

from __future__ import annotations

import itertools
import re
from dataclasses import dataclass, field
from pathlib import Path

from agentaudit.audit import audit
from agentaudit.capabilities import tag_server
from agentaudit.fixes import FixOption, has_trifecta, trifecta_fixes
from agentaudit.models import Finding, Server, Severity
from agentaudit.policy import Policy, Waiver, apply_policy
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
    waiver: dict[str, str] | None = None  # set when the active policy accepts this trifecta
    fix_options: list[FixOption] = field(default_factory=list)  # smallest fixes, best first
    # The fewest servers this change adds whose removal makes the trifecta disappear.
    drop_hint: list[str] = field(default_factory=list)
    drop_movable: bool = True  # False if those servers are a trifecta on their own


@dataclass
class PolicyChange:
    """What the change does to agent.policy.toml. Reviewers must look at added waivers."""

    added_waivers: list[Waiver] = field(default_factory=list)
    removed_waivers: list[Waiver] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        return not (self.added_waivers or self.removed_waivers or self.notes)


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
    policy: PolicyChange = field(default_factory=PolicyChange)
    policy_mode: str = "base"  # which policy suppressed findings: base | head | none

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
            or not self.policy.is_empty
        )

    def introduces_risk(self, fail_on: Severity) -> bool:
        """True if the change adds a failing finding or creates or widens a trifecta."""
        if any(t.kind in ("new", "widened") and t.waiver is None for t in self.trifectas):
            return True
        return any(
            not f.advisory and f.waiver is None and f.severity.rank >= fail_on.rank
            for f in self.new_findings
        )


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
    def collect(findings: list[Finding], root: Path) -> dict[str, tuple[set[str], dict | None]]:
        found: dict[str, tuple[set[str], dict | None]] = {}
        for f in findings:
            if f.rule_id == "AA100":
                name = _config_name(f, root)
                servers, waiver = found.get(name, (set(), f.waiver))
                # A scope counts as accepted only if every trifecta finding in it is waived.
                found[name] = (servers | set(f.server.split(", ")), waiver and f.waiver)
        return found

    old, new = collect(base, base_root), collect(head, head_root)
    changes = []
    for config in sorted(new):
        servers, waiver = new[config]
        if config not in old:
            changes.append(TrifectaChange(config, "new", sorted(servers), waiver=waiver))
        elif grown := servers - old[config][0]:
            changes.append(
                TrifectaChange(config, "widened", sorted(servers), sorted(grown), waiver=waiver)
            )
    for config in sorted(old.keys() - new.keys()):
        changes.append(TrifectaChange(config, "resolved", sorted(old[config][0])))
    return changes


def _relative(server: Server, root: Path) -> str:
    try:
        return server.source.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return server.source.name


def _suggest_fixes(
    trifectas: list[TrifectaChange], head: list[Server], added: list[Server], head_root: Path
) -> None:
    """Attach the smallest fixes to each unaccepted new or widened trifecta, in place.

    For a trifecta this change creates, also look for the fewest servers the change added whose
    removal makes it disappear: that is the most direct advice for the author.
    """
    added_ids = {s.id for s in added}
    for change in trifectas:
        if change.kind == "resolved" or change.waiver is not None:
            continue
        scope = [s for s in head if _relative(s, head_root) == change.config]
        options = next(iter(trifecta_fixes(scope).values()), [])
        change.fix_options = options[:3]
        if change.kind != "new":
            continue
        mine = [s for s in scope if s.id in added_ids]
        for size in range(1, len(mine) + 1):
            for combo in itertools.combinations(mine, size):
                gone = {s.id for s in combo}
                if not has_trifecta([s for s in scope if s.id not in gone]):
                    change.drop_hint = sorted(gone)
                    change.drop_movable = not has_trifecta(list(combo))
                    return
            # no subset of this size is enough; try larger ones


def policy_change(base: Policy, head: Policy) -> PolicyChange:
    notes = []
    if base.fail_on != head.fail_on:
        notes.append(
            f"fail_on: {base.fail_on.value if base.fail_on else 'unset'} -> "
            f"{head.fail_on.value if head.fail_on else 'unset'}"
        )
    for rule in sorted(base.severity.keys() | head.severity.keys()):
        a, b = base.severity.get(rule), head.severity.get(rule)
        if a != b:
            notes.append(
                f"severity {rule}: {a.value if a else 'default'} -> {b.value if b else 'default'}"
            )
    if base.max_waiver_days != head.max_waiver_days:
        notes.append(f"max_waiver_days: {base.max_waiver_days} -> {head.max_waiver_days}")
    return PolicyChange(
        added_waivers=[w for w in head.waivers if w not in base.waivers],
        removed_waivers=[w for w in base.waivers if w not in head.waivers],
        notes=notes,
    )


def active_policy(mode: str, base: Policy, head: Policy) -> Policy:
    """The policy that suppresses findings. `base` stops a PR from waiving its own risk."""
    return {"base": base, "head": head}.get(mode, Policy())


def compute_diff(
    base: list[Server],
    head: list[Server],
    base_root: Path,
    head_root: Path,
    base_policy: Policy | None = None,
    head_policy: Policy | None = None,
    policy_mode: str = "base",
) -> Diff:
    base_policy, head_policy = base_policy or Policy(), head_policy or Policy()
    active = active_policy(policy_mode, base_policy, head_policy)
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

    base_findings = apply_policy(audit(base), active)
    head_findings = apply_policy(audit(head), active)
    base_keys = {_key(f) for f in base_findings if f.rule_id != "AA100"}
    head_keys = {_key(f) for f in head_findings if f.rule_id != "AA100"}
    trifectas = _trifectas(base_findings, head_findings, base_root, head_root)
    _suggest_fixes(
        trifectas, head, [new[sid] for sid in sorted(new.keys() - old.keys())], head_root
    )
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
        trifectas=trifectas,
        policy=policy_change(base_policy, head_policy),
        policy_mode=policy_mode,
    )
