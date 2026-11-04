"""Render a Diff as plain text, GitHub-safe Markdown or JSON.

Server names, tool names, descriptions, arguments and URLs all come from files a pull request
author controls. In Markdown every such value is placed inside a code span or code block, so
it cannot inject links, images, HTML or @mentions into a PR comment. Credential-looking
arguments are masked by agentaudit.diff before they reach any renderer.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable

from agentaudit.capabilities import tag_server
from agentaudit.diff import Diff, TrifectaChange, launch_line
from agentaudit.models import Finding, Server, Severity
from agentaudit.policy import Waiver

MARKER = "<!-- agentaudit-diff -->"
SPAN_LIMIT = 200
BLOCK_LIMIT = 600


def _clip(text: str, limit: int) -> str:
    text = text.replace("\r", "")
    return text if len(text) <= limit else text[: limit - 1] + "..."


def _code(text: str, limit: int = SPAN_LIMIT) -> str:
    """An inline code span that survives any content, safe inside a table cell."""
    text = " ".join(_clip(text, limit).split()).replace("|", "\\|")
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    pad = " " if text.startswith("`") or text.endswith("`") else ""
    return f"{fence}{pad}{text or ' '}{pad}{fence}"


def _block(text: str, limit: int = BLOCK_LIMIT) -> list[str]:
    text = _clip(text, limit)
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * max(3, longest + 1)
    return [fence + "text", text, fence]


def _caps(server: Server) -> str:
    tags = tag_server(server)
    return ", ".join(f"{c.value} via '{kw}'" for c, kw in tags.items()) or "none detected"


def _finding_line(f: Finding) -> str:
    where = f"{f.server}:{f.tool}" if f.tool else f.server
    return f"[{f.severity.value}] {f.rule_id} {where}: {f.message}"


def _trifecta_sentence(kind: str) -> str:
    return {
        "new": "NEW lethal trifecta",
        "widened": "Lethal trifecta WIDENED",
        "resolved": "Lethal trifecta resolved",
    }[kind]


_SELF_WAIVER_NOTE = (
    "Waivers added by this change are NOT applied to this check: a change cannot waive its own "
    "risk. A reviewer must approve them, and they take effect once merged."
)


def _waiver_note(waiver: dict[str, str]) -> str:
    return f"{waiver['reason']} (owner {waiver['owner']}, expires {waiver['expires']})"


def _fix_items(change: TrifectaChange, name: Callable[[str], str]) -> list[str]:
    """Fix suggestions for a trifecta; `name` formats a server id (code span in Markdown)."""
    items = []
    if change.drop_hint:
        names = ", ".join(name(s) for s in change.drop_hint)
        if change.drop_movable:
            items.append(
                f"Drop or move the server(s) this change adds ({names}): without them there is "
                "no trifecta."
            )
        else:
            items.append(
                f"Remove the server(s) this change adds ({names}), or restrict their tools. "
                "They can do all three on their own, so moving them elsewhere does not help."
            )
    items += [option.describe(name) for option in change.fix_options]
    return items


def _waiver_text(w: Waiver) -> str:
    return f"{w.label()}: {w.reason} (owner {w.owner}, expires {w.expires})"


def to_text(diff: Diff, fail_on: Severity) -> str:
    if diff.is_empty:
        return "No capability changes.\n"
    out = [
        "RISK INTRODUCED" if diff.introduces_risk(fail_on) else "No new risk introduced",
        "",
    ]
    for t in diff.trifectas:
        extra = f" (adds {', '.join(t.added_servers)})" if t.added_servers else ""
        accepted = f" [accepted by policy: {_waiver_note(t.waiver)}]" if t.waiver else ""
        out.append(
            f"{_trifecta_sentence(t.kind)} in {t.config}{extra}: {', '.join(t.servers)}{accepted}"
        )
        if items := _fix_items(t, str):
            out += ["  Smallest fixes:"] + [f"    - {item}" for item in items]
    if diff.new_findings:
        out += ["", "New findings:"] + [f"  {_finding_line(f)}" for f in diff.new_findings]
    if diff.added:
        out += ["", "Servers added:"]
        out += [f"  {s.id}: {launch_line(s)}  [{_caps(s)}]" for s in diff.added]
    if diff.removed:
        out += ["", "Servers removed:"] + [f"  {s.id}" for s in diff.removed]
    if diff.changed:
        out += ["", "Servers changed:"]
        for c in diff.changed:
            out += [f"  {c.server}"] + [f"    {d}" for d in c.details]
    if diff.capabilities:
        out += ["", "Capability changes:"]
        for c in diff.capabilities:
            gained = ", ".join(f"{k} via '{v}'" for k, v in c.gained.items())
            lost = ", ".join(c.lost)
            out.append(
                f"  {c.server}: "
                + "; ".join(
                    filter(
                        None, [f"gained {gained}" if gained else "", f"lost {lost}" if lost else ""]
                    )
                )
            )
    if diff.tools:
        out += ["", "Tool changes:"]
        for t in diff.tools:
            out.append(f"  {t.server}:{t.tool} {t.kind}")
            if t.kind == "changed":
                out += [
                    f"    before: {_clip(t.before, SPAN_LIMIT)}",
                    f"    after:  {_clip(t.after, SPAN_LIMIT)}",
                ]
    if diff.resolved_findings:
        out += ["", "Resolved:"] + [f"  {_finding_line(f)}" for f in diff.resolved_findings]
    if not diff.policy.is_empty:
        out += ["", "Policy changes in this change (agent.policy.toml):"]
        out += [f"  waiver added: {_waiver_text(w)}" for w in diff.policy.added_waivers]
        out += [f"  waiver removed: {_waiver_text(w)}" for w in diff.policy.removed_waivers]
        out += [f"  {n}" for n in diff.policy.notes]
        if diff.policy.added_waivers and diff.policy_mode == "base":
            out.append(_SELF_WAIVER_NOTE)
    return "\n".join(out) + "\n"


def to_markdown(diff: Diff, fail_on: Severity) -> str:
    risk = diff.introduces_risk(fail_on)
    lines = [MARKER, "## agentaudit: capability changes", ""]
    if diff.is_empty:
        return "\n".join(lines + ["No capability changes in this pull request.", ""])
    lines.append(
        "**This change introduces risk.** Review it before merging."
        if risk
        else "No new risk introduced, but the setup changed:"
    )
    for t in diff.trifectas:
        extra = (
            f", adding {', '.join(_code(s) for s in t.added_servers)}" if t.added_servers else ""
        )
        lines += [
            "",
            f"### {_trifecta_sentence(t.kind)}",
            "",
            f"In {_code(t.config)}{extra}. Servers involved: "
            + ", ".join(_code(s) for s in t.servers),
        ]
        if t.waiver:
            lines.append(f"\nAccepted by policy: {_code(_waiver_note(t.waiver))}")
        elif t.kind != "resolved":
            lines.append(
                "\nUntrusted input can reach private data and a channel that sends data out."
            )
            if items := _fix_items(t, _code):
                lines += ["", "Smallest fixes:", ""] + [f"- {item}" for item in items]
    if diff.new_findings:
        lines += [
            "",
            "### New findings",
            "",
            "| Severity | Rule | Where | Message |",
            "|---|---|---|---|",
        ]
        for f in diff.new_findings:
            where = f"{f.server}:{f.tool}" if f.tool else f.server
            tag = f.severity.value + (" (advisory)" if f.advisory else "")
            tag += " (waived)" if f.waiver else ""
            lines.append(f"| {tag} | {f.rule_id} | {_code(where)} | {_code(f.message)} |")
    if diff.added:
        lines += ["", "### Servers added", ""]
        lines += [
            f"- {_code(s.id)} runs {_code(launch_line(s))}; capabilities: {_code(_caps(s))}"
            for s in diff.added
        ]
    if diff.removed:
        lines += ["", "### Servers removed", ""] + [f"- {_code(s.id)}" for s in diff.removed]
    if diff.changed:
        lines += ["", "### Servers changed", ""]
        for c in diff.changed:
            lines.append(f"- {_code(c.server)}")
            lines += [f"  - {_code(d)}" for d in c.details]
    if diff.capabilities:
        lines += ["", "### Capability changes", ""]
        for c in diff.capabilities:
            parts = []
            if c.gained:
                parts.append(
                    "gained " + _code(", ".join(f"{k} via '{v}'" for k, v in c.gained.items()))
                )
            if c.lost:
                parts.append("lost " + _code(", ".join(c.lost)))
            lines.append(f"- {_code(c.server)}: " + "; ".join(parts))
    if diff.tools:
        lines += ["", "### Tool changes", ""]
        for t in diff.tools:
            lines.append(f"- {_code(t.server + ':' + t.tool)} {t.kind}")
            if t.kind == "changed":
                lines += (
                    ["", "Before:"] + _block(t.before) + ["", "After:"] + _block(t.after) + [""]
                )
    if diff.resolved_findings:
        lines += ["", "### Resolved", ""]
        lines += [f"- {_code(_finding_line(f))}" for f in diff.resolved_findings]
    if not diff.policy.is_empty:
        lines += ["", "### Policy changes (`agent.policy.toml`)", ""]
        lines += [f"- waiver added: {_code(_waiver_text(w))}" for w in diff.policy.added_waivers]
        lines += [
            f"- waiver removed: {_code(_waiver_text(w))}" for w in diff.policy.removed_waivers
        ]
        lines += [f"- {_code(n)}" for n in diff.policy.notes]
        if diff.policy.added_waivers and diff.policy_mode == "base":
            lines += ["", f"**{_SELF_WAIVER_NOTE}**"]
    return "\n".join(lines) + "\n"


def to_json(diff: Diff, fail_on: Severity) -> str:
    def finding(f: Finding) -> dict:
        return {
            "rule": f.rule_id,
            "severity": f.severity.value,
            "message": f.message,
            "server": f.server,
            "tool": f.tool,
            "advisory": f.advisory,
            "waiver": f.waiver,
        }

    data = {
        "introduces_risk": diff.introduces_risk(fail_on),
        "servers_added": [
            {
                "id": s.id,
                "launch": launch_line(s),
                "capabilities": {c.value: kw for c, kw in tag_server(s).items()},
            }
            for s in diff.added
        ],
        "servers_removed": [s.id for s in diff.removed],
        "servers_changed": [{"id": c.server, "details": c.details} for c in diff.changed],
        "capability_changes": [
            {"id": c.server, "gained": c.gained, "lost": c.lost} for c in diff.capabilities
        ],
        "tool_changes": [
            {
                "server": t.server,
                "tool": t.tool,
                "kind": t.kind,
                "before": t.before,
                "after": t.after,
            }
            for t in diff.tools
        ],
        "trifectas": [
            {
                "config": t.config,
                "kind": t.kind,
                "servers": t.servers,
                "added_servers": t.added_servers,
                "waiver": t.waiver,
                "drop_hint": t.drop_hint,
                "drop_movable": t.drop_movable,
                "fixes": [o.describe() for o in t.fix_options],
            }
            for t in diff.trifectas
        ],
        "new_findings": [finding(f) for f in diff.new_findings],
        "resolved_findings": [finding(f) for f in diff.resolved_findings],
        "policy": {
            "mode": diff.policy_mode,
            "waivers_added": [_waiver_text(w) for w in diff.policy.added_waivers],
            "waivers_removed": [_waiver_text(w) for w in diff.policy.removed_waivers],
            "notes": diff.policy.notes,
        },
    }
    return json.dumps(data, indent=2) + "\n"
