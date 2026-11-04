"""Machine-readable and shareable reports: JSON, SARIF 2.1.0, Markdown and an SVG badge."""

from __future__ import annotations

import json
from pathlib import Path
from xml.sax.saxutils import escape

from agentaudit import __version__
from agentaudit.models import Finding, Server, Severity
from agentaudit.rules import load_rules

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://github.com/AbdulRehman19-bit/agentaudit"
TRIFECTA_TITLE = "Lethal trifecta"

_SARIF_LEVEL = {
    Severity.INFO: "note",
    Severity.LOW: "note",
    Severity.MEDIUM: "warning",
    Severity.HIGH: "error",
    Severity.CRITICAL: "error",
}


def _ordered(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (-f.severity.rank, f.rule_id, f.server, f.tool or ""))


def _uri(path: Path | None, root: Path) -> str | None:
    if path is None:
        return None
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_uri()


def to_json(servers: list[Server], findings: list[Finding], root: Path) -> str:
    report = {
        "tool": {"name": "agentaudit", "version": __version__},
        "servers": sorted(s.id for s in servers),
        "findings": [
            {
                "rule": f.rule_id,
                "severity": f.severity.value,
                "message": f.message,
                "server": f.server,
                "tool": f.tool,
                "config": _uri(f.source, root),
                "evidence": f.evidence,
                "advisory": f.advisory,
                "waiver": f.waiver,
                "fix": f.fix,
            }
            for f in _ordered(findings)
        ],
    }
    return json.dumps(report, indent=2) + "\n"


def to_sarif(findings: list[Finding], root: Path) -> str:
    rules = [{"id": r.id, "shortDescription": {"text": r.title}} for r in load_rules()]
    rules.append({"id": "AA100", "shortDescription": {"text": TRIFECTA_TITLE}})
    results = []
    for f in _ordered(findings):
        result: dict = {
            "ruleId": f.rule_id,
            "level": "note" if f.advisory else _SARIF_LEVEL[f.severity],
            "message": {"text": f"{f.server}: {f.message}"},
            "properties": {
                "server": f.server,
                "tool": f.tool,
                "evidence": f.evidence,
                "suggestions": f.fix,
            },
        }
        if f.waiver:
            result["suppressions"] = [
                {
                    "kind": "external",
                    "justification": f.waiver["reason"],
                    "properties": {"owner": f.waiver["owner"], "expires": f.waiver["expires"]},
                }
            ]
        uri = _uri(f.source, root)
        if uri:
            result["locations"] = [{"physicalLocation": {"artifactLocation": {"uri": uri}}}]
        results.append(result)
    sarif = {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "agentaudit",
                        "version": __version__,
                        "informationUri": INFO_URI,
                        "rules": sorted(rules, key=lambda r: r["id"]),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(sarif, indent=2) + "\n"


def to_markdown(servers: list[Server], findings: list[Finding]) -> str:
    lines = [
        "# agentaudit report",
        "",
        f"{len(servers)} MCP server(s), {len(findings)} finding(s).",
        "",
    ]
    if not findings:
        return "\n".join(lines + ["No findings.", ""])
    lines += ["| Severity | Rule | Server | Message |", "|---|---|---|---|"]
    for f in _ordered(findings):
        where = f"{f.server}:{f.tool}" if f.tool else f.server
        message = f.message.replace("|", "\\|")
        level = f"{f.severity.value} (waived)" if f.waiver else f.severity.value
        lines.append(f"| {level} | {f.rule_id} | `{where}` | {message} |")
    for f in _ordered(findings):
        if f.rule_id == "AA100":
            lines += ["", f"### Trifecta paths ({f.server})", ""]
            lines += [f"- {e}" for e in f.evidence]
            if f.fix and not f.waiver:
                lines += ["", "Smallest fixes:", ""] + [f"- {line}" for line in f.fix]
    return "\n".join(lines) + "\n"


def to_badge(findings: list[Finding], fail_on: Severity = Severity.HIGH) -> str:
    failing = sum(
        1 for f in findings if not f.advisory and not f.waiver and f.severity.rank >= fail_on.rank
    )
    if failing:
        text, color = f"{failing} issue{'s' if failing != 1 else ''}", "#c53030"
    elif findings:
        text, color = f"{len(findings)} low-risk", "#b7791f"
    else:
        text, color = "passing", "#2f855a"
    label = "agentaudit"
    lw, rw = 6 * len(label) + 14, 6 * len(text) + 14
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{lw + rw}" height="20" role="img" '
        f'aria-label="{label}: {escape(text)}"><rect width="{lw}" height="20" fill="#4a5568"/>'
        f'<rect x="{lw}" width="{rw}" height="20" fill="{color}"/>'
        '<g fill="#fff" font-family="Verdana,sans-serif" font-size="11" text-anchor="middle">'
        f'<text x="{lw / 2}" y="14">{label}</text>'
        f'<text x="{lw + rw / 2}" y="14">{escape(text)}</text></g></svg>\n'
    )
