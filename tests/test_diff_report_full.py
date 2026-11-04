"""One rich change that touches every section of the diff report, in all three formats."""

import json
import re
from datetime import date
from pathlib import Path

import pytest

from toolvet.diff import _config_name, _relative, compute_diff
from toolvet.diff_render import to_json, to_markdown, to_text
from toolvet.models import Finding, Server, Severity, Tool
from toolvet.policy import parse_policy

TODAY = date(2026, 11, 4)
HOSTILE = "Reads files. ``` @octocat [x](http://evil.example) <img src=x onerror=1> | # heading"


def waiver(rule, server, reason, owner="alice", expires="2027-01-01"):
    return {
        "rule": rule,
        "server": server,
        "reason": reason,
        "owner": owner,
        "expires": expires,
    }


@pytest.fixture
def diff(tmp_path):
    b, h = tmp_path / "base", tmp_path / "head"

    def server(root, name, **kw):
        kw.setdefault("command", "node")
        return Server(name=name, client="mcp", source=root / ".mcp.json", **kw)

    base = [
        server(
            b,
            "fetcher",
            command="npx",
            args=["-y", "mcp-pkg@1.0.0"],
            env={"OLD_TOKEN": "x"},
            tools=[Tool(name="read", description="Reads."), Tool(name="old", description="Old")],
        ),
        server(b, "docs", command=None, url="https://docs.example/mcp"),
        server(b, "gone"),
        server(b, "pkg", command="npx", args=["-y", "left-pad"]),
        server(b, "shrinks", args=["browser-x"]),
    ]
    head = [
        server(
            h,
            "fetcher",
            command="bunx",
            args=["-y", "fetch-mcp@2.0.0", "--token", "SECRET123"],
            env={"NEW_KEY": "y"},
            tools=[Tool(name="read", description=HOSTILE), Tool(name="write", description="New")],
        ),
        server(h, "docs", command=None, url="https://docs.example/v2"),
        server(h, "pkg", command="npx", args=["-y", "left-pad@1.3.0"]),
        server(h, "shrinks", args=["plain"]),
        server(h, "postgres", args=["postgres"]),
        server(h, "mailer", command="uvx", args=["mcp-server-smtp"]),
    ]
    base_policy = parse_policy({"waiver": [waiver("TV002", "mcp:old", "removed later")]}, TODAY)
    head_policy = parse_policy(
        {
            "fail_on": "medium",
            "max_waiver_days": 30,
            "severity": {"TV003": "high"},
            "waiver": [waiver("TV002", "mcp:mailer", "throwaway token", "bob", "2026-11-30")],
        },
        TODAY,
    )
    return compute_diff(base, head, b, h, base_policy, head_policy, "base")


def flat(text: str) -> str:
    return " ".join(text.split())


def test_text_report_covers_every_section(diff):
    text = flat(to_text(diff, Severity.HIGH))
    for expected in (
        "RISK INTRODUCED",
        "NEW lethal trifecta",
        "Servers added:",
        "Servers removed:",
        "Servers changed:",
        "command: npx -> bunx",
        "args: -y mcp-pkg@1.0.0 -> -y fetch-mcp@2.0.0 --token ***",
        "url: https://docs.example/mcp -> https://docs.example/v2",
        "env vars added: NEW_KEY",
        "env vars removed: OLD_TOKEN",
        "Capability changes:",
        "gained untrusted_source via",
        "lost untrusted_source, sink",
        "Tool changes:",
        "mcp:fetcher:write added",
        "mcp:fetcher:old removed",
        "mcp:fetcher:read changed",
        "before: Reads.",
        "Resolved:",
        "TV003",
        "Policy changes in this change",
        "waiver added: TV002 on mcp:mailer: throwaway token (owner bob",
        "waiver removed: TV002 on mcp:old",
        "fail_on: unset -> medium",
        "severity TV003: default -> high",
        "max_waiver_days: 365 -> 30",
        "NOT applied to this check",
    ):
        assert expected in text, expected
    assert "SECRET123" not in text


def test_markdown_report_covers_every_section_and_stays_safe(diff):
    md = to_markdown(diff, Severity.HIGH)
    for expected in (
        "**This change introduces risk.**",
        "### NEW lethal trifecta",
        "### Servers added",
        "### Servers removed",
        "### Servers changed",
        "### Capability changes",
        "### Tool changes",
        "Before:",
        "After:",
        "### Resolved",
        "### Policy changes",
        "NOT applied to this check",
    ):
        assert expected in md, expected
    assert "SECRET123" not in md
    prose = re.sub(r"(`{3,}).*?\1", "", md, flags=re.DOTALL)
    prose = re.sub(r"(`+).*?\1", "", prose)
    for danger in ("@octocat", "http://evil.example", "<img", "onerror", "# heading"):
        assert danger not in prose, danger


def test_json_report_covers_every_section(diff):
    data = json.loads(to_json(diff, Severity.HIGH))
    assert data["introduces_risk"] is True
    assert {s["id"] for s in data["servers_added"]} == {"mcp:mailer", "mcp:postgres"}
    assert data["servers_removed"] == ["mcp:gone"]
    changed = {c["id"]: c["details"] for c in data["servers_changed"]}
    assert any("***" in d for d in changed["mcp:fetcher"])
    assert any(d.startswith("url:") for d in changed["mcp:docs"])
    assert {c["id"] for c in data["capability_changes"]} >= {"mcp:fetcher", "mcp:shrinks"}
    assert {(t["tool"], t["kind"]) for t in data["tool_changes"]} == {
        ("write", "added"),
        ("old", "removed"),
        ("read", "changed"),
    }
    assert data["trifectas"][0]["kind"] == "new"
    # OLD_TOKEN (a literal secret) is gone and left-pad is now pinned: both findings resolved
    assert sorted(f["rule"] for f in data["resolved_findings"]) == ["TV002", "TV003"]
    assert data["policy"]["mode"] == "base"
    assert len(data["policy"]["waivers_added"]) == 1 and len(data["policy"]["waivers_removed"]) == 1
    assert "max_waiver_days: 365 -> 30" in data["policy"]["notes"]
    assert "SECRET123" not in json.dumps(data)


def test_head_policy_mode_drops_the_self_waiver_note(tmp_path, diff):
    # same change, but the new policy is trusted: the note about unapplied waivers goes away
    trusted = compute_diff(
        [],
        [],
        tmp_path,
        tmp_path,
        None,
        parse_policy({"waiver": [waiver("TV002", "mcp:x", "r")]}, TODAY),
        "head",
    )
    assert "NOT applied" not in to_text(trusted, Severity.HIGH)
    assert "NOT applied" not in to_markdown(trusted, Severity.HIGH)


def test_an_accepted_trifecta_is_labelled_in_every_format(tmp_path):
    b, h = tmp_path / "base", tmp_path / "head"
    names = ("search", "postgres", "smtp")
    head = [Server(name=n, client="mcp", source=h / ".mcp.json", command="node") for n in names]
    policy = parse_policy(
        {
            "waiver": [
                {
                    "rule": "TV100",
                    "servers": [f"mcp:{n}" for n in names],
                    "reason": "sandboxed",
                    "owner": "alice",
                    "expires": "2027-01-01",
                }
            ]
        },
        TODAY,
    )
    d = compute_diff([], head, b, h, policy, policy, "base")
    assert "accepted by policy" in to_text(d, Severity.HIGH)
    assert "Accepted by policy" in to_markdown(d, Severity.HIGH)
    assert json.loads(to_json(d, Severity.HIGH))["trifectas"][0]["waiver"]["owner"] == "alice"
    assert not d.introduces_risk(Severity.LOW)


def test_new_findings_table_marks_advisory_and_waived(diff):
    diff.new_findings = [
        Finding(rule_id="ML001", severity=Severity.MEDIUM, message="m", server="s", advisory=True),
        Finding(
            rule_id="TV002",
            severity=Severity.HIGH,
            message="m",
            server="s",
            waiver={"reason": "r", "owner": "o", "expires": "2027-01-01"},
        ),
    ]
    md = to_markdown(diff, Severity.HIGH)
    assert "medium (advisory)" in md and "high (waived)" in md


def test_an_empty_diff_says_so_in_every_format(tmp_path):
    empty = compute_diff([], [], tmp_path, tmp_path)
    assert to_text(empty, Severity.HIGH) == "No capability changes.\n"
    assert "No capability changes in this pull request." in to_markdown(empty, Severity.HIGH)
    assert json.loads(to_json(empty, Severity.HIGH))["introduces_risk"] is False


def test_paths_outside_the_scan_root_fall_back_to_the_file_name(tmp_path):
    outside = Path(__file__)
    finding = Finding(
        rule_id="TV100", severity=Severity.CRITICAL, message="m", server="s", source=outside
    )
    assert _config_name(finding, tmp_path) == outside.name
    assert _config_name(finding.model_copy(update={"source": None}), tmp_path) == "?"
    server = Server(name="s", client="c", source=outside)
    assert _relative(server, tmp_path) == outside.name
