import json
from pathlib import Path

from typer.testing import CliRunner

from toolvet.cli import app
from toolvet.graph import MAX_FIXES_LISTED, find_trifectas
from toolvet.models import Server

runner = CliRunner()


def make(name: str, source: str = "a.json") -> Server:
    return Server(name=name, client="t", source=Path(source), command="node")


def repo(tmp_path: Path, *names: str, policy: str = "") -> Path:
    servers = {n: {"command": "node"} for n in names}
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    if policy:
        (tmp_path / "agent.policy.toml").write_text(policy, encoding="utf-8")
    return tmp_path


def test_trifecta_findings_carry_fixes():
    (finding,) = find_trifectas([make("search"), make("postgres"), make("smtp")])
    assert 1 <= len(finding.fix) <= MAX_FIXES_LISTED
    assert any("t:smtp" in line and "sends data out" in line for line in finding.fix)


def test_gmail_alone_says_moving_does_not_help():
    (finding,) = find_trifectas([make("gmail")])
    assert "moving it does not help" in finding.fix[0]


def test_terminal_report_lists_the_smallest_fixes(tmp_path):
    result = runner.invoke(
        app, ["scan", str(repo(tmp_path, "search", "postgres", "smtp")), "--no-user"]
    )
    text = " ".join(result.output.split())
    assert "Smallest fixes" in text and "separate agent profile" in text


def test_json_sarif_and_markdown_include_the_fixes(tmp_path):
    path = repo(tmp_path, "search", "postgres", "smtp")
    base = ["scan", str(path), "--no-user", "--format"]
    data = json.loads(runner.invoke(app, [*base, "json"]).output)
    trifecta = next(f for f in data["findings"] if f["rule"] == "TV100")
    assert trifecta["fix"]
    sarif = json.loads(runner.invoke(app, [*base, "sarif"]).output)
    result = next(r for r in sarif["runs"][0]["results"] if r["ruleId"] == "TV100")
    assert result["properties"]["suggestions"] == trifecta["fix"]
    markdown = runner.invoke(app, [*base, "markdown"]).output
    assert "Smallest fixes:" in markdown


def test_waived_trifecta_does_not_nag_about_fixes(tmp_path):
    from datetime import date, timedelta

    expires = (date.today() + timedelta(days=30)).isoformat()
    policy = (
        '[[waiver]]\nrule = "TV100"\nservers = ["mcp:postgres", "mcp:search", "mcp:smtp"]\n'
        f'reason = "sandboxed"\nowner = "alice"\nexpires = {expires}\n'
    )
    path = repo(tmp_path, "search", "postgres", "smtp", policy=policy)
    result = runner.invoke(app, ["scan", str(path), "--no-user"])
    assert result.exit_code == 0
    assert "Smallest fixes" not in result.output
    assert (
        "Smallest fixes"
        not in runner.invoke(app, ["scan", str(path), "--no-user", "--format", "markdown"]).output
    )
