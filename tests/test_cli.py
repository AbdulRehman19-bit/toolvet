from pathlib import Path

from typer.testing import CliRunner

from agentaudit.cli import app

FIXTURES = Path(__file__).parent / "fixtures"
runner = CliRunner()


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "agentaudit" in result.output


def test_scan_reports_findings_and_fails_on_high():
    result = runner.invoke(app, ["scan", str(FIXTURES / "claude_desktop"), "--no-user"])
    assert result.exit_code == 1
    assert "filesystem" in result.output
    assert "3 MCP server" in result.output
    assert "AA002" in result.output


def test_scan_reports_trifecta_with_evidence():
    result = runner.invoke(app, ["scan", str(FIXTURES / "claude_desktop"), "--no-user"])
    assert "AA100" in result.output
    assert "untrusted_source via" in result.output


def test_fail_on_threshold_is_respected():
    args = ["scan", str(FIXTURES / "cursor"), "--no-user", "--fail-on", "critical"]
    result = runner.invoke(app, args)
    assert result.exit_code == 0
    assert "AA005" in result.output


def test_scan_with_no_findings(tmp_path):
    (tmp_path / ".mcp.json").write_text(
        '{"mcpServers": {"ok": {"command": "node", "args": ["server.js"]}}}', encoding="utf-8"
    )
    result = runner.invoke(app, ["scan", str(tmp_path), "--no-user"])
    assert result.exit_code == 0
    assert "No findings" in result.output


def test_scan_with_no_servers(tmp_path):
    result = runner.invoke(app, ["scan", str(tmp_path), "--no-user"])
    assert result.exit_code == 0
    assert "No MCP servers found" in result.output


def _repo(tmp_path, args='["server.js"]'):
    (tmp_path / ".mcp.json").write_text(
        '{"mcpServers": {"ok": {"command": "node", "args": ' + args + "}}}", encoding="utf-8"
    )


def test_lock_then_verify_clean(tmp_path):
    _repo(tmp_path)
    result = runner.invoke(app, ["lock", str(tmp_path)])
    assert result.exit_code == 0
    assert "Locked 1 server" in result.output
    assert "not pinned" in result.output
    assert (tmp_path / "agent.lock").is_file()
    result = runner.invoke(app, ["verify", str(tmp_path)])
    assert result.exit_code == 0
    assert "No drift" in result.output


def test_verify_fails_on_drift(tmp_path):
    _repo(tmp_path)
    runner.invoke(app, ["lock", str(tmp_path)])
    _repo(tmp_path, args='["evil.js"]')
    result = runner.invoke(app, ["verify", str(tmp_path)])
    assert result.exit_code == 1
    assert "config changed" in result.output


def test_verify_without_lockfile_exits_2(tmp_path):
    _repo(tmp_path)
    result = runner.invoke(app, ["verify", str(tmp_path)])
    assert result.exit_code == 2
    assert "cannot read" in result.output


def test_lock_with_no_servers_fails(tmp_path):
    result = runner.invoke(app, ["lock", str(tmp_path)])
    assert result.exit_code == 1


def test_tool_snapshot_is_pinned_and_rug_pull_detected(tmp_path):
    from agentaudit.models import Tool
    from agentaudit.snapshot import write_snapshot

    _repo(tmp_path)
    write_snapshot(tmp_path / "agent.tools.json", {"mcp:ok": [Tool(name="t", description="safe")]})
    result = runner.invoke(app, ["lock", str(tmp_path)])
    assert "1 with tool definitions" in result.output
    write_snapshot(tmp_path / "agent.tools.json", {"mcp:ok": [Tool(name="t", description="evil")]})
    result = runner.invoke(app, ["verify", str(tmp_path)])
    assert result.exit_code == 1
    assert "tool changed" in result.output
