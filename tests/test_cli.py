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


def test_fail_on_threshold_is_respected():
    args = ["scan", str(FIXTURES / "claude_desktop"), "--no-user", "--fail-on", "critical"]
    result = runner.invoke(app, args)
    assert result.exit_code == 0
    assert "AA003" in result.output


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
