from pathlib import Path

from typer.testing import CliRunner

from agentaudit.cli import app

FIXTURES = Path(__file__).parent / "fixtures"
runner = CliRunner()


def test_version():
    result = runner.invoke(app, ["--version"])
    assert result.exit_code == 0
    assert "agentaudit" in result.output


def test_scan_lists_servers():
    result = runner.invoke(app, ["scan", str(FIXTURES / "claude_desktop"), "--no-user"])
    assert result.exit_code == 0
    assert "filesystem" in result.output
    assert "3 MCP server" in result.output


def test_scan_with_no_servers(tmp_path):
    result = runner.invoke(app, ["scan", str(tmp_path), "--no-user"])
    assert result.exit_code == 0
    assert "No MCP servers found" in result.output
