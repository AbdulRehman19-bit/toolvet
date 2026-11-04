from pathlib import Path

from toolvet.discovery import discover, parse_config

FIXTURES = Path(__file__).parent / "fixtures"


def test_claude_desktop_fixture():
    servers = discover(FIXTURES / "claude_desktop")
    assert {s.name for s in servers} == {"filesystem", "fetch", "github"}
    assert all(s.client == "claude-desktop" for s in servers)
    github = next(s for s in servers if s.name == "github")
    assert github.env["GITHUB_PERSONAL_ACCESS_TOKEN"].startswith("ghp_")


def test_cursor_fixture_includes_remote_server():
    servers = {s.name: s for s in discover(FIXTURES / "cursor")}
    assert servers["postgres"].command == "npx"
    assert servers["remote-docs"].url == "http://docs.example.test/mcp"


def test_vscode_uses_servers_key():
    servers = discover(FIXTURES / "vscode")
    assert {s.name for s in servers} == {"shell", "slack"}
    assert all(s.client == "vscode" for s in servers)


def test_malformed_and_missing_configs_are_ignored(tmp_path):
    bad = tmp_path / ".mcp.json"
    bad.write_text("{not json", encoding="utf-8")
    assert parse_config(bad, "mcp", "mcpServers") == []
    assert parse_config(tmp_path / "nope.json", "mcp", "mcpServers") == []
    bad.write_text('{"mcpServers": {"a": 1, "b": {"command": "x"}}}', encoding="utf-8")
    assert [s.name for s in parse_config(bad, "mcp", "mcpServers")] == ["b"]


def test_inline_tools_are_parsed(tmp_path):
    cfg = tmp_path / ".mcp.json"
    cfg.write_text(
        '{"mcpServers": {"s": {"command": "x", "tools": '
        '[{"name": "t", "description": "d", "inputSchema": {"type": "object"}}, 5]}}}',
        encoding="utf-8",
    )
    (server,) = discover(tmp_path)
    assert server.tools[0].input_schema == {"type": "object"}
    assert len(server.tools) == 1


def test_user_level_configs_with_home(tmp_path, monkeypatch):
    monkeypatch.setenv("APPDATA", str(tmp_path / "AppData"))
    (tmp_path / ".cursor").mkdir()
    (tmp_path / ".cursor" / "mcp.json").write_text(
        '{"mcpServers": {"u": {"command": "x"}}}', encoding="utf-8"
    )
    repo = tmp_path / "repo"
    repo.mkdir()
    assert [s.name for s in discover(repo, home=tmp_path)] == ["u"]
