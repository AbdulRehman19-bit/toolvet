from pathlib import Path

from agentaudit.discovery import discover
from agentaudit.models import Server, Severity
from agentaudit.rules import Hit, Rule, load_rules, run_rules

FIXTURES = Path(__file__).parent / "fixtures"


def make(**kw) -> Server:
    kw.setdefault("name", "s")
    return Server(client="test", source=Path("mcp.json"), **kw)


def ids(server: Server) -> set[str]:
    return {f.rule_id for f in run_rules([server])}


def test_shell_launch_and_name():
    assert "AA001" in ids(make(command="bash", args=["-c", "x"]))
    assert "AA001" in ids(make(command="C:\\Windows\\cmd.exe"))
    assert "AA001" in ids(make(command="npx", args=["-y", "mcp-shell-server@1.0.0"]))
    assert "AA001" not in ids(make(command="npx", args=["-y", "pkg@1.0.0"]))


def test_secret_env_ignores_placeholders_and_hides_value():
    server = make(
        command="x",
        env={"API_TOKEN": "abc123", "DB_PASSWORD": "${env:DB}", "KEY": "", "HOME": "/h"},
    )
    findings = [f for f in run_rules([server]) if f.rule_id == "AA002"]
    assert [f.evidence for f in findings] == [["API_TOKEN"]]
    assert "abc123" not in findings[0].message


def test_unpinned_package_variants():
    assert "AA003" in ids(make(command="npx", args=["-y", "pkg"]))
    assert "AA003" in ids(make(command="npx", args=["pkg@latest"]))
    assert "AA003" in ids(make(command="uvx", args=["--from", "tool", "run"]))
    assert "AA003" not in ids(make(command="npx", args=["-y", "@scope/pkg@1.2.3"]))
    assert "AA003" not in ids(make(command="uvx", args=["pkg==1.0"]))
    assert "AA003" not in ids(make(command="uvx", args=["--from", "tool==2.0", "run"]))
    assert "AA003" not in ids(make(command="npx", args=["./local"]))
    assert "AA003" not in ids(make(command="python", args=["server.py"]))
    assert "AA003" not in ids(make(command="npx", args=["-y"]))


def test_wildcard_paths():
    for arg in ["/", "~", "C:\\", "d:/", "/home/*"]:
        assert "AA004" in ids(make(command="x", args=[arg])), arg
    assert "AA004" not in ids(make(command="x", args=["--root", "/home/me/project"]))


def test_plain_http():
    assert "AA005" in ids(make(url="http://example.test/mcp"))
    assert "AA005" not in ids(make(url="https://example.test/mcp"))
    assert "AA005" not in ids(make(url="http://localhost:3000/mcp"))


def test_fixture_findings():
    findings = run_rules(discover(FIXTURES / "claude_desktop"))
    by_rule = {(f.rule_id, f.server.split(":")[1]) for f in findings}
    assert ("AA002", "github") in by_rule
    assert ("AA003", "fetch") in by_rule
    assert ("AA003", "filesystem") not in by_rule


def test_plugin_rules_can_be_passed_explicitly():
    custom = Rule("XX001", "custom", lambda s: [Hit(Severity.LOW, "hi")])
    findings = run_rules([make(command="x")], rules=[custom])
    assert [f.rule_id for f in findings] == ["XX001"]
    assert findings[0].server == "test:s"


def test_load_rules_sorted_and_includes_builtins():
    ids_ = [r.id for r in load_rules()]
    assert ids_ == sorted(ids_)
    assert {"AA001", "AA005"} <= set(ids_)
