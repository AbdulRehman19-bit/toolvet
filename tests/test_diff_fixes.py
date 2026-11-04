import json
import re
import subprocess
from datetime import date, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentaudit.cli import app

runner = CliRunner()


def git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-C", str(repo), *args],
        check=True,
        capture_output=True,
    )


def write(repo: Path, *names: str, policy: str | None = None) -> None:
    servers = {n: {"command": "node"} for n in names}
    (repo / ".mcp.json").write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    if policy is not None:
        (repo / "agent.policy.toml").write_text(policy, encoding="utf-8")


def commit(repo: Path, message: str = "c") -> None:
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q", "-b", "main")
    write(tmp_path, "search", "postgres")
    commit(tmp_path, "base")
    git(tmp_path, "tag", "base")
    return tmp_path


def diff(repo, fmt="json", base="base", *extra):
    result = runner.invoke(app, ["diff", str(repo), "--base", base, "--format", fmt, *extra])
    return result


def trifecta(repo, base="base", *extra):
    data = json.loads(diff(repo, "json", base, *extra).output)
    return data["trifectas"][0]


def test_new_trifecta_points_at_the_server_the_change_adds(repo):
    write(repo, "search", "postgres", "smtp")
    t = trifecta(repo)
    assert t["kind"] == "new" and t["drop_hint"] == ["mcp:smtp"] and t["drop_movable"]
    # the other layers are still offered, but the same fix is not listed twice
    assert t["fixes"] and not any(
        "Move `mcp:smtp`" in f or "Move mcp:smtp" in f for f in t["fixes"]
    )
    assert not any(f.startswith("Move mcp:smtp") for f in t["fixes"])


def test_hint_names_only_the_servers_that_are_needed(repo):
    write(repo, "search", "postgres", "smtp", "calc")  # calc has nothing to do with it
    assert trifecta(repo)["drop_hint"] == ["mcp:smtp"]


def test_hint_includes_every_added_server_when_all_are_needed(repo):
    write(repo, "search", "postgres", "smtp", "webhook")  # two sinks: both must go
    assert trifecta(repo)["drop_hint"] == ["mcp:smtp", "mcp:webhook"]


def test_added_server_that_is_a_trifecta_alone_is_not_told_to_move(repo):
    write(repo, "search", "gmail")
    git(repo, "checkout", "-q", "--", ".")
    git(repo, "checkout", "-q", "-b", "other")
    write(repo, "calc")
    commit(repo, "calc base")
    git(repo, "tag", "calc-base")
    write(repo, "calc", "gmail")
    t = trifecta(repo, "calc-base")
    assert t["drop_hint"] == ["mcp:gmail"] and not t["drop_movable"]
    md = diff(repo, "markdown", "calc-base").output
    assert "moving them elsewhere does not help" in md


def test_widened_trifecta_has_fixes_but_no_drop_hint(repo):
    write(repo, "search", "postgres", "smtp")
    commit(repo, "accepted trifecta")
    git(repo, "tag", "has-trifecta")
    write(repo, "search", "postgres", "smtp", "slack")
    t = trifecta(repo, "has-trifecta")
    assert t["kind"] == "widened" and t["drop_hint"] == [] and t["fixes"]


def test_resolved_trifecta_has_no_fixes(repo):
    write(repo, "search", "postgres", "smtp")
    commit(repo, "trifecta")
    git(repo, "tag", "has-trifecta")
    write(repo, "search", "postgres")
    t = trifecta(repo, "has-trifecta")
    assert t["kind"] == "resolved" and t["fixes"] == [] and t["drop_hint"] == []


def test_accepted_trifecta_gets_no_fix_nagging(repo):
    expires = (date.today() + timedelta(days=60)).isoformat()
    policy = (
        '[[waiver]]\nrule = "AA100"\nservers = ["mcp:postgres", "mcp:search", "mcp:smtp"]\n'
        f'reason = "sandboxed"\nowner = "alice"\nexpires = {expires}\n'
    )
    write(repo, "search", "postgres", policy=policy)
    commit(repo, "policy")
    git(repo, "tag", "with-policy")
    write(repo, "search", "postgres", "smtp", policy=policy)
    t = trifecta(repo, "with-policy")
    assert t["waiver"] and t["fixes"] == [] and t["drop_hint"] == []


def test_markdown_comment_lists_the_fixes(repo):
    write(repo, "search", "postgres", "smtp")
    md = diff(repo, "markdown").output
    assert "Smallest fixes:" in md
    assert "Drop or move the server(s) this change adds (`mcp:smtp`)" in md
    assert "Consider moving one of these servers" not in md


def test_terminal_output_lists_the_fixes(repo):
    write(repo, "search", "postgres", "smtp")
    out = " ".join(diff(repo, "terminal").output.split())
    assert "Smallest fixes:" in out and "Drop or move the server(s) this change adds" in out


def test_hostile_server_names_cannot_escape_the_fix_text(repo):
    write(repo, "search", "postgres", "smtp-@octocat")
    md = diff(repo, "markdown").output
    assert "Smallest fixes:" in md
    stripped = re.sub(r"(`+).*?\1", "", re.sub(r"(`{3,}).*?\1", "", md, flags=re.DOTALL))
    assert "@octocat" not in stripped
