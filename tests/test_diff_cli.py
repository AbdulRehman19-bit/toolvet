import json
import re
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from agentaudit.cli import app
from agentaudit.diff_render import MARKER
from agentaudit.models import Tool
from agentaudit.snapshot import write_snapshot

runner = CliRunner()


def git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-C", str(repo), *args],
        check=True,
        capture_output=True,
    )


def mcp(servers: dict) -> str:
    return json.dumps({"mcpServers": servers})


def commit(repo: Path, servers: dict | None = None, message: str = "c") -> None:
    if servers is not None:
        (repo / ".mcp.json").write_text(mcp(servers), encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q", "-b", "main")
    commit(tmp_path, {"search": {"command": "node"}, "postgres": {"command": "node"}}, "base")
    git(tmp_path, "tag", "base")
    return tmp_path


def run(repo, *args):
    return runner.invoke(app, ["diff", str(repo), *args])


def strip_code(markdown: str) -> str:
    """Remove fenced blocks and inline code spans; what remains is what GitHub would render."""
    markdown = re.sub(r"(`{3,}).*?\1", "", markdown, flags=re.DOTALL)
    return re.sub(r"(`+).*?\1", "", markdown)


def test_adding_a_sink_fails_and_explains_why(repo):
    (repo / ".mcp.json").write_text(
        mcp(
            {
                "search": {"command": "node"},
                "postgres": {"command": "node"},
                "smtp": {"command": "node"},
            }
        ),
        encoding="utf-8",
    )
    result = run(repo, "--base", "base")
    assert result.exit_code == 1
    assert "RISK INTRODUCED" in result.output
    assert "NEW lethal trifecta" in result.output
    assert "mcp:smtp" in result.output.replace("\n", "")


def test_no_changes_is_clean(repo):
    result = run(repo, "--base", "base")
    assert result.exit_code == 0
    assert "No capability changes" in result.output


def test_removing_a_server_that_resolves_nothing_is_not_risk(repo):
    (repo / ".mcp.json").write_text(mcp({"search": {"command": "node"}}), encoding="utf-8")
    result = run(repo, "--base", "base")
    assert result.exit_code == 0
    assert "Servers removed" in result.output


def test_markdown_comment_has_marker_and_sections(repo):
    (repo / ".mcp.json").write_text(
        mcp(
            {
                "search": {"command": "node"},
                "postgres": {"command": "node"},
                "smtp": {"command": "node"},
            }
        ),
        encoding="utf-8",
    )
    result = run(repo, "--base", "base", "--format", "markdown")
    assert result.exit_code == 1
    assert result.output.startswith(MARKER)
    assert "### NEW lethal trifecta" in result.output
    assert "### Servers added" in result.output
    assert "`mcp:smtp`" in result.output


def test_json_output_and_file(repo, tmp_path):
    (repo / ".mcp.json").write_text(mcp({"search": {"command": "node"}}), encoding="utf-8")
    out = tmp_path / "d.json"
    result = run(repo, "--base", "base", "--format", "json", "-o", str(out))
    assert result.exit_code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["introduces_risk"] is False
    assert data["servers_removed"] == ["mcp:postgres"]


def test_head_ref_compares_two_commits_not_the_working_tree(repo):
    commit(
        repo,
        {
            "search": {"command": "node"},
            "postgres": {"command": "node"},
            "smtp": {"command": "node"},
        },
        "adds smtp",
    )
    (repo / ".mcp.json").write_text(mcp({}), encoding="utf-8")  # uncommitted, must be ignored
    result = run(repo, "--base", "base", "--head", "HEAD")
    assert result.exit_code == 1
    assert "NEW lethal trifecta" in result.output


def test_fail_on_threshold_applies_to_new_findings(repo):
    (repo / ".mcp.json").write_text(
        mcp(
            {
                "search": {"command": "node"},
                "postgres": {"command": "node"},
                "pkg": {"command": "npx", "args": ["-y", "left-pad"]},
            }
        ),
        encoding="utf-8",
    )
    assert run(repo, "--base", "base").exit_code == 0  # AA003 is medium, below the default
    assert run(repo, "--base", "base", "--fail-on", "medium").exit_code == 1


def test_errors_exit_2(repo, tmp_path_factory):
    assert run(repo).exit_code == 2
    result = run(repo, "--base", "no-such-ref")
    assert result.exit_code == 2 and "unknown git ref" in result.output
    result = run(repo, "--base", "--upload-pack=evil")
    assert result.exit_code == 2
    plain = tmp_path_factory.mktemp("plain")
    assert run(plain, "--base", "HEAD").exit_code == 2


def test_untrusted_text_cannot_escape_code_in_a_pr_comment(repo):
    evil = (
        "Reads files. ``` </details> @octocat [click](http://evil.example) "
        "<img src=x onerror=alert(1)> ````` | ## fake heading"
    )
    git(repo, "checkout", "-q", "-b", "pr")
    (repo / ".mcp.json").write_text(
        mcp(
            {
                "search": {"command": "node"},
                "postgres": {"command": "node"},
                "@octocat `x`": {"command": "node", "args": ["--token", "SUPERSECRET"]},
            }
        ),
        encoding="utf-8",
    )
    write_snapshot(repo / "agent.tools.json", {"mcp:search": [Tool(name="t", description=evil)]})
    commit(repo)
    git(repo, "checkout", "-q", "main")
    git(repo, "checkout", "-q", "pr", "--", "agent.tools.json")
    commit(repo, None, "snapshot only")
    git(repo, "checkout", "-q", "pr")
    # Change the description between base and head so a before/after block is rendered.
    base_tool = Tool(name="t", description="Reads files.")
    git(repo, "checkout", "-q", "main")
    write_snapshot(repo / "agent.tools.json", {"mcp:search": [base_tool]})
    commit(repo, None, "base snapshot")
    git(repo, "checkout", "-q", "pr")

    result = run(repo, "--base", "main", "--head", "pr", "--format", "markdown")
    assert "SUPERSECRET" not in result.output
    rendered = strip_code(result.output)
    for danger in (
        "@octocat",
        "http://evil.example",
        "<img",
        "onerror",
        "</details>",
        "fake heading",
    ):
        assert danger not in rendered, danger
    assert "### Tool changes" in result.output
