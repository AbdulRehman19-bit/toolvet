import json
import subprocess
from datetime import date, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from toolvet.cli import app

runner = CliRunner()
EXPIRES = (date.today() + timedelta(days=90)).isoformat()


def git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-C", str(repo), *args],
        check=True,
        capture_output=True,
    )


def servers(*names: str) -> dict:
    return {name: {"command": "node"} for name in names}


def write(repo: Path, mcp_servers: dict, policy: str | None = None) -> None:
    (repo / ".mcp.json").write_text(json.dumps({"mcpServers": mcp_servers}), encoding="utf-8")
    policy_file = repo / "agent.policy.toml"
    if policy is None:
        policy_file.unlink(missing_ok=True)
    else:
        policy_file.write_text(policy, encoding="utf-8")


def commit(repo: Path, message: str = "c") -> None:
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)


def trifecta_waiver(*names: str) -> str:
    listed = ", ".join(f'"mcp:{n}"' for n in names)
    return (
        f'\n[[waiver]]\nrule = "TV100"\nservers = [{listed}]\n'
        f'reason = "runs in a sandbox"\nowner = "alice"\nexpires = {EXPIRES}\n'
    )


def finding_waiver(server: str, rule: str = "TV002") -> str:
    return (
        f'\n[[waiver]]\nrule = "{rule}"\nserver = "{server}"\nreason = "throwaway token"\n'
        f'owner = "bob"\nexpires = {EXPIRES}\n'
    )


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q", "-b", "main")
    write(tmp_path, servers("search", "postgres"))
    commit(tmp_path, "base")
    git(tmp_path, "tag", "base")
    return tmp_path


def run(repo, *args):
    return runner.invoke(app, ["diff", str(repo), "--base", "base", *args])


def flat(text: str) -> str:
    return text.replace("\n", " ").replace("|", " ")


def test_a_change_cannot_waive_its_own_trifecta(repo):
    write(
        repo, servers("search", "postgres", "smtp"), trifecta_waiver("search", "postgres", "smtp")
    )
    result = run(repo)
    assert result.exit_code == 1
    assert "RISK INTRODUCED" in result.output
    assert "waiver added" in result.output
    assert "NOT applied to this check" in flat(result.output)


def test_head_mode_trusts_the_new_policy(repo):
    write(
        repo, servers("search", "postgres", "smtp"), trifecta_waiver("search", "postgres", "smtp")
    )
    result = run(repo, "--policy", "head")
    assert result.exit_code == 0
    assert "accepted by policy" in flat(result.output)
    assert "NOT applied" not in result.output


def test_none_mode_ignores_waivers_entirely(repo):
    write(
        repo, servers("search", "postgres", "smtp"), trifecta_waiver("search", "postgres", "smtp")
    )
    assert run(repo, "--policy", "none").exit_code == 1


def test_trifecta_accepted_on_the_base_branch_stays_accepted(repo):
    write(
        repo, servers("search", "postgres", "smtp"), trifecta_waiver("search", "postgres", "smtp")
    )
    commit(repo, "accept")
    git(repo, "tag", "accepted")
    write(
        repo,
        servers("search", "postgres", "smtp", "notes-only"),
        trifecta_waiver("search", "postgres", "smtp"),
    )
    result = runner.invoke(app, ["diff", str(repo), "--base", "accepted"])
    assert result.exit_code == 0, result.output


def test_widening_an_accepted_trifecta_fails_even_though_it_was_waived(repo):
    write(
        repo, servers("search", "postgres", "smtp"), trifecta_waiver("search", "postgres", "smtp")
    )
    commit(repo, "accept")
    git(repo, "tag", "accepted")
    write(
        repo,
        servers("search", "postgres", "smtp", "slack"),
        trifecta_waiver("search", "postgres", "smtp"),
    )
    result = runner.invoke(app, ["diff", str(repo), "--base", "accepted"])
    assert result.exit_code == 1
    assert "WIDENED" in result.output


def test_base_waiver_for_a_known_server_applies_to_a_change_to_it(repo):
    secret = {"mailer": {"command": "node", "env": {"SMTP_PASSWORD": "x"}}}
    write(repo, {**servers("search", "postgres"), **secret}, finding_waiver("mcp:mailer"))
    commit(repo, "accept")
    git(repo, "tag", "accepted")
    changed = {"mailer": {"command": "node", "args": ["--v2"], "env": {"SMTP_PASSWORD": "y"}}}
    write(repo, {**servers("search", "postgres"), **changed}, finding_waiver("mcp:mailer"))
    result = runner.invoke(app, ["diff", str(repo), "--base", "accepted"])
    assert result.exit_code == 0, result.output


def test_a_new_server_is_not_covered_by_a_waiver_for_another(repo):
    write(
        repo,
        {**servers("search"), "mailer": {"command": "node", "env": {"A_TOKEN": "x"}}},
        finding_waiver("mcp:mailer"),
    )
    commit(repo, "accept")
    git(repo, "tag", "accepted")
    write(
        repo,
        {
            **servers("search"),
            "mailer": {"command": "node", "env": {"A_TOKEN": "x"}},
            "mailer2": {"command": "node", "env": {"B_TOKEN": "y"}},
        },
        finding_waiver("mcp:mailer"),
    )
    result = runner.invoke(app, ["diff", str(repo), "--base", "accepted"])
    assert result.exit_code == 1
    assert "mcp:mailer2" in flat(result.output)


def test_waived_new_finding_is_shown_but_does_not_fail(repo):
    write(repo, servers("search", "postgres"), finding_waiver("mcp:*"))
    commit(repo, "policy only")
    git(repo, "tag", "policy")
    write(
        repo,
        {
            **servers("search", "postgres"),
            "mailer": {"command": "node", "env": {"SMTP_PASSWORD": "x"}},
        },
        finding_waiver("mcp:*"),
    )
    result = runner.invoke(app, ["diff", str(repo), "--base", "policy", "--format", "markdown"])
    assert result.exit_code == 0
    assert "(waived)" in result.output


def test_policy_fail_on_from_the_base_branch_is_the_default(repo):
    write(repo, servers("search", "postgres"), 'fail_on = "medium"\n')
    commit(repo, "policy")
    git(repo, "tag", "strict")
    write(
        repo,
        {**servers("search", "postgres"), "pkg": {"command": "npx", "args": ["-y", "left-pad"]}},
        'fail_on = "medium"\n',
    )
    assert runner.invoke(app, ["diff", str(repo), "--base", "strict"]).exit_code == 1
    args = ["diff", str(repo), "--base", "strict", "--fail-on", "high"]
    assert runner.invoke(app, args).exit_code == 0


def test_policy_edits_are_reported_for_review(repo):
    write(repo, servers("search", "postgres"), 'fail_on = "critical"\n[severity]\nTV003 = "low"\n')
    result = run(repo, "--format", "json")
    data = json.loads(result.output)
    notes = " ".join(data["policy"]["notes"])
    assert "severity TV003: default -> low" in notes and "fail_on: unset -> critical" in notes
    assert data["policy"]["mode"] == "base"


def test_removed_waivers_are_reported(repo):
    write(repo, servers("search", "postgres"), finding_waiver("mcp:search"))
    commit(repo, "with waiver")
    git(repo, "tag", "with-waiver")
    write(repo, servers("search", "postgres"), None)
    result = runner.invoke(app, ["diff", str(repo), "--base", "with-waiver"])
    assert "waiver removed" in result.output


def test_invalid_policy_in_the_change_exits_2(repo):
    write(repo, servers("search", "postgres"), "bogus = 1\n")
    assert run(repo).exit_code == 2


def test_markdown_comment_warns_reviewers_and_stays_safe(repo):
    hostile = (
        '\n[[waiver]]\nrule = "TV002"\nserver = "@octocat `x`"\n'
        'reason = "see [click](http://evil.example) <img src=x>"\nowner = "@evil"\n'
        f"expires = {EXPIRES}\n"
    )
    write(repo, servers("search", "postgres"), hostile)
    result = run(repo, "--format", "markdown")
    text = result.output
    assert "### Policy changes" in text and "NOT applied to this check" in text
    import re

    stripped = re.sub(r"(`+).*?\1", "", re.sub(r"(`{3,}).*?\1", "", text, flags=re.DOTALL))
    for danger in ("@octocat", "@evil", "http://evil.example", "<img"):
        assert danger not in stripped, danger
