import json
from datetime import date, timedelta
from pathlib import Path

from typer.testing import CliRunner

from agentaudit.cli import app

runner = CliRunner()


def iso(days: int) -> str:
    return (date.today() + timedelta(days=days)).isoformat()


def repo(tmp_path: Path, servers: dict, policy: str | None = None) -> Path:
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    if policy is not None:
        (tmp_path / "agent.policy.toml").write_text(policy, encoding="utf-8")
    return tmp_path


def scan(path: Path, *args: str):
    return runner.invoke(app, ["scan", str(path), "--no-user", *args])


SECRET = {"mailer": {"command": "node", "env": {"SMTP_PASSWORD": "hunter2"}}}


def waiver(rule="AA002", server="mcp:mailer", days=90, extra="") -> str:
    return (
        f'\n[[waiver]]\nrule = "{rule}"\nserver = "{server}"\nreason = "sandbox account"\n'
        f'owner = "alice"\nexpires = {iso(days)}\n{extra}'
    )


def test_unwaived_secret_fails(tmp_path):
    assert scan(repo(tmp_path, SECRET)).exit_code == 1


def test_waiver_stops_the_failure_but_stays_visible(tmp_path):
    path = repo(tmp_path, SECRET, waiver())
    result = scan(path)
    assert result.exit_code == 0
    assert "(waived)" in result.output
    assert "sandbox account" in result.output.replace("\n", " ")
    data = json.loads(scan(path, "--format", "json").output)
    assert data["findings"][0]["waiver"]["owner"] == "alice"
    sarif = json.loads(scan(path, "--format", "sarif").output)
    assert sarif["runs"][0]["results"][0]["suppressions"][0]["justification"] == "sandbox account"


def test_expired_waiver_no_longer_applies_and_is_called_out(tmp_path):
    path = repo(tmp_path, SECRET, waiver(days=-3))
    result = scan(path)
    assert result.exit_code == 1
    assert "expired" in result.output


def test_waiver_expiring_soon_warns_but_still_applies(tmp_path):
    result = scan(repo(tmp_path, SECRET, waiver(days=5)))
    assert result.exit_code == 0
    assert "expires on" in result.output


def test_unused_waiver_is_reported(tmp_path):
    result = scan(repo(tmp_path, {"ok": {"command": "node"}}, waiver(server="mcp:ghost")))
    assert result.exit_code == 0
    assert "matches no current finding" in result.output


def trifecta_servers(*extra: str) -> dict:
    names = ["search", "postgres", "smtp", *extra]
    return {name: {"command": "node"} for name in names}


TRIFECTA = (
    '\n[[waiver]]\nrule = "AA100"\nservers = ["mcp:postgres", "mcp:search", "mcp:smtp"]\n'
    f'reason = "all three run in a sandbox"\nowner = "alice"\nexpires = {iso(90)}\n'
)


def test_trifecta_waiver_accepts_exactly_what_was_reviewed(tmp_path):
    assert scan(repo(tmp_path, trifecta_servers())).exit_code == 1
    assert scan(repo(tmp_path, trifecta_servers(), TRIFECTA)).exit_code == 0


def test_widening_a_waived_trifecta_fails_again(tmp_path):
    path = repo(tmp_path, trifecta_servers("slack"), TRIFECTA)
    result = scan(path)
    assert result.exit_code == 1
    assert "mcp:slack" in result.output.replace("\n", "").replace("|", "").replace(" ", "")


def test_invalid_policy_exits_2_and_lists_every_problem(tmp_path):
    bad = 'fail_on = "loud"\n[[waiver]]\nrule = "AA002"\nserver = "x"\nreason = ""\nowner = ""\n'
    result = scan(repo(tmp_path, SECRET, bad))
    assert result.exit_code == 2
    for problem in ("fail_on", "reason is required", "owner is required", "expires is required"):
        assert problem in result.output.replace("\n", " ")


def test_policy_fail_on_is_the_default_and_the_flag_overrides_it(tmp_path):
    servers = {"pkg": {"command": "npx", "args": ["-y", "left-pad"]}}  # AA003, medium
    path = repo(tmp_path, servers, 'fail_on = "medium"\n')
    assert scan(path).exit_code == 1
    assert scan(path, "--fail-on", "high").exit_code == 0
    bare = tmp_path / "no-policy"
    bare.mkdir()
    assert scan(repo(bare, servers)).exit_code == 0  # no policy: default high


def test_severity_override_changes_the_outcome(tmp_path):
    servers = {"pkg": {"command": "npx", "args": ["-y", "left-pad"]}}
    path = repo(tmp_path, servers, '[severity]\nAA003 = "high"\n')
    assert scan(path).exit_code == 1


def test_explicit_policy_file(tmp_path):
    path = repo(tmp_path, SECRET)
    other = tmp_path / "elsewhere.toml"
    other.write_text(waiver().lstrip(), encoding="utf-8")
    assert scan(path, "--policy", str(other)).exit_code == 0


def test_badge_and_markdown_respect_waivers(tmp_path):
    path = repo(tmp_path, SECRET, waiver())
    assert "low-risk" in scan(path, "--format", "badge").output
    assert "(waived)" in scan(path, "--format", "markdown").output


def check(path: Path, *args: str):
    return runner.invoke(app, ["policy", "check", str(path), *args])


def test_policy_check_lists_waivers(tmp_path):
    result = check(repo(tmp_path, SECRET, waiver()))
    assert result.exit_code == 0
    assert "1 waiver(s)" in result.output and "alice" in result.output


def test_policy_check_fails_on_expired_and_strict_on_unused(tmp_path):
    assert check(repo(tmp_path, SECRET, waiver(days=-1))).exit_code == 1
    unused = repo(tmp_path, {"ok": {"command": "node"}}, waiver(server="mcp:ghost"))
    assert check(unused).exit_code == 0
    assert check(unused, "--strict").exit_code == 1


def test_policy_check_without_a_policy(tmp_path):
    result = check(repo(tmp_path, SECRET))
    assert result.exit_code == 0 and "empty" in result.output


def test_policy_check_with_invalid_policy(tmp_path):
    assert check(repo(tmp_path, SECRET, "bogus = 1\n")).exit_code == 2
