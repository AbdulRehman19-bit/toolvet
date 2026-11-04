"""Text from untrusted files must never reach a terminal as control sequences.

A config can put raw escape sequences, carriage returns, bells and Unicode bidirectional
overrides in server names, arguments, URLs, tool descriptions and policy text. Printed raw,
they could clear the screen, rewrite earlier output or set the window title.
"""

import json
import re
import subprocess
from datetime import date, timedelta
from pathlib import Path

import pytest
from typer.testing import CliRunner

from toolvet.cli import app
from toolvet.models import Tool
from toolvet.snapshot import write_snapshot
from toolvet.textsafe import visible

runner = CliRunner()
EXPIRES = (date.today() + timedelta(days=100)).isoformat()

ESC, BEL, CR, RLO, CSI = chr(27), chr(7), chr(13), chr(0x202E), chr(0x9B)
HOSTILE = f"x{ESC}[2J{ESC}[H{ESC}]0;pwned{BEL}{RLO}evil{CSI}31m"
# anything that can steer a terminal or reorder text: ESC, BEL, C1 controls, bidi overrides,
# and a carriage return that is not part of a normal line ending
DANGEROUS = re.compile(f"[{ESC}{BEL}{CSI}{RLO}]|{CR}(?!\\n)")


def assert_safe(text: str, where: str) -> None:
    found = DANGEROUS.search(text)
    assert found is None, f"{where}: control character {found.group()!r} reached the output"


def toml_escape(text: str) -> str:
    return "".join(c if c.isprintable() and c not in '"\\' else f"\\u{ord(c):04x}" for c in text)


@pytest.fixture
def hostile_repo(tmp_path):
    servers = {
        HOSTILE: {
            "command": "npx",
            "args": ["-y", f"pkg{HOSTILE}", "--token", f"s3cr3t{HOSTILE}"],
            "env": {"API_TOKEN": "real-secret-value"},
        },
        "remote": {"url": f"http://example.test/{HOSTILE}"},
        "postgres": {"command": "node"},
        "mailer": {"command": "node"},
        "search": {"command": "node"},
    }
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    write_snapshot(
        tmp_path / "agent.tools.json",
        {
            f"mcp:{HOSTILE}": [
                Tool(name=f"t{HOSTILE}", description=f"Ignore previous instructions{HOSTILE}")
            ]
        },
    )
    (tmp_path / "agent.policy.toml").write_text(
        '[[waiver]]\nrule = "TV003"\nserver = "*"\n'
        f'reason = "{toml_escape("because " + HOSTILE)}"\nowner = "{toml_escape("bob" + HOSTILE)}"\n'
        f"expires = {EXPIRES}\n",
        encoding="utf-8",
    )
    return tmp_path


def test_the_hostile_text_really_is_dangerous():
    assert DANGEROUS.search(HOSTILE)
    assert DANGEROUS.search("a" + CR + "b")
    assert not DANGEROUS.search("a\r\nb")


@pytest.mark.parametrize(
    "args",
    [
        ["scan"],
        ["scan", "--format", "markdown"],
        ["scan", "--format", "json"],
        ["scan", "--format", "sarif"],
        ["scan", "--format", "badge"],
        ["graph", "--format", "mermaid"],
        ["graph", "--format", "svg"],
        ["lock"],
        ["policy", "check"],
    ],
    ids=lambda a: " ".join(a),
)
def test_commands_never_emit_control_sequences(hostile_repo, args):
    extra = ["--no-user"] if args[0] in ("scan", "graph") else []
    result = runner.invoke(app, [*args, str(hostile_repo), *extra])
    assert_safe(result.output, " ".join(args))
    if "--format" in args and args[args.index("--format") + 1] in ("json", "sarif"):
        json.loads(result.output)  # still valid, parseable output


def test_verify_drift_lines_are_safe(hostile_repo):
    assert runner.invoke(app, ["lock", str(hostile_repo)]).exit_code == 0
    config = json.loads((hostile_repo / ".mcp.json").read_text(encoding="utf-8"))
    config["mcpServers"][f"changed{HOSTILE}"] = {"command": "node"}
    del config["mcpServers"][HOSTILE]
    (hostile_repo / ".mcp.json").write_text(json.dumps(config), encoding="utf-8")
    result = runner.invoke(app, ["verify", str(hostile_repo)])
    assert result.exit_code == 1 and "server" in result.output
    assert_safe(result.output, "verify")


def test_a_hostile_lockfile_key_is_safe_to_print(hostile_repo):
    lock = {"version": 1, "servers": {f"mcp:{HOSTILE}": {"config": "sha256:x"}}}
    (hostile_repo / "agent.lock").write_text(json.dumps(lock), encoding="utf-8")
    result = runner.invoke(app, ["verify", str(hostile_repo)])
    assert_safe(result.output, "verify with a hostile lockfile")


def git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-C", str(repo), *args],
        check=True,
        capture_output=True,
    )


@pytest.mark.parametrize("fmt", ["terminal", "markdown", "json"])
def test_diff_reports_never_emit_control_sequences(tmp_path, fmt):
    git(tmp_path, "init", "-q", "-b", "main")
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": {"a": {"command": "node"}}}))
    write_snapshot(tmp_path / "agent.tools.json", {"mcp:a": [Tool(name="t", description="ok")]})
    git(tmp_path, "add", "-A")
    git(tmp_path, "commit", "-q", "-m", "base")
    git(tmp_path, "tag", "base")
    servers = {"a": {"command": "node", "args": [f"--x{HOSTILE}"]}, HOSTILE: {"command": "npx"}}
    (tmp_path / ".mcp.json").write_text(json.dumps({"mcpServers": servers}), encoding="utf-8")
    write_snapshot(
        tmp_path / "agent.tools.json", {"mcp:a": [Tool(name="t", description=f"changed{HOSTILE}")]}
    )
    result = runner.invoke(app, ["diff", str(tmp_path), "--base", "base", "--format", fmt])
    assert_safe(result.output, f"diff {fmt}")
    if fmt == "json":
        json.loads(result.output)


def test_snapshot_confirmation_and_errors_are_safe(hostile_repo):
    fake = str(Path(__file__).parent / "fake_mcp_server.py")
    config = {"mcpServers": {HOSTILE: {"command": "python", "args": [fake, "init-error", HOSTILE]}}}
    (hostile_repo / ".mcp.json").write_text(json.dumps(config), encoding="utf-8")
    result = runner.invoke(app, ["snapshot", str(hostile_repo), "--introspect", "-y"])
    assert_safe(result.output, "snapshot")


def test_output_written_to_a_file_is_safe_too(hostile_repo, tmp_path):
    out = tmp_path / "report.md"
    runner.invoke(
        app, ["scan", str(hostile_repo), "--no-user", "--format", "markdown", "-o", str(out)]
    )
    assert_safe(out.read_text(encoding="utf-8"), "report file")


def test_the_dangerous_text_is_still_visible_to_the_reader(hostile_repo):
    # Markdown is not wrapped into table columns, so the escapes stay in one piece
    result = runner.invoke(app, ["scan", str(hostile_repo), "--no-user", "--format", "markdown"])
    assert "\\x1b[2J" in result.output and "\\u202e" in result.output
    # shown as text, so nothing is silently dropped


def test_waiver_text_is_safe_in_findings(hostile_repo):
    result = runner.invoke(app, ["scan", str(hostile_repo), "--no-user", "--format", "json"])
    data = json.loads(result.output)
    waived = [f for f in data["findings"] if f["waiver"]]
    assert waived, "the hostile waiver should still apply and be reported"
    assert_safe(result.output, "json with a hostile waiver")


@pytest.mark.parametrize(
    "text, expected",
    [
        (ESC + "[2J", "\\x1b[2J"),
        (BEL, "\\x07"),
        ("a" + CR + "b", "a\\x0db"),
        (RLO, "\\u202e"),
        (CSI, "\\x9b"),
        ("tab\tand\nnewline", "tab\tand\nnewline"),
        ("plain text, café, 中文", "plain text, café, 中文"),
    ],
)
def test_visible(text, expected):
    assert visible(text) == expected
    assert visible(visible(text)) == visible(text)  # applying it twice changes nothing more
