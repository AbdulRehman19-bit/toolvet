"""Regression tests for false positives and negatives found by hand-checking a real-world scan.

Each case is a pattern seen in real public configs where toolvet was wrong.
"""

from pathlib import Path

import pytest

from toolvet.capabilities import tag_server
from toolvet.models import Capability, Server
from toolvet.rules import run_rules


def make(name="s", **kw) -> Server:
    return Server(name=name, client="t", source=Path("a.json"), **kw)


def rules(server: Server) -> set[str]:
    return {f.rule_id for f in run_rules([server])}


@pytest.mark.parametrize(
    "value",
    [
        "ANTHROPIC_API_KEY_HERE",
        "YOUR_OPENAI_API_KEY",
        "your-api-key",
        "your api key",
        "paste-your-token-here",
        "xxxxxxxx",
        "********",
        "sk-...",
        "<token>",
        "[token]",
        "changeme",
        "replace_me",
        "REDACTED",
        "insert-key",
        "",
        "${env:TOKEN}",
        "$TOKEN",
        "env:TOKEN",
    ],
)
def test_placeholder_values_are_not_secrets(value):
    assert "TV002" not in rules(make(env={"API_KEY": value}))


@pytest.mark.parametrize(
    "value",
    ["ghp_16C7e42F292c6912E7710c838347Ae178B4a", "s3cr3tvalue", "hunter2", "AKIAIOSFODNN7EXAMPLE1"],
)
def test_real_looking_values_are_still_flagged(value):
    assert "TV002" in rules(make(env={"API_KEY": value}))


def test_placeholder_credential_flag_value_is_not_a_secret():
    assert "TV008" not in rules(make(command="x", args=["--token", "YOUR_TOKEN_HERE"]))
    assert "TV008" in rules(make(command="x", args=["--token", "abc123def456"]))


@pytest.mark.parametrize(
    "command, args",
    [
        ("uv", ["run", "python", "-m", "my.local.module"]),
        ("uv", ["run", "server.py"]),
        ("npm", ["run", "start"]),
        ("pnpm", ["run", "dev"]),
        ("pnpm", ["--silent", "start"]),
        ("yarn", ["run", "serve"]),
        ("yarn", ["start"]),
        ("bun", ["run", "index.ts"]),
        ("pipx", ["list"]),
    ],
)
def test_running_local_code_is_not_an_unpinned_package(command, args):
    assert "TV003" not in rules(make(command=command, args=args))


@pytest.mark.parametrize(
    "command, args",
    [
        ("npx", ["-y", "left-pad"]),
        ("bunx", ["left-pad"]),
        ("uvx", ["left-pad"]),
        ("uvx", ["--python", "3.12", "left-pad"]),
        ("pnpm", ["dlx", "left-pad"]),
        ("yarn", ["dlx", "left-pad"]),
        ("npm", ["exec", "left-pad"]),
        ("bun", ["x", "left-pad"]),
        ("pipx", ["run", "left-pad"]),
        ("uv", ["tool", "run", "left-pad"]),
    ],
)
def test_fetching_runners_are_still_checked(command, args):
    assert "TV003" in rules(make(command=command, args=args))


def test_python_version_flag_value_is_not_taken_for_the_package():
    from toolvet.rules.builtin import _package_spec

    server = make(command="uvx", args=["--python", "3.12", "--with", "extra", "real-pkg@1.0.0"])
    assert _package_spec(server) == "real-pkg@1.0.0"
    assert "TV003" not in rules(server)


@pytest.mark.parametrize("name", ["chrome-devtools", "seleniumbase-mcp", "firefox", "webdriver"])
def test_browser_automation_servers_are_untrusted_sources_and_sinks(name):
    tags = tag_server(make(name=name, command="node"))
    assert Capability.UNTRUSTED_SOURCE in tags and Capability.SINK in tags


@pytest.mark.parametrize(
    "args", [["nx", "mcp"], ["eslint", "--mcp"], ["tsx", "src/cli.ts"], ["@bytebase/dbhub"]]
)
def test_npx_without_dash_y_is_a_low_note_about_local_copies(args):
    findings = [f for f in run_rules([make(command="npx", args=args)]) if f.rule_id == "TV003"]
    assert [f.severity.value for f in findings] == ["low"]
    assert "locally installed copy" in findings[0].message


@pytest.mark.parametrize(
    "command, args",
    [
        ("npx", ["-y", "left-pad"]),
        ("npx", ["--yes", "left-pad"]),
        ("npx", ["left-pad@latest"]),
        ("uvx", ["left-pad"]),
        ("bunx", ["left-pad"]),
    ],
)
def test_fetched_latest_is_still_medium(command, args):
    findings = [f for f in run_rules([make(command=command, args=args)]) if f.rule_id == "TV003"]
    assert [f.severity.value for f in findings] == ["medium"]
