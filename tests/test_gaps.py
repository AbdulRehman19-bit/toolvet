"""Tests for code paths that had no coverage: plugins, platform paths, error handling."""

import importlib
import importlib.metadata
import io
import subprocess
import sys
from pathlib import Path

import pytest

from toolvet import introspect as introspect_module
from toolvet.discovery import _claude_desktop_path, parse_config
from toolvet.gitbase import GitError, resolve_ref
from toolvet.introspect import IntrospectError, introspect
from toolvet.launch import effective
from toolvet.models import Server, Severity
from toolvet.policy import PolicyError, parse_policy
from toolvet.rules import Hit, Rule, load_rules, run_rules


def make(name="s", **kw) -> Server:
    kw.setdefault("command", "node")
    return Server(name=name, client="t", source=Path("a.json"), **kw)


# --- rule plugins ----------------------------------------------------------------------------


class FakeEntryPoint:
    def __init__(self, obj):
        self.obj = obj

    def load(self):
        return self.obj


def test_rule_plugins_are_loaded_from_the_toolvet_rules_entry_point_group(monkeypatch):
    plugin = Rule("XX001", "plugin rule", lambda server: [Hit(Severity.LOW, "from a plugin")])
    asked = []

    def fake_entry_points(group):
        asked.append(group)
        return [FakeEntryPoint(plugin), FakeEntryPoint("not a rule object")]

    monkeypatch.setattr("toolvet.rules.entry_points", fake_entry_points)
    ids = [r.id for r in load_rules()]
    assert asked == ["toolvet.rules"]
    assert "XX001" in ids and "TV001" in ids
    assert "not a rule object" not in ids
    assert "XX001" in {f.rule_id for f in run_rules([make()])}
    assert "XX001" not in [r.id for r in load_rules(plugins=False)]


# --- discovery -------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "platform, tail",
    [
        ("darwin", "Library/Application Support/Claude/claude_desktop_config.json"),
        ("linux", ".config/Claude/claude_desktop_config.json"),
    ],
)
def test_claude_desktop_config_location_per_platform(monkeypatch, tmp_path, platform, tail):
    monkeypatch.setattr(sys, "platform", platform)
    assert _claude_desktop_path(tmp_path) == tmp_path / tail


def test_configs_with_the_wrong_shape_yield_no_servers(tmp_path):
    for text in ('{"mcpServers": []}', '{"mcpServers": "x"}', "[1, 2]", "null"):
        path = tmp_path / "c.json"
        path.write_text(text, encoding="utf-8")
        assert parse_config(path, "mcp", "mcpServers") == []


# --- version ---------------------------------------------------------------------------------


def test_version_falls_back_when_the_package_metadata_is_missing(monkeypatch):
    import toolvet

    def missing(name):
        raise importlib.metadata.PackageNotFoundError(name)

    monkeypatch.setattr(importlib.metadata, "version", missing)
    try:
        importlib.reload(toolvet)
        assert toolvet.__version__ == "0+unknown"
    finally:
        monkeypatch.undo()
        importlib.reload(toolvet)
    assert toolvet.__version__ != "0+unknown"


# --- launch wrappers -------------------------------------------------------------------------


def test_cmd_wrapper_with_an_unterminated_quote_is_left_alone():
    server = make(command="cmd", args=["/c", 'npx "unterminated'])
    assert effective(server) == server


# --- git -------------------------------------------------------------------------------------


def test_a_git_timeout_is_reported_not_raised(monkeypatch, tmp_path):
    def slow(*args, **kwargs):
        raise subprocess.TimeoutExpired("git", 30)

    monkeypatch.setattr("toolvet.gitbase.subprocess.run", slow)
    with pytest.raises(GitError, match="timed out"):
        resolve_ref(tmp_path, "HEAD")


# --- policy ----------------------------------------------------------------------------------


def test_policy_shape_errors_are_reported():
    with pytest.raises(PolicyError, match=r"\[severity\] must be a table"):
        parse_policy({"severity": "high"})
    waiver = {"rule": "TV002", "server": "x", "reason": "r", "owner": "o", "tool": 5}
    with pytest.raises(PolicyError, match="tool must be a string"):
        parse_policy({"waiver": [dict(waiver, expires="2027-01-01")]})


# --- introspection error paths ---------------------------------------------------------------


def test_a_launch_failure_is_reported(monkeypatch):
    def boom(*args, **kwargs):
        raise OSError(13, "Permission denied")

    monkeypatch.setattr(introspect_module.subprocess, "Popen", boom)
    with pytest.raises(IntrospectError, match="could not launch: Permission denied"):
        introspect(make(command=sys.executable))


class BrokenPipeStdin:
    def write(self, text):
        raise OSError("broken pipe")

    def flush(self):
        pass


class FakeProc:
    def __init__(self, stdin):
        self.stdin = stdin
        self.stdout = io.StringIO("")
        self.killed = False
        self.waits = 0

    def terminate(self):
        pass

    def kill(self):
        self.killed = True

    def wait(self, timeout=None):
        self.waits += 1
        if self.waits == 1 and timeout is not None:
            raise subprocess.TimeoutExpired("server", timeout)


def test_writing_to_a_closed_server_is_reported():
    session = introspect_module._Session(FakeProc(BrokenPipeStdin()), timeout=5)
    with pytest.raises(IntrospectError, match="server closed its input"):
        session.notify("notifications/initialized")


def test_a_deadline_that_has_already_passed_times_out_immediately():
    session = introspect_module._Session(FakeProc(io.StringIO()), timeout=0)
    with pytest.raises(IntrospectError, match="timed out waiting for tools/list"):
        session.request("tools/list", {})


def test_a_server_that_will_not_stop_is_killed():
    class StubbornStdin(io.StringIO):
        def close(self):
            raise OSError("already closed")

    proc = FakeProc(StubbornStdin())
    introspect_module._stop(proc)
    assert proc.killed and proc.waits == 2
