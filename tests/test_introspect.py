import sys
from pathlib import Path

import pytest

from toolvet.introspect import IntrospectError, introspect
from toolvet.models import Server

FAKE = str(Path(__file__).parent / "fake_mcp_server.py")


def fake(mode: str, **kw) -> Server:
    return Server(
        name="fake",
        client="test",
        source=Path("a.json"),
        command=sys.executable,
        args=[FAKE, mode],
        **kw,
    )


@pytest.mark.parametrize("mode", ["ok", "noisy"])
def test_lists_tools(mode):
    tools = introspect(fake(mode), timeout=15)
    assert [t.name for t in tools] == ["read_file", "write_file"]
    assert tools[0].description == "Reads a file"
    assert tools[0].input_schema == {"type": "object"}
    assert tools[1].input_schema == {}


def test_follows_pagination():
    assert [t.name for t in introspect(fake("paged"), timeout=15)] == ["read_file", "write_file"]


def test_silent_server_times_out():
    with pytest.raises(IntrospectError, match="timed out"):
        introspect(fake("silent"), timeout=1)


def test_server_that_exits():
    with pytest.raises(IntrospectError, match="exited|closed"):
        introspect(fake("exit"), timeout=15)


def test_error_responses():
    with pytest.raises(IntrospectError, match="initialize failed: nope"):
        introspect(fake("init-error"), timeout=15)
    with pytest.raises(IntrospectError, match="tools/list failed: boom"):
        introspect(fake("list-error"), timeout=15)


def test_non_stdio_and_missing_commands():
    remote = Server(name="r", client="t", source=Path("a"), url="https://x.test")
    with pytest.raises(IntrospectError, match="not a stdio server"):
        introspect(remote)
    missing = Server(name="m", client="t", source=Path("a"), command="definitely-not-a-command-xyz")
    with pytest.raises(IntrospectError, match="command not found"):
        introspect(missing)


def test_env_placeholders_do_not_override_real_environment(monkeypatch):
    monkeypatch.setenv("REAL_VAR", "kept")
    from toolvet.introspect import _launch_env

    env = _launch_env(fake("ok", env={"REAL_VAR": "${env:REAL_VAR}", "NEW": "1", "EMPTY": ""}))
    assert env["REAL_VAR"] == "kept"
    assert env["NEW"] == "1"
    assert "EMPTY" not in env or env["EMPTY"] == ""
