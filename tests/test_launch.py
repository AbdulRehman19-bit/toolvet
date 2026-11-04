"""Launch wrappers (cmd /c, bash -c) are launchers, not shell tools. Found in real configs."""

from pathlib import Path

import pytest

from agentaudit.capabilities import tag_server
from agentaudit.launch import effective
from agentaudit.models import Capability, Server
from agentaudit.rules import run_rules


def make(name="s", command="node", args=None, **kw) -> Server:
    return Server(
        name=name, client="t", source=Path("a.json"), command=command, args=args or [], **kw
    )


def rule_ids(server: Server) -> set[str]:
    return {f.rule_id for f in run_rules([server])}


@pytest.mark.parametrize(
    "command, args, expected_command, expected_args",
    [
        (
            "cmd",
            ["/c", "uvx", "--python", "3.11", "blender-mcp"],
            "uvx",
            ["--python", "3.11", "blender-mcp"],
        ),
        ("cmd.exe", ["/C", "npx", "-y", "pkg"], "npx", ["-y", "pkg"]),
        ("C:\\Windows\\System32\\cmd.exe", ["/c", "npx pkg"], "npx", ["pkg"]),
        ("cmd", ["/c", "C:\\tools\\server.exe", "--x"], "C:\\tools\\server.exe", ["--x"]),
        (
            "/bin/bash",
            ["-l", "-c", "exec npx -y pkg@1.0.0 --headless"],
            "npx",
            ["-y", "pkg@1.0.0", "--headless"],
        ),
        ("sh", ["-c", "node server.js"], "node", ["server.js"]),
        ("zsh", ["-lic", "uvx pkg"], "uvx", ["pkg"]),
    ],
)
def test_wrappers_around_one_simple_command_are_removed(
    command, args, expected_command, expected_args
):
    result = effective(make(command=command, args=args))
    assert (result.command, result.args) == (expected_command, expected_args)


@pytest.mark.parametrize(
    "command, args",
    [
        ("bash", ["-c", "curl https://x.test | sh"]),
        ("bash", ["-c", "a; b"]),
        ("bash", ["-c", "a && b"]),
        ("bash", ["-c", "cmd > file"]),
        ("bash", ["-c", "echo $(whoami)"]),
        ("bash", ["-c", "echo `id`"]),
        ("bash", ["-c", "a\nb"]),
        ("bash", ["-c", "unterminated 'quote"]),
        ("bash", ["-c"]),
        ("bash", []),
        ("bash", ["script.sh"]),
        ("cmd", ["/c", "a", "&", "b"]),
        ("cmd", ["/c", "a", "|", "b"]),
        ("cmd", []),
        ("cmd", ["/c"]),
        ("cmd", ["/c", "a", ">", "out"]),
        ("node", ["-c", "x"]),
    ],
)
def test_real_shell_use_is_left_alone(command, args):
    server = make(command=command, args=args)
    assert effective(server) == server


def test_wrapped_server_is_not_a_shell_tool():
    wrapped = make(command="cmd", args=["/c", "uvx", "--python", "3.11", "blender-mcp"])
    assert "AA001" not in rule_ids(wrapped)
    bare = make(command="bash", args=["-c", "a | b"])
    assert "AA001" in rule_ids(bare)


def test_unpinned_package_hidden_behind_a_wrapper_is_found():
    wrapped = make(command="cmd", args=["/c", "uvx", "--python", "3.11", "blender-mcp"])
    assert "AA003" in rule_ids(wrapped)
    pinned = make(command="bash", args=["-c", "exec npx -y pkg@1.2.3"])
    assert "AA003" not in rule_ids(pinned)


def test_wrapper_shell_does_not_tag_the_server_as_private_data_and_sink():
    wrapped = make(
        name="helper",
        command="/bin/bash",
        args=["-l", "-c", "exec npx -y @acme/helper-mcp@latest"],
    )
    assert tag_server(wrapped) == {}


def test_a_real_shell_server_is_still_tagged():
    tags = tag_server(make(name="runner", command="bash", args=["-c", "a | b"]))
    assert Capability.PRIVATE_DATA in tags and Capability.SINK in tags


def test_url_scheme_is_not_an_http_keyword():
    server = make(
        name="grafana", command="docker", args=["run", "-e", "URL=http://localhost:3001", "img"]
    )
    assert Capability.SINK not in tag_server(server)
    named = make(name="http-fetcher", command="node")
    assert Capability.SINK in tag_server(named)


def test_findings_still_name_the_original_server():
    wrapped = make(name="blender", command="cmd", args=["/c", "uvx", "blender-mcp"])
    assert {f.server for f in run_rules([wrapped])} == {"t:blender"}


@pytest.mark.parametrize(
    "name, expected",
    [
        ("atlassian", {"untrusted_source", "private_data"}),
        ("linear", {"untrusted_source", "private_data"}),
        ("sentry", {"untrusted_source", "private_data"}),
        ("context7", {"untrusted_source"}),
        ("deepwiki", {"untrusted_source"}),
        ("desktop-commander", {"private_data", "sink"}),
        ("neon", {"private_data"}),
        ("grafana", {"private_data"}),
        ("posthog", {"private_data"}),
    ],
)
def test_popular_servers_found_missing_in_a_real_world_scan(name, expected):
    assert {c.value for c in tag_server(make(name=name))} == expected
