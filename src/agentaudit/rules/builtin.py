"""Built-in deterministic rules."""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import PurePath

from agentaudit.models import Server, Severity
from agentaudit.rules import Hit, rule

_RUNNERS = {"npx", "bunx", "uvx", "pipx", "pnpm", "yarn", "npm", "bun", "uv"}
_SHELLS = {"sh", "bash", "zsh", "fish", "dash", "cmd", "powershell", "pwsh"}
_SECRET_KEY = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)", re.IGNORECASE)
_PLACEHOLDER = re.compile(r"^\s*($|\$|\$\{|<|\{\{|%.*%$|env:)")
_ROOT_PATHS = {"/", "~", "*", "**", "/home", "/Users", "/etc", "/root", "/var"}
_DRIVE_ROOT = re.compile(r"^[A-Za-z]:[\\/]?$")


def _command_name(server: Server) -> str:
    if not server.command:
        return ""
    return PurePath(server.command.replace("\\", "/")).name.lower().removesuffix(".exe")


def _package_spec(server: Server) -> str | None:
    """Return the package a runner like npx or uvx will fetch, if there is one."""
    if _command_name(server) not in _RUNNERS:
        return None
    args = list(server.args)
    if "--from" in args and args.index("--from") + 1 < len(args):
        return args[args.index("--from") + 1]
    skip = {"run", "dlx", "x", "exec", "tool"}
    for arg in args:
        if arg.startswith("-") or arg in skip:
            continue
        return arg
    return None


@rule("AA001", "Shell access")
def shell_access(server: Server) -> Iterator[Hit]:
    spec = _package_spec(server) or ""
    if _command_name(server) in _SHELLS:
        yield Hit(
            Severity.HIGH, "Server is launched through a shell", evidence=[server.command or ""]
        )
    elif re.search(r"(shell|terminal)", f"{server.name} {spec}", re.IGNORECASE):
        yield Hit(
            Severity.HIGH,
            "Server name or package suggests shell execution",
            evidence=[spec or server.name],
        )


@rule("AA002", "Secrets in env vars")
def secret_env(server: Server) -> Iterator[Hit]:
    for key, value in server.env.items():
        if _SECRET_KEY.search(key) and not _PLACEHOLDER.match(value):
            yield Hit(
                Severity.HIGH,
                f"Env var {key} holds a literal secret in the config; reference it instead",
                evidence=[key],
            )


@rule("AA003", "Unpinned package")
def unpinned_package(server: Server) -> Iterator[Hit]:
    spec = _package_spec(server)
    if not spec or spec.startswith((".", "/", "~")) or re.match(r"^[A-Za-z]:[\\/]", spec):
        return
    version = spec.rsplit("@", 1)[1] if spec.rfind("@") > 0 else None
    if version is None and "==" in spec:
        version = spec.split("==", 1)[1]
    if version in (None, "", "latest"):
        yield Hit(Severity.MEDIUM, f"Package {spec} is not pinned to a version", evidence=[spec])


@rule("AA004", "Wildcard or root path")
def wildcard_path(server: Server) -> Iterator[Hit]:
    for arg in server.args:
        if arg.startswith("-"):
            continue
        if arg in _ROOT_PATHS or _DRIVE_ROOT.match(arg) or arg.endswith(("/*", "\\*")):
            yield Hit(
                Severity.HIGH, f"Argument {arg!r} grants access to a very broad path", evidence=[arg]
            )


@rule("AA005", "Plain HTTP remote server")
def plain_http(server: Server) -> Iterator[Hit]:
    url = server.url or ""
    if url.startswith("http://") and not re.match(r"http://(localhost|127\.0\.0\.1|\[::1\])", url):
        yield Hit(Severity.MEDIUM, "Remote server is reached over unencrypted HTTP", evidence=[url])
