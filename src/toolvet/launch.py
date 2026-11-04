"""See through launch wrappers: `cmd /c npx ...` and `bash -c "exec npx ..."`.

MCP clients on Windows often have to start `npx` and `uvx` through `cmd /c`, and on macOS and
Linux through a login shell. That shell is only a launcher, not a shell tool the agent can use,
so the rules and capability tags should look at the command it launches. A wrapper counts as
a launcher only when its payload is one simple command. Pipes, `;`, `&&`, redirects and
substitutions mean real shell scripting, and those are left as they are.
"""

from __future__ import annotations

import re
import shlex
from pathlib import PurePath

from toolvet.models import Server

POSIX_SHELLS = {"sh", "bash", "zsh", "dash", "fish"}
_POSIX_SCRIPTING = re.compile(r"[;|&<>`$()\n]")
_CMD_SCRIPTING = re.compile(r"[&|<>^%()\n]")
_POSIX_COMMAND_FLAG = re.compile(r"^-[A-Za-z]*c$")


def program_name(command: str | None) -> str:
    if not command:
        return ""
    return PurePath(command.replace("\\", "/")).name.lower().removesuffix(".exe")


def _posix_inner(args: list[str]) -> list[str] | None:
    for i, arg in enumerate(args):
        if _POSIX_COMMAND_FLAG.match(arg):
            if i + 1 >= len(args) or _POSIX_SCRIPTING.search(args[i + 1]):
                return None
            try:
                tokens = shlex.split(args[i + 1])
            except ValueError:
                return None
            if tokens and tokens[0] == "exec":
                tokens = tokens[1:]
            return tokens or None
    return None


def _cmd_inner(args: list[str]) -> list[str] | None:
    for i, arg in enumerate(args):
        if arg.lower() in ("/c", "/k"):
            rest = args[i + 1 :]
            if len(rest) == 1 and " " in rest[0]:  # cmd /c "npx -y pkg"
                try:
                    rest = [t.strip('"') for t in shlex.split(rest[0], posix=False)]
                except ValueError:
                    return None
            if not rest or any(_CMD_SCRIPTING.search(token) for token in rest):
                return None
            return rest
    return None


def effective(server: Server) -> Server:
    """The server as it really launches: wrappers around one simple command are removed."""
    name = program_name(server.command)
    if name in POSIX_SHELLS:
        inner = _posix_inner(server.args)
    elif name == "cmd":
        inner = _cmd_inner(server.args)
    else:
        return server
    if not inner:
        return server
    return server.model_copy(update={"command": inner[0], "args": inner[1:]})
