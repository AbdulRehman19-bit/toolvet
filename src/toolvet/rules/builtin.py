"""Built-in deterministic rules."""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import PurePath

from toolvet.models import Server, Severity
from toolvet.rules import Hit, rule

_ALWAYS_FETCH = {"npx", "bunx", "uvx"}
# Runners that fetch a package only through one subcommand. `npm run`, `pnpm run`, `uv run`
# and the like execute local project code, so they are not "unpinned packages".
_FETCH_SUBCOMMANDS = {
    "pipx": {"run"},
    "pnpm": {"dlx"},
    "yarn": {"dlx"},
    "npm": {"exec", "x"},
    "bun": {"x"},
}
# Flags that take a value, so the value is not mistaken for the package name.
_VALUE_FLAGS = {
    "--python",
    "-p",
    "--with",
    "-w",
    "--index-url",
    "--extra-index-url",
    "--index",
    "--directory",
    "-C",
    "--cache-dir",
    "--prefix",
    "--registry",
}
_SHELLS = {"sh", "bash", "zsh", "fish", "dash", "cmd", "powershell", "pwsh"}
_SECRET_KEY = re.compile(r"(KEY|TOKEN|SECRET|PASSWORD|PASSWD|CREDENTIAL)", re.IGNORECASE)
_PLACEHOLDER = re.compile(r"^\s*($|\$|\$\{|<|\{\{|%.*%$|env:)")
# Values that are obviously stand-ins, such as ANTHROPIC_API_KEY_HERE or your-api-key.
_OBVIOUS_PLACEHOLDER = re.compile(
    r"""^\s*(
        your[_\- ].*
        | .*[_\- ]here
        | x{3,} | \*{3,} | \.{3,}
        | \[.*\]
        | (sk|pk|key|token)[_\-]?(\.{3,}|x{3,}|\*+)
        | change[_\- ]?me | replace[_\- ]?me | placeholder | redacted | dummy | todo
        | insert[_\- ].* | paste[_\- ].*
    )\s*$""",
    re.IGNORECASE | re.VERBOSE,
)


def _is_placeholder(value: str) -> bool:
    """True for an empty value, a variable reference, or an obvious stand-in for a secret."""
    return bool(_PLACEHOLDER.match(value) or _OBVIOUS_PLACEHOLDER.match(value))


_ROOT_PATHS = {"/", "~", "*", "**", "/home", "/Users", "/etc", "/root", "/var"}
_DRIVE_ROOT = re.compile(r"^[A-Za-z]:[\\/]?$")


def _command_name(server: Server) -> str:
    if not server.command:
        return ""
    return PurePath(server.command.replace("\\", "/")).name.lower().removesuffix(".exe")


def _package_spec(server: Server) -> str | None:
    """Return the package a runner like npx or uvx will fetch, if there is one."""
    name, args = _command_name(server), list(server.args)
    positional = [(i, a) for i, a in enumerate(args) if not a.startswith("-")]
    if name in _ALWAYS_FETCH:
        rest = args
    elif name in _FETCH_SUBCOMMANDS:
        if not positional or positional[0][1] not in _FETCH_SUBCOMMANDS[name]:
            return None
        rest = args[positional[0][0] + 1 :]
    elif name == "uv":  # only `uv tool run <pkg>` fetches; `uv run ...` runs local code
        if [a for _, a in positional[:2]] != ["tool", "run"]:
            return None
        rest = args[positional[1][0] + 1 :]
    else:
        return None
    if "--from" in rest and rest.index("--from") + 1 < len(rest):
        return rest[rest.index("--from") + 1]
    skip_next = False
    for arg in rest:
        if skip_next:
            skip_next = False
        elif arg in _VALUE_FLAGS:
            skip_next = True
        elif not arg.startswith("-"):
            return arg
    return None


@rule("TV001", "Shell access")
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


@rule("TV002", "Secrets in env vars")
def secret_env(server: Server) -> Iterator[Hit]:
    for key, value in server.env.items():
        if _SECRET_KEY.search(key) and not _is_placeholder(value):
            yield Hit(
                Severity.HIGH,
                f"Env var {key} holds a literal secret in the config; reference it instead",
                evidence=[key],
            )


@rule("TV003", "Unpinned package")
def unpinned_package(server: Server) -> Iterator[Hit]:
    spec = _package_spec(server)
    if not spec or spec.startswith((".", "/", "~")) or re.match(r"^[A-Za-z]:[\\/]", spec):
        return
    version = spec.rsplit("@", 1)[1] if spec.rfind("@") > 0 else None
    if version is None and "==" in spec:
        version = spec.split("==", 1)[1]
    if version not in (None, "", "latest"):
        return
    # `npx tool` without -y cannot download in a non-interactive launch (npx would prompt on the
    # MCP channel), so it only works if the tool is already installed locally, where the
    # project's lockfile pins it. Still worth knowing about, but not a fetched-latest risk.
    local_only = (
        _command_name(server) == "npx"
        and version is None
        and not any(arg in ("-y", "--yes") for arg in server.args)
    )
    if local_only:
        yield Hit(
            Severity.LOW,
            f"{spec} has no version and no -y: npx will use a locally installed copy if there "
            "is one (pinned by your lockfile), otherwise it needs a prompt",
            evidence=[spec],
        )
    else:
        yield Hit(Severity.MEDIUM, f"Package {spec} is not pinned to a version", evidence=[spec])


@rule("TV004", "Wildcard or root path")
def wildcard_path(server: Server) -> Iterator[Hit]:
    for arg in server.args:
        if arg.startswith("-"):
            continue
        if arg in _ROOT_PATHS or _DRIVE_ROOT.match(arg) or arg.endswith(("/*", "\\*")):
            yield Hit(
                Severity.HIGH,
                f"Argument {arg!r} grants access to a very broad path",
                evidence=[arg],
            )


@rule("TV005", "Plain HTTP remote server")
def plain_http(server: Server) -> Iterator[Hit]:
    url = server.url or ""
    if url.startswith("http://") and not re.match(r"http://(localhost|127\.0\.0\.1|\[::1\])", url):
        yield Hit(Severity.MEDIUM, "Remote server is reached over unencrypted HTTP", evidence=[url])


_INJECTION = [
    r"ignore (all |any )?(previous|prior|above) instructions",
    r"do not (tell|inform|mention|reveal)[^.]{0,40}\buser\b",
    r"<important>",
    r"before (using|calling) this tool[^.]{0,60}\b(read|send|open)\b",
    r"(~|/home/\w+)/\.(ssh|aws)|id_rsa|\.env\b",
]
_CRED_URL = re.compile(r"://[^/@\s:]+:[^/@\s]+@")
_CRED_QUERY = re.compile(r"[?&](token|key|api_key|apikey|secret|password)=[^&]+", re.IGNORECASE)
_CRED_FLAG = re.compile(r"^--?(token|password|passwd|secret|api-?key)(=.+)?$", re.IGNORECASE)
_DOWNLOAD_EXEC = re.compile(
    r"(curl|wget)\b[^|;]*\|\s*(sudo\s+)?(sh|bash)|\biex\b|invoke-expression", re.IGNORECASE
)


@rule("TV006", "Suspicious tool description")
def suspicious_description(server: Server) -> Iterator[Hit]:
    for tool in server.tools:
        for pattern in _INJECTION:
            match = re.search(pattern, tool.description, re.IGNORECASE)
            if match:
                yield Hit(
                    Severity.HIGH,
                    f"Tool description contains instruction-like text ({match.group(0)!r})",
                    tool=tool.name,
                    evidence=[match.group(0)],
                )


@rule("TV007", "Credentials in server URL")
def url_credentials(server: Server) -> Iterator[Hit]:
    url = server.url or ""
    if _CRED_URL.search(url) or _CRED_QUERY.search(url):
        yield Hit(
            Severity.HIGH,
            "Server URL embeds credentials; use a header or env reference instead",
            evidence=[url.split("?")[0].split("@")[-1]],
        )


@rule("TV008", "Credentials in arguments")
def arg_credentials(server: Server) -> Iterator[Hit]:
    args = server.args
    for i, arg in enumerate(args):
        if _CRED_URL.search(arg):
            yield Hit(Severity.HIGH, "Argument embeds a credentialed URL", evidence=["<url>"])
        elif _CRED_FLAG.match(arg):
            has_value = "=" in arg or (i + 1 < len(args) and not args[i + 1].startswith("-"))
            value = arg.split("=", 1)[1] if "=" in arg else (args[i + 1] if has_value else "")
            if has_value and not _is_placeholder(value):
                yield Hit(
                    Severity.HIGH,
                    f"Flag {arg.split('=')[0]} passes a literal secret on the command line",
                    evidence=[arg.split("=")[0]],
                )


@rule("TV009", "Download and execute")
def download_exec(server: Server) -> Iterator[Hit]:
    line = " ".join([server.command or "", *server.args])
    if _command_name(server) in {"curl", "wget"} or _DOWNLOAD_EXEC.search(line):
        yield Hit(
            Severity.HIGH, "Server launch downloads and runs remote code", evidence=[line[:80]]
        )


@rule("TV010", "Risky container options")
def risky_container(server: Server) -> Iterator[Hit]:
    if _command_name(server) not in {"docker", "podman"}:
        return
    args = server.args
    for i, arg in enumerate(args):
        value = args[i + 1] if i + 1 < len(args) else ""
        mount = value if arg in {"-v", "--volume"} else arg.split("=", 1)[-1]
        if arg == "--privileged":
            yield Hit(Severity.HIGH, "Container runs with --privileged", evidence=[arg])
        elif arg in {"-v", "--volume"} or arg.startswith(("-v=", "--volume=")):
            if mount.startswith(("/:", "/var/run/docker.sock")) or "docker.sock" in mount:
                yield Hit(
                    Severity.HIGH,
                    "Container mounts the host root or Docker socket",
                    evidence=[mount],
                )
        elif arg in {"--network=host", "--net=host"} or (
            arg in {"--network", "--net"} and value == "host"
        ):
            yield Hit(Severity.MEDIUM, "Container shares the host network", evidence=[arg])
