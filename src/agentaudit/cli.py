"""Command line entry point."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from agentaudit import __version__
from agentaudit.audit import audit
from agentaudit.discovery import discover
from agentaudit.introspect import IntrospectError, introspect
from agentaudit.lockfile import LOCK_NAME, LockError, read_lock, write_lock
from agentaudit.lockfile import verify as verify_lock
from agentaudit.models import Finding, Server, Severity
from agentaudit.snapshot import SNAPSHOT_NAME, apply_snapshot, write_snapshot

app = typer.Typer(help="Audit AI agent tool (MCP) configurations.", no_args_is_help=True)
console = Console()

_STYLES = {
    Severity.INFO: "dim",
    Severity.LOW: "cyan",
    Severity.MEDIUM: "yellow",
    Severity.HIGH: "red",
    Severity.CRITICAL: "bold red",
}


def _version(value: bool) -> None:
    if value:
        typer.echo(f"agentaudit {__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: Annotated[
        bool, typer.Option("--version", callback=_version, is_eager=True, help="Show version.")
    ] = False,
) -> None:
    """agentaudit: find dangerous tool combinations and pin what was approved."""


def _findings_table(findings: list[Finding]) -> Table:
    table = Table(title=f"{len(findings)} finding(s)")
    for column in ("Severity", "Rule", "Server", "Message"):
        table.add_column(column)
    ordered = sorted(findings, key=lambda f: (-f.severity.rank, f.rule_id, f.server))
    for f in ordered:
        style = _STYLES[f.severity]
        where = f"{f.server}:{f.tool}" if f.tool else f.server
        message = f.message
        if f.rule_id == "AA100":
            message += "\n" + "\n".join(f"  {line}" for line in f.evidence)
        table.add_row(f"[{style}]{f.severity.value}[/]", f.rule_id, where, message)
    return table


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="Repository or directory to scan.")] = Path("."),
    user: Annotated[
        bool, typer.Option("--user/--no-user", help="Also scan user-level client configs.")
    ] = True,
    fail_on: Annotated[
        Severity, typer.Option("--fail-on", help="Exit 1 if a finding is at least this severe.")
    ] = Severity.HIGH,
) -> None:
    """Discover MCP servers, check rules, build the capability graph and report."""
    servers = discover(path, home=Path.home() if user else None)
    if not servers:
        console.print("No MCP servers found.")
        raise typer.Exit()
    table = Table(title=f"{len(servers)} MCP server(s)")
    for column in ("Client", "Server", "Launch", "Config"):
        table.add_column(column)
    for s in servers:
        launch = s.url or " ".join(filter(None, [s.command, *s.args]))
        table.add_row(s.client, s.name, launch, str(s.source))
    console.print(table)

    findings = audit(servers)
    if findings:
        console.print(_findings_table(findings))
    else:
        console.print("No findings.")
    if any(f.severity.rank >= fail_on.rank for f in findings):
        raise typer.Exit(1)


def _project_servers(path: Path, user: bool) -> list[Server]:
    """Servers for lock/verify: project configs plus tool snapshot, user configs opt-in."""
    servers = discover(path, home=Path.home() if user else None)
    snapshot = path / SNAPSHOT_NAME
    return apply_snapshot(servers, snapshot) if snapshot.is_file() else servers


_USER_OPTION = typer.Option(
    "--user/--no-user", help="Include user-level client configs (off by default for CI)."
)


@app.command()
def lock(
    path: Annotated[Path, typer.Argument(help="Repository to lock.")] = Path("."),
    user: Annotated[bool, _USER_OPTION] = False,
) -> None:
    """Write agent.lock with hashes of every server and, if known, every tool."""
    servers = _project_servers(path, user)
    if not servers:
        console.print("No MCP servers found; nothing to lock.")
        raise typer.Exit(1)
    write_lock(path / LOCK_NAME, servers)
    with_tools = sum(1 for s in servers if s.tools)
    console.print(f"Locked {len(servers)} server(s) ({with_tools} with tool definitions).")
    if with_tools < len(servers):
        console.print(
            f"[yellow]Tool descriptions are not pinned for {len(servers) - with_tools} server(s);"
            " run `agentaudit snapshot --introspect` first to pin them.[/]"
        )


@app.command()
def verify(
    path: Annotated[Path, typer.Argument(help="Repository to verify.")] = Path("."),
    user: Annotated[bool, _USER_OPTION] = False,
) -> None:
    """Compare the current setup with agent.lock; exit 1 on any drift."""
    try:
        approved = read_lock(path / LOCK_NAME)
    except LockError as exc:
        console.print(f"[red]{exc}[/]")
        raise typer.Exit(2) from exc
    drift = verify_lock(approved, _project_servers(path, user))
    if not drift:
        console.print("No drift: everything matches agent.lock.")
        return
    console.print(f"[red]{len(drift)} change(s) since agent.lock was written:[/]")
    for item in drift:
        console.print(f"  - {item}", markup=False)
    raise typer.Exit(1)


@app.command()
def snapshot(
    path: Annotated[Path, typer.Argument(help="Repository to snapshot.")] = Path("."),
    introspect_servers: Annotated[
        bool,
        typer.Option(
            "--introspect",
            help="Launch each configured server and record its tools (required).",
        ),
    ] = False,
    yes: Annotated[bool, typer.Option("--yes", "-y", help="Skip the confirmation prompt.")] = False,
    timeout: Annotated[float, typer.Option(help="Seconds to wait for each server.")] = 30.0,
    user: Annotated[bool, _USER_OPTION] = False,
) -> None:
    """Record every server's real tool definitions in agent.tools.json (runs the servers)."""
    if not introspect_servers:
        console.print(
            "snapshot launches your configured MCP servers to read their tool definitions. "
            "Nothing runs unless you opt in: re-run with --introspect."
        )
        raise typer.Exit(2)
    servers = discover(path, home=Path.home() if user else None)
    runnable = [s for s in servers if s.command]
    for s in servers:
        if not s.command:
            console.print(f"[yellow]Skipping {s.id}: remote servers cannot be introspected.[/]")
    if not runnable:
        console.print("No stdio servers to introspect.")
        raise typer.Exit(1)
    console.print("This will run:")
    for s in runnable:
        console.print(f"  {s.id}: {' '.join([s.command or '', *s.args])}", markup=False)
    if not yes and not typer.confirm("Launch these commands?"):
        raise typer.Exit(1)
    tools_by_server, failed = {}, 0
    for s in runnable:
        try:
            tools_by_server[s.id] = introspect(s, timeout=timeout)
        except IntrospectError as exc:
            failed += 1
            console.print(f"[red]{s.id}: {exc}[/]")
        else:
            console.print(f"{s.id}: {len(tools_by_server[s.id])} tool(s)")
    if tools_by_server:
        write_snapshot(path / SNAPSHOT_NAME, tools_by_server)
        console.print(f"Wrote {SNAPSHOT_NAME}. Run `agentaudit lock` to pin it.")
    if failed:
        raise typer.Exit(1)
