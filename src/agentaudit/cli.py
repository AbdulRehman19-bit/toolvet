"""Command line entry point."""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.table import Table

from agentaudit import __version__
from agentaudit.discovery import discover

app = typer.Typer(help="Audit AI agent tool (MCP) configurations.", no_args_is_help=True)
console = Console()


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


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="Repository or directory to scan.")] = Path("."),
    user: Annotated[
        bool, typer.Option("--user/--no-user", help="Also scan user-level client configs.")
    ] = True,
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
