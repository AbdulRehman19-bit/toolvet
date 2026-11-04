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
from agentaudit.models import Finding, Severity

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
