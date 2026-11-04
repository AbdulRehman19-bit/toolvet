"""Command line entry point."""

from __future__ import annotations

import tempfile
from enum import Enum
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.markup import escape
from rich.table import Table
from rich.text import Text

from agentaudit import __version__
from agentaudit.audit import audit, load_servers
from agentaudit.diff import compute_diff
from agentaudit.diff_render import to_json as diff_json
from agentaudit.diff_render import to_markdown as diff_markdown
from agentaudit.diff_render import to_text as diff_text
from agentaudit.discovery import discover
from agentaudit.gitbase import GitError, materialize
from agentaudit.graph import build_graph
from agentaudit.graph_export import to_mermaid, to_svg
from agentaudit.introspect import IntrospectError, introspect
from agentaudit.lockfile import LOCK_NAME, LockError, read_lock, write_lock
from agentaudit.lockfile import verify as verify_lock
from agentaudit.ml.classifier import Classifier, MLUnavailable, classify_servers
from agentaudit.models import Finding, Server, Severity
from agentaudit.reporters import to_badge, to_json, to_markdown, to_sarif
from agentaudit.snapshot import SNAPSHOT_NAME, apply_snapshot, write_snapshot

app = typer.Typer(help="Audit AI agent tool (MCP) configurations.", no_args_is_help=True)
# emoji=False: names like `mcp:notes:time` contain `:notes:`, which Rich would render as an
# emoji (and crash on consoles that cannot encode it). highlight=False keeps output plain.
console = Console(emoji=False, highlight=False)
err_console = Console(stderr=True, emoji=False, highlight=False)

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


def counts(finding: Finding) -> bool:
    """Whether a finding can fail a build: not advisory and not covered by a waiver."""
    return not finding.advisory and finding.waiver is None


def _fails(findings: list[Finding], fail_on: Severity) -> bool:
    """True if a non-advisory finding is at least `fail_on`. Advisory findings never fail."""
    return any(counts(f) and f.severity.rank >= fail_on.rank for f in findings)


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
        if f.waiver:
            message += (
                f"\n  waived by {f.waiver['owner']} until {f.waiver['expires']}: "
                f"{f.waiver['reason']}"
            )
        label = f.severity.value
        if f.advisory:
            label += " (advisory)"
        if f.waiver:
            label += " (waived)"
        table.add_row(Text(label, style=style), f.rule_id, Text(where), Text(message))
    return table


class ReportFormat(str, Enum):
    terminal = "terminal"
    json = "json"
    sarif = "sarif"
    markdown = "markdown"
    badge = "badge"


def _render(
    format: ReportFormat,
    servers: list[Server],
    findings: list[Finding],
    root: Path,
    fail_on: Severity,
) -> str:
    if format is ReportFormat.json:
        return to_json(servers, findings, root)
    if format is ReportFormat.sarif:
        return to_sarif(findings, root)
    if format is ReportFormat.markdown:
        return to_markdown(servers, findings)
    return to_badge(findings, fail_on)


def _audit(servers: list[Server], classify: bool) -> list[Finding]:
    findings = audit(servers)
    if not classify:
        return findings
    try:
        classifier = Classifier()
    except MLUnavailable as exc:
        err_console.print(f"[red]{escape(str(exc))}[/]")
        raise typer.Exit(2) from exc
    if not any(t.description.strip() for s in servers for t in s.tools):
        err_console.print(
            "[yellow]No tool descriptions to classify. Run `agentaudit snapshot --introspect` "
            "to record them.[/]"
        )
    return [*findings, *classify_servers(servers, classifier)]


def _emit(text: str, output: Path | None) -> None:
    if output:
        output.write_text(text, encoding="utf-8")
        console.print(f"Wrote {escape(str(output))}")
    else:
        typer.echo(text, nl=False)


@app.command()
def scan(
    path: Annotated[Path, typer.Argument(help="Repository or directory to scan.")] = Path("."),
    user: Annotated[
        bool, typer.Option("--user/--no-user", help="Also scan user-level client configs.")
    ] = True,
    fail_on: Annotated[
        Severity, typer.Option("--fail-on", help="Exit 1 if a finding is at least this severe.")
    ] = Severity.HIGH,
    format: Annotated[
        ReportFormat, typer.Option("--format", help="Report format.")
    ] = ReportFormat.terminal,
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write the report to a file.")
    ] = None,
    classify: Annotated[
        bool,
        typer.Option(
            "--classify",
            help="Also score tool descriptions with the local ML classifier (advisory only; "
            "needs agentaudit[ml]).",
        ),
    ] = False,
) -> None:
    """Discover MCP servers, check rules, build the capability graph and report."""
    servers = _project_servers(path, user)
    if format is not ReportFormat.terminal:
        findings = _audit(servers, classify)
        _emit(_render(format, servers, findings, path, fail_on), output)
        if _fails(findings, fail_on):
            raise typer.Exit(1)
        return
    if not servers:
        console.print("No MCP servers found.")
        raise typer.Exit()
    table = Table(title=f"{len(servers)} MCP server(s)")
    for column in ("Client", "Server", "Launch", "Config"):
        table.add_column(column)
    for s in servers:
        launch = s.url or " ".join(filter(None, [s.command, *s.args]))
        table.add_row(Text(s.client), Text(s.name), Text(launch), Text(str(s.source)))
    console.print(table)

    findings = _audit(servers, classify)
    if findings:
        console.print(_findings_table(findings))
    else:
        console.print("No findings.")
    if _fails(findings, fail_on):
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
        console.print(f"[red]{escape(str(exc))}[/]")
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
            console.print(
                f"[yellow]Skipping {escape(s.id)}: remote servers cannot be introspected.[/]"
            )
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
            console.print(f"[red]{escape(s.id)}: {escape(str(exc))}[/]")
        else:
            console.print(f"{escape(s.id)}: {len(tools_by_server[s.id])} tool(s)")
    if tools_by_server:
        write_snapshot(path / SNAPSHOT_NAME, tools_by_server)
        console.print(f"Wrote {SNAPSHOT_NAME}. Run `agentaudit lock` to pin it.")
    if failed:
        raise typer.Exit(1)


class GraphFormat(str, Enum):
    mermaid = "mermaid"
    svg = "svg"


@app.command()
def graph(
    path: Annotated[Path, typer.Argument(help="Repository or directory to scan.")] = Path("."),
    format: Annotated[GraphFormat, typer.Option("--format", help="Output format.")] = (
        GraphFormat.mermaid
    ),
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write to a file instead of stdout.")
    ] = None,
    user: Annotated[
        bool, typer.Option("--user/--no-user", help="Also scan user-level client configs.")
    ] = True,
) -> None:
    """Export the capability graph as Mermaid text or SVG."""
    servers = _project_servers(path, user)
    capability_graph = build_graph(servers)
    if not capability_graph.nodes:
        console.print("No capabilities found; nothing to draw.")
        raise typer.Exit(1)
    text = (
        to_mermaid(capability_graph) if format is GraphFormat.mermaid else to_svg(capability_graph)
    )
    if output:
        output.write_text(text, encoding="utf-8")
        console.print(f"Wrote {escape(str(output))}")
    else:
        typer.echo(text, nl=False)


class DiffFormat(str, Enum):
    terminal = "terminal"
    markdown = "markdown"
    json = "json"


@app.command("diff")
def diff_command(
    path: Annotated[Path, typer.Argument(help="Repository to compare.")] = Path("."),
    base: Annotated[str, typer.Option("--base", help="Git ref to compare against.")] = "",
    head: Annotated[
        str | None,
        typer.Option("--head", help="Git ref for the new state (default: the working tree)."),
    ] = None,
    format: Annotated[DiffFormat, typer.Option("--format", help="Report format.")] = (
        DiffFormat.terminal
    ),
    output: Annotated[
        Path | None, typer.Option("--output", "-o", help="Write the report to a file.")
    ] = None,
    fail_on: Annotated[
        Severity, typer.Option("--fail-on", help="Exit 1 if the change adds a finding this severe.")
    ] = Severity.HIGH,
) -> None:
    """Show what a change does to your agent's capabilities, compared with a git ref."""
    if not base:
        console.print("[red]--base is required, for example --base origin/main[/]")
        raise typer.Exit(2)
    with tempfile.TemporaryDirectory() as tmp:
        base_dir = Path(tmp) / "base"
        try:
            materialize(path, base, base_dir)
            head_dir = path
            if head:
                head_dir = Path(tmp) / "head"
                materialize(path, head, head_dir)
        except GitError as exc:
            console.print(f"[red]{escape(str(exc))}[/]")
            raise typer.Exit(2) from exc
        result = compute_diff(load_servers(base_dir), load_servers(head_dir), base_dir, head_dir)
    if format is DiffFormat.markdown:
        text = diff_markdown(result, fail_on)
    elif format is DiffFormat.json:
        text = diff_json(result, fail_on)
    else:
        text = diff_text(result, fail_on)
    if output:
        output.write_text(text, encoding="utf-8")
        console.print(f"Wrote {escape(str(output))}")
    elif format is DiffFormat.terminal:
        console.print(text, markup=False, soft_wrap=True)
    else:
        typer.echo(text, nl=False)
    if result.introduces_risk(fail_on):
        raise typer.Exit(1)
