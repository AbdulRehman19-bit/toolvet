"""One call that runs every check: per-server rules plus cross-server graph analysis."""

from __future__ import annotations

from pathlib import Path

from toolvet.discovery import discover
from toolvet.graph import find_trifectas
from toolvet.models import Finding, Server
from toolvet.rules import Rule, run_rules
from toolvet.snapshot import SNAPSHOT_NAME, apply_snapshot


def load_servers(path: Path, home: Path | None = None) -> list[Server]:
    """Discover servers under `path` and attach tool definitions from agent.tools.json."""
    servers = discover(path, home=home)
    snapshot = path / SNAPSHOT_NAME
    return apply_snapshot(servers, snapshot) if snapshot.is_file() else servers


def audit(servers: list[Server], rules: list[Rule] | None = None) -> list[Finding]:
    return [*run_rules(servers, rules), *find_trifectas(servers)]
