"""One call that runs every check: per-server rules plus cross-server graph analysis."""

from __future__ import annotations

from agentaudit.graph import find_trifectas
from agentaudit.models import Finding, Server
from agentaudit.rules import Rule, run_rules


def audit(servers: list[Server], rules: list[Rule] | None = None) -> list[Finding]:
    return [*run_rules(servers, rules), *find_trifectas(servers)]
