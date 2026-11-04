"""Rule engine. A rule is a function from one Server to zero or more Hits.

Writing a rule::

    from agentaudit.rules import Hit, rule
    from agentaudit.models import Severity

    @rule("XX001", "Example rule")
    def example(server):
        if server.command == "bad":
            yield Hit(Severity.HIGH, "Uses the bad command")

Third-party packages expose Rule objects through the ``agentaudit.rules`` entry-point group.
"""

from __future__ import annotations

import importlib
from collections.abc import Callable, Iterable, Iterator
from dataclasses import dataclass, field
from importlib.metadata import entry_points

from agentaudit.models import Finding, Server, Severity


@dataclass(frozen=True)
class Hit:
    severity: Severity
    message: str
    tool: str | None = None
    evidence: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    check: Callable[[Server], Iterable[Hit]]


_REGISTRY: dict[str, Rule] = {}


def rule(rule_id: str, title: str) -> Callable[[Callable[[Server], Iterable[Hit]]], Rule]:
    def decorator(func: Callable[[Server], Iterable[Hit]]) -> Rule:
        registered = Rule(rule_id, title, func)
        _REGISTRY[rule_id] = registered
        return registered

    return decorator


def load_rules(plugins: bool = True) -> list[Rule]:
    """Return built-in rules plus any rules registered through entry points."""
    importlib.import_module("agentaudit.rules.builtin")
    rules = dict(_REGISTRY)
    if plugins:
        for ep in entry_points(group="agentaudit.rules"):
            loaded = ep.load()
            if isinstance(loaded, Rule):
                rules[loaded.id] = loaded
    return sorted(rules.values(), key=lambda r: r.id)


def run_rules(servers: Iterable[Server], rules: list[Rule] | None = None) -> list[Finding]:
    active = rules if rules is not None else load_rules()
    return list(_run(servers, active))


def _run(servers: Iterable[Server], rules: list[Rule]) -> Iterator[Finding]:
    for server in servers:
        for r in rules:
            for hit in r.check(server):
                yield Finding(
                    rule_id=r.id,
                    severity=hit.severity,
                    message=hit.message,
                    server=server.id,
                    tool=hit.tool,
                    source=server.source,
                    evidence=hit.evidence,
                )
