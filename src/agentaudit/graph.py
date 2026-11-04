"""Capability graph and lethal-trifecta detection.

Servers configured together in one config file form one agent session. Within a session,
each (server, capability) pair is a node. Untrusted sources point at private-data readers,
and private-data readers point at sinks. Any source -> private -> sink path is a trifecta.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

import networkx as nx

from agentaudit.capabilities import tag_server
from agentaudit.models import Capability, Finding, Server, Severity

MAX_PATHS_LISTED = 5


def node_id(server: Server, capability: Capability) -> str:
    return f"{server.id}#{capability.value}"


def build_graph(servers: list[Server]) -> nx.DiGraph:
    """Build one graph over all servers; edges only connect servers sharing a config file."""
    graph = nx.DiGraph()
    by_scope: dict[Path, list[Server]] = defaultdict(list)
    for server in servers:
        by_scope[server.source].append(server)
    for scope, members in by_scope.items():
        nodes: dict[Capability, list[str]] = defaultdict(list)
        for server in members:
            for capability, keyword in tag_server(server).items():
                nid = node_id(server, capability)
                graph.add_node(
                    nid,
                    server=server.id,
                    capability=capability.value,
                    keyword=keyword,
                    scope=str(scope),
                )
                nodes[capability].append(nid)
        for source in nodes[Capability.UNTRUSTED_SOURCE]:
            for private in nodes[Capability.PRIVATE_DATA]:
                graph.add_edge(source, private)
        for private in nodes[Capability.PRIVATE_DATA]:
            for sink in nodes[Capability.SINK]:
                graph.add_edge(private, sink)
    return graph


def _describe(graph: nx.DiGraph, path: list[str]) -> str:
    steps = [
        f"{graph.nodes[n]['server']} ({graph.nodes[n]['capability']} via "
        f"'{graph.nodes[n]['keyword']}')"
        for n in path
    ]
    return " -> ".join(steps)


def find_trifectas(servers: list[Server]) -> list[Finding]:
    """Report one finding per config file that contains a source -> private -> sink path."""
    graph = build_graph(servers)
    by_scope: dict[str, list[list[str]]] = defaultdict(list)
    sources = [n for n, d in graph.nodes(data=True) if d["capability"] == "untrusted_source"]
    sinks = [n for n, d in graph.nodes(data=True) if d["capability"] == "sink"]
    for source in sources:
        for sink in sinks:
            if source == sink:
                continue
            for path in nx.all_simple_paths(graph, source, sink, cutoff=2):
                if len(path) == 3:
                    by_scope[graph.nodes[source]["scope"]].append(path)
    findings = []
    for scope, paths in sorted(by_scope.items()):
        involved = sorted({graph.nodes[n]["server"] for p in paths for n in p})
        single = len(involved) == 1
        kind = "inside one server" if single else f"across {len(involved)} servers"
        extra = len(paths) - MAX_PATHS_LISTED
        evidence = [_describe(graph, p) for p in paths[:MAX_PATHS_LISTED]]
        if extra > 0:
            evidence.append(f"... and {extra} more path(s)")
        findings.append(
            Finding(
                rule_id="AA100",
                severity=Severity.CRITICAL,
                message=(
                    f"Lethal trifecta {kind}: untrusted input can reach private data "
                    "and a channel that sends data out"
                ),
                server=", ".join(involved),
                source=Path(scope),
                evidence=evidence,
            )
        )
    return findings
