"""Smallest-fix suggestions for lethal trifectas.

Within one config file, a trifecta exists exactly when all three capability layers (untrusted
source, private data, sink) are present: every source reaches every private-data reader, and
every reader reaches every sink. To break it you must empty one layer, and the only way to
empty a layer is to take out every server that supplies it. So the cheapest fix is the layer
supplied by the fewest servers. That makes the answer exact, not a heuristic, and every part
of it can be explained from the capability tags.
"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass

from agentaudit.capabilities import tag_server
from agentaudit.models import Capability, Server

S, P, K = Capability.UNTRUSTED_SOURCE, Capability.PRIVATE_DATA, Capability.SINK
LAYERS = (S, P, K)
DOES = {S: "reads untrusted input", P: "reads private data", K: "sends data out"}
WITHOUT = {
    S: "nothing in this config reads untrusted input",
    P: "nothing in this config reads private data",
    K: "nothing in this config can send data out",
}


def layers_of(servers: list[Server]) -> dict[Capability, dict[str, str]]:
    """For each layer, the servers that supply it and the keyword that tagged them."""
    result: dict[Capability, dict[str, str]] = {c: {} for c in LAYERS}
    for server in servers:
        for capability, keyword in tag_server(server).items():
            result[capability][server.id] = keyword
    return result


def has_trifecta(servers: list[Server]) -> bool:
    return all(layers_of(servers)[c] for c in LAYERS)


@dataclass(frozen=True)
class FixOption:
    layers: tuple[Capability, ...]  # the layer(s) this option empties
    servers: tuple[str, ...]  # server ids to take out of this config
    reasons: tuple[str, ...]  # "<server> (<layer> via '<keyword>')"
    movable: bool  # False if these servers form a trifecta all by themselves
    capabilities_lost: int  # how much else leaves with them (smaller is gentler)

    def describe(self, name: Callable[[str], str] = lambda s: s) -> str:
        names = ", ".join(name(s) for s in self.servers)
        many = len(self.servers) > 1
        layer = self.layers[0]
        if not self.movable:
            return (
                f"{names} can read untrusted input, read private data and send data out on its "
                "own, so moving it does not help. Remove it, or restrict its tools so it only "
                "does one of those."
            )
        role = (
            f"the only servers here that {DOES[layer]}"
            if many
            else (f"the only server here that {DOES[layer]}")
        )
        return (
            f"Move {names} to a separate agent profile (or remove {'them' if many else 'it'}). "
            f"{'They are' if many else 'It is'} {role}, so {WITHOUT[layer]} afterwards."
        )


def _options(servers: list[Server]) -> list[FixOption]:
    by_layer = layers_of(servers)
    caps = {s.id: set(tag_server(s)) for s in servers}
    merged: dict[tuple[str, ...], list[Capability]] = defaultdict(list)
    for layer in LAYERS:
        merged[tuple(sorted(by_layer[layer]))].append(layer)
    options = []
    for ids, layers in merged.items():
        moved = [s for s in servers if s.id in ids]
        options.append(
            FixOption(
                layers=tuple(layers),
                servers=ids,
                reasons=tuple(
                    f"{sid} ({layers[0].value} via '{by_layer[layers[0]][sid]}')" for sid in ids
                ),
                movable=not has_trifecta(moved),
                capabilities_lost=sum(len(caps[sid]) for sid in ids),
            )
        )
    options.sort(
        key=lambda o: (
            len(o.servers),
            not o.movable,
            o.capabilities_lost,
            LAYERS.index(o.layers[0]),
        )
    )
    return options


def trifecta_fixes(servers: list[Server]) -> dict[str, list[FixOption]]:
    """Best-first fix options for every config file that has a trifecta, keyed by config path."""
    by_scope: dict[str, list[Server]] = defaultdict(list)
    for server in servers:
        by_scope[str(server.source)].append(server)
    return {
        scope: _options(members) for scope, members in by_scope.items() if has_trifecta(members)
    }
