"""Export the capability graph as Mermaid text or a standalone SVG."""

from __future__ import annotations

from xml.sax.saxutils import escape

import networkx as nx

COLUMNS = ["untrusted_source", "private_data", "sink"]
TITLES = {
    "untrusted_source": "Reads untrusted input",
    "private_data": "Reads private data",
    "sink": "Sends data out",
}
FILLS = {"untrusted_source": "#fff4d6", "private_data": "#e6f0ff", "sink": "#fde3e3"}
STROKES = {"untrusted_source": "#b7791f", "private_data": "#2b6cb0", "sink": "#c53030"}


def _label(graph: nx.DiGraph, node: str) -> str:
    data = graph.nodes[node]
    return f"{data['server']} ({data['keyword']})"


def _ordered(graph: nx.DiGraph) -> list[str]:
    return sorted(graph.nodes, key=lambda n: (COLUMNS.index(graph.nodes[n]["capability"]), n))


def to_mermaid(graph: nx.DiGraph) -> str:
    ids = {node: f"n{i}" for i, node in enumerate(_ordered(graph))}
    lines = ["flowchart LR"]
    for node, nid in ids.items():
        label = _label(graph, node).replace('"', "'")
        lines.append(f'    {nid}["{label}"]:::{graph.nodes[node]["capability"]}')
    for src, dst in sorted(graph.edges, key=lambda e: (ids[e[0]], ids[e[1]])):
        lines.append(f"    {ids[src]} --> {ids[dst]}")
    for capability in COLUMNS:
        lines.append(
            f"    classDef {capability} fill:{FILLS[capability]},stroke:{STROKES[capability]}"
        )
    return "\n".join(lines) + "\n"


def to_svg(graph: nx.DiGraph) -> str:
    col_w, node_w, node_h, gap, pad, head = 300, 240, 44, 16, 24, 40
    by_col = {c: [n for n in _ordered(graph) if graph.nodes[n]["capability"] == c] for c in COLUMNS}
    rows = max((len(v) for v in by_col.values()), default=1)
    width = pad * 2 + col_w * len(COLUMNS) - (col_w - node_w)
    height = pad * 2 + head + rows * (node_h + gap)
    pos: dict[str, tuple[int, int]] = {}
    for ci, capability in enumerate(COLUMNS):
        for ri, node in enumerate(by_col[capability]):
            pos[node] = (pad + ci * col_w, pad + head + ri * (node_h + gap))
    out = [
        (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
            f'viewBox="0 0 {width} {height}" font-family="sans-serif" font-size="13">'
        ),
        (
            '<defs><marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" '
            'markerHeight="7" orient="auto"><path d="M0 0L10 5L0 10z" fill="#718096"/>'
            "</marker></defs>"
        ),
        f'<rect width="{width}" height="{height}" fill="#ffffff"/>',
    ]
    for ci, capability in enumerate(COLUMNS):
        out.append(
            f'<text x="{pad + ci * col_w}" y="{pad + 14}" font-weight="bold" fill="#2d3748">'
            f"{escape(TITLES[capability])}</text>"
        )
    for src, dst in sorted(graph.edges):
        (x1, y1), (x2, y2) = pos[src], pos[dst]
        out.append(
            f'<line x1="{x1 + node_w}" y1="{y1 + node_h // 2}" x2="{x2}" y2="{y2 + node_h // 2}" '
            'stroke="#718096" stroke-width="1.2" marker-end="url(#arrow)"/>'
        )
    for node, (x, y) in pos.items():
        capability = graph.nodes[node]["capability"]
        out.append(
            f'<rect x="{x}" y="{y}" width="{node_w}" height="{node_h}" rx="6" '
            f'fill="{FILLS[capability]}" stroke="{STROKES[capability]}"/>'
            f'<text x="{x + 10}" y="{y + node_h // 2 + 5}" fill="#1a202c">'
            f"{escape(_label(graph, node))}</text>"
        )
    out.append("</svg>")
    return "\n".join(out) + "\n"
