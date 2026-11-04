from pathlib import Path
from xml.etree import ElementTree

from typer.testing import CliRunner

from toolvet.cli import app
from toolvet.discovery import discover
from toolvet.graph import build_graph
from toolvet.graph_export import to_mermaid, to_svg

FIXTURES = Path(__file__).parent / "fixtures"
runner = CliRunner()


def fixture_graph():
    return build_graph(discover(FIXTURES / "claude_desktop"))


def test_mermaid_has_nodes_edges_and_classes():
    text = to_mermaid(fixture_graph())
    assert text.startswith("flowchart LR")
    assert "claude-desktop:filesystem (filesystem)" in text
    assert "-->" in text
    assert ":::private_data" in text
    assert "classDef sink" in text


def test_svg_is_well_formed_and_escaped():
    svg = to_svg(fixture_graph())
    root = ElementTree.fromstring(svg)
    assert root.tag.endswith("svg")
    assert "Reads private data" in svg
    assert svg.count("<line") == fixture_graph().number_of_edges()


def test_svg_escapes_special_characters():
    graph = fixture_graph()
    node = next(iter(graph.nodes))
    graph.nodes[node]["server"] = "a<b>&c"
    ElementTree.fromstring(to_svg(graph))


def test_cli_graph_stdout_and_file(tmp_path):
    result = runner.invoke(app, ["graph", str(FIXTURES / "claude_desktop"), "--no-user"])
    assert result.exit_code == 0
    assert result.output.startswith("flowchart LR")
    out = tmp_path / "g.svg"
    args = [
        "graph",
        str(FIXTURES / "claude_desktop"),
        "--no-user",
        "--format",
        "svg",
        "-o",
        str(out),
    ]
    result = runner.invoke(app, args)
    assert result.exit_code == 0
    ElementTree.fromstring(out.read_text(encoding="utf-8"))


def test_cli_graph_with_nothing_to_draw(tmp_path):
    result = runner.invoke(app, ["graph", str(tmp_path), "--no-user"])
    assert result.exit_code == 1


def test_empty_svg_still_renders():
    import networkx as nx

    ElementTree.fromstring(to_svg(nx.DiGraph()))
