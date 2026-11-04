from pathlib import Path

from toolvet.capabilities import tag_server
from toolvet.discovery import discover
from toolvet.graph import MAX_PATHS_LISTED, build_graph, find_trifectas
from toolvet.models import Capability, Server, Severity, Tool

FIXTURES = Path(__file__).parent / "fixtures"


def make(name: str, source: str = "a.json", **kw) -> Server:
    return Server(name=name, client="test", source=Path(source), **kw)


def test_tag_server_names_the_keyword():
    tags = tag_server(make("web", command="uvx", args=["mcp-server-fetch"]))
    assert tags == {Capability.UNTRUSTED_SOURCE: "fetch", Capability.SINK: "fetch"}


def test_tags_come_from_url_host_and_tool_names():
    assert Capability.SINK in tag_server(make("x", url="https://hooks.slack.com/mcp"))
    assert Capability.PRIVATE_DATA in tag_server(make("x", tools=[Tool(name="read_files")]))
    assert tag_server(make("x", command="node", args=["server.js"])) == {}


def test_cross_server_trifecta():
    servers = [
        make("browser"),
        make("postgres"),
        make("mailer", command="uvx", args=["smtp-server"]),
    ]
    (finding,) = find_trifectas(servers)
    assert finding.rule_id == "TV100"
    assert finding.severity is Severity.CRITICAL
    assert "across 3 servers" in finding.message
    assert any("test:browser" in e and "test:postgres" in e for e in finding.evidence)


def test_no_trifecta_without_a_sink():
    assert find_trifectas([make("search"), make("postgres")]) == []


def test_no_trifecta_without_private_data():
    assert find_trifectas([make("search"), make("smtp")]) == []


def test_servers_in_different_configs_do_not_combine():
    servers = [make("search", "a.json"), make("postgres", "b.json"), make("smtp", "c.json")]
    assert find_trifectas(servers) == []


def test_single_server_trifecta():
    (finding,) = find_trifectas([make("gmail")])
    assert "inside one server" in finding.message


def test_long_path_lists_are_truncated():
    servers = [make(f"search-{i}") for i in range(3)]
    servers += [make(f"postgres-{i}") for i in range(3)]
    servers += [make(f"smtp-{i}") for i in range(3)]
    (finding,) = find_trifectas(servers)
    assert len(finding.evidence) == MAX_PATHS_LISTED + 1
    assert finding.evidence[-1] == "... and 22 more path(s)"


def test_graph_edges_follow_source_private_sink_order():
    graph = build_graph([make("search"), make("postgres"), make("smtp")])
    assert graph.has_edge("test:search#untrusted_source", "test:postgres#private_data")
    assert graph.has_edge("test:postgres#private_data", "test:smtp#sink")
    assert not graph.has_edge("test:search#untrusted_source", "test:smtp#sink")


def test_fixture_trifectas():
    claude = find_trifectas(discover(FIXTURES / "claude_desktop"))
    assert len(claude) == 1 and "filesystem" in claude[0].server
    assert find_trifectas(discover(FIXTURES / "cursor")) == []
    vscode = find_trifectas(discover(FIXTURES / "vscode"))
    assert len(vscode) == 1 and "vscode:slack" in vscode[0].server
