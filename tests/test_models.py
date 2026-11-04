from pathlib import Path

from agentaudit.models import Server, Severity


def test_server_id_combines_client_and_name():
    server = Server(name="fs", client="cursor", source=Path("mcp.json"))
    assert server.id == "cursor:fs"


def test_severity_ranks_increase():
    assert Severity.LOW.rank < Severity.HIGH.rank < Severity.CRITICAL.rank
