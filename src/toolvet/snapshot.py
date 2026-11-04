"""agent.tools.json: a saved copy of each server's real tool definitions.

MCP configs only say how to launch a server. Tool names, descriptions and schemas exist at
runtime, so they are captured by `toolvet snapshot --introspect` and read from here.
"""

from __future__ import annotations

import json
from pathlib import Path

from toolvet.models import Server, Tool

SNAPSHOT_NAME = "agent.tools.json"


def tool_to_dict(tool: Tool) -> dict:
    return {"name": tool.name, "description": tool.description, "inputSchema": tool.input_schema}


def write_snapshot(path: Path, tools_by_server: dict[str, list[Tool]]) -> None:
    data = {
        "servers": {
            server_id: [tool_to_dict(t) for t in sorted(tools, key=lambda t: t.name)]
            for server_id, tools in sorted(tools_by_server.items())
        }
    }
    path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def load_snapshot(path: Path) -> dict[str, list[Tool]]:
    """Read a snapshot file. A missing or malformed file yields an empty mapping."""
    try:
        servers = json.loads(path.read_text(encoding="utf-8")).get("servers", {})
    except (OSError, ValueError, AttributeError):
        return {}
    result: dict[str, list[Tool]] = {}
    for server_id, raw in servers.items():
        if isinstance(raw, list):
            result[server_id] = [
                Tool(
                    name=t["name"],
                    description=t.get("description", ""),
                    input_schema=t.get("inputSchema", {}),
                )
                for t in raw
                if isinstance(t, dict) and isinstance(t.get("name"), str)
            ]
    return result


def apply_snapshot(servers: list[Server], path: Path) -> list[Server]:
    """Attach snapshot tools to servers that do not already declare tools inline."""
    snapshot = load_snapshot(path)
    return [
        s.model_copy(update={"tools": snapshot[s.id]}) if not s.tools and s.id in snapshot else s
        for s in servers
    ]
