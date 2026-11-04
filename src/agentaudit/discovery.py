"""Find MCP configurations for supported clients. One small parser per client."""

from __future__ import annotations

import json
import os
import sys
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from agentaudit.models import Server, Tool

# client -> (config path relative to a root, key holding the server map)
_PROJECT_CONFIGS = {
    "cursor": (".cursor/mcp.json", "mcpServers"),
    "vscode": (".vscode/mcp.json", "servers"),
    "mcp": (".mcp.json", "mcpServers"),
}


def _claude_desktop_path(home: Path) -> Path:
    if sys.platform == "win32":
        appdata = Path(os.environ.get("APPDATA", home / "AppData" / "Roaming"))
        return appdata / "Claude" / "claude_desktop_config.json"
    if sys.platform == "darwin":
        return home / "Library/Application Support/Claude/claude_desktop_config.json"
    return home / ".config/Claude/claude_desktop_config.json"


def _parse_tools(raw: Any) -> list[Tool]:
    if not isinstance(raw, list):
        return []
    return [
        Tool(
            name=t["name"],
            description=t.get("description", ""),
            input_schema=t.get("inputSchema") or t.get("input_schema") or {},
        )
        for t in raw
        if isinstance(t, dict) and isinstance(t.get("name"), str)
    ]


def parse_config(path: Path, client: str, key: str) -> list[Server]:
    """Parse one config file. Malformed or missing files yield no servers."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    entries = data.get(key) if isinstance(data, dict) else None
    if not isinstance(entries, dict):
        return []
    servers = []
    for name, entry in entries.items():
        if not isinstance(entry, dict):
            continue
        env = entry.get("env") if isinstance(entry.get("env"), dict) else {}
        servers.append(
            Server(
                name=name,
                client=client,
                source=path,
                command=entry.get("command"),
                args=[str(a) for a in entry.get("args", [])],
                env={str(k): str(v) for k, v in env.items()},
                url=entry.get("url"),
                tools=_parse_tools(entry.get("tools")),
            )
        )
    return servers


def _candidates(root: Path, home: Path | None) -> Iterator[tuple[Path, str, str]]:
    for client, (rel, key) in _PROJECT_CONFIGS.items():
        yield root / rel, client, key
    if home is not None:
        yield _claude_desktop_path(home), "claude-desktop", "mcpServers"
        yield home / ".cursor/mcp.json", "cursor", "mcpServers"


def discover(root: Path, home: Path | None = None) -> list[Server]:
    """Discover servers in a repo `root` and, if `home` is given, user-level configs."""
    root = root.resolve()
    if (root / "claude_desktop_config.json").is_file():
        # A directory holding a Claude Desktop config directly (used by fixtures).
        candidates = [(root / "claude_desktop_config.json", "claude-desktop", "mcpServers")]
        candidates += list(_candidates(root, home))
    else:
        candidates = list(_candidates(root, home))
    seen: set[Path] = set()
    servers: list[Server] = []
    for path, client, key in candidates:
        resolved = path.resolve()
        if resolved in seen or not path.is_file():
            continue
        seen.add(resolved)
        servers.extend(parse_config(path, client, key))
    return servers
