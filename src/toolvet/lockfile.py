"""agent.lock: hashes of what was approved, so silent changes fail CI.

Each server gets a hash of its launch definition (command, args, env var *names*, url) and,
when tool definitions are known, a hash of every tool's name, description and schema.
Env var values are never hashed or stored, so secrets cannot leak through the lockfile.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path

from toolvet.models import Server, Tool

LOCK_NAME = "agent.lock"
LOCK_VERSION = 1


class LockError(ValueError):
    """The lockfile is missing, malformed or from an unsupported version."""


def _digest(payload: object) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def config_hash(server: Server) -> str:
    return _digest(
        {
            "command": server.command,
            "args": server.args,
            "env_keys": sorted(server.env),
            "url": server.url,
        }
    )


def tool_hash(tool: Tool) -> str:
    return _digest(
        {"name": tool.name, "description": tool.description, "schema": tool.input_schema}
    )


def build_lock(servers: list[Server]) -> dict:
    entries = {}
    for server in sorted(servers, key=lambda s: s.id):
        entry: dict = {"config": config_hash(server)}
        if server.tools:
            entry["tools"] = {
                t.name: tool_hash(t) for t in sorted(server.tools, key=lambda t: t.name)
            }
        entries[server.id] = entry
    return {"version": LOCK_VERSION, "servers": entries}


def write_lock(path: Path, servers: list[Server]) -> None:
    path.write_text(
        json.dumps(build_lock(servers), indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )


def read_lock(path: Path) -> dict:
    """Read a lockfile. Raises LockError if it is missing, malformed or a newer version."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise LockError(f"cannot read {path}: {exc.strerror}") from exc
    except ValueError as exc:
        raise LockError(f"{path} is not valid JSON") from exc
    if not isinstance(data, dict) or not isinstance(data.get("servers"), dict):
        raise LockError(f"{path} is not an toolvet lockfile")
    if data.get("version") != LOCK_VERSION:
        raise LockError(f"{path} has unsupported version {data.get('version')!r}")
    return data


@dataclass(frozen=True)
class Drift:
    kind: str
    subject: str
    detail: str

    def __str__(self) -> str:
        return f"{self.kind}: {self.subject} {self.detail}".rstrip()


def verify(lock: dict, servers: list[Server]) -> list[Drift]:
    """Compare approved state in `lock` with the current servers. Empty list means no drift."""
    approved = lock["servers"]
    current = build_lock(servers)["servers"]
    drift: list[Drift] = []
    for sid in sorted(current.keys() - approved.keys()):
        drift.append(Drift("server added", sid, "is not in the lockfile"))
    for sid in sorted(approved.keys() - current.keys()):
        drift.append(Drift("server removed", sid, "is in the lockfile but no longer configured"))
    for sid in sorted(approved.keys() & current.keys()):
        old, new = approved[sid], current[sid]
        if old["config"] != new["config"]:
            drift.append(
                Drift("config changed", sid, "launch command, args, env names or url differ")
            )
        old_tools, new_tools = old.get("tools"), new.get("tools")
        if old_tools is None or new_tools is None:
            if (old_tools is None) != (new_tools is None):
                state = "gained" if old_tools is None else "lost"
                drift.append(Drift("tools snapshot", sid, f"{state} tool definitions"))
            continue
        for name in sorted(new_tools.keys() - old_tools.keys()):
            drift.append(Drift("tool added", f"{sid}:{name}", ""))
        for name in sorted(old_tools.keys() - new_tools.keys()):
            drift.append(Drift("tool removed", f"{sid}:{name}", ""))
        for name in sorted(old_tools.keys() & new_tools.keys()):
            if old_tools[name] != new_tools[name]:
                drift.append(
                    Drift("tool changed", f"{sid}:{name}", "name, description or schema differ")
                )
    return drift
