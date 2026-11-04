"""Opt-in introspection: launch an MCP stdio server and ask it for its tools.

This runs the server's configured command, exactly as the user's own client would. It is
not a sandbox. `scan` never calls this; only `agentaudit snapshot --introspect` does.
"""

from __future__ import annotations

import json
import os
import queue
import shutil
import subprocess
import threading
import time
from typing import Any

from agentaudit.models import Server, Tool

PROTOCOL_VERSION = "2025-06-18"
MAX_PAGES = 50


class IntrospectError(Exception):
    """The server could not be launched or did not answer correctly."""


def _launch_env(server: Server) -> dict[str, str]:
    env = dict(os.environ)
    # Placeholders like ${env:TOKEN} are resolved by the client; keep the real environment.
    env.update({k: v for k, v in server.env.items() if v and not v.lstrip().startswith("$")})
    return env


class _Session:
    def __init__(self, proc: subprocess.Popen, timeout: float):
        self.proc = proc
        self.deadline = time.monotonic() + timeout
        self.messages: queue.Queue[dict | None] = queue.Queue()
        self._next_id = 0
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            try:
                message = json.loads(line)
            except ValueError:
                continue  # servers sometimes print logs to stdout; ignore non-JSON lines
            if isinstance(message, dict):
                self.messages.put(message)
        self.messages.put(None)

    def _send(self, payload: dict[str, Any]) -> None:
        assert self.proc.stdin is not None
        try:
            self.proc.stdin.write(json.dumps(payload) + "\n")
            self.proc.stdin.flush()
        except OSError as exc:
            raise IntrospectError("server closed its input") from exc

    def notify(self, method: str) -> None:
        self._send({"jsonrpc": "2.0", "method": method})

    def request(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self._next_id += 1
        request_id = self._next_id
        self._send({"jsonrpc": "2.0", "id": request_id, "method": method, "params": params})
        while True:
            remaining = self.deadline - time.monotonic()
            if remaining <= 0:
                raise IntrospectError(f"timed out waiting for {method}")
            try:
                message = self.messages.get(timeout=remaining)
            except queue.Empty:
                raise IntrospectError(f"timed out waiting for {method}") from None
            if message is None:
                raise IntrospectError("server exited before answering")
            if message.get("id") != request_id:
                continue
            if "error" in message:
                error = message["error"]
                text = error.get("message", error) if isinstance(error, dict) else error
                raise IntrospectError(f"{method} failed: {text}")
            result = message.get("result")
            return result if isinstance(result, dict) else {}


def introspect(server: Server, timeout: float = 30.0) -> list[Tool]:
    """Return the tools a stdio server exposes. Raises IntrospectError on any failure."""
    if not server.command:
        raise IntrospectError("not a stdio server (no command to launch)")
    executable = shutil.which(server.command)
    if executable is None:
        raise IntrospectError(f"command not found: {server.command}")
    try:
        proc = subprocess.Popen(
            [executable, *server.args],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            env=_launch_env(server),
        )
    except OSError as exc:
        raise IntrospectError(f"could not launch: {exc.strerror or exc}") from exc
    try:
        session = _Session(proc, timeout)
        session.request(
            "initialize",
            {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": {"name": "agentaudit", "version": "0"},
            },
        )
        session.notify("notifications/initialized")
        tools: list[Tool] = []
        cursor: str | None = None
        for _ in range(MAX_PAGES):
            result = session.request("tools/list", {"cursor": cursor} if cursor else {})
            for raw in result.get("tools", []):
                if isinstance(raw, dict) and isinstance(raw.get("name"), str):
                    tools.append(
                        Tool(
                            name=raw["name"],
                            description=raw.get("description") or "",
                            input_schema=raw.get("inputSchema") or {},
                        )
                    )
            cursor = result.get("nextCursor")
            if not cursor:
                break
        return tools
    finally:
        _stop(proc)


def _stop(proc: subprocess.Popen) -> None:
    for stream in (proc.stdin,):
        try:
            if stream:
                stream.close()
        except OSError:
            pass
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()
