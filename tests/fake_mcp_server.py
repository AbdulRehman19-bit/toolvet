"""A tiny fake MCP stdio server used by the introspection tests.

Usage: fake_mcp_server.py MODE   where MODE is one of
ok, paged, silent, exit, init-error, list-error, noisy
"""

import json
import sys

mode = sys.argv[1]
TOOLS = [
    {"name": "read_file", "description": "Reads a file", "inputSchema": {"type": "object"}},
    {"name": "write_file", "description": "Writes a file"},
]


def reply(request_id, result=None, error=None):
    message = {"jsonrpc": "2.0", "id": request_id}
    message.update({"error": error} if error else {"result": result})
    print(json.dumps(message), flush=True)


if mode == "exit":
    sys.exit(0)

for line in sys.stdin:
    request = json.loads(line)
    method, request_id = request.get("method"), request.get("id")
    if mode == "silent":
        continue
    if mode == "noisy":
        print("starting up...", flush=True)
        print(json.dumps({"jsonrpc": "2.0", "method": "notifications/message"}), flush=True)
    if method == "initialize":
        if mode == "init-error":
            reply(request_id, error={"code": -1, "message": "nope"})
        else:
            reply(request_id, {"protocolVersion": "2025-06-18", "capabilities": {}})
    elif method == "tools/list":
        if mode == "list-error":
            reply(request_id, error="boom")
        elif mode == "paged":
            cursor = request.get("params", {}).get("cursor")
            if cursor is None:
                reply(request_id, {"tools": TOOLS[:1], "nextCursor": "p2"})
            else:
                reply(request_id, {"tools": TOOLS[1:]})
        else:
            reply(request_id, {"tools": TOOLS + [{"description": "no name"}]})
