# agentaudit design notes

Source of truth: `agentaudit - Project Proposal.pdf`. This file records decisions that refine it.

## Resolved gaps

### 1. MCP configs do not contain tool definitions
Client configs say how to launch a server, not what tools it exposes. Tool names,
descriptions and schemas exist only at runtime, so rug-pull detection needs them.

Decision:
- `agentaudit scan` stays fully offline and never executes anything. Capability tags
  come from a fixed lookup table over server name, command and args (no inference).
- `agentaudit snapshot --introspect` is an explicit opt-in. It launches each configured
  server over stdio, sends `initialize` and `tools/list`, and writes `agent.tools.json`.
  The user already runs these servers in their client; the command prints exactly what
  it will launch and asks for confirmation (`--yes` for CI).
- `agentaudit lock` hashes the server definition (command, args, env keys, url) and,
  when `agent.tools.json` exists, every tool's name, description and schema.
- `agentaudit verify` fails on any added, removed or changed server or tool.
- Sandboxed execution is still v0.4; introspection is not a sandbox.

### 2. Launch timeline vs 30-day disclosure
The proposal launches right after week 6 but requires a 30-day disclosure wait.
Decision: start the research scan and private disclosures in week 3, after v0.1.
The public launch is gated on the 30-day window ending, not on the calendar.
v0.2 and v0.3 ship on schedule regardless.

### 3. Open questions closed
- Licence: MIT.
- First three clients: Claude Desktop, Cursor, VS Code.
- Name: `agentaudit` is free on PyPI (checked 2026-11-04).
