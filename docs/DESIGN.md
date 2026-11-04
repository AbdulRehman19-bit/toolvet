# toolvet design notes

Source of truth: the original project proposal (kept locally, not published; it was written
before the project was renamed from `agentaudit` to `toolvet`). This file records decisions
that refine it.

## Resolved gaps

### 1. MCP configs do not contain tool definitions
Client configs say how to launch a server, not what tools it exposes. Tool names,
descriptions and schemas exist only at runtime, so rug-pull detection needs them.

Decision:
- `toolvet scan` stays fully offline and never executes anything. Capability tags
  come from a fixed lookup table over server name, command and args (no inference).
- `toolvet snapshot --introspect` is an explicit opt-in. It launches each configured
  server over stdio, sends `initialize` and `tools/list`, and writes `agent.tools.json`.
  The user already runs these servers in their client; the command prints exactly what
  it will launch and asks for confirmation (`--yes` for CI).
- `toolvet lock` hashes the server definition (command, args, env keys, url) and,
  when `agent.tools.json` exists, every tool's name, description and schema.
- `toolvet verify` fails on any added, removed or changed server or tool.
- Sandboxed execution is still v0.4; introspection is not a sandbox.

### 2. Launch timeline vs 30-day disclosure
The proposal launches right after week 6 but requires a 30-day disclosure wait.
Decision: start the research scan and private disclosures in week 3, after v0.1.
The public launch is gated on the 30-day window ending, not on the calendar.
v0.2 and v0.3 ship on schedule regardless.

### 3. Prior art check (2026-11-04) changes the positioning
The proposal assumed other scanners check servers one at a time and marked its `mcp-scan`
comparison "unverified". Checked against primary sources, that was wrong:
- `mcp-scan` is now Snyk Agent Scan (`snyk/agent-scan`, PyPI `snyk-agent-scan`). It needs a
  `SNYK_TOKEN` and sends tool names and descriptions to Snyk's API.
- Invariant's Toxic Flow Analysis already models cross-tool flows with the lethal-trifecta
  framing, and the original MCP-Scan pinned tool hashes.
So "cross-server trifecta graph" is NOT a unique feature. The defensible differences are:
offline-by-default with no account, deterministic and explainable tagging, an
`agent.lock` committed to the repo and reviewed in pull requests, SARIF and an Action, and
community rule plugins. The README comparison table states this; launch copy must not claim
that other scanners miss cross-server combinations.

### 4. Open questions closed
- Licence: MIT.
- First three clients: Claude Desktop, Cursor, VS Code.
- Name: the project started as `agentaudit`. PyPI rejected that name on 2026-11-04 as too
  similar to the active project `agent-audit` (PyPI treats names that differ only by `-`, `_`
  or `.` as the same, and an exact-name lookup does not reveal that). It was renamed to
  `toolvet`, which was free on PyPI (exact and separator variants) and had no established
  GitHub project of that name. Rule ids moved from `AA###` to `TV###` at the same time.
  Lesson for any future name check: test separator variants and search GitHub, not just
  the exact PyPI name.
