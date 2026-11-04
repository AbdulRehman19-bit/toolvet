# agentaudit

Find dangerous combinations of AI agent tools (MCP servers) before attackers do, and pin what you approved so silent changes fail CI.

Every MCP server you install can look safe on its own. agentaudit shows what they can do **together**.

![Three servers form one exfiltration path](docs/trifecta.svg)

*One agent session, three servers that each pass review alone: a web fetcher reads untrusted content, a filesystem server reads private files, and a GitHub or fetch tool can send data out. agentaudit reports the source-to-sink path.*

## Why

Two attacks matter most when you give an agent tools:

- **The lethal trifecta.** One agent holds a tool that reads untrusted content (web pages, email, issues), a tool that reads private data (files, secrets, databases) and a tool that sends data out (HTTP, email, git push). An instruction hidden in a web page can then exfiltrate private data. The danger exists only in the combination.
- **The rug pull.** A server ships a harmless tool description, you approve it, and a later update quietly changes the description or schema. Nothing asks you again.

## Install

```bash
pipx run agentaudit scan        # once published to PyPI
# until then, from a clone:
uv sync && uv run agentaudit scan
```

Requires Python 3.11+. Not yet published to PyPI.

## Use

```bash
agentaudit scan [path]      # discover servers, run rules, build the graph, report
agentaudit lock             # write agent.lock
agentaudit verify           # compare with agent.lock; exit 1 on any change
agentaudit snapshot --introspect   # opt in: launch servers and record their real tools
agentaudit graph --format mermaid|svg
```

`scan` runs fully offline and never executes anything. It exits 1 if any finding is at least `--fail-on` (default `high`).

### Pin what you approved

```bash
agentaudit snapshot --introspect   # asks before running each configured server
agentaudit lock                    # hashes servers and every tool's name, description, schema
git add agent.lock agent.tools.json && git commit
# in CI:
agentaudit verify
```

`agent.lock` is reviewed in pull requests like any lockfile. Environment variable **values** are never stored or hashed; only their names are.

MCP configs only say how to launch a server, not what tools it exposes. Without a snapshot, `lock` pins each server's launch definition but not its tool descriptions, and `lock` tells you so. Introspection runs the commands from your own config, exactly as your MCP client does. It is not a sandbox.

## What it checks

| Rule | Severity | Finds |
|---|---|---|
| AA001 | high | Server launched through a shell, or named like a shell tool |
| AA002 | high | Literal secrets in `env` |
| AA003 | medium | Unpinned `npx` / `uvx` / `pipx` packages |
| AA004 | high | Root or wildcard paths (`/`, `~`, `C:\`, `/home/*`) |
| AA005 | medium | Plain `http://` remote servers |
| AA006 | high | Instruction-like text in tool descriptions (needs tool data) |
| AA007 | high | Credentials in a server URL |
| AA008 | high | Credentials in command-line arguments |
| AA009 | high | Download-and-execute launch commands |
| AA010 | high / medium | Privileged containers, host root or Docker socket mounts, host network |
| AA100 | critical | Lethal trifecta: untrusted source, private data and sink in one config |

Supported configs: Claude Desktop, Cursor, VS Code (`.vscode/mcp.json`) and a generic `.mcp.json`.

## How the trifecta check works, and its limits

Capability tags come from a fixed keyword table ([capabilities.py](src/agentaudit/capabilities.py)) matched against each server's name, command, arguments, URL host and tool names. There is no inference, and every finding prints the keyword behind each tag, so you can check it line by line.

That makes it explainable, but not precise:

- A server is tagged by keyword, not by what it actually does. Expect false positives (a server with "search" in its name counts as untrusted input) and false negatives (an unrecognised server gets no tags).
- Servers combine only when they live in the same config file, which is treated as one agent session.
- Findings are heuristic. Treat AA100 as "look at this", not proof of a vulnerability.

## Writing a rule

A rule is a function from one server to findings. See [CONTRIBUTING.md](CONTRIBUTING.md); a first rule takes about ten minutes.

## Status

Pre-release (v0.1). Roadmap: SARIF/JSON output and a GitHub Action (v0.2), an opt-in local classifier (v0.3). See [docs/DESIGN.md](docs/DESIGN.md).

## Licence

MIT
