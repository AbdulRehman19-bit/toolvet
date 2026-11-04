# Changelog

All notable changes to this project are documented here. Versions follow
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-04

First release.

### Added
- `scan`: discovers MCP servers for Claude Desktop, Cursor, VS Code and `.mcp.json`; runs rules AA001-AA010; builds the capability graph and reports lethal-trifecta paths (AA100). Exits 1 at `--fail-on` (default `high`).
- `lock` and `verify`: `agent.lock` records hashes of each server's launch definition and tool definitions; `verify` fails on any added, removed or changed server or tool.
- `snapshot --introspect`: opt-in, asks before launching each configured stdio server, and records its tools in `agent.tools.json`.
- `graph --format mermaid|svg`: exports the capability graph.
- Rule plugins through the `agentaudit.rules` entry-point group.
