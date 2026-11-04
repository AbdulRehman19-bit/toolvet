# Changelog

All notable changes to this project are documented here. Versions follow
[Semantic Versioning](https://semver.org/).

## [0.2.0] - 2026-11-04

### Added
- `scan --format json|sarif|markdown|badge` with `--output`; SARIF 2.1.0 for GitHub code scanning. Empty scans still produce a valid report.
- GitHub Action (`action.yml`): scans, writes SARIF, optionally uploads it, and runs `verify` when `agent.lock` exists. It installs from the tagged action source.
- README badge (`--format badge`).
- Documentation site under `docs/` (rules reference, CI guide) for GitHub Pages.

### Fixed
- `scan` now reads `agent.tools.json`, so tool-description rules (AA006) apply to snapshotted tools. Previously only tools declared inline in a config were checked.

## [0.1.0] - 2026-11-04

First release.

### Added
- `scan`: discovers MCP servers for Claude Desktop, Cursor, VS Code and `.mcp.json`; runs rules AA001-AA010; builds the capability graph and reports lethal-trifecta paths (AA100). Exits 1 at `--fail-on` (default `high`).
- `lock` and `verify`: `agent.lock` records hashes of each server's launch definition and tool definitions; `verify` fails on any added, removed or changed server or tool.
- `snapshot --introspect`: opt-in, asks before launching each configured stdio server, and records its tools in `agent.tools.json`.
- `graph --format mermaid|svg`: exports the capability graph.
- Rule plugins through the `agentaudit.rules` entry-point group.
