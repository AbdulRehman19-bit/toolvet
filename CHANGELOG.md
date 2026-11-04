# Changelog

All notable changes to this project are documented here. Versions follow
[Semantic Versioning](https://semver.org/).

## [0.5.0] - 2026-11-04

### Added
- `agent.policy.toml`: a default `fail_on`, per-rule severity overrides, and **waivers** with a required reason, owner and expiry (capped at 365 days by default). Invalid policies are rejected with every problem listed.
- A trifecta (AA100) waiver lists the exact servers it accepts and covers only a trifecta made of those servers, so adding a server stops the waiver applying.
- Waived findings stay visible: shown as `(waived)` with reason and owner, written to SARIF as native suppressions and to JSON, and never fail `scan`, `diff` or the badge.
- `agentaudit policy check [--strict]` reports expired, soon-to-expire and unused waivers; `scan` prints the same notes.
- `diff --policy base|head|none`: by default the **base** branch's policy applies, so a pull request cannot waive its own risk. Waivers, severity and `fail_on` changes made by the change are listed for reviewers. Action input `diff-policy`.
- `scan` and `diff` take `fail_on` from the policy unless `--fail-on` is given.

## [0.4.0] - 2026-11-04

### Added
- `diff`: compares MCP configs at a git ref (`--base`, optional `--head`, default the working tree) and reports what a change does to capabilities: servers added, removed or changed, capabilities gained or lost, tool description changes, findings introduced or resolved, and trifectas created, widened or resolved. Exits 1 if the change adds a finding at or above `--fail-on` or creates or widens a trifecta. Reads from git without checking anything out or running anything.
- The GitHub Action runs `diff` on pull requests, writes the report to the job summary and keeps a single comment up to date (new inputs `diff` and `comment`).
- Pull request comments are safe against hostile input: server names, tool descriptions and arguments are rendered only inside code spans or blocks, and credential-looking arguments are masked.

## [0.3.0] - 2026-11-04

### Added
- `scan --classify`: an optional local ONNX classifier (20 KB, install `agentaudit[ml]`) that scores tool descriptions for prompt-injection and exfiltration wording. Runs offline. Long descriptions are scored in overlapping windows.
- Advisory findings: heuristic findings are marked `advisory`, shown as such, reported as SARIF `note`, and never fail `scan` or the badge, whatever `--fail-on` says.
- `classify` input for the GitHub Action.
- `training/` scripts to rebuild the datasets, retrain, export to ONNX and evaluate, plus `docs/classifier.md` with measured accuracy.

### Fixed
- Terminal output rendered text from your configs as Rich markup. A server or tool name such as `mcp:notes:time` was shown with an emoji in place of `:notes:` and crashed `scan` on consoles that cannot encode it (for example redirected output on Windows); names containing `[...]` were dropped or raised errors. User-controlled text is now printed literally.

### Notes
- Accuracy is measured on synthetic and small hand-written data. False-positive rate: 0.8% on held-out synthetic data, 11.4% (95% interval 4.5% to 26%) on the hand-written set. A real-world rate has not been measured yet; see `docs/classifier.md`.

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
