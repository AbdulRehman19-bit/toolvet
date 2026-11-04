# Changelog

All notable changes to this project are documented here. Versions follow
[Semantic Versioning](https://semver.org/).

## [0.7.0] - 2026-11-04

### Changed (breaking)
- **Renamed from `agentaudit` to `toolvet`.** PyPI rejected `agentaudit` as too similar to the existing, active project `agent-audit`, and the two names would have been confused. The command is now `toolvet`, the Python package `toolvet`, the plugin entry-point group `toolvet.rules`, and the GitHub Action `AbdulRehman19-bit/toolvet`. Earlier entries below keep the old name as history.
- **Rule ids moved from `AA###` to `TV###`** (`AA001` is now `TV001`, `AA100` is now `TV100`, and so on). Update severity overrides and waivers in `agent.policy.toml` accordingly.
- The pull request comment marker is now `<!-- toolvet-diff -->`; an old comment is not updated, a new one is created.
- `agent.lock`, `agent.tools.json` and `agent.policy.toml` keep their names.

## [0.6.3] - 2026-11-04

### Changed
- Packaging for PyPI: SPDX licence expression, authors, keywords, classifiers and project URLs; README links and images are absolute so they render on PyPI; install instructions describe `pipx run agentaudit`.
- Added a publish workflow (`publish.yml`) that uploads to PyPI with Trusted Publishing when a version tag is pushed, after checking the tag matches the package version and the tests pass.

## [0.6.2] - 2026-11-04

### Fixed
Found by hand-checking verdicts on real public configs:
- Launch wrappers (`cmd /c npx ...`, `bash -l -c "exec npx ..."`) are now seen through. Previously the wrapper shell was reported as high-severity shell access (AA001), its `bash` keyword tagged every wrapped server as private data plus a sink (which produced a false trifecta), and an unpinned package behind the wrapper was missed. A shell counts as a launcher only when its payload is one simple command; pipes, `;`, `&&`, redirects and substitutions are still treated as real shell use.
- A URL scheme is no longer a keyword: `http://localhost:3001` in an argument no longer tags a server as an HTTP sink.

### Added
- More widely used servers are recognised: ticketing and wiki tools (`atlassian`, `confluence`, `linear`: untrusted source and private data), `sentry`, documentation and content sources (`context7`, `deepwiki`, `huggingface`, `arxiv`, `markitdown`, `webclaw`), file and terminal access (`desktop-commander`), and database and observability servers (`neon`, `planetscale`, `turso`, `snowflake`, `bigquery`, `dynamodb`, `clickhouse`, `grafana`, `posthog`, `datadog`, `prometheus`, `greptile`).

### Notes
- On a test of 137 servers from 83 popular public repos, the table recognised 36% of servers, so a clean scan means "nothing recognised", not "safe". The README now says so.

## [0.6.1] - 2026-11-04

### Fixed
Found by hand-checking agentaudit's verdicts against real public configs:
- AA002 no longer flags obvious placeholders such as `ANTHROPIC_API_KEY_HERE`, `YOUR_OPENAI_API_KEY`, `your-api-key`, `xxxx`, `<token>` or `changeme` as literal secrets. This was a common false positive in example configs.
- AA003 no longer flags commands that run local project code (`uv run`, `npm run`, `pnpm run`, `yarn run`, `bun run`). Only subcommands that fetch a package are checked (`pnpm dlx`, `npm exec`, `bun x`, `pipx run`, `uv tool run`), and flag values such as `uvx --python 3.12 pkg` are no longer mistaken for the package name.
- `npx tool` with no version and no `-y` is now a low-severity note about local copies instead of a medium unpinned-package finding.
- Browser-automation servers (`chrome-devtools`, `selenium`, `seleniumbase`, `webdriver`, `firefox`, `chrome`, `chromium`) are now tagged as untrusted sources and sinks.

## [0.6.0] - 2026-11-04

### Added
- Smallest-fix suggestions on every lethal-trifecta finding. Within one config a trifecta exists exactly when all three layers are present, so the cheapest fix is the layer the fewest servers supply; removing or moving those servers breaks every path. The result is exact (tested against exhaustive search) and says when moving does not help, for a server that can do all three on its own.
- Pull request comments (`diff`) list the fixes, led by the fewest servers the change adds whose removal makes a new trifecta disappear. Server names are rendered inside code spans.
- Fixes appear in terminal output, JSON (`fix`), SARIF (`properties.suggestions`) and Markdown reports. Accepted (waived) trifectas get no fix suggestions.

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
