# Security policy

toolvet reads files that other people write (MCP configs, tool descriptions, policy files) and
prints reports from them, so reports about it are taken seriously.

## Reporting a vulnerability

Please report it privately, not in a public issue:
https://github.com/AbdulRehman19-bit/toolvet/security/advisories/new

Include the toolvet version (`toolvet --version`), what you did, what you expected and what
happened. A minimal config that reproduces it helps a lot. Remove any real secrets from it first.

This is a small project maintained by one person, so I cannot promise a response time. I will
acknowledge a report, and fix confirmed issues in the next release.

## What counts as a vulnerability

- **Code execution where there should be none.** Only `toolvet snapshot --introspect` launches
  anything, and it lists the commands and asks first. Anything that makes another command run
  code from a config is a vulnerability.
- **Output that escapes its formatting.** Text from a scanned file (server names, arguments,
  URLs, tool descriptions, policy text) breaking out of a report: terminal control sequences,
  or links, HTML or `@mentions` getting into a pull request comment or other Markdown.
- **Secret leakage.** A secret value from a config appearing in a report, comment, lockfile
  or log. Variable names are shown on purpose; values never should be.
- **`toolvet diff` reading outside the repository,** or passing an option to git instead of a
  ref.
- **A policy bypass.** A pull request being able to waive its own risk, or a waiver applying to
  something it does not name.
- **Supply chain.** The PyPI package or the GitHub Action not matching the tagged source.

## What does not

- **A risky server toolvet does not recognise.** Detection uses a fixed keyword table and
  misses many servers by design. Please open a normal issue (there is an issue form for it).
- **A heuristic false positive or false negative** in a rule. Also a normal issue.

## Supported versions

toolvet is pre-1.0. Only the latest release receives fixes.
