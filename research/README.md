# Research scan

`scan_public.py` measures how often popular public repos commit risky MCP configurations,
using agentaudit's own rules. It backs the aggregate numbers in launch material.

## Method

1. Search GitHub for non-fork, non-archived repos on agent and MCP topics, sorted by stars.
2. Walk them in star order and keep the first N that commit an MCP config
   (`.mcp.json`, `.cursor/mcp.json` or `.vscode/mcp.json`).
3. Parse and audit each config with agentaudit in a temporary directory, then delete it.
   Nothing is executed; configs are only read as JSON.
4. Record counts only: servers, which rules fired, whether a trifecta was found.

```bash
uv run python research/scan_public.py --out <local-dir> --max-repos 100
```

## Limits to state whenever the numbers are quoted

- The sample is **popular repos that commit an MCP config**, not "all MCP setups". Configs people
  keep private, or in user-level files (for example Claude Desktop's), are not covered.
- A committed config is often a demo or an example, not someone's production setup.
- Rule hits are heuristics from a fixed keyword table; the trifecta count is "worth reviewing",
  not "vulnerable".
- Star-ranked sampling over GitHub topics is biased toward well-known projects.

## Ethics

- `results.jsonl` (per-repo, names included) is written to a local directory and **must not be
  published or committed**. Only `aggregate.json` is meant to be shared.
- Env values are never recorded; findings carry variable names only. If a committed config holds
  what looks like a live secret, tell the owner privately so they can rotate it.
- Do not name a project publicly before it has been told privately and at least 30 days have
  passed. Prefer aggregate statements even after that.
