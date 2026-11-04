# Using agentaudit in CI

## GitHub Action

```yaml
- uses: actions/checkout@v4
- uses: AbdulRehman19-bit/agentaudit@v0.2.0
  with:
    fail-on: high
    upload-sarif: "true"
```

| Input | Default | Meaning |
|---|---|---|
| `path` | `.` | Directory to scan |
| `fail-on` | `high` | Fail at or above this severity |
| `verify` | `true` | Run `agentaudit verify` when `agent.lock` exists |
| `sarif-file` | `agentaudit.sarif` | Where the SARIF report is written |
| `upload-sarif` | `false` | Upload to code scanning (needs `security-events: write`) |

The SARIF report is always written and uploaded even when the scan fails, so findings show up in the Security tab.

## Pin what you approved

```bash
agentaudit snapshot --introspect   # launches your servers, with confirmation
agentaudit lock
git add agent.lock agent.tools.json
```

From then on, `agentaudit verify` (run by the Action) fails when a server's command, arguments, environment variable names or URL change, or when any tool is added, removed, or has a different name, description or schema. Review the change in the pull request, and re-run `agentaudit lock` to approve it.

Environment variable values are never written to `agent.lock`.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Clean, or nothing at or above `--fail-on` |
| 1 | Findings at or above `--fail-on`, or drift found by `verify` |
| 2 | `verify` could not read `agent.lock`, or `snapshot` ran without `--introspect` |
