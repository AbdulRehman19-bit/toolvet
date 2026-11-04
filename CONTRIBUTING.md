# Contributing

Thanks for helping. The fastest way in is a new rule.

## Setup

```bash
git clone https://github.com/AbdulRehman19-bit/agentaudit
cd agentaudit
uv sync
uv run pytest        # 90% coverage is enforced in CI
uv run ruff check .
```

## Write your first rule in 10 minutes

A rule takes one `Server` and yields zero or more `Hit`s. Add it to
[src/agentaudit/rules/builtin.py](src/agentaudit/rules/builtin.py):

```python
@rule("AA011", "Debug flag enabled")
def debug_flag(server: Server) -> Iterator[Hit]:
    if "--debug" in server.args:
        yield Hit(Severity.LOW, "Server runs with --debug", evidence=["--debug"])
```

Then add a test in `tests/test_rules.py`, covering at least one case that should fire and one that should not:

```python
def test_debug_flag():
    assert "AA011" in ids(make(command="x", args=["--debug"]))
    assert "AA011" not in ids(make(command="x", args=["--verbose"]))
```

Guidelines:

- **Deterministic only.** A rule that can fail CI must not guess. Heuristic or ML signals must never fail CI on their own.
- **Never print secret values.** Put the env var or flag *name* in `evidence`, not its value.
- **Pick severity honestly.** `high` means "fix before you ship this config".
- Use the next free `AA###` id and add a row to the table in the README.

### Rules from a separate package

Expose a `Rule` object through the `agentaudit.rules` entry-point group:

```toml
[project.entry-points."agentaudit.rules"]
my_rule = "my_package.rules:my_rule"
```

## Other contributions

- **Client parsers** live in [discovery.py](src/agentaudit/discovery.py). Add a fixture under `tests/fixtures/<client>/` with the parser.
- **Capability keywords** live in [capabilities.py](src/agentaudit/capabilities.py). Say in the PR why the keyword implies the capability.

## Pull requests

Keep PRs small, include tests, and run `uv run ruff format .` first.
