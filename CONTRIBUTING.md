# Contributing

Thanks for helping. The fastest way in is a new rule.

## Setup

```bash
git clone https://github.com/AbdulRehman19-bit/toolvet
cd toolvet
uv sync
uv run pytest        # 90% coverage is enforced in CI
uv run ruff check .
```

## Write your first rule in 10 minutes

A rule takes one `Server` and yields zero or more `Hit`s. Add it to
[src/toolvet/rules/builtin.py](src/toolvet/rules/builtin.py):

```python
@rule("TV011", "Debug flag enabled")
def debug_flag(server: Server) -> Iterator[Hit]:
    if "--debug" in server.args:
        yield Hit(Severity.LOW, "Server runs with --debug", evidence=["--debug"])
```

Then add a test in `tests/test_rules.py`, covering at least one case that should fire and one that should not:

```python
def test_debug_flag():
    assert "TV011" in ids(make(command="x", args=["--debug"]))
    assert "TV011" not in ids(make(command="x", args=["--verbose"]))
```

Guidelines:

- **Deterministic only.** A rule that can fail CI must not guess. Heuristic or ML signals must never fail CI on their own.
- **Never print secret values.** Put the env var or flag *name* in `evidence`, not its value.
- **Pick severity honestly.** `high` means "fix before you ship this config".
- Use the next free `TV###` id and add a row to the table in the README.

### Rules from a separate package

Expose a `Rule` object through the `toolvet.rules` entry-point group:

```toml
[project.entry-points."toolvet.rules"]
my_rule = "my_package.rules:my_rule"
```

## Other contributions

- **Client parsers** live in [discovery.py](src/toolvet/discovery.py). Add a fixture under `tests/fixtures/<client>/` with the parser.
- **Capability keywords** live in [capabilities.py](src/toolvet/capabilities.py). Say in the PR why the keyword implies the capability.

## Where to start

- Issues labelled **good first issue** are scoped to an afternoon: a rule, a batch of server
  keywords, or a config format for another client.
- Missed a server? Use the "Server not recognised" issue form. Adding it is a few lines in
  `capabilities.py`, and it improves every scan.
- Found a security problem? Report it privately, see [SECURITY.md](SECURITY.md).

## Pull requests

Keep PRs small, include tests, and run `uv run ruff format .` first. The pull request template
has the checklist.

Text from scanned files is untrusted. Anything you print or write from it must go through
`toolvet.textsafe.visible` (terminals) or a code span (Markdown), and tests should feed it
hostile input.
