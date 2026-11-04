## What this changes

<!-- One or two sentences. -->

## Checklist

- [ ] Tests added or updated (`uv run pytest`, coverage stays at or above 90%)
- [ ] `uv run ruff check .` and `uv run ruff format .` pass
- [ ] New rule? It has a test that fires and one that does not, and a row in the README table
      and in `docs/rules.md`
- [ ] New capability keyword? The PR explains why the keyword implies the capability
- [ ] User-visible change? `CHANGELOG.md` has an entry under "Unreleased"
- [ ] Nothing from a scanned file is printed or written without going through the existing
      helpers (`toolvet.textsafe.visible` for terminals, code spans for Markdown)
