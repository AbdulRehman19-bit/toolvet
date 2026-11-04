"""The same input must give byte-identical output, whatever Python's hash seed is."""

import os
import subprocess
import sys
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
SEEDS = ["0", "1", "2", "5", "7"]

RUN = "import sys; from toolvet.cli import app; sys.argv = ['toolvet', *sys.argv[1:]]; app()"


def run(seed: str, *args: str) -> str:
    env = {**os.environ, "PYTHONHASHSEED": seed, "COLUMNS": "200"}
    result = subprocess.run(
        [sys.executable, "-c", RUN, *args], capture_output=True, text=True, env=env, check=False
    )
    return result.stdout


@pytest.mark.parametrize(
    "args",
    [
        ["scan", str(FIXTURES / "claude_desktop"), "--no-user", "--format", "json"],
        ["scan", str(FIXTURES / "claude_desktop"), "--no-user", "--format", "sarif"],
        ["scan", str(FIXTURES / "vscode"), "--no-user", "--format", "markdown"],
        ["scan", str(FIXTURES / "claude_desktop"), "--no-user"],
        ["graph", str(FIXTURES / "claude_desktop"), "--no-user", "--format", "svg"],
    ],
    ids=["json", "sarif", "markdown", "terminal", "svg"],
)
def test_output_does_not_depend_on_the_hash_seed(args):
    outputs = {seed: run(seed, *args) for seed in SEEDS}
    assert all(outputs.values()), "the command produced no output"
    assert len(set(outputs.values())) == 1, {s: hash(o) for s, o in outputs.items()}


def test_capability_tags_come_out_in_a_fixed_order():
    snippet = (
        "from pathlib import Path; from toolvet.capabilities import tag_server; "
        "from toolvet.models import Server; "
        "s = Server(name='x', client='t', source=Path('a'), command='npx', args=['fetch-mcp']); "
        "print([c.value for c in tag_server(s)])"
    )
    results = set()
    for seed in SEEDS:
        env = {**os.environ, "PYTHONHASHSEED": seed}
        out = subprocess.run(
            [sys.executable, "-c", snippet], capture_output=True, text=True, env=env, check=False
        )
        results.add(out.stdout.strip())
    assert results == {"['untrusted_source', 'sink']"}


def test_diff_report_capability_lists_do_not_depend_on_the_hash_seed():
    snippet = (
        "from pathlib import Path; from toolvet.diff import compute_diff; "
        "from toolvet.diff_render import to_text; from toolvet.models import Server, Severity; "
        "mk = lambda root, args: Server(name='fetcher', client='t', source=Path(root) / 'a.json', "
        "command='npx', args=args); "
        "old, new = mk('b', ['pkg']), mk('h', ['fetch-mcp']); "
        "added = Server(name='bro', client='t', source=Path('h') / 'a.json', command='npx', "
        "args=['playwright-mcp']); "
        "print(to_text(compute_diff([old], [new, added], Path('b'), Path('h')), Severity.HIGH))"
    )
    outputs = set()
    for seed in SEEDS:
        env = {**os.environ, "PYTHONHASHSEED": seed}
        out = subprocess.run(
            [sys.executable, "-c", snippet], capture_output=True, text=True, env=env, check=False
        )
        assert out.returncode == 0, out.stderr
        outputs.add(out.stdout)
    assert len(outputs) == 1
    assert "untrusted_source via 'fetch', sink via 'fetch'" in next(iter(outputs))
