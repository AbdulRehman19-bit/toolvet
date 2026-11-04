import subprocess
from pathlib import Path

import pytest

from toolvet.diff import compute_diff, launch_line, mask_args
from toolvet.gitbase import GitError, materialize, resolve_ref
from toolvet.models import Server, Severity, Tool


def git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-C", str(repo), *args],
        check=True,
        capture_output=True,
    )


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q", "-b", "main")
    return tmp_path


def commit(repo: Path, files: dict[str, str], message: str = "c") -> None:
    for rel, text in files.items():
        target = repo / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", message)


def srv(root: Path, name: str, **kw) -> Server:
    kw.setdefault("command", "node")
    return Server(name=name, client="mcp", source=root / ".mcp.json", **kw)


def roots(tmp_path: Path) -> tuple[Path, Path]:
    return tmp_path / "base", tmp_path / "head"


def diff(tmp_path, base, head):
    b, h = roots(tmp_path)
    return compute_diff(
        [srv(b, *x[0], **x[1]) for x in base], [srv(h, *x[0], **x[1]) for x in head], b, h
    )


def test_unchanged_setup_is_an_empty_diff(tmp_path):
    same = [(("a",), {"args": ["x"]})]
    assert diff(tmp_path, same, same).is_empty


def test_adding_a_sink_creates_a_new_trifecta(tmp_path):
    base = [(("search",), {}), (("postgres",), {})]
    head = base + [(("smtp",), {})]
    d = diff(tmp_path, base, head)
    assert [(t.kind, t.config) for t in d.trifectas] == [("new", ".mcp.json")]
    assert [s.name for s in d.added] == ["smtp"]
    assert d.introduces_risk(Severity.CRITICAL)


def test_adding_a_server_to_an_existing_trifecta_widens_it(tmp_path):
    base = [(("search",), {}), (("postgres",), {}), (("smtp",), {})]
    d = diff(tmp_path, base, base + [(("slack",), {})])
    (t,) = d.trifectas
    assert t.kind == "widened" and t.added_servers == ["mcp:slack"]
    assert d.introduces_risk(Severity.CRITICAL)


def test_removing_a_server_resolves_the_trifecta(tmp_path):
    base = [(("search",), {}), (("postgres",), {}), (("smtp",), {})]
    d = diff(tmp_path, base, base[:2])
    assert [t.kind for t in d.trifectas] == ["resolved"]
    assert not d.introduces_risk(Severity.LOW)


def test_capability_gain_when_a_package_changes(tmp_path):
    d = diff(
        tmp_path,
        [(("tool",), {"command": "npx", "args": ["pkg@1.0.0"]})],
        [(("tool",), {"command": "npx", "args": ["fetch-pkg@1.0.0"]})],
    )
    (c,) = d.capabilities
    assert set(c.gained) == {"untrusted_source", "sink"} and not c.lost
    assert d.changed[0].details[0].startswith("args:")


def test_capability_loss(tmp_path):
    d = diff(tmp_path, [(("fetch",), {})], [(("tool",), {})])
    assert d.removed and d.added  # renamed: shows as removed + added, not a silent change
    d = diff(tmp_path, [(("tool",), {"args": ["fetch"]})], [(("tool",), {"args": ["x"]})])
    assert set(d.capabilities[0].lost) == {"untrusted_source", "sink"}


def test_env_var_names_not_values(tmp_path):
    d = diff(
        tmp_path, [(("a",), {"env": {"OLD": "1"}})], [(("a",), {"env": {"NEW_TOKEN": "s3cret"}})]
    )
    text = " ".join(d.changed[0].details)
    assert "NEW_TOKEN" in text and "OLD" in text and "s3cret" not in text


def test_credentials_in_args_are_masked(tmp_path):
    d = diff(
        tmp_path,
        [(("a",), {"args": ["--token", "oldsecret", "postgresql://u:pw1@h/db"]})],
        [(("a",), {"args": ["--token=newsecret", "postgresql://u:pw2@h/db", "--password", "p"]})],
    )
    text = " ".join(d.changed[0].details)
    for leaked in ("oldsecret", "newsecret", "pw1", "pw2", " p "):
        assert leaked not in text
    assert "***" in text


def test_mask_args_and_launch_line():
    assert mask_args(["--api-key", "k", "--v", "x"]) == ["--api-key", "***", "--v", "x"]
    assert mask_args(["--token"]) == ["--token"]
    s = Server(name="r", client="c", source=Path("a"), url="https://u:p@host/mcp?token=abc")
    assert launch_line(s) == "host/mcp"


def test_tool_changes(tmp_path):
    base = [
        (
            ("a",),
            {
                "tools": [
                    Tool(name="keep", description="x"),
                    Tool(name="gone", description="g"),
                    Tool(name="edit", description="before"),
                ]
            },
        )
    ]
    head = [
        (
            ("a",),
            {
                "tools": [
                    Tool(name="keep", description="x"),
                    Tool(name="new", description="n"),
                    Tool(name="edit", description="after"),
                ]
            },
        )
    ]
    d = diff(tmp_path, base, head)
    assert {(t.tool, t.kind) for t in d.tools} == {
        ("gone", "removed"),
        ("new", "added"),
        ("edit", "changed"),
    }
    edit = next(t for t in d.tools if t.tool == "edit")
    assert (edit.before, edit.after) == ("before", "after")


def test_new_and_resolved_findings(tmp_path):
    d = diff(
        tmp_path,
        [(("a",), {"command": "npx", "args": ["pkg@1.0.0"]})],
        [(("a",), {"command": "npx", "args": ["-y", "pkg"]})],
    )
    assert [f.rule_id for f in d.new_findings] == ["TV003"]
    assert d.introduces_risk(Severity.MEDIUM) and not d.introduces_risk(Severity.HIGH)
    back = diff(
        tmp_path,
        [(("a",), {"command": "npx", "args": ["-y", "pkg"]})],
        [(("a",), {"command": "npx", "args": ["pkg@1.0.0"]})],
    )
    assert [f.rule_id for f in back.resolved_findings] == ["TV003"]
    assert not back.introduces_risk(Severity.LOW)


def test_advisory_findings_do_not_count_as_risk(tmp_path):
    d = diff(tmp_path, [(("a",), {})], [(("a",), {})])
    from toolvet.models import Finding

    d.new_findings.append(
        Finding(rule_id="ML001", severity=Severity.CRITICAL, message="m", server="s", advisory=True)
    )
    assert not d.introduces_risk(Severity.LOW)


def test_materialize_reads_files_as_they_were_at_a_ref(repo, tmp_path):
    commit(repo, {".mcp.json": '{"mcpServers": {"old": {"command": "x"}}}'}, "base")
    git(repo, "tag", "base")
    commit(
        repo,
        {
            ".mcp.json": '{"mcpServers": {"new": {"command": "y"}}}',
            ".vscode/mcp.json": '{"servers": {}}',
        },
        "head",
    )
    dest = tmp_path / "out"
    assert materialize(repo, "base", dest) == [".mcp.json"]
    assert "old" in (dest / ".mcp.json").read_text(encoding="utf-8")
    dest2 = tmp_path / "out2"
    assert set(materialize(repo, "HEAD", dest2)) == {".mcp.json", ".vscode/mcp.json"}


def test_materialize_works_from_a_subdirectory(repo, tmp_path):
    commit(repo, {"app/.mcp.json": '{"mcpServers": {}}', "other.txt": "x"})
    dest = tmp_path / "out"
    assert materialize(repo / "app", "HEAD", dest) == [".mcp.json"]


@pytest.mark.parametrize("ref", ["", "-x", "--output=/tmp/x", "--upload-pack=evil"])
def test_option_like_refs_are_rejected(repo, ref):
    commit(repo, {"a.txt": "x"})
    with pytest.raises(GitError, match="invalid git ref"):
        resolve_ref(repo, ref)


def test_unknown_ref_and_non_repo(repo, tmp_path_factory):
    commit(repo, {"a.txt": "x"})
    with pytest.raises(GitError, match="unknown git ref"):
        resolve_ref(repo, "no-such-branch")
    with pytest.raises(GitError, match="not inside a git repository"):
        resolve_ref(tmp_path_factory.mktemp("plain"), "HEAD")


def test_missing_git_binary(repo, monkeypatch):
    monkeypatch.setenv("PATH", "")
    with pytest.raises(GitError, match="git is not installed"):
        resolve_ref(repo, "HEAD")
