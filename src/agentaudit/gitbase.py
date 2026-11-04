"""Read MCP config files as they were at a git ref, without checking anything out."""

from __future__ import annotations

import subprocess
from pathlib import Path

from agentaudit.discovery import _PROJECT_CONFIGS
from agentaudit.policy import POLICY_NAME
from agentaudit.snapshot import SNAPSHOT_NAME

CONFIG_FILES = [rel for rel, _ in _PROJECT_CONFIGS.values()] + [
    "claude_desktop_config.json",
    SNAPSHOT_NAME,
    POLICY_NAME,
]
TIMEOUT = 30


class GitError(Exception):
    """git is missing, the path is not a repository, or a ref does not exist."""


def _git(repo: Path, *args: str) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(
            ["git", "-C", str(repo), *args],
            capture_output=True,
            timeout=TIMEOUT,
            check=False,
        )
    except FileNotFoundError as exc:
        raise GitError("git is not installed or not on PATH") from exc
    except subprocess.TimeoutExpired as exc:
        raise GitError("git timed out") from exc


def resolve_ref(repo: Path, ref: str) -> str:
    """Return the commit id for `ref`. Rejects option-like refs so they cannot reach git."""
    if not ref or ref.startswith("-"):
        raise GitError(f"invalid git ref: {ref!r}")
    result = _git(repo, "rev-parse", "--verify", "--quiet", "--end-of-options", f"{ref}^{{commit}}")
    if result.returncode != 0:
        probe = _git(repo, "rev-parse", "--is-inside-work-tree")
        if probe.returncode != 0:
            raise GitError(f"{repo} is not inside a git repository")
        raise GitError(f"unknown git ref: {ref!r} (in CI, fetch it first: fetch-depth: 0)")
    return result.stdout.decode().strip()


def materialize(repo: Path, ref: str, dest: Path) -> list[str]:
    """Write the config files that exist at `ref` into `dest`; return their relative paths."""
    commit = resolve_ref(repo, ref)
    written = []
    for rel in CONFIG_FILES:
        result = _git(repo, "show", f"{commit}:./{rel}")
        if result.returncode != 0:
            continue  # the file does not exist at that ref
        target = dest / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(result.stdout)
        written.append(rel)
    return written
