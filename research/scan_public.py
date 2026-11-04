"""Scan MCP configs committed to the most-starred public repos, and report aggregates only.

Method: search GitHub for repos on agent/MCP topics, sort by stars, and keep the first N that
commit an MCP config (.mcp.json, .cursor/mcp.json, .vscode/mcp.json). Each config is parsed
and audited with toolvet itself, entirely offline once downloaded. Nothing is executed.

Ethics (see research/README.md):
- Per-repo results are written to a LOCAL file you choose and must not be published.
- Only the aggregate summary is meant to be shared.
- Config files are parsed in a temporary directory and deleted. Env values are never
  recorded; findings carry variable NAMES only.
- Do not name a project publicly before it has been privately notified and 30 days passed.

Run:  uv run python research/scan_public.py --out <dir> [--max-repos 100]
Optional: set GITHUB_TOKEN for higher API limits.
"""

from __future__ import annotations

import argparse
import json
import os
import tempfile
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

from toolvet.audit import audit
from toolvet.discovery import discover

TOPICS = [
    "mcp-server",
    "mcp",
    "model-context-protocol",
    "mcp-client",
    "claude-code",
    "cursor",
    "ai-agents",
    "ai-agent",
    # added to widen the pool when the first 8 topics yielded only 83 repos with a config
    "mcp-servers",
    "modelcontextprotocol",
    "claude",
    "claude-desktop",
    "cursor-ai",
    "llm-agents",
    "agentic-ai",
    "ai-tools",
]
CONFIG_PATHS = [".mcp.json", ".cursor/mcp.json", ".vscode/mcp.json"]
MAX_BYTES = 200_000
USER_AGENT = "toolvet-research (+https://github.com/AbdulRehman19-bit/toolvet)"


def fetch(url: str, retries: int = 3, limit: int = MAX_BYTES + 1) -> tuple[int, bytes]:
    headers = {"User-Agent": USER_AGENT, "Accept": "application/vnd.github+json"}
    if token := os.environ.get("GITHUB_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(
                urllib.request.Request(url, headers=headers), timeout=30
            ) as r:
                return r.status, r.read(limit)
        except urllib.error.HTTPError as exc:
            if exc.code in (403, 429) and "api.github.com" in url:
                print(f"  rate limited; sleeping 65s (attempt {attempt + 1})", flush=True)
                time.sleep(65)
                continue
            return exc.code, b""
        except (urllib.error.URLError, TimeoutError):
            time.sleep(2)
    return 0, b""


def candidates(pages: int) -> list[dict]:
    seen: dict[str, dict] = {}
    for topic in TOPICS:
        for page in range(1, pages + 1):
            url = (
                "https://api.github.com/search/repositories?q=topic:"
                + topic
                + "&sort=stars&order=desc&per_page=100&page="
                + str(page)
            )
            status, body = fetch(url, limit=8_000_000)
            if status != 200:
                print(f"  search {topic} p{page}: HTTP {status}", flush=True)
                continue
            for item in json.loads(body).get("items", []):
                if not item["fork"] and not item["archived"]:
                    seen[item["full_name"]] = {
                        "repo": item["full_name"],
                        "stars": item["stargazers_count"],
                        "branch": item["default_branch"],
                    }
            time.sleep(7)  # unauthenticated search limit: 10 requests per minute
    return sorted(seen.values(), key=lambda r: -r["stars"])


def analyse(entry: dict) -> dict | None:
    """Download the repo's MCP configs, audit them, and return counts only."""
    with tempfile.TemporaryDirectory() as tmp:
        root, found = Path(tmp), []
        for rel in CONFIG_PATHS:
            url = f"https://raw.githubusercontent.com/{entry['repo']}/{entry['branch']}/{rel}"
            status, body = fetch(url)
            if status == 200 and len(body) <= MAX_BYTES:
                try:
                    json.loads(body)
                except ValueError:
                    continue
                target = root / rel
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes(body)
                found.append(rel)
            time.sleep(0.15)
        if not found:
            return None
        servers = discover(root, home=None)
        if not servers:
            return None
        findings = audit(servers)
        per_server = Counter()
        for f in findings:
            if f.rule_id != "TV100":
                per_server[(f"{f.rule_id}:{f.severity.value}", f.server)] += 1
        trifecta = [f for f in findings if f.rule_id == "TV100"]
        return {
            "repo": entry["repo"],
            "stars": entry["stars"],
            "configs": found,
            "servers": len(servers),
            "stdio": sum(1 for s in servers if s.command),
            "remote": sum(1 for s in servers if s.url),
            "servers_with_rule": dict(Counter(rule for rule, _ in per_server)),
            "high_or_critical": sum(1 for f in findings if f.severity.rank >= 3),
            "trifecta": bool(trifecta),
            "trifecta_single_server": any("inside one server" in f.message for f in trifecta),
        }


def summarise(rows: list[dict]) -> dict:
    n = len(rows)
    servers = sum(r["servers"] for r in rows)
    rule_servers: Counter = Counter()
    rule_repos: Counter = Counter()
    for r in rows:
        for rule, count in r["servers_with_rule"].items():
            rule_servers[rule] += count
            rule_repos[rule] += 1
    return {
        "repos_with_mcp_config": n,
        "servers_total": servers,
        "repos_with_trifecta": sum(r["trifecta"] for r in rows),
        "repos_with_trifecta_only_within_one_server": sum(
            r["trifecta_single_server"] for r in rows
        ),
        "repos_with_any_high_or_critical": sum(r["high_or_critical"] > 0 for r in rows),
        "repos_with_rule": dict(sorted(rule_repos.items())),
        "servers_with_rule": dict(sorted(rule_servers.items())),
        "median_stars": sorted(r["stars"] for r in rows)[n // 2] if n else 0,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--max-repos", type=int, default=100)
    parser.add_argument("--max-checked", type=int, default=600)
    parser.add_argument("--pages", type=int, default=3)
    parser.add_argument(
        "--reanalyse",
        type=Path,
        help="results.jsonl from an earlier run: re-fetch those repos and apply the current rules",
    )
    args = parser.parse_args()
    args.out.mkdir(parents=True, exist_ok=True)
    results = args.out / "results.jsonl"
    done = {}
    if results.exists():
        for line in results.read_text(encoding="utf-8").splitlines():
            row = json.loads(line)
            done[row["repo"]] = row
    print(f"resuming with {len(done)} repos already analysed", flush=True)

    if args.reanalyse:
        # Recompute with the current rules for repos found earlier; no GitHub search needed.
        earlier = [json.loads(line) for line in args.reanalyse.read_text("utf-8").splitlines()]
        pool = [{"repo": r["repo"], "stars": r["stars"], "branch": "HEAD"} for r in earlier]
        args.max_repos = args.max_checked = len(pool) + 1
    else:
        pool = candidates(args.pages)
    print(f"{len(pool)} candidate repos", flush=True)
    checked = 0
    for entry in pool:
        if len(done) >= args.max_repos or checked >= args.max_checked:
            break
        checked += 1
        if entry["repo"] in done:
            continue
        row = analyse(entry)
        if row:
            done[row["repo"]] = row
            with results.open("a", encoding="utf-8") as f:
                f.write(json.dumps(row) + "\n")
            print(f"  [{len(done)}/{args.max_repos}] checked {checked}: found config", flush=True)
        elif checked % 25 == 0:
            print(f"  checked {checked} repos, {len(done)} with configs", flush=True)
    summary = summarise(list(done.values()))
    summary["candidates_checked"] = checked
    (args.out / "aggregate.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
