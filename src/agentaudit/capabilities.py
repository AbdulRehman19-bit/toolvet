"""Fixed lookup table that tags servers with capabilities. No inference: every tag names
the keyword that caused it, so any trifecta finding can be explained line by line."""

from __future__ import annotations

import re
from urllib.parse import urlparse

from agentaudit.launch import effective
from agentaudit.models import Capability, Server

S, P, K = Capability.UNTRUSTED_SOURCE, Capability.PRIVATE_DATA, Capability.SINK

# keyword -> capabilities it implies. Keywords match whole tokens of the server's
# name, command, arguments, URL host and tool names ("mcp-server-fetch" -> fetch).
KEYWORDS: dict[str, frozenset[Capability]] = {
    # reads content an attacker can influence
    "fetch": frozenset({S, K}),
    "browser": frozenset({S, K}),
    "puppeteer": frozenset({S, K}),
    "playwright": frozenset({S, K}),
    # ticketing and wiki tools: text written by other people, company data, and the ability
    # to comment or create
    "atlassian": frozenset({S, P, K}),
    "confluence": frozenset({S, P, K}),
    "linear": frozenset({S, P, K}),
    # error tracking: strings that end users control, plus internal data
    "sentry": frozenset({S, P}),
    # public content pulled into the agent's context
    "context7": frozenset({S}),
    "deepwiki": frozenset({S}),
    "huggingface": frozenset({S}),
    "arxiv": frozenset({S}),
    "markitdown": frozenset({S}),
    "webclaw": frozenset({S}),
    # file and terminal access on the user's machine
    "commander": frozenset({P, K}),
    "chrome": frozenset({S, K}),
    "chromium": frozenset({S, K}),
    "devtools": frozenset({S, K}),
    "selenium": frozenset({S, K}),
    "seleniumbase": frozenset({S, K}),
    "webdriver": frozenset({S, K}),
    "firefox": frozenset({S, K}),
    "scrape": frozenset({S}),
    "scraper": frozenset({S}),
    "firecrawl": frozenset({S}),
    "crawl": frozenset({S}),
    "brave": frozenset({S}),
    "tavily": frozenset({S}),
    "search": frozenset({S}),
    "rss": frozenset({S}),
    "reddit": frozenset({S}),
    "twitter": frozenset({S, K}),
    "jira": frozenset({S}),
    "github": frozenset({S, K}),
    "gitlab": frozenset({S, K}),
    "slack": frozenset({S, K}),
    "discord": frozenset({S, K}),
    "telegram": frozenset({S, K}),
    "gmail": frozenset({S, P, K}),
    "imap": frozenset({S, P}),
    "email": frozenset({S, K}),
    # holds private data
    "filesystem": frozenset({P}),
    "files": frozenset({P}),
    "postgres": frozenset({P}),
    "postgresql": frozenset({P}),
    "mysql": frozenset({P}),
    "sqlite": frozenset({P}),
    "mongodb": frozenset({P}),
    "redis": frozenset({P}),
    "supabase": frozenset({P}),
    "neon": frozenset({P}),
    "planetscale": frozenset({P}),
    "turso": frozenset({P}),
    "snowflake": frozenset({P}),
    "bigquery": frozenset({P}),
    "dynamodb": frozenset({P}),
    "clickhouse": frozenset({P}),
    "grafana": frozenset({P}),
    "posthog": frozenset({P}),
    "datadog": frozenset({P}),
    "prometheus": frozenset({P}),
    "greptile": frozenset({P}),
    "vault": frozenset({P}),
    "secrets": frozenset({P}),
    "1password": frozenset({P}),
    "keychain": frozenset({P}),
    "notion": frozenset({P}),
    "gdrive": frozenset({P}),
    "obsidian": frozenset({P}),
    "calendar": frozenset({P}),
    "memory": frozenset({P}),
    # runs arbitrary commands: can read private data and send it out
    "shell": frozenset({P, K}),
    "terminal": frozenset({P, K}),
    "bash": frozenset({P, K}),
    "powershell": frozenset({P, K}),
    "exec": frozenset({P, K}),
    # sends data out
    "http": frozenset({K}),
    "webhook": frozenset({K}),
    "smtp": frozenset({K}),
    "sendgrid": frozenset({K}),
    "twilio": frozenset({K}),
    "s3": frozenset({K}),
    "upload": frozenset({K}),
}


def _tokens(server: Server) -> list[str]:
    server = effective(server)  # `bash -c "npx ..."` is a launcher, not a shell tool
    parts = [server.name, server.command or "", *server.args, *(t.name for t in server.tools)]
    if server.url:
        parts.append(urlparse(server.url).netloc)
    text = " ".join(parts).lower()
    # A URL scheme is not a keyword: `http://localhost` must not tag a server as an HTTP sink.
    text = re.sub(r"\bhttps?://", " ", text)
    return [t for t in re.split(r"[^a-z0-9]+", text) if t]


def tag_server(server: Server) -> dict[Capability, str]:
    """Map each capability the server has to the first keyword that implies it."""
    tags: dict[Capability, str] = {}
    for token in _tokens(server):
        for capability in KEYWORDS.get(token, ()):
            tags.setdefault(capability, token)
    return tags
