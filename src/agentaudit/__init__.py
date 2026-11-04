"""agentaudit: audit combinations of MCP servers and pin what was approved."""

from importlib.metadata import PackageNotFoundError, version

try:
    # One source of truth: the version in pyproject.toml, as recorded when the package is built.
    __version__ = version("agentaudit")
except PackageNotFoundError:  # running from a source tree that was never installed
    __version__ = "0+unknown"
