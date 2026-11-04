"""Shared pydantic models. Every stage reads and writes these."""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


class Capability(str, Enum):
    UNTRUSTED_SOURCE = "untrusted_source"
    PRIVATE_DATA = "private_data"
    SINK = "sink"


class Tool(BaseModel):
    name: str
    description: str = ""
    input_schema: dict[str, Any] = Field(default_factory=dict)


class Server(BaseModel):
    name: str
    client: str
    source: Path
    command: str | None = None
    args: list[str] = Field(default_factory=list)
    env: dict[str, str] = Field(default_factory=dict)
    url: str | None = None
    tools: list[Tool] = Field(default_factory=list)

    @property
    def id(self) -> str:
        return f"{self.client}:{self.name}"


class Finding(BaseModel):
    rule_id: str
    severity: Severity
    message: str
    server: str
    tool: str | None = None
    source: Path | None = None
    evidence: list[str] = Field(default_factory=list)
    # Heuristic findings (such as the ML classifier) are shown but never fail CI.
    advisory: bool = False
