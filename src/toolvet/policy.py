"""agent.policy.toml: severity overrides and accountable, expiring waivers.

    fail_on = "high"            # optional default for `scan` and `diff`
    max_waiver_days = 365       # optional cap on how far ahead a waiver may expire

    [severity]
    TV003 = "high"              # raise or lower a rule's severity

    [[waiver]]
    rule = "TV002"
    server = "mcp:mailer"       # exact id or glob; "*" must be written explicitly
    reason = "token is a throwaway for a sandbox account"
    owner = "alice"
    expires = 2027-03-01

A trifecta (TV100) waiver lists the exact servers it accepts, and only covers a trifecta whose
servers are all in that list. Adding a server makes the trifecta wider than what was accepted,
so the waiver stops applying and the finding returns.
"""

from __future__ import annotations

import fnmatch
import tomllib
from dataclasses import dataclass, field
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from toolvet.models import Finding, Severity
from toolvet.rules import load_rules

POLICY_NAME = "agent.policy.toml"
DEFAULT_MAX_WAIVER_DAYS = 365
EXPIRY_WARNING_DAYS = 14
TRIFECTA_RULE = "TV100"
KNOWN_KEYS = {"fail_on", "max_waiver_days", "severity", "waiver"}
WAIVER_KEYS = {"rule", "server", "servers", "tool", "reason", "owner", "expires"}


class PolicyError(ValueError):
    """The policy file is unreadable or invalid. The message lists every problem."""


@dataclass(frozen=True)
class Waiver:
    rule: str
    reason: str
    owner: str
    expires: date
    server: str | None = None
    servers: tuple[str, ...] = ()
    tool: str | None = None

    def label(self) -> str:
        target = ", ".join(self.servers) if self.rule == TRIFECTA_RULE else self.server
        return f"{self.rule} on {target}" + (f" tool {self.tool}" if self.tool else "")


@dataclass(frozen=True)
class Policy:
    fail_on: Severity | None = None
    severity: dict[str, Severity] = field(default_factory=dict)
    waivers: tuple[Waiver, ...] = ()
    max_waiver_days: int = DEFAULT_MAX_WAIVER_DAYS


@dataclass(frozen=True)
class PolicyProblem:
    kind: str  # expired | expiring | unused
    waiver: Waiver
    message: str


def known_rule_ids() -> set[str]:
    return {r.id for r in load_rules(plugins=False)} | {TRIFECTA_RULE, "ML001"}


def _as_date(value: Any) -> date | None:
    if isinstance(value, date):
        return value
    if isinstance(value, str):
        try:
            return date.fromisoformat(value)
        except ValueError:
            return None
    return None


def parse_policy(data: dict[str, Any], today: date | None = None) -> Policy:
    today = today or date.today()
    errors: list[str] = []
    for key in sorted(set(data) - KNOWN_KEYS):
        errors.append(f"unknown key {key!r}")
    rules = known_rule_ids()

    fail_on = None
    if "fail_on" in data:
        try:
            fail_on = Severity(str(data["fail_on"]).lower())
        except ValueError:
            errors.append(
                f"fail_on {data['fail_on']!r} is not one of {[s.value for s in Severity]}"
            )

    max_days = data.get("max_waiver_days", DEFAULT_MAX_WAIVER_DAYS)
    if not isinstance(max_days, int) or isinstance(max_days, bool) or max_days < 1:
        errors.append("max_waiver_days must be a positive whole number")
        max_days = DEFAULT_MAX_WAIVER_DAYS

    severity: dict[str, Severity] = {}
    raw_severity = data.get("severity", {})
    if not isinstance(raw_severity, dict):
        errors.append("[severity] must be a table")
        raw_severity = {}
    for rule_id, level in raw_severity.items():
        if rule_id not in rules:
            errors.append(f"[severity] unknown rule {rule_id!r}")
            continue
        try:
            severity[rule_id] = Severity(str(level).lower())
        except ValueError:
            errors.append(f"[severity] {rule_id}: {level!r} is not a severity")

    waivers: list[Waiver] = []
    raw_waivers = data.get("waiver", [])
    if not isinstance(raw_waivers, list):
        errors.append("waivers must be written as [[waiver]] tables")
        raw_waivers = []
    horizon = today + timedelta(days=max_days)
    for i, raw in enumerate(raw_waivers, start=1):
        where = f"waiver #{i}"
        if not isinstance(raw, dict):
            errors.append(f"{where} must be a table")
            continue
        for key in sorted(set(raw) - WAIVER_KEYS):
            errors.append(f"{where}: unknown key {key!r}")
        problems_before = len(errors)
        rule = raw.get("rule")
        if rule not in rules:
            errors.append(f"{where}: unknown or missing rule {rule!r}")
        for required in ("reason", "owner"):
            value = raw.get(required)
            if not isinstance(value, str) or not value.strip():
                errors.append(f"{where}: {required} is required and must not be empty")
        expires = _as_date(raw.get("expires"))
        if expires is None:
            errors.append(f"{where}: expires is required (a date such as 2027-03-01)")
        elif expires > horizon:
            errors.append(
                f"{where}: expires {expires} is more than {max_days} days away (limit {horizon})"
            )
        server, servers = raw.get("server"), raw.get("servers", [])
        if rule == TRIFECTA_RULE:
            if not (
                isinstance(servers, list) and servers and all(isinstance(s, str) for s in servers)
            ):
                errors.append(f"{where}: a trifecta waiver must list the exact servers it accepts")
            if server is not None:
                errors.append(f"{where}: use servers = [...] for {TRIFECTA_RULE}, not server")
        else:
            if not isinstance(server, str) or not server:
                errors.append(f'{where}: server is required (use "*" to cover every server)')
            if servers:
                errors.append(f"{where}: servers is only for {TRIFECTA_RULE}; use server")
        tool = raw.get("tool")
        if tool is not None and not isinstance(tool, str):
            errors.append(f"{where}: tool must be a string")
        if len(errors) == problems_before:
            waivers.append(
                Waiver(
                    rule=rule,
                    reason=raw["reason"].strip(),
                    owner=raw["owner"].strip(),
                    expires=expires,
                    server=server if rule != TRIFECTA_RULE else None,
                    servers=tuple(servers) if rule == TRIFECTA_RULE else (),
                    tool=tool,
                )
            )
    if errors:
        raise PolicyError("invalid policy:\n" + "\n".join(f"  - {e}" for e in errors))
    return Policy(fail_on, severity, tuple(waivers), max_days)


def load_policy(path: Path, today: date | None = None) -> Policy:
    """Load a policy file. A missing file is an empty policy; a broken one raises PolicyError."""
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return Policy()
    except OSError as exc:
        raise PolicyError(f"cannot read {path}: {exc.strerror}") from exc
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise PolicyError(f"{path.name} is not valid TOML: {exc}") from exc
    try:
        return parse_policy(data, today)
    except PolicyError as exc:
        raise PolicyError(f"{path.name}: {exc}") from exc


def matches(waiver: Waiver, finding: Finding) -> bool:
    """Whether `waiver` covers `finding`, ignoring expiry."""
    if waiver.rule != finding.rule_id:
        return False
    if waiver.rule == TRIFECTA_RULE:
        involved = set(finding.server.split(", "))
        return involved <= set(waiver.servers)
    if waiver.server is None or not fnmatch.fnmatchcase(finding.server, waiver.server):
        return False
    return waiver.tool is None or fnmatch.fnmatchcase(finding.tool or "", waiver.tool)


def apply_policy(
    findings: list[Finding], policy: Policy, today: date | None = None
) -> list[Finding]:
    """Apply severity overrides, then mark findings covered by an unexpired waiver."""
    today = today or date.today()
    active = [w for w in policy.waivers if w.expires >= today]
    result = []
    for finding in findings:
        update: dict[str, Any] = {}
        if finding.rule_id in policy.severity:
            update["severity"] = policy.severity[finding.rule_id]
        candidate = finding.model_copy(update=update) if update else finding
        waiver = next((w for w in active if matches(w, candidate)), None)
        if waiver:
            candidate = candidate.model_copy(
                update={
                    "waiver": {
                        "reason": waiver.reason,
                        "owner": waiver.owner,
                        "expires": waiver.expires.isoformat(),
                    }
                }
            )
        result.append(candidate)
    return result


def policy_problems(
    policy: Policy, findings: list[Finding], today: date | None = None
) -> list[PolicyProblem]:
    """Expired and soon-to-expire waivers, and waivers that cover nothing any more."""
    today = today or date.today()
    soon = today + timedelta(days=EXPIRY_WARNING_DAYS)
    problems = []
    for waiver in policy.waivers:
        if waiver.expires < today:
            problems.append(
                PolicyProblem("expired", waiver, f"{waiver.label()} expired on {waiver.expires}")
            )
        elif waiver.expires <= soon:
            problems.append(
                PolicyProblem("expiring", waiver, f"{waiver.label()} expires on {waiver.expires}")
            )
        if not any(matches(waiver, f) for f in findings):
            problems.append(
                PolicyProblem("unused", waiver, f"{waiver.label()} matches no current finding")
            )
    return problems
