# Policy and waivers

`agent.policy.toml` lives in your repo next to `agent.lock`. It does three things: sets a default `fail_on`, changes the severity of rules, and records **waivers**, which are findings you have looked at and accepted.

```toml
fail_on = "high"          # default for `scan` and `diff`
max_waiver_days = 180     # waivers may not expire further ahead than this (default 365)

[severity]
AA003 = "high"            # unpinned packages are not acceptable here

[[waiver]]
rule = "AA002"
server = "mcp:mailer"     # exact id or a glob; write "*" explicitly to cover everything
reason = "token belongs to a throwaway sandbox account"
owner = "alice"
expires = 2027-03-01

[[waiver]]
rule = "AA100"            # lethal trifecta: list exactly the servers you reviewed
servers = ["mcp:fetch", "mcp:filesystem", "mcp:github"]
reason = "agent runs in a container with no real data mounted"
owner = "bob"
expires = 2027-01-15
```

## Why waivers are strict

A waiver system that is easy to abuse becomes a way to switch the tool off. So:

- **Every waiver needs a reason, an owner and an expiry date.** There is no open-ended waiver. Expiry is capped (365 days unless you lower `max_waiver_days`). When one expires, the finding comes back.
- **A waiver must name its target.** For most rules, `server` is required; use `"*"` if you really mean every server. A waiver for one server never covers another.
- **A trifecta waiver lists the exact servers you accepted.** It covers a trifecta made only of those servers. If someone adds a fourth server, the trifecta is wider than what was reviewed, so the waiver stops applying and the finding returns. Without this, accepting one trifecta would silently accept every later widening.
- **Waived findings stay visible.** They do not fail the build, but they still appear in reports with the reason and owner, and in SARIF as native suppressions, so reviewers and code scanning can see them.

## A change cannot waive its own risk

On pull requests, `agentaudit diff` applies the policy from the **base** branch. A PR that adds a risky server and also adds a waiver for it in the same change still fails, and the comment lists the new waiver for reviewers with a note that it is not applied. Once a reviewer approves and merges the waiver, it takes effect for later changes.

In practice this is two small pull requests: one that adds the waiver (the check passes because nothing risky changed), then one that adds the server.

If your team protects `agent.policy.toml` with CODEOWNERS and wants one-step changes, use `--policy head` (or trust the new policy through the Action). `--policy none` ignores waivers entirely.

## Keeping the policy healthy

```bash
agentaudit policy check            # lists waivers; exit 1 if any has expired
agentaudit policy check --strict   # also fail on waivers expiring within 14 days or matching nothing
```

`scan` also prints a note for expired, soon-to-expire and unused waivers. Remove unused waivers: they hide nothing today but would silently cover a future finding.

## Rules for the file itself

An invalid policy is an error (exit code 2) that lists every problem, instead of being ignored: unknown keys, unknown rule ids, missing reasons or owners, bad dates, and trifecta waivers without a server list are all rejected. A typo should never quietly turn a waiver off, or on.
