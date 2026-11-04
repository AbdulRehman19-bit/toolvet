# Rules reference

| Rule | Severity | Title |
|---|---|---|
| [TV001](#aa001-shell-access) | high | Shell access |
| [TV002](#aa002-secrets-in-env-vars) | high | Secrets in env vars |
| [TV003](#aa003-unpinned-package) | medium | Unpinned package |
| [TV004](#aa004-wildcard-or-root-path) | high | Wildcard or root path |
| [TV005](#aa005-plain-http-remote-server) | medium | Plain HTTP remote server |
| [TV006](#aa006-suspicious-tool-description) | high | Suspicious tool description |
| [TV007](#aa007-credentials-in-server-url) | high | Credentials in server URL |
| [TV008](#aa008-credentials-in-arguments) | high | Credentials in arguments |
| [TV009](#aa009-download-and-execute) | high | Download and execute |
| [TV010](#aa010-risky-container-options) | high / medium | Risky container options |
| [TV100](#aa100-lethal-trifecta) | critical | Lethal trifecta |

## TV001 Shell access
The server is launched through `sh`, `bash`, `cmd`, `powershell` and similar, or its name or package contains "shell" or "terminal". A shell tool can run anything the agent is talked into running. **Fix:** use a purpose-built server, or restrict the allowed commands.

## TV002 Secrets in env vars
An `env` entry whose name contains KEY, TOKEN, SECRET, PASSWORD or CREDENTIAL holds a literal value. Config files get committed and synced. **Fix:** reference the variable (`${env:NAME}` or your client's equivalent). The report shows the variable name, never the value.

## TV003 Unpinned package
`npx -y`, `uvx`, `bunx`, `pipx run`, `pnpm dlx` and similar fetch the latest version on each launch, so an upstream change reaches you without review (medium). **Fix:** pin a version: `pkg@1.2.3` or `pkg==1.2.3`. `@latest` counts as unpinned.

Two cases are deliberately *not* reported as unpinned fetches. `uv run`, `npm run`, `pnpm run` and similar run your own project's code, so they are not checked. `npx tool` with no version and no `-y` cannot download in a non-interactive launch, so it only works if `tool` is already installed locally (where your lockfile pins it); that is reported as a low-severity note instead.

## TV004 Wildcard or root path
An argument such as `/`, `~`, `C:\`, `/home` or `/home/*` gives the server access to far more than it needs. **Fix:** point it at one project directory.

## TV005 Plain HTTP remote server
A remote server URL starts with `http://` (not localhost). Traffic, including tool results, is readable and modifiable in transit. **Fix:** use `https://`.

## TV006 Suspicious tool description
A tool description contains instruction-like text such as "ignore previous instructions", `<IMPORTANT>`, "do not tell the user", or references to `~/.ssh`. This is tool poisoning. It needs tool definitions, so run `toolvet snapshot --introspect` first. **Fix:** do not use the server until the description is explained.

## TV007 Credentials in server URL
A remote URL embeds `user:password@` or a `token=`, `key=` or `password=` query parameter. URLs end up in logs. **Fix:** use a header or an environment reference.

## TV008 Credentials in arguments
A launch argument contains a credentialed URL (`postgresql://user:pass@host/db`) or passes a literal value to `--token`, `--password` or `--api-key`. Command lines are visible in process lists. **Fix:** pass secrets through the environment.

## TV009 Download and execute
The launch command pipes a download into a shell (`curl ... | sh`), uses `iex` or `Invoke-Expression`, or is `curl`/`wget` itself. The code that runs is whatever the remote host serves at launch time. **Fix:** install a pinned release and run that.

## TV010 Risky container options
A `docker` or `podman` server runs `--privileged`, mounts the host root or the Docker socket (both high), or shares the host network (medium). **Fix:** drop the option, or mount a single data directory.

## TV100 Lethal trifecta
Within one config file, a path exists from an untrusted source, through a private-data reader, to a sink. Tags come from a fixed keyword table and each finding lists the keyword behind every hop. This is a heuristic: treat it as "review this combination", and split the servers across separate agent configs if the combination is not needed.
