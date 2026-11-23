# Ollama network audits

ReliAgent never talks to the network itself (see
[`docs/THREAT_MODEL.md`](../docs/THREAT_MODEL.md)), but it runs inference
through [Ollama](https://ollama.com), whose own behaviour is outside our
control. Each Ollama version ReliAgent targets gets one audit here:
`ollama_v<version>.md` records what that version connects to, observed
on a real machine, and how to turn it off.

The sidecar warns at every `reli run` when the Ollama it talks to is not
in `AUDITED_OLLAMA_VERSIONS` (`python-core/src/reliagent_python/main.py`).
It does not refuse to run: an unaudited version works, it just has not
been checked.

## Method

Two independent observers, while Ollama runs as `ollama serve` (the server
only, not the desktop app):

1. **A logging proxy that denies everything.** `ollama serve` is started
   with `HTTPS_PROXY` and `HTTP_PROXY` (the variables Go's HTTP client
   reads) pointing to [`tools/audit_proxy.py`](tools/audit_proxy.py),
   which writes down every request it receives (`CONNECT host:port` for
   HTTPS, escaped so the audited program cannot forge log lines) and
   answers `403`, so nothing leaves the machine. Ollama's server log then
   also names the full URL of each refused request.
2. **A connection watcher** that polls the TCP connections of every
   `ollama*` process (every ~0.3 s in practice) and records any remote
   address that is not loopback — this would catch traffic that ignores
   the proxy
   ([`tools/watch_connections.ps1`](tools/watch_connections.ps1) on
   Windows; on Linux or macOS, a loop over `ss -tnp` or
   `lsof -i -a -c ollama` does the same).

Scenarios, in this order:

- **A. Start and idle**: `ollama serve` with nothing else running.
- **B. A real `reli run`**: version check, model verification (`/api/show`
  plus the SHA-256 of the 4.7 GB blob) and two inferences with the pinned
  model.
- **C. Positive control**: `ollama pull` of a tag that does not exist. It
  must show up in the proxy log; if it does not, the method is broken and
  the audit is void.
- **D. The same start with the mitigation applied** (for example
  `OLLAMA_NO_CLOUD=1`), to check that it really removes what A found.

Logs stay on the auditor's machine (they contain local paths); the
`ollama_v<version>.md` file reports hosts, URLs and conclusions only.

## Limits

- Polling can miss a connection that opens and closes between two samples;
  the proxy cannot miss an HTTP request made through Go's default
  transport, but would miss raw sockets. Using both narrows the gap.
- DNS queries go through the operating system's resolver and are not
  attributed to Ollama.
- Only the behaviour observed in these scenarios is covered. The desktop
  app (tray icon, auto-update) is a separate program and is not audited.
