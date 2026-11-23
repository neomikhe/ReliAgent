# Network audit — Ollama 0.31.2

| | |
|---|---|
| Ollama | 0.31.2, Windows x86-64, `ollama serve` (server only, desktop app not running) |
| Model | `qwen2.5:7b-instruct-q4_K_M` (the pinned model, see `MODEL_SHA256.txt`) |
| Date | 2026-11-23 |
| Method | [`README.md`](README.md): denying logging proxy + TCP connection watcher, scenarios A–D, plus a read of the relevant Ollama source at tag `v0.31.2` |

## Result

**With default settings, `ollama serve` 0.31.2 contacts `ollama.com` on its
own, without any request from ReliAgent: twice at start-up, then again
every few hours for as long as it runs. With `OLLAMA_NO_CLOUD=1` it made
no outbound connection in any scenario, and ReliAgent works unchanged.**

Inference itself (what `reli run` asks for) caused no outbound traffic in
either configuration.

## What was observed

| Scenario | Outbound requests (all denied by the proxy) | TCP to a non-loopback address |
|---|---|---|
| A. Start, then 15 min idle | `GET https://ollama.com/api/experimental/model-recommendations` and `GET https://ollama.com/api/tags?ts=…` at start-up; the first one again 4 min later | none |
| B. `reli run` with the pinned model (version check, `/api/show`, SHA-256 of the 4.7 GB blob, agent + LLM critic) | none | none |
| C. Control: `ollama pull` of a tag that does not exist | `GET https://registry.ollama.ai/v2/library/…/manifests/…` — captured, so the method works | none |
| D. Start with `OLLAMA_NO_CLOUD=1`, then `reli run`, then idle | none | none |

The full URLs come from Ollama's own log, which names each request the
proxy refused. The TCP watcher took 4,288 samples over the 21 minutes of
scenarios A–D and saw no connection that bypassed the proxy.

## What the two requests are (source, tag `v0.31.2`)

- **Model recommendations** (`server/model_recommendations.go`):
  `GET https://ollama.com/api/experimental/model-recommendations` with an
  `Accept` header and no body, to refresh a list of suggested (mostly
  cloud) models. It runs at start-up and then every 4 hours with jitter;
  after a failure it retries sooner (observed: a retry after 4 min, the
  next one scheduled 15 min later). When
  `OLLAMA_NO_CLOUD` is set, `refresh()` returns before building any
  request: the timer keeps firing, but nothing is sent.
- **Cloud model catalogue** (`server/model_show_cache.go`,
  `hydrateCloud`): `GET https://ollama.com/api/tags` with Ollama's client
  version in a header, to cache the cloud models' metadata. It is skipped
  entirely when `OLLAMA_NO_CLOUD` is set.

Neither request carries prompts, model output, file names or anything
from ReliAgent. What ollama.com does learn from them: that an Ollama
server is running at your IP address, when, and its version.

## Recommendation

- Start Ollama with **`OLLAMA_NO_CLOUD=1`** (for the desktop app, set it
  as a user environment variable and restart the app). ReliAgent only
  uses the local model; it needs none of Ollama's cloud features.
- For a stronger control than a setting, block outbound traffic
  for the Ollama executables in your firewall, and unblock it only while
  you run `ollama pull`.
- `ollama pull` contacts `registry.ollama.ai` by design; it is the only
  network access ReliAgent's setup needs, and you run it yourself.

## Not covered

- The desktop app (tray icon, auto-update) is a separate program and was
  not audited; run `ollama serve` directly, or disable its update checks.
- Linux and macOS builds were not observed; the source paths above are
  the same on every platform.
- Behaviour on code paths these scenarios did not reach (cloud models,
  web search, `ollama signin`), which ReliAgent never uses.
