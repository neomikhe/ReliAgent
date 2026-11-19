"""JSON-RPC 2.0 server over stdin/stdout (NDJSON framing).

The Rust kernel spawns this module as a child process via
`std::process::Command` and communicates over pipes. One JSON object per
line, `\n`-terminated — no Content-Length headers, no batching.

stdout is reserved exclusively for JSON-RPC traffic. All diagnostics go to
stderr so they do not corrupt the wire protocol.

## Methods

- `ping() -> {"pong": true}`
- `agent.run(prompt: str, backend: "ollama" | "mock") -> AgentRunResult`

  `backend` is mandatory. `"ollama"` verifies the local daemon and the pinned
  model (see `model_integrity`) before any inference, and runs the LLM critic
  as a second layer. `"mock"` uses the deterministic pattern-matching agent
  (tests and offline demos).

## Error codes

Standard JSON-RPC 2.0 codes are used:

- `-32700` parse error (not valid JSON)
- `-32600` invalid request (shape is wrong)
- `-32601` method not found
- `-32602` invalid params
- `-32603` internal error (handler raised)

Application codes (`error.data.kind` repeats them as a string):

- `-32010` `ollama_unreachable` — nothing listening on 127.0.0.1:11434
- `-32011` `model_missing` — Ollama lacks the pinned tag (`data.model`)
- `-32012` `model_integrity` — Ollama's blob is not the pinned weights
- `-32013` `llm_error` — Ollama failed during generation
"""

from __future__ import annotations

import json
import os
import sys
import traceback
from typing import Any, Callable

from reliagent_python.llm_client import MockOllamaClient
from reliagent_python.model_integrity import (
    CANONICAL_MODEL,
    ModelIntegrityError,
    verify_model,
)
from reliagent_python.ollama_http import (
    ModelMissing,
    OllamaClient,
    OllamaError,
    OllamaUnreachable,
)
from reliagent_python.orchestrator import Orchestrator

# JSON-RPC error codes
_PARSE_ERROR = -32700
_INVALID_REQUEST = -32600
_METHOD_NOT_FOUND = -32601
_INVALID_PARAMS = -32602
_INTERNAL_ERROR = -32603

# Códigos de aplicación (rango -32000..-32099). Rust los replica en
# src/bridge/mod.rs; cambiarlos rompe el contrato.
RPC_OLLAMA_UNREACHABLE = -32010
RPC_MODEL_MISSING = -32011
RPC_MODEL_INTEGRITY = -32012
RPC_LLM_ERROR = -32013

_BACKENDS = ("ollama", "mock")


def _log(msg: str) -> None:
    print(f"[reliagent-py] {msg}", file=sys.stderr, flush=True)


# --- Handlers -----------------------------------------------------------


def _handle_ping(_params: dict) -> dict:
    return {"pong": True}


def _handle_agent_run(params: dict) -> dict:
    prompt = params.get("prompt")
    if not isinstance(prompt, str) or not prompt:
        raise _RpcError(_INVALID_PARAMS, "prompt must be a non-empty string")
    backend = params.get("backend")
    if not isinstance(backend, str) or backend not in _BACKENDS:
        raise _RpcError(_INVALID_PARAMS, f"backend must be one of {list(_BACKENDS)}")

    if backend == "mock":
        orch = Orchestrator(agent_client=MockOllamaClient())
    else:
        client = _verified_ollama_client()
        # El mismo modelo actúa de crítico: solo puede rechazar.
        orch = Orchestrator(agent_client=client, llm_critic_client=client)

    try:
        result = orch.run(prompt)
    except OllamaError as e:
        raise _RpcError(RPC_LLM_ERROR, str(e), {"kind": "llm_error"}) from e
    return result.to_dict()


def _make_ollama_client(tag: str) -> OllamaClient:
    return OllamaClient(tag)


def _verified_ollama_client() -> OllamaClient:
    """Comprueba daemon, modelo e integridad antes de cualquier inferencia."""
    pin = CANONICAL_MODEL
    client = _make_ollama_client(pin.tag)
    try:
        client.version()
        info = client.show()
        _log(f"verifying SHA-256 of {pin.tag} ({pin.size / 1e9:.1f} GB)...")
        verify_model(info, pin)
    except OllamaUnreachable as e:
        raise _RpcError(RPC_OLLAMA_UNREACHABLE, str(e), {"kind": "ollama_unreachable"}) from e
    except ModelMissing as e:
        raise _RpcError(
            RPC_MODEL_MISSING, str(e), {"kind": "model_missing", "model": pin.tag}
        ) from e
    except ModelIntegrityError as e:
        raise _RpcError(RPC_MODEL_INTEGRITY, str(e), {"kind": "model_integrity"}) from e
    except OllamaError as e:
        raise _RpcError(RPC_LLM_ERROR, str(e), {"kind": "llm_error"}) from e
    return client


_METHODS: dict[str, Callable[[dict], dict]] = {
    "ping": _handle_ping,
    "agent.run": _handle_agent_run,
}


# --- JSON-RPC plumbing --------------------------------------------------


class _RpcError(Exception):
    def __init__(self, code: int, message: str, data: Any = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.data = data


def _error_response(req_id: Any, code: int, message: str, data: Any = None) -> dict:
    err: dict[str, Any] = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": req_id, "error": err}


def _success_response(req_id: Any, result: Any) -> dict:
    return {"jsonrpc": "2.0", "id": req_id, "result": result}


def _dispatch(request: dict) -> dict | None:
    """Run a single request. Returns the response dict, or None for a
    notification (no `id` field → JSON-RPC says no response).
    """
    req_id = request.get("id")
    is_notification = "id" not in request

    if request.get("jsonrpc") != "2.0":
        if is_notification:
            return None
        return _error_response(req_id, _INVALID_REQUEST, "jsonrpc must be '2.0'")

    method = request.get("method")
    if not isinstance(method, str):
        if is_notification:
            return None
        return _error_response(req_id, _INVALID_REQUEST, "method must be a string")

    handler = _METHODS.get(method)
    if handler is None:
        if is_notification:
            return None
        return _error_response(req_id, _METHOD_NOT_FOUND, f"method not found: {method}")

    params = request.get("params", {})
    if not isinstance(params, dict):
        if is_notification:
            return None
        return _error_response(req_id, _INVALID_PARAMS, "params must be an object")

    try:
        result = handler(params)
    except _RpcError as e:
        if is_notification:
            return None
        return _error_response(req_id, e.code, e.message, e.data)
    except Exception as e:  # noqa: BLE001 — top of dispatch must not leak
        # Solo el tipo: el texto puede venir de datos externos (secuencias de
        # escape, rutas). El traceback completo solo con RELI_SIDECAR_DEBUG.
        _log(f"handler crashed: {type(e).__name__}")
        if os.environ.get("RELI_SIDECAR_DEBUG"):
            _log(traceback.format_exc())
        if is_notification:
            return None
        return _error_response(
            req_id, _INTERNAL_ERROR, f"internal error ({type(e).__name__})"
        )

    if is_notification:
        return None
    return _success_response(req_id, result)


def _write_response(stdout, response: dict) -> None:
    stdout.write(json.dumps(response, separators=(",", ":")) + "\n")
    stdout.flush()


def serve(stdin=None, stdout=None) -> int:
    """Main server loop. Reads NDJSON from stdin, writes NDJSON to stdout.

    Returns 0 on clean EOF. Never raises on per-request errors; those are
    returned to the caller as JSON-RPC error responses.
    """
    if stdin is None:
        stdin = sys.stdin
    if stdout is None:
        stdout = sys.stdout

    _log("sidecar ready (json-rpc 2.0 / ndjson)")
    for raw_line in stdin:
        line = raw_line.strip()
        if not line:
            continue

        try:
            request = json.loads(line)
        except json.JSONDecodeError as e:
            # No way to know the id if we can't parse. Respond with null id
            # per JSON-RPC spec.
            _write_response(
                stdout, _error_response(None, _PARSE_ERROR, f"parse error: {e}")
            )
            continue

        if not isinstance(request, dict):
            _write_response(
                stdout,
                _error_response(None, _INVALID_REQUEST, "request must be an object"),
            )
            continue

        response = _dispatch(request)
        if response is not None:
            _write_response(stdout, response)

    _log("sidecar shutting down (stdin closed)")
    return 0


def main() -> int:
    return serve()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
