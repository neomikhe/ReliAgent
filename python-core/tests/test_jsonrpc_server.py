"""JSON-RPC 2.0 NDJSON server tests.

We drive `serve()` with in-memory stdin/stdout streams rather than spawning
a subprocess. The cross-process integration test (spawning the real Python
via `std::process::Command`) lives on the Rust side.
"""

from __future__ import annotations

import hashlib
import io
import json

import pytest

from reliagent_python import main
from reliagent_python.main import serve
from reliagent_python.model_integrity import ModelPin
from reliagent_python.ollama_http import OllamaClient


def _drive(requests: list[dict]) -> list[dict]:
    """Feed `requests` through the server as NDJSON and return parsed
    responses."""
    stdin = io.StringIO(
        "\n".join(json.dumps(r) for r in requests) + "\n"
    )
    stdout = io.StringIO()
    rc = serve(stdin=stdin, stdout=stdout)
    assert rc == 0
    lines = [ln for ln in stdout.getvalue().splitlines() if ln.strip()]
    return [json.loads(ln) for ln in lines]


class TestPing:
    def test_ping_returns_pong(self):
        responses = _drive([{"jsonrpc": "2.0", "id": 1, "method": "ping"}])
        assert responses == [
            {"jsonrpc": "2.0", "id": 1, "result": {"pong": True}}
        ]

    def test_ping_with_params_ignored(self):
        responses = _drive(
            [{"jsonrpc": "2.0", "id": 2, "method": "ping", "params": {"extra": 1}}]
        )
        assert responses[0]["result"] == {"pong": True}


def _agent_run(params: dict) -> dict:
    return _drive([{"jsonrpc": "2.0", "id": 7, "method": "agent.run", "params": params}])[0]


class TestAgentRun:
    def test_agent_run_happy_path(self):
        response = _agent_run({"prompt": "write 'hola' to notes/hi.txt", "backend": "mock"})
        result = response["result"]
        assert result["verdict"] == "approve"
        assert result["proposal"]["args"]["path"] == "notes/hi.txt"

    def test_agent_run_rejects_bad_request(self):
        result = _agent_run({"prompt": "what is love?", "backend": "mock"})["result"]
        assert result["verdict"] == "reject"
        assert result["critic_stage"] == "deterministic"

    def test_agent_run_requires_prompt(self):
        response = _agent_run({"backend": "mock"})
        assert response["error"]["code"] == -32602

    def test_agent_run_requires_explicit_backend(self):
        # Sin valor por defecto: un llamador que olvide el backend no debe
        # acabar usando el mock en silencio.
        response = _agent_run({"prompt": "write 'a' to a.txt"})
        assert response["error"]["code"] == -32602

    @pytest.mark.parametrize("backend", ["openai", "", None, True])
    def test_agent_run_rejects_unknown_backend(self, backend):
        response = _agent_run({"prompt": "write 'a' to a.txt", "backend": backend})
        assert response["error"]["code"] == -32602


AGENT_PROPOSAL = {"tool": "write_file", "args": {"path": "notes/a.txt", "content": "hola"}}


def _chat(content: dict) -> dict:
    return {"message": {"role": "assistant", "content": json.dumps(content)}}


@pytest.fixture
def ollama_backend(fake_ollama, tmp_path, monkeypatch):
    """Apunta el backend ollama al servidor falso y fija un modelo pequeño
    cuyo blob existe en tmp_path."""
    weights = b"pesos de prueba"
    pin = ModelPin(tag="test:1b", sha256=hashlib.sha256(weights).hexdigest(), size=len(weights))
    blob = tmp_path / "blobs" / f"sha256-{pin.sha256}"
    blob.parent.mkdir()
    blob.write_bytes(weights)
    monkeypatch.setattr(main, "CANONICAL_MODEL", pin)
    monkeypatch.setattr(
        main, "_make_ollama_client", lambda tag: OllamaClient(tag, port=fake_ollama.port)
    )
    fake_ollama.respond_json("GET", "/api/version", {"version": "0.31.2"})
    fake_ollama.respond_json("POST", "/api/show", {"modelfile": f"FROM {blob}\n"})
    fake_ollama.blob = blob
    return fake_ollama


class TestOllamaBackend:
    def test_happy_path_uses_agent_and_llm_critic(self, ollama_backend):
        ollama_backend.respond_json(
            "POST", "/api/chat", _chat(AGENT_PROPOSAL), _chat({"verdict": "approve"})
        )
        result = _agent_run({"prompt": "crea notes/a.txt", "backend": "ollama"})["result"]
        assert result["verdict"] == "approve"
        assert result["critic_stage"] == "ok"
        assert result["proposal"] == AGENT_PROPOSAL
        chats = ollama_backend.requests_to("/api/chat")
        assert len(chats) == 2  # agente + crítico LLM
        assert all(c.body["model"] == "test:1b" for c in chats)

    def _approve(self, ollama_backend):
        ollama_backend.respond_json(
            "POST", "/api/chat", _chat(AGENT_PROPOSAL), _chat({"verdict": "approve"})
        )
        return _agent_run({"prompt": "crea notes/a.txt", "backend": "ollama"})["result"]

    def test_audited_ollama_version_is_not_flagged(self, ollama_backend, capsys):
        self._approve(ollama_backend)
        assert "not been audited" not in capsys.readouterr().err

    def test_unaudited_ollama_version_warns_but_still_runs(self, ollama_backend, capsys):
        ollama_backend.respond_json("GET", "/api/version", {"version": "0.99.0-rc1"})
        assert self._approve(ollama_backend)["verdict"] == "approve"
        err = capsys.readouterr().err
        assert "not been audited" in err
        assert "0.99.0-rc1" in err
        assert "0.31.2" in err

    def test_odd_version_string_is_never_echoed(self, ollama_backend, capsys):
        # Lo que responde en el puerto no es de confianza (puede no ser Ollama).
        hostile = "1.0\x1b[2J\u202e; rm -rf ~"
        ollama_backend.respond_json("GET", "/api/version", {"version": hostile})
        self._approve(ollama_backend)
        err = capsys.readouterr().err
        assert "not been audited" in err
        assert "\x1b" not in err and "\u202e" not in err and "rm -rf" not in err

    def test_llm_critic_can_reject(self, ollama_backend):
        ollama_backend.respond_json(
            "POST",
            "/api/chat",
            _chat(AGENT_PROPOSAL),
            _chat({"verdict": "reject", "reason": "no me fío"}),
        )
        result = _agent_run({"prompt": "crea notes/a.txt", "backend": "ollama"})["result"]
        assert result["verdict"] == "reject"
        assert result["critic_stage"] == "llm"

    def test_unreachable_ollama_returns_specific_error(self, monkeypatch, closed_port):
        monkeypatch.setattr(
            main, "_make_ollama_client", lambda tag: OllamaClient(tag, port=closed_port)
        )
        error = _agent_run({"prompt": "x", "backend": "ollama"})["error"]
        assert error["code"] == main.RPC_OLLAMA_UNREACHABLE
        assert error["data"]["kind"] == "ollama_unreachable"

    def test_missing_model_returns_specific_error(self, ollama_backend):
        ollama_backend.respond_json("POST", "/api/show", {"error": "not found"}, status=404)
        error = _agent_run({"prompt": "x", "backend": "ollama"})["error"]
        assert error["code"] == main.RPC_MODEL_MISSING
        assert error["data"] == {"kind": "model_missing", "model": "test:1b"}

    def test_tampered_model_blocks_inference(self, ollama_backend):
        ollama_backend.blob.write_bytes(b"pesos de prueBa")  # mismo tamaño
        error = _agent_run({"prompt": "x", "backend": "ollama"})["error"]
        assert error["code"] == main.RPC_MODEL_INTEGRITY
        assert error["data"]["kind"] == "model_integrity"
        assert ollama_backend.requests_to("/api/chat") == []

    def test_generation_failure_returns_specific_error(self, ollama_backend):
        ollama_backend.respond_json("POST", "/api/chat", {"error": "boom"}, status=500)
        error = _agent_run({"prompt": "x", "backend": "ollama"})["error"]
        assert error["code"] == main.RPC_LLM_ERROR
        assert error["data"]["kind"] == "llm_error"

    def test_error_codes_are_distinct_server_range(self):
        codes = {
            main.RPC_OLLAMA_UNREACHABLE,
            main.RPC_MODEL_MISSING,
            main.RPC_MODEL_INTEGRITY,
            main.RPC_LLM_ERROR,
        }
        assert len(codes) == 4
        # Rango reservado por JSON-RPC 2.0 para errores de implementación.
        assert all(-32099 <= c <= -32000 for c in codes)


class TestProtocolErrors:
    def test_method_not_found(self):
        responses = _drive(
            [{"jsonrpc": "2.0", "id": 3, "method": "does.not.exist"}]
        )
        assert responses[0]["error"]["code"] == -32601

    def test_parse_error(self):
        stdin = io.StringIO("this is not json\n")
        stdout = io.StringIO()
        serve(stdin=stdin, stdout=stdout)
        response = json.loads(stdout.getvalue().strip())
        assert response["error"]["code"] == -32700
        assert response["id"] is None

    def test_invalid_request_non_object(self):
        stdin = io.StringIO("[1,2,3]\n")
        stdout = io.StringIO()
        serve(stdin=stdin, stdout=stdout)
        response = json.loads(stdout.getvalue().strip())
        assert response["error"]["code"] == -32600

    def test_wrong_jsonrpc_version(self):
        responses = _drive([{"jsonrpc": "1.0", "id": 4, "method": "ping"}])
        assert responses[0]["error"]["code"] == -32600

    def test_non_string_method(self):
        responses = _drive([{"jsonrpc": "2.0", "id": 5, "method": 42}])
        assert responses[0]["error"]["code"] == -32600

    def test_non_object_params(self):
        responses = _drive(
            [{"jsonrpc": "2.0", "id": 6, "method": "ping", "params": "nope"}]
        )
        assert responses[0]["error"]["code"] == -32602


class TestUnexpectedErrors:
    def test_crash_does_not_leak_details_or_traceback(self, monkeypatch, capsys):
        def boom(_params):
            raise RuntimeError("detalle interno \x1b[2J /ruta/secreta")

        monkeypatch.setitem(main._METHODS, "boom", boom)
        response = _drive([{"jsonrpc": "2.0", "id": 1, "method": "boom"}])[0]
        assert response["error"]["code"] == -32603
        assert "secreta" not in response["error"]["message"]
        err = capsys.readouterr().err
        assert "Traceback" not in err
        assert "secreta" not in err
        assert "\x1b" not in err
        assert "RuntimeError" in err  # el tipo sí ayuda a diagnosticar

    def test_debug_env_enables_traceback(self, monkeypatch, capsys):
        def boom(_params):
            raise RuntimeError("detalle")

        monkeypatch.setitem(main._METHODS, "boom", boom)
        monkeypatch.setenv("RELI_SIDECAR_DEBUG", "1")
        _drive([{"jsonrpc": "2.0", "id": 1, "method": "boom"}])
        assert "Traceback" in capsys.readouterr().err


class TestNotifications:
    def test_notification_produces_no_response(self):
        """JSON-RPC 2.0 — a request without `id` is a notification; no
        response is written, even on error."""
        stdin = io.StringIO(
            json.dumps({"jsonrpc": "2.0", "method": "ping"}) + "\n"
            + json.dumps({"jsonrpc": "2.0", "method": "does.not.exist"}) + "\n"
        )
        stdout = io.StringIO()
        serve(stdin=stdin, stdout=stdout)
        assert stdout.getvalue() == ""


class TestStreaming:
    def test_multiple_requests_in_one_session(self):
        responses = _drive(
            [
                {"jsonrpc": "2.0", "id": 1, "method": "ping"},
                {"jsonrpc": "2.0", "id": 2, "method": "ping"},
                {"jsonrpc": "2.0", "id": 3, "method": "ping"},
            ]
        )
        assert [r["id"] for r in responses] == [1, 2, 3]
        assert all(r["result"] == {"pong": True} for r in responses)

    def test_blank_lines_ignored(self):
        stdin = io.StringIO(
            "\n\n"
            + json.dumps({"jsonrpc": "2.0", "id": 1, "method": "ping"})
            + "\n\n"
        )
        stdout = io.StringIO()
        serve(stdin=stdin, stdout=stdout)
        lines = [ln for ln in stdout.getvalue().splitlines() if ln.strip()]
        assert len(lines) == 1
