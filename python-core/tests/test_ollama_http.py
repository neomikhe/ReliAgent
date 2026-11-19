"""Pruebas del cliente HTTP de Ollama (solo biblioteca estándar).

Todas usan un servidor HTTP real en 127.0.0.1 (`fake_ollama`), no mocks.
"""

from __future__ import annotations

import json
import socket
import threading
import time

import pytest

from reliagent_python import ollama_http
from reliagent_python.ollama_http import (
    ModelMissing,
    OllamaClient,
    OllamaError,
    OllamaUnreachable,
)
from tests.conftest import FakeResponse

TAG = "qwen2.5:7b-instruct-q4_K_M"


def _client(fake) -> OllamaClient:
    return OllamaClient(TAG, port=fake.port)


def _serve_raw(script: list[tuple[bytes, float]]) -> int:
    """Servidor TCP de una sola conexión que, tras leer la petición, envía
    cada fragmento después de su retardo. Para respuestas HTTP inválidas o
    lentas que http.server no sabe producir."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)

    def run() -> None:
        with srv:
            conn, _ = srv.accept()
            with conn:
                conn.recv(65536)
                try:
                    for chunk, delay in script:
                        time.sleep(delay)
                        conn.sendall(chunk)
                except OSError:
                    pass  # el cliente cerró antes: es lo esperado

    threading.Thread(target=run, daemon=True).start()
    return srv.getsockname()[1]


class TestVersion:
    def test_returns_server_version(self, fake_ollama):
        fake_ollama.respond_json("GET", "/api/version", {"version": "0.31.2"})
        assert _client(fake_ollama).version() == "0.31.2"

    def test_unreachable_port_raises_ollama_unreachable(self, closed_port):
        with pytest.raises(OllamaUnreachable):
            OllamaClient(TAG, port=closed_port).version()


class TestShow:
    def test_sends_model_name_and_returns_payload(self, fake_ollama):
        fake_ollama.respond_json("POST", "/api/show", {"modelfile": "FROM x"})
        assert _client(fake_ollama).show() == {"modelfile": "FROM x"}
        assert fake_ollama.requests_to("/api/show")[0].body == {"model": TAG}

    def test_404_raises_model_missing(self, fake_ollama):
        fake_ollama.respond_json(
            "POST", "/api/show", {"error": "model not found"}, status=404
        )
        with pytest.raises(ModelMissing):
            _client(fake_ollama).show()


class TestGenerate:
    def test_sends_deterministic_non_streaming_json_chat(self, fake_ollama):
        fake_ollama.respond_json(
            "POST", "/api/chat", {"message": {"role": "assistant", "content": "{}"}}
        )
        _client(fake_ollama).generate("SYS", "USER")
        body = fake_ollama.requests_to("/api/chat")[0].body
        assert body["model"] == TAG
        assert body["stream"] is False
        assert body["format"] == "json"
        assert body["options"]["temperature"] == 0
        assert body["messages"] == [
            {"role": "system", "content": "SYS"},
            {"role": "user", "content": "USER"},
        ]

    def test_returns_message_content(self, fake_ollama):
        fake_ollama.respond_json(
            "POST",
            "/api/chat",
            {"message": {"role": "assistant", "content": '{"tool": null}'}},
        )
        assert _client(fake_ollama).generate("s", "u") == '{"tool": null}'

    def test_missing_message_content_raises(self, fake_ollama):
        fake_ollama.respond_json("POST", "/api/chat", {"done": True})
        with pytest.raises(OllamaError):
            _client(fake_ollama).generate("s", "u")


class TestTransportHardening:
    def test_server_error_raises_ollama_error(self, fake_ollama):
        fake_ollama.respond_json("GET", "/api/version", {"error": "x"}, status=500)
        with pytest.raises(OllamaError):
            _client(fake_ollama).version()

    def test_invalid_json_raises_ollama_error(self, fake_ollama):
        fake_ollama.respond("GET", "/api/version", FakeResponse(200, b"not json"))
        with pytest.raises(OllamaError):
            _client(fake_ollama).version()

    def test_redirects_are_not_followed(self, fake_ollama):
        target = f"http://127.0.0.1:{fake_ollama.port}/elsewhere"
        fake_ollama.respond(
            "GET", "/api/version", FakeResponse(302, b"", {"Location": target})
        )
        fake_ollama.respond_json("GET", "/elsewhere", {"version": "evil"})
        with pytest.raises(OllamaError):
            _client(fake_ollama).version()
        assert fake_ollama.requests_to("/elsewhere") == []

    def test_proxy_environment_is_ignored(self, fake_ollama, monkeypatch, closed_port):
        # Si el cliente respetara estas variables, la petición iría a un
        # proxy inexistente y fallaría. Los prompts nunca deben salir por
        # un proxy.
        proxy = f"http://127.0.0.1:{closed_port}"
        for var in ("HTTP_PROXY", "http_proxy", "ALL_PROXY", "all_proxy"):
            monkeypatch.setenv(var, proxy)
        for var in ("NO_PROXY", "no_proxy"):
            monkeypatch.delenv(var, raising=False)
        fake_ollama.respond_json("GET", "/api/version", {"version": "0.31.2"})
        assert _client(fake_ollama).version() == "0.31.2"

    def test_ollama_host_environment_is_ignored(self, fake_ollama, monkeypatch):
        # 203.0.113.0/24 es TEST-NET-3: nunca enrutable.
        monkeypatch.setenv("OLLAMA_HOST", "http://203.0.113.7:11434")
        fake_ollama.respond_json("GET", "/api/version", {"version": "0.31.2"})
        assert _client(fake_ollama).version() == "0.31.2"

    def test_oversized_response_is_rejected(self, fake_ollama, monkeypatch):
        monkeypatch.setattr(ollama_http, "_MAX_RESPONSE_BYTES", 64)
        big = json.dumps({"version": "x" * 200}).encode()
        fake_ollama.respond("GET", "/api/version", FakeResponse(200, big))
        with pytest.raises(OllamaError):
            _client(fake_ollama).version()

    def test_deeply_nested_json_is_an_ollama_error(self, fake_ollama):
        body = b"[" * 100_000 + b"]" * 100_000
        fake_ollama.respond("GET", "/api/version", FakeResponse(200, body))
        with pytest.raises(OllamaError):
            _client(fake_ollama).version()

    def test_huge_integer_is_an_ollama_error(self, fake_ollama):
        body = b'{"version": 1' + b"1" * 6000 + b"}"
        fake_ollama.respond("GET", "/api/version", FakeResponse(200, body))
        with pytest.raises(OllamaError):
            _client(fake_ollama).version()

    def test_invalid_status_line_is_an_ollama_error_without_echo(self):
        port = _serve_raw([(b"\x1b]0;pwned\x07 nonsense\r\n\r\n", 0)])
        with pytest.raises(OllamaError) as exc:
            OllamaClient(TAG, port=port).version()
        assert "\x1b" not in str(exc.value)
        assert "pwned" not in str(exc.value)

    def test_slow_drip_response_hits_total_deadline(self, monkeypatch):
        # Un byte cada 0,2 s: ninguna lectura individual agota el timeout del
        # socket, pero la respuesta completa nunca debe superar el plazo total.
        monkeypatch.setattr(ollama_http, "_METADATA_TIMEOUT", 0.5)
        head = b"HTTP/1.1 200 OK\r\nContent-Length: 1000\r\n\r\n{"
        port = _serve_raw([(head, 0)] + [(b" ", 0.2)] * 20)
        start = time.monotonic()
        with pytest.raises(OllamaError):
            OllamaClient(TAG, port=port).version()
        assert time.monotonic() - start < 2.0

    def test_base_url_is_always_loopback(self):
        assert OllamaClient(TAG).base_url == "http://127.0.0.1:11434"

    @pytest.mark.parametrize("port", [0, -1, 65536, "11434"])
    def test_invalid_port_rejected(self, port):
        with pytest.raises(ValueError):
            OllamaClient(TAG, port=port)
