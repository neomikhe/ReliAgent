"""Fixtures compartidas.

`fake_ollama` levanta un servidor HTTP real en 127.0.0.1 (puerto efímero)
que imita los endpoints de Ollama que usa el sidecar. Así las pruebas
ejercitan el cliente HTTP de verdad (sockets, cabeceras, códigos de estado)
sin depender de un daemon de Ollama instalado.
"""

from __future__ import annotations

import json
import socket
import threading
from collections import deque
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest


@dataclass
class FakeResponse:
    status: int = 200
    body: bytes = b"{}"
    headers: dict[str, str] = field(default_factory=dict)


@dataclass
class RecordedRequest:
    method: str
    path: str
    body: dict | None


class FakeOllama:
    """Rutas configurables: (método, path) -> cola de respuestas. La última
    respuesta de cada cola se repite si se piden más de las encoladas."""

    def __init__(self) -> None:
        self._routes: dict[tuple[str, str], deque[FakeResponse]] = {}
        self.requests: list[RecordedRequest] = []
        self.port = 0

    def respond(self, method: str, path: str, *responses: FakeResponse) -> None:
        self._routes[(method, path)] = deque(responses)

    def respond_json(self, method: str, path: str, *payloads: object, status: int = 200) -> None:
        self.respond(
            method,
            path,
            *(FakeResponse(status, json.dumps(p).encode("utf-8")) for p in payloads),
        )

    def requests_to(self, path: str) -> list[RecordedRequest]:
        return [r for r in self.requests if r.path == path]

    def _next(self, method: str, path: str) -> FakeResponse:
        queue = self._routes.get((method, path))
        if not queue:
            return FakeResponse(404, b'{"error":"no route in fake"}')
        return queue.popleft() if len(queue) > 1 else queue[0]


def _make_handler(fake: FakeOllama) -> type[BaseHTTPRequestHandler]:
    class Handler(BaseHTTPRequestHandler):
        def _serve(self, method: str) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(length) if length else b""
            body = json.loads(raw) if raw else None
            fake.requests.append(RecordedRequest(method, self.path, body))
            resp = fake._next(method, self.path)
            self.send_response(resp.status)
            for k, v in resp.headers.items():
                self.send_header(k, v)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(resp.body)))
            self.end_headers()
            self.wfile.write(resp.body)

        def do_GET(self) -> None:  # noqa: N802 — nombre impuesto por http.server
            self._serve("GET")

        def do_POST(self) -> None:  # noqa: N802
            self._serve("POST")

        def log_message(self, format: str, *args: object) -> None:  # noqa: A002
            # Silencio: el ruido de http.server no aporta en las pruebas.
            return

    return Handler


@pytest.fixture
def fake_ollama():
    fake = FakeOllama()
    server = ThreadingHTTPServer(("127.0.0.1", 0), _make_handler(fake))
    fake.port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield fake
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def closed_port() -> int:
    """Un puerto de loopback en el que no escucha nadie."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
