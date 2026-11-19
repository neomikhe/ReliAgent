"""Cliente HTTP mínimo para el daemon local de Ollama.

Solo biblioteca estándar (urllib), a propósito:

- El host está fijado a 127.0.0.1. `OLLAMA_HOST` se ignora: los prompts y el
  contenido de archivos nunca deben salir de la máquina.
- Las variables de proxy (`HTTP_PROXY`, `ALL_PROXY`, ...) se ignoran.
- Las redirecciones no se siguen.
- Las respuestas tienen un tamaño máximo; un servidor local hostil no puede
  agotar la memoria del sidecar.
- No se envían credenciales (`OLLAMA_API_KEY` no se lee).

Endpoints usados: `GET /api/version`, `POST /api/show`, `POST /api/chat`.
"""

from __future__ import annotations

import http.client
import json
import time
import urllib.error
import urllib.request
from typing import Any

LOOPBACK_HOST = "127.0.0.1"
DEFAULT_PORT = 11434

# /api/show de qwen2.5 7B ocupa ~50 KB; las respuestas de chat, unos pocos KB.
_MAX_RESPONSE_BYTES = 8 * 1024 * 1024

# Tiempos de espera (segundos), usados como timeout de socket y como plazo
# total de la respuesta. La generación en CPU puede tardar minutos.
_METADATA_TIMEOUT = 10.0
_GENERATION_TIMEOUT = 600.0
_READ_CHUNK = 64 * 1024


class OllamaError(Exception):
    """Fallo hablando con Ollama (HTTP, JSON inválido, respuesta inesperada)."""


class OllamaUnreachable(OllamaError):
    """No hay nada escuchando en el puerto de Ollama."""


class ModelMissing(OllamaError):
    """Ollama responde pero no tiene el modelo pedido."""


class _RefuseRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        # Devolver None hace que urllib lance HTTPError con el código 3xx.
        return None


class OllamaClient:
    """Cliente síncrono de una sola petición por llamada, sin streaming."""

    def __init__(self, model: str, port: int = DEFAULT_PORT) -> None:
        if not isinstance(port, int) or isinstance(port, bool) or not 0 < port < 65536:
            raise ValueError(f"invalid port: {port!r}")
        self.model = model
        self.base_url = f"http://{LOOPBACK_HOST}:{port}"
        self._opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}), _RefuseRedirects()
        )

    def version(self) -> str:
        data = self._request("GET", "/api/version", None, _METADATA_TIMEOUT)
        version = data.get("version")
        if not isinstance(version, str):
            raise OllamaError("/api/version response has no version string")
        return version

    def show(self) -> dict[str, Any]:
        return self._request(
            "POST", "/api/show", {"model": self.model}, _METADATA_TIMEOUT
        )

    def generate(self, system: str, user: str) -> str:
        data = self._request(
            "POST",
            "/api/chat",
            {
                "model": self.model,
                "messages": [
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                "stream": False,
                "format": "json",
                "options": {"temperature": 0},
            },
            _GENERATION_TIMEOUT,
        )
        message = data.get("message")
        content = message.get("content") if isinstance(message, dict) else None
        if not isinstance(content, str):
            raise OllamaError("/api/chat response has no message.content")
        return content

    def _request(
        self, method: str, path: str, body: dict | None, timeout: float
    ) -> dict[str, Any]:
        # Los mensajes de error nunca incluyen texto enviado por el servidor:
        # quien escuche en el puerto no es de confianza y la CLI los imprime.
        payload = json.dumps(body).encode("utf-8") if body is not None else None
        req = urllib.request.Request(
            self.base_url + path,
            data=payload,
            method=method,
            headers={"Content-Type": "application/json", "Accept": "application/json"},
        )
        deadline = time.monotonic() + timeout
        try:
            with self._opener.open(req, timeout=timeout) as resp:
                raw = _read_bounded(resp, deadline, f"{method} {path}")
        except urllib.error.HTTPError as e:
            if e.code == 404 and path == "/api/show":
                raise ModelMissing(f"model {self.model!r} not found in Ollama") from e
            raise OllamaError(f"{method} {path} returned HTTP {e.code}") from e
        except urllib.error.URLError as e:
            if isinstance(e.reason, ConnectionRefusedError):
                raise OllamaUnreachable(f"nothing listening on {self.base_url}") from e
            raise OllamaError(f"{method} {path} failed: {type(e.reason).__name__}") from e
        except http.client.HTTPException as e:
            raise OllamaError(f"{method} {path} returned an invalid HTTP response") from e
        except (TimeoutError, OSError) as e:
            raise OllamaError(f"{method} {path} failed: {type(e).__name__}") from e

        try:
            data = json.loads(raw)
        except (ValueError, RecursionError) as e:
            # ValueError cubre JSON inválido, UTF-8 inválido y enteros enormes.
            raise OllamaError(f"{method} {path} returned invalid JSON") from e
        if not isinstance(data, dict):
            raise OllamaError(f"{method} {path} returned a non-object")
        return data


def _read_bounded(resp: Any, deadline: float, what: str) -> bytes:
    """Lee el cuerpo con límite de tamaño y plazo total (contra respuestas
    que gotean un byte cada pocos segundos)."""
    chunks: list[bytes] = []
    received = 0
    while True:
        if time.monotonic() > deadline:
            raise OllamaError(f"{what} exceeded its time limit")
        chunk = resp.read1(_READ_CHUNK)
        if not chunk:
            return b"".join(chunks)
        received += len(chunk)
        if received > _MAX_RESPONSE_BYTES:
            raise OllamaError(f"{what} response exceeds {_MAX_RESPONSE_BYTES} bytes")
        chunks.append(chunk)
