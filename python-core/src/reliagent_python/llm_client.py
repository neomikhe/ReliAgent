"""LLM clients for the orchestrator.

Two implementations ship here:

- `MockOllamaClient`: deterministic pattern-matching agent used for tests and
  offline smoke runs. Always the default.
- `OllamaClient`: thin wrapper around the `ollama` Python package. Used when
  the caller wires it explicitly. Not exercised in CI (would require a live
  daemon at `localhost:11434`).

Both clients return raw JSON strings — parsing/validation lives in the
orchestrator, not here.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Protocol


class LLMClient(Protocol):
    """Minimal contract the orchestrator depends on."""

    def generate(self, system: str, user: str) -> str:  # pragma: no cover - protocol
        ...


# --- Mock ---------------------------------------------------------------


@dataclass
class MockOllamaClient:
    """Deterministic client. Recognizes a couple of English/Spanish
    phrasings and emits a JSON proposal. Everything else returns a null
    proposal with a reason.
    """

    _WRITE_PATTERNS = (
        # "write 'hello' to notes/hello.txt"
        re.compile(
            r"""write\s+(?P<q>['"])(?P<content>.+?)(?P=q)\s+to\s+(?P<path>[\w./\-]+)""",
            re.IGNORECASE,
        ),
        # "escribe 'hola' en notes/hola.txt"
        re.compile(
            r"""escribe\s+(?P<q>['"])(?P<content>.+?)(?P=q)\s+en\s+(?P<path>[\w./\-]+)""",
            re.IGNORECASE,
        ),
        # "save X to Y" / "guarda X en Y"
        re.compile(
            r"""(?:save|guarda)\s+(?P<q>['"])(?P<content>.+?)(?P=q)\s+"""
            r"""(?:to|en)\s+(?P<path>[\w./\-]+)""",
            re.IGNORECASE,
        ),
    )

    _READ_PATTERNS = (
        # "read notes/hello.txt" / "read file notes/hello.txt"
        re.compile(
            r"""read(?:\s+file)?\s+(?P<path>[\w./\-]+)""",
            re.IGNORECASE,
        ),
        # "lee notes/hello.txt" / "leer archivo notes/hello.txt"
        re.compile(
            r"""(?:lee|leer)(?:\s+(?:el\s+)?archivo)?\s+(?P<path>[\w./\-]+)""",
            re.IGNORECASE,
        ),
        # "show contents of notes/a.txt" / "muestra el contenido de notes/a.txt"
        re.compile(
            r"""(?:show|muestra)\s+(?:the\s+)?(?:contents?|contenido)\s+"""
            r"""(?:of|de(?:l)?)\s+(?P<path>[\w./\-]+)""",
            re.IGNORECASE,
        ),
    )

    _LIST_PATTERNS = (
        # "list notes/" / "list dir notes" / "ls notes"
        re.compile(
            r"""(?:list(?:\s+(?:dir|directory))?|ls)\s+(?P<path>[\w./\-]+)""",
            re.IGNORECASE,
        ),
        # "lista notes" / "lista el directorio notes"
        re.compile(
            r"""(?:lista|listar)(?:\s+(?:el\s+)?(?:directorio|carpeta))?\s+"""
            r"""(?P<path>[\w./\-]+)""",
            re.IGNORECASE,
        ),
    )

    _LIST_ROOT_PATTERNS = (
        re.compile(r"""\b(?:list|ls)\b\s*$""", re.IGNORECASE),
        re.compile(r"""\blista(?:r)?\b\s*$""", re.IGNORECASE),
    )

    def generate(self, system: str, user: str) -> str:
        del system  # unused: the mock doesn't care about the system prompt
        for pattern in self._WRITE_PATTERNS:
            m = pattern.search(user)
            if m:
                return json.dumps(
                    {
                        "tool": "write_file",
                        "args": {
                            "path": m.group("path"),
                            "content": m.group("content"),
                        },
                    }
                )
        # list-root before read/list-with-path so "list" alone doesn't
        # accidentally get caught by a read pattern via backtracking.
        for pattern in self._LIST_ROOT_PATTERNS:
            if pattern.search(user.strip()):
                return json.dumps(
                    {"tool": "list_dir", "args": {"path": ""}}
                )
        for pattern in self._LIST_PATTERNS:
            m = pattern.search(user)
            if m:
                return json.dumps(
                    {
                        "tool": "list_dir",
                        "args": {"path": m.group("path")},
                    }
                )
        for pattern in self._READ_PATTERNS:
            m = pattern.search(user)
            if m:
                return json.dumps(
                    {
                        "tool": "read_file",
                        "args": {"path": m.group("path")},
                    }
                )
        return json.dumps(
            {
                "tool": None,
                "reason": "mock client could not parse the request into a known tool call",
            }
        )


@dataclass
class MockCriticClient:
    """Echoes whatever the rule-based critic already decided. Useful when
    tests want to drive the orchestrator without any real LLM in the loop.
    """

    verdict: str = "approve"
    reason: str = ""

    def generate(self, system: str, user: str) -> str:
        del system, user
        if self.verdict == "approve":
            return json.dumps({"verdict": "approve"})
        return json.dumps({"verdict": "reject", "reason": self.reason or "mock reject"})


# --- Real Ollama --------------------------------------------------------


class OllamaClient:
    """Thin wrapper over the `ollama` package. Kept intentionally simple:
    one-shot `chat` calls, no streaming, no tools API. Real integration work
    lives in a later milestone.
    """

    def __init__(self, model: str = "qwen2.5:7b-instruct-q4_K_M", host: str | None = None):
        # Import lazily so tests that only use the mock don't need ollama
        # installed.
        try:
            import ollama  # type: ignore[import-not-found]
        except ImportError as e:  # pragma: no cover - env-dependent
            raise RuntimeError(
                "The `ollama` package is required for OllamaClient. "
                "Install it (pip install ollama) or use MockOllamaClient."
            ) from e
        self._ollama = ollama
        self._model = model
        self._host = host

    def generate(self, system: str, user: str) -> str:  # pragma: no cover - network
        client = (
            self._ollama.Client(host=self._host) if self._host else self._ollama
        )
        resp = client.chat(
            model=self._model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            options={"temperature": 0.0},
        )
        return resp["message"]["content"]
