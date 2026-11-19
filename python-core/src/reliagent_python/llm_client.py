"""LLM client contract and deterministic clients for the orchestrator.

- `LLMClient`: the protocol the orchestrator depends on.
- `MockOllamaClient`: deterministic pattern-matching agent used for tests and
  offline demos (`reli run --mock-llm`).
- `MockCriticClient`: fixed-verdict critic for tests.

The real client lives in `ollama_http.OllamaClient`.

All clients return raw JSON strings — parsing/validation lives in the
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
