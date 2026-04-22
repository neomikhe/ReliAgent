"""Tests for the mock LLM clients. The real OllamaClient is not tested
here — it requires a live daemon.
"""

from __future__ import annotations

import json

from reliagent_python.llm_client import MockCriticClient, MockOllamaClient


class TestMockOllamaClient:
    def test_english_write_phrase(self):
        c = MockOllamaClient()
        raw = c.generate("", "please write 'hola mundo' to notes/hi.txt now")
        data = json.loads(raw)
        assert data == {
            "tool": "write_file",
            "args": {"path": "notes/hi.txt", "content": "hola mundo"},
        }

    def test_spanish_escribe_phrase(self):
        c = MockOllamaClient()
        raw = c.generate("", "por favor escribe 'hola' en notas/a.txt")
        data = json.loads(raw)
        assert data["tool"] == "write_file"
        assert data["args"]["content"] == "hola"
        assert data["args"]["path"] == "notas/a.txt"

    def test_save_phrase(self):
        c = MockOllamaClient()
        raw = c.generate("", "save 'log entry' to logs/today.log")
        data = json.loads(raw)
        assert data["args"]["path"] == "logs/today.log"

    def test_unparseable_returns_null_tool(self):
        c = MockOllamaClient()
        raw = c.generate("", "what is the meaning of life?")
        data = json.loads(raw)
        assert data["tool"] is None
        assert "reason" in data

    def test_english_read_phrase(self):
        c = MockOllamaClient()
        raw = c.generate("", "please read notes/hi.txt and tell me what's inside")
        data = json.loads(raw)
        assert data == {"tool": "read_file", "args": {"path": "notes/hi.txt"}}

    def test_english_read_file_phrase(self):
        c = MockOllamaClient()
        raw = c.generate("", "read file reports/q1.md for me")
        data = json.loads(raw)
        assert data["tool"] == "read_file"
        assert data["args"]["path"] == "reports/q1.md"

    def test_spanish_lee_phrase(self):
        c = MockOllamaClient()
        raw = c.generate("", "lee notes/saludo.txt por favor")
        data = json.loads(raw)
        assert data == {"tool": "read_file", "args": {"path": "notes/saludo.txt"}}

    def test_english_list_phrase(self):
        c = MockOllamaClient()
        raw = c.generate("", "list notes/")
        data = json.loads(raw)
        assert data == {"tool": "list_dir", "args": {"path": "notes/"}}

    def test_list_dir_phrase(self):
        c = MockOllamaClient()
        raw = c.generate("", "list dir projects")
        data = json.loads(raw)
        assert data == {"tool": "list_dir", "args": {"path": "projects"}}

    def test_spanish_lista_phrase(self):
        c = MockOllamaClient()
        raw = c.generate("", "lista el directorio reports")
        data = json.loads(raw)
        assert data == {"tool": "list_dir", "args": {"path": "reports"}}

    def test_bare_list_defaults_to_root(self):
        c = MockOllamaClient()
        raw = c.generate("", "list")
        data = json.loads(raw)
        assert data == {"tool": "list_dir", "args": {"path": ""}}

    def test_bare_ls_defaults_to_root(self):
        c = MockOllamaClient()
        raw = c.generate("", "ls")
        data = json.loads(raw)
        assert data == {"tool": "list_dir", "args": {"path": ""}}

    def test_write_beats_read_in_priority(self):
        # Writing takes precedence when both are technically matchable.
        c = MockOllamaClient()
        raw = c.generate("", "write 'read me' to notes/note.txt")
        data = json.loads(raw)
        assert data["tool"] == "write_file"


class TestMockCriticClient:
    def test_default_approves(self):
        c = MockCriticClient()
        data = json.loads(c.generate("", ""))
        assert data == {"verdict": "approve"}

    def test_reject_carries_reason(self):
        c = MockCriticClient(verdict="reject", reason="simulated denial")
        data = json.loads(c.generate("", ""))
        assert data == {"verdict": "reject", "reason": "simulated denial"}
