"""JSON-RPC 2.0 NDJSON server tests.

We drive `serve()` with in-memory stdin/stdout streams rather than spawning
a subprocess. The cross-process integration test (spawning the real Python
via `std::process::Command`) lives on the Rust side.
"""

from __future__ import annotations

import io
import json

from reliagent_python.main import serve


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


class TestAgentRun:
    def test_agent_run_happy_path(self):
        responses = _drive(
            [
                {
                    "jsonrpc": "2.0",
                    "id": 7,
                    "method": "agent.run",
                    "params": {"prompt": "write 'hola' to notes/hi.txt"},
                }
            ]
        )
        assert len(responses) == 1
        result = responses[0]["result"]
        assert result["verdict"] == "approve"
        assert result["proposal"]["args"]["path"] == "notes/hi.txt"

    def test_agent_run_rejects_bad_request(self):
        responses = _drive(
            [
                {
                    "jsonrpc": "2.0",
                    "id": 8,
                    "method": "agent.run",
                    "params": {"prompt": "what is love?"},
                }
            ]
        )
        result = responses[0]["result"]
        assert result["verdict"] == "reject"
        assert result["critic_stage"] == "deterministic"

    def test_agent_run_requires_prompt(self):
        responses = _drive(
            [{"jsonrpc": "2.0", "id": 9, "method": "agent.run", "params": {}}]
        )
        assert "error" in responses[0]
        assert responses[0]["error"]["code"] == -32602


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
