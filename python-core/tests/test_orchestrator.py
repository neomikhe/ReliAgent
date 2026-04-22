"""Orchestrator end-to-end tests against mock clients."""

from __future__ import annotations

import json
from dataclasses import dataclass

from reliagent_python.llm_client import MockCriticClient, MockOllamaClient
from reliagent_python.orchestrator import Orchestrator


@dataclass
class _FixedClient:
    """Returns a canned response regardless of input."""

    raw: str

    def generate(self, system: str, user: str) -> str:
        del system, user
        return self.raw


class TestHappyPath:
    def test_mock_agent_approves_simple_write(self):
        orch = Orchestrator(agent_client=MockOllamaClient())
        r = orch.run("write 'hola' to notes/hi.txt")
        assert r.verdict == "approve"
        assert r.proposal == {
            "tool": "write_file",
            "args": {"path": "notes/hi.txt", "content": "hola"},
        }
        assert r.critic_stage == "ok"
        assert r.reason == ""

    def test_llm_critic_approves(self):
        orch = Orchestrator(
            agent_client=MockOllamaClient(),
            llm_critic_client=MockCriticClient(verdict="approve"),
        )
        r = orch.run("write 'hola' to notes/hi.txt")
        assert r.verdict == "approve"
        assert r.critic_stage == "ok"


class TestRejection:
    def test_agent_cannot_fulfill_request(self):
        """MockOllamaClient returns `{tool: null, reason: ...}` for
        prompts it can't parse. The deterministic critic rejects that."""
        orch = Orchestrator(agent_client=MockOllamaClient())
        r = orch.run("what is love?")
        assert r.verdict == "reject"
        assert r.critic_stage == "deterministic"

    def test_invalid_json_from_agent(self):
        orch = Orchestrator(agent_client=_FixedClient(raw="not json at all"))
        r = orch.run("anything")
        assert r.verdict == "reject"
        assert r.critic_stage == "parse"
        assert "invalid JSON" in r.reason

    def test_path_traversal_rejected_deterministically(self):
        proposal = {
            "tool": "write_file",
            "args": {"path": "../etc/passwd", "content": "x"},
        }
        orch = Orchestrator(agent_client=_FixedClient(raw=json.dumps(proposal)))
        r = orch.run("irrelevant")
        assert r.verdict == "reject"
        assert r.critic_stage == "deterministic"
        assert "parent traversal" in r.reason

    def test_llm_critic_can_downgrade_approval(self):
        """Even if the deterministic critic passes, the LLM critic can reject."""
        orch = Orchestrator(
            agent_client=MockOllamaClient(),
            llm_critic_client=MockCriticClient(
                verdict="reject", reason="vibes are off"
            ),
        )
        r = orch.run("write 'hola' to notes/hi.txt")
        assert r.verdict == "reject"
        assert r.critic_stage == "llm"
        assert r.reason == "vibes are off"

    def test_llm_critic_invalid_json_is_rejected(self):
        orch = Orchestrator(
            agent_client=MockOllamaClient(),
            llm_critic_client=_FixedClient(raw="garbage"),
        )
        r = orch.run("write 'hola' to notes/hi.txt")
        assert r.verdict == "reject"
        assert r.critic_stage == "llm"


class TestTrace:
    def test_trace_includes_stages(self):
        orch = Orchestrator(
            agent_client=MockOllamaClient(),
            llm_critic_client=MockCriticClient(verdict="approve"),
        )
        r = orch.run("write 'hola' to notes/hi.txt")
        # Three trace markers: agent raw bytes, deterministic, llm.
        assert any("agent.raw_bytes=" in t for t in r.trace)
        assert any("deterministic_critic.verdict=approve" in t for t in r.trace)
        assert any("llm_critic.verdict=approve" in t for t in r.trace)

    def test_result_is_serializable(self):
        orch = Orchestrator(agent_client=MockOllamaClient())
        r = orch.run("write 'x' to a.txt")
        # Round-trip through JSON to prove the bridge can send this over
        # the wire without tripping on non-serializable fields.
        round_tripped = json.loads(json.dumps(r.to_dict()))
        assert round_tripped["verdict"] == "approve"
