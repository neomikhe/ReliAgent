"""Agent ↔ critic loop.

The orchestrator owns the basic two-turn flow:

1. `agent_client.generate(system_agent, user_prompt)` → raw JSON string.
2. Parse; if malformed → auto-reject.
3. Run deterministic critic (`critic.review_proposal`).
4. If still `approve`, optionally run a second-layer LLM critic (can only
   downgrade to reject, never upgrade to approve).
5. Return a bundled `AgentRunResult`.

No filesystem side-effects live in this module. The Rust kernel is the sole
executor of mutating tool calls.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

from reliagent_python.critic import CriticVerdict, review_proposal
from reliagent_python.llm_client import LLMClient

_PROMPTS_DIR = Path(__file__).parent / "prompts"


def _read_prompt(name: str) -> str:
    return (_PROMPTS_DIR / name).read_text(encoding="utf-8")


@dataclass
class AgentRunResult:
    proposal: dict[str, Any] | None
    verdict: str  # "approve" | "reject"
    reason: str = ""
    agent_raw: str = ""
    critic_stage: str = ""  # "parse" | "deterministic" | "llm" | "ok"
    trace: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Orchestrator:
    agent_client: LLMClient
    llm_critic_client: LLMClient | None = None

    def run(self, prompt: str) -> AgentRunResult:
        trace: list[str] = []
        system_agent = _read_prompt("system_agent.md")
        raw = self.agent_client.generate(system_agent, prompt)
        trace.append(f"agent.raw_bytes={len(raw)}")

        try:
            proposal = json.loads(raw)
        except json.JSONDecodeError as e:
            return AgentRunResult(
                proposal=None,
                verdict="reject",
                reason=f"agent produced invalid JSON: {e}",
                agent_raw=raw,
                critic_stage="parse",
                trace=trace,
            )

        verdict = review_proposal(proposal)
        trace.append(f"deterministic_critic.verdict={verdict.verdict}")
        if verdict.verdict == "reject":
            return AgentRunResult(
                proposal=proposal if isinstance(proposal, dict) else None,
                verdict="reject",
                reason=verdict.reason,
                agent_raw=raw,
                critic_stage="deterministic",
                trace=trace,
            )

        if self.llm_critic_client is not None:
            system_critic = _read_prompt("system_critic.md")
            critic_raw = self.llm_critic_client.generate(
                system_critic, json.dumps(proposal)
            )
            llm_verdict = _parse_llm_critic_verdict(critic_raw)
            trace.append(f"llm_critic.verdict={llm_verdict.verdict}")
            if llm_verdict.verdict == "reject":
                return AgentRunResult(
                    proposal=proposal,
                    verdict="reject",
                    reason=llm_verdict.reason,
                    agent_raw=raw,
                    critic_stage="llm",
                    trace=trace,
                )

        return AgentRunResult(
            proposal=proposal,
            verdict="approve",
            reason="",
            agent_raw=raw,
            critic_stage="ok",
            trace=trace,
        )


def _parse_llm_critic_verdict(raw: str) -> CriticVerdict:
    """Be tolerant of the LLM critic not returning perfect JSON. A reject-by-
    default policy here would be overly aggressive: the deterministic critic
    already passed, so on parse failure we conservatively reject but
    distinguish the reason.
    """
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return CriticVerdict("reject", "llm critic returned invalid JSON")
    if not isinstance(data, dict):
        return CriticVerdict("reject", "llm critic returned non-object")
    verdict = data.get("verdict")
    if verdict == "approve":
        return CriticVerdict("approve")
    reason = data.get("reason") or "rejected by llm critic"
    return CriticVerdict("reject", reason)
