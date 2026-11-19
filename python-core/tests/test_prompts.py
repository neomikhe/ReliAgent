"""El prompt del agente debe describir exactamente las herramientas que el
crítico determinista acepta; si divergen, el LLM real propone herramientas
que se rechazan o ignora herramientas que existen."""

from __future__ import annotations

import re
from pathlib import Path

from reliagent_python.critic import _KNOWN_TOOLS

PROMPTS = Path(__file__).resolve().parents[1] / "src" / "reliagent_python" / "prompts"


def _documented_tools(prompt: str) -> set[str]:
    # Herramientas documentadas como "- `nombre(args)`" en la sección de tools.
    return set(re.findall(r"^- `([a-z_]+)\(", prompt, re.MULTILINE))


def test_agent_prompt_documents_every_known_tool():
    prompt = (PROMPTS / "system_agent.md").read_text(encoding="utf-8")
    assert _documented_tools(prompt) == set(_KNOWN_TOOLS)
