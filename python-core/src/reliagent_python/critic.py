"""Rule-based critic.

The deterministic critic runs BEFORE any LLM-based critic. It enforces the
rejection heuristics listed in `prompts/system_critic.md`. An LLM critic may
be layered on top later — it can only reject further, never approve what
this module rejected.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

_SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA|OPENSSH|EC|DSA|PGP) PRIVATE KEY-----"),
    re.compile(r"AKIA[0-9A-Z]{16}"),  # AWS access key
    re.compile(r"sk-[A-Za-z0-9]{20,}"),  # OpenAI-like secret
    re.compile(r"ghp_[A-Za-z0-9]{30,}"),  # GitHub PAT
    re.compile(r"xox[aboprs]-[A-Za-z0-9-]{10,}"),  # Slack tokens
)

_DANGEROUS_PATH_PREFIXES = (
    ".ssh/",
    ".aws/",
    ".gnupg/",
    ".config/gh/",
)

_KNOWN_TOOLS = frozenset({"write_file", "read_file", "list_dir"})


@dataclass
class CriticVerdict:
    verdict: str  # "approve" | "reject"
    reason: str = ""

    def to_dict(self) -> dict:
        d: dict = {"verdict": self.verdict}
        if self.verdict == "reject":
            d["reason"] = self.reason
        return d


def review_proposal(proposal: dict) -> CriticVerdict:
    """Run deterministic checks on a tool proposal.

    Returns an `approve` verdict only if the proposal is well-formed AND does
    not trip any of the heuristics. Does not call out to any LLM.
    """
    if not isinstance(proposal, dict):
        return CriticVerdict("reject", "proposal is not an object")

    tool = proposal.get("tool")
    if tool is None:
        return CriticVerdict("reject", proposal.get("reason") or "no tool proposed")
    if tool not in _KNOWN_TOOLS:
        return CriticVerdict("reject", f"unknown tool: {tool!r}")

    args = proposal.get("args")
    if not isinstance(args, dict):
        return CriticVerdict("reject", "args is missing or not an object")

    path = args.get("path")
    # list_dir allows an empty path (== sandbox root); the other tools
    # require a concrete path string.
    if tool == "list_dir":
        if path is None:
            path = ""
        if not isinstance(path, str):
            return CriticVerdict("reject", "path must be a string")
    else:
        if not isinstance(path, str) or not path:
            return CriticVerdict("reject", "path is missing or empty")

    if tool == "write_file":
        content = args.get("content")
        if not isinstance(content, str):
            return CriticVerdict("reject", "content is missing or not a string")
    else:
        content = None

    # Path heuristics — these mirror (not replace) the Rust policy engine.
    # The Rust kernel is still authoritative; this is early rejection.
    # list_dir with empty path means "sandbox root" and is safe to skip.
    if path:
        if "\0" in path:
            return CriticVerdict("reject", "path contains a null byte")
        if path.startswith("/") or path.startswith("\\"):
            return CriticVerdict("reject", "path is absolute")
        if re.match(r"^[A-Za-z]:", path):
            return CriticVerdict(
                "reject", "path starts with a Windows drive letter"
            )
        # Reject any segment exactly equal to "..", in any OS-y separator.
        segments = re.split(r"[\\/]+", path)
        if any(seg == ".." for seg in segments):
            return CriticVerdict("reject", "path contains parent traversal")
        for bad in _DANGEROUS_PATH_PREFIXES:
            if path.startswith(bad) or f"/{bad}" in path or f"\\{bad}" in path:
                return CriticVerdict("reject", f"path targets sensitive prefix: {bad}")

    # Content heuristics — only meaningful for write_file.
    if content is not None:
        for pat in _SECRET_PATTERNS:
            if pat.search(content):
                return CriticVerdict(
                    "reject", "content matches a known secret/credential pattern"
                )

    return CriticVerdict("approve")
