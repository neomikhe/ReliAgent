"""Deterministic critic tests.

These mirror the rejection heuristics documented in system_critic.md. Keep
them in sync with `critic.py` — if a heuristic is added there, add a test
here.
"""

from __future__ import annotations

import pytest

from reliagent_python.critic import review_proposal


def _ok(path: str = "notes/hello.txt", content: str = "hello") -> dict:
    return {"tool": "write_file", "args": {"path": path, "content": content}}


class TestShape:
    def test_non_dict_rejected(self):
        v = review_proposal("nope")  # type: ignore[arg-type]
        assert v.verdict == "reject"

    def test_missing_tool_rejected(self):
        v = review_proposal({"args": {}})
        assert v.verdict == "reject"
        assert "no tool" in v.reason

    def test_null_tool_uses_reason(self):
        v = review_proposal({"tool": None, "reason": "cannot satisfy"})
        assert v.verdict == "reject"
        assert v.reason == "cannot satisfy"

    def test_unknown_tool_rejected(self):
        v = review_proposal({"tool": "delete_everything", "args": {}})
        assert v.verdict == "reject"
        assert "unknown tool" in v.reason

    def test_missing_args_rejected(self):
        v = review_proposal({"tool": "write_file"})
        assert v.verdict == "reject"

    def test_missing_path_rejected(self):
        v = review_proposal({"tool": "write_file", "args": {"content": "x"}})
        assert v.verdict == "reject"

    def test_empty_path_rejected(self):
        v = review_proposal(_ok(path=""))
        assert v.verdict == "reject"

    def test_non_string_content_rejected(self):
        v = review_proposal(
            {"tool": "write_file", "args": {"path": "x.txt", "content": 123}}
        )
        assert v.verdict == "reject"


class TestPath:
    @pytest.mark.parametrize("path", ["/etc/passwd", "\\windows\\system32\\x"])
    def test_absolute_paths_rejected(self, path: str):
        v = review_proposal(_ok(path=path))
        assert v.verdict == "reject"
        assert "absolute" in v.reason

    def test_windows_drive_rejected(self):
        v = review_proposal(_ok(path="C:\\secret.txt"))
        assert v.verdict == "reject"
        assert "drive letter" in v.reason

    @pytest.mark.parametrize(
        "path",
        ["../etc/passwd", "a/../b", "a\\..\\b", "..", "subdir/../../etc"],
    )
    def test_parent_traversal_rejected(self, path: str):
        v = review_proposal(_ok(path=path))
        assert v.verdict == "reject"
        assert "parent traversal" in v.reason

    def test_null_byte_rejected(self):
        v = review_proposal(_ok(path="notes/\0evil.txt"))
        assert v.verdict == "reject"
        assert "null byte" in v.reason

    @pytest.mark.parametrize(
        "path",
        [".ssh/id_rsa", ".aws/credentials", ".gnupg/secring.gpg", ".config/gh/hosts.yml"],
    )
    def test_sensitive_prefixes_rejected(self, path: str):
        v = review_proposal(_ok(path=path))
        assert v.verdict == "reject"
        assert "sensitive prefix" in v.reason

    def test_sensitive_prefix_nested_rejected(self):
        v = review_proposal(_ok(path="home/.ssh/authorized_keys"))
        assert v.verdict == "reject"


class TestContent:
    def test_openai_like_secret_rejected(self):
        v = review_proposal(_ok(content="token = sk-" + "A" * 40))
        assert v.verdict == "reject"

    def test_aws_key_rejected(self):
        v = review_proposal(_ok(content="AWS_KEY=AKIA" + "A" * 16))
        assert v.verdict == "reject"

    def test_github_pat_rejected(self):
        v = review_proposal(_ok(content="token: ghp_" + "a" * 36))
        assert v.verdict == "reject"

    def test_private_key_header_rejected(self):
        v = review_proposal(
            _ok(content="-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIB...\n")
        )
        assert v.verdict == "reject"


class TestHappyPath:
    def test_simple_write_approved(self):
        v = review_proposal(_ok())
        assert v.verdict == "approve"
        assert v.reason == ""

    def test_nested_relative_path_approved(self):
        v = review_proposal(_ok(path="projects/2026/notes.md"))
        assert v.verdict == "approve"


class TestReadFile:
    def test_simple_read_approved(self):
        v = review_proposal({"tool": "read_file", "args": {"path": "notes/a.txt"}})
        assert v.verdict == "approve"

    def test_read_absolute_rejected(self):
        v = review_proposal({"tool": "read_file", "args": {"path": "/etc/passwd"}})
        assert v.verdict == "reject"
        assert "absolute" in v.reason

    def test_read_parent_traversal_rejected(self):
        v = review_proposal({"tool": "read_file", "args": {"path": "../secrets"}})
        assert v.verdict == "reject"
        assert "parent traversal" in v.reason

    def test_read_sensitive_prefix_rejected(self):
        v = review_proposal(
            {"tool": "read_file", "args": {"path": ".ssh/id_rsa"}}
        )
        assert v.verdict == "reject"

    def test_read_empty_path_rejected(self):
        v = review_proposal({"tool": "read_file", "args": {"path": ""}})
        assert v.verdict == "reject"

    def test_read_missing_path_rejected(self):
        v = review_proposal({"tool": "read_file", "args": {}})
        assert v.verdict == "reject"

    def test_read_ignores_content_arg(self):
        # content is irrelevant for read — should not trigger secret scan.
        v = review_proposal(
            {
                "tool": "read_file",
                "args": {"path": "notes/a.txt", "content": "sk-" + "A" * 40},
            }
        )
        assert v.verdict == "approve"


class TestListDir:
    def test_simple_list_approved(self):
        v = review_proposal({"tool": "list_dir", "args": {"path": "notes"}})
        assert v.verdict == "approve"

    def test_list_empty_path_approved(self):
        # Empty path means sandbox root — must be allowed.
        v = review_proposal({"tool": "list_dir", "args": {"path": ""}})
        assert v.verdict == "approve"

    def test_list_missing_path_approved(self):
        # Missing path also means root.
        v = review_proposal({"tool": "list_dir", "args": {}})
        assert v.verdict == "approve"

    def test_list_parent_traversal_rejected(self):
        v = review_proposal({"tool": "list_dir", "args": {"path": "../"}})
        assert v.verdict == "reject"
        assert "parent traversal" in v.reason

    def test_list_absolute_rejected(self):
        v = review_proposal({"tool": "list_dir", "args": {"path": "/etc"}})
        assert v.verdict == "reject"

    def test_list_windows_drive_rejected(self):
        v = review_proposal({"tool": "list_dir", "args": {"path": "C:\\Windows"}})
        assert v.verdict == "reject"

    def test_list_path_must_be_string(self):
        v = review_proposal({"tool": "list_dir", "args": {"path": 42}})
        assert v.verdict == "reject"
