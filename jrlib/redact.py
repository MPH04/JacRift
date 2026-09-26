"""Bound untrusted tool output and strip credential-shaped text."""

from __future__ import annotations

import re

_PATTERNS = (
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"glpat-[A-Za-z0-9_\-]{20,}"),
    re.compile(r"xox[baprs]-[A-Za-z0-9\-]{10,}"),
    re.compile(r"Bearer\s+[A-Za-z0-9._\-]{8,}", re.IGNORECASE),
    re.compile(
        r"(?i)(aws_secret_access_key|aws_access_key_id|api[_-]?key|secret|token|password|authorization)"
        r"(\s*[=:]\s*)(\S+)"
    ),
)


def redact(text: str, limit: int = 8000) -> str:
    if text is None:
        return ""
    cleaned = str(text)
    cleaned = _PATTERNS[0].sub("[redacted-aws-access-key]", cleaned)
    cleaned = _PATTERNS[1].sub("[redacted-github-token]", cleaned)
    cleaned = _PATTERNS[2].sub("[redacted-github-token]", cleaned)
    cleaned = _PATTERNS[3].sub("[redacted-gitlab-token]", cleaned)
    cleaned = _PATTERNS[4].sub("[redacted-slack-token]", cleaned)
    cleaned = _PATTERNS[5].sub("Bearer [redacted]", cleaned)
    cleaned = _PATTERNS[6].sub(r"\1\2[redacted]", cleaned)
    cleaned = cleaned.replace("\x00", "")
    if len(cleaned) > limit:
        return cleaned[:limit] + "\n…[truncated]"
    return cleaned
