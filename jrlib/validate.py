"""Repository submission checks. Fail closed on anything we will not clone."""

from __future__ import annotations

import re

_OWNER = r"[A-Za-z0-9](?:[A-Za-z0-9._-]{0,38})"
_REPO = r"[A-Za-z0-9._-]{1,100}"
_GITHUB = re.compile(rf"^https://github\.com/({_OWNER})/({_REPO})(?:\.git)?/?$")
_FIXTURE = re.compile(r"^fixture://([a-z0-9][a-z0-9-]{0,40})$")

# Built-in demonstration repositories. These are copied from this tree, never fetched.
FIXTURES = {
    "safe-buggy": "fixtures/safe_buggy",
}

_UNSUPPORTED = (
    "file://",
    "ssh://",
    "git://",
    "http://",
    "ftp://",
)


def validate_submission(repository_url: object, authorization_confirmed: object, scope: object) -> dict:
    """Return {ok, error, repository_url, kind, fixture, scope}."""
    if authorization_confirmed is not True:
        return _no("authorization_required")
    if scope != "repository_only":
        return _no("unsupported_scope")
    if not isinstance(repository_url, str):
        return _no("malformed_url")
    raw = repository_url.strip()
    if raw == "" or len(raw) > 300:
        return _no("malformed_url")
    if any(ch.isspace() for ch in raw) or "\\" in raw:
        return _no("malformed_url")
    lowered = raw.lower()
    if lowered.startswith("git@") or any(lowered.startswith(prefix) for prefix in _UNSUPPORTED):
        return _no("unsupported_scheme")
    if "@" in raw or ".." in raw:
        return _no("malformed_url")
    fixture = _FIXTURE.match(raw)
    if fixture:
        name = fixture.group(1)
        if name not in FIXTURES:
            return _no("unsupported_repository")
        return {
            "ok": True,
            "error": "",
            "repository_url": f"fixture://{name}",
            "kind": "fixture",
            "fixture": name,
            "scope": "repository_only",
        }
    match = _GITHUB.match(raw)
    if not match:
        if "://" in raw and not lowered.startswith("https://"):
            return _no("unsupported_scheme")
        if lowered.startswith("https://") and "github.com" not in lowered:
            return _no("unsupported_repository")
        return _no("malformed_url")
    owner, repo = match.group(1), match.group(2)
    if repo.endswith(".git"):
        repo = repo[: -len(".git")]
    if owner in {".", ".."} or repo in {".", "..", ""}:
        return _no("malformed_url")
    return {
        "ok": True,
        "error": "",
        "repository_url": f"https://github.com/{owner}/{repo}",
        "kind": "github",
        "fixture": "",
        "scope": "repository_only",
    }


def _no(error: str) -> dict:
    return {
        "ok": False,
        "error": error,
        "repository_url": "",
        "kind": "",
        "fixture": "",
        "scope": "",
    }
