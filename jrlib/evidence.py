"""Normalize tool failures into one evidence record."""

from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone

CATEGORIES = {
    "JAC_SYNTAX_ERROR",
    "JAC_TYPE_ERROR",
    "JAC_RUNTIME_ERROR",
    "BROKEN_IMPORT",
    "BUILD_FAILURE",
    "TEST_FAILURE",
    "UNHANDLED_EXCEPTION",
    "WALKER_FAILURE",
    "GRAPH_INCONSISTENCY",
    "STATE_INVARIANT_FAILURE",
    "API_CONTRACT_FAILURE",
    "TIMEOUT",
    "RESOURCE_EXHAUSTION",
    "PARSER_FAILURE",
    "MEMORY_SAFETY_FAILURE",
    "UNDEFINED_BEHAVIOR",
    "CONFIGURATION_ERROR",
}

_LINE = re.compile(r"([A-Za-z0-9_./-]+\.jac):(\d+)")
_PY_LINE = re.compile(r'File "([^"]+\.jac)", line (\d+)')


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def classify_output(tool: str, stdout: str, stderr: str, exit_code: int, timed_out: bool) -> str:
    blob = f"{stdout}\n{stderr}"
    if timed_out:
        return "TIMEOUT"
    if tool == "jac_test" and exit_code != 0:
        return "TEST_FAILURE"
    event = _event_category(stdout)
    if event:
        return event
    lowered = blob.lower()
    if "resource temporarily unavailable" in lowered or "blockingioerror" in lowered:
        return "RESOURCE_EXHAUSTION"
    if "error[e000" in lowered or "syntax error" in lowered or "unexpected token" in lowered or "missing ')'" in lowered:
        return "JAC_SYNTAX_ERROR"
    if (
        "importerror" in lowered
        or "modulenotfounderror" in lowered
        or "cannot import" in lowered
        or "no module named" in lowered
        or "module not found" in lowered
    ):
        return "BROKEN_IMPORT"
    if "traceback" in lowered or "unhandled" in lowered:
        return "UNHANDLED_EXCEPTION"
    if tool == "jac_check" and exit_code != 0:
        if "type" in lowered or "incompatible" in lowered or "error[" in lowered:
            return "JAC_TYPE_ERROR"
        return "CONFIGURATION_ERROR"
    if exit_code != 0 and tool == "jac_run":
        return "JAC_RUNTIME_ERROR"
    return ""


def _event_category(stdout: str) -> str:
    for line in stdout.splitlines():
        if "JACRIFT_EVENT" not in line:
            continue
        if "{" in line:
            # Category is taken only from the allowlist, later.
            match = re.search(r'"category"\s*:\s*"([A-Z_]+)"', line)
            if match and match.group(1) in CATEGORIES:
                return match.group(1)
        if "STATE_INVARIANT_FAILURE" in line or "complete_before_verification" in line:
            return "STATE_INVARIANT_FAILURE"
        if "WALKER_FAILURE" in line:
            return "WALKER_FAILURE"
    if "STATE_INVARIANT_FAILURE" in stdout or "complete_before_verification" in stdout:
        return "STATE_INVARIANT_FAILURE"
    if "WALKER_FAILURE" in stdout:
        return "WALKER_FAILURE"
    return ""


def _display_path(file: str) -> str:
    marker = "/repository/"
    if marker in file:
        return file.split(marker, 1)[1]
    return file


def _library_frame(file: str) -> bool:
    lowered = file.replace("\\", "/")
    return "site-packages/" in lowered or "/jaclang/" in lowered


def locate(stdout: str, stderr: str, fallback_file: str) -> tuple[str, int]:
    blob = stderr + "\n" + stdout
    found = [(match.group(1), int(match.group(2))) for match in _PY_LINE.finditer(blob)]
    found.extend((match.group(1), int(match.group(2))) for match in _LINE.finditer(blob))
    project = [(file, line) for file, line in found if not _library_frame(file)]
    if project:
        return _display_path(project[0][0]), project[0][1]
    for line in stdout.splitlines():
        if "JACRIFT_EVENT" not in line or '"file"' not in line:
            continue
        file_match = re.search(r'"file"\s*:\s*"([^"]+)"', line)
        line_match = re.search(r'"line"\s*:\s*(\d+)', line)
        if file_match:
            return _display_path(file_match.group(1)), int(line_match.group(1)) if line_match else 0
    if found:
        return _display_path(found[0][0]), found[0][1]
    return fallback_file, 0


def fingerprint(category: str, file: str, line: int, exit_code: int, stdout: str, stderr: str) -> str:
    marker = ""
    for line_text in (stdout + "\n" + stderr).splitlines():
        if line_text.strip():
            marker = line_text.strip()[:180]
            break
    raw = f"{category}|{file}|{line}|{exit_code}|{marker}"
    return hashlib.sha256(raw.encode("utf-8", "replace")).hexdigest()[:16]


def make_evidence(
    job_id: str,
    source: str,
    category: str,
    command: list,
    exit_code: int,
    stdout: str,
    stderr: str,
    file: str,
    line: int,
    execution_id: str,
    timed_out: bool = False,
) -> dict:
    if category not in CATEGORIES:
        category = "CONFIGURATION_ERROR"
    return {
        "evidence_id": "ev-" + fingerprint(category, file, line, exit_code, stdout, stderr),
        "job_id": job_id,
        "source": source,
        "category": category,
        "execution_id": execution_id,
        "file": file,
        "line": line,
        "command": command,
        "exit_code": exit_code,
        "stdout": stdout,
        "stderr": stderr,
        "reproducible": False,
        "success_count": 0,
        "attempt_count": 0,
        "minimized": False,
        "minimize_reason": "",
        "original_input": "",
        "minimal_input": "",
        "input_kind": "none",
        "counter_outcome": "not_run",
        "signature": fingerprint(category, file, line, exit_code, stdout, stderr),
        "timestamp": now_iso(),
        "timed_out": timed_out,
        "tool": command[0] if command else source,
    }
