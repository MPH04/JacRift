"""Per-job state under var/jobs/<id>/. One campaign file is not the product."""

from __future__ import annotations

import json
import os
import re
import secrets
import threading
from datetime import datetime, timezone
from pathlib import Path

from jrlib.redact import redact

JOB_ID = re.compile(r"^JR-[0-9A-F]{6}$")
_LOCKS: dict[str, threading.Lock] = {}
_LOCKS_GUARD = threading.Lock()

PHASES = (
    "QUEUED",
    "PREPARING_SANDBOX",
    "CLONING",
    "INSPECTING",
    "STATIC_ANALYSIS",
    "BUILDING",
    "TESTING",
    "RUNTIME_ANALYSIS",
    "MUTATION",
    "REPRODUCING",
    "MINIMIZING",
    "TRIAGING",
    "COMPLETE",
)

TERMINAL = {"COMPLETE", "FAILED", "CANCELLED"}

# Labels shown on the analysis dashboard. Internal phases map onto these.
DISPLAY_STAGES = (
    "Repository Received",
    "Sandbox Created",
    "Repository Cloned",
    "Project Discovered",
    "Static Analysis",
    "Tests",
    "Runtime Analysis",
    "Reproduction",
    "Investigation",
    "Complete",
)

_PHASE_TO_STAGE = {
    "QUEUED": "Repository Received",
    "PREPARING_SANDBOX": "Sandbox Created",
    "CLONING": "Repository Cloned",
    "INSPECTING": "Project Discovered",
    "STATIC_ANALYSIS": "Static Analysis",
    "BUILDING": "Static Analysis",
    "TESTING": "Tests",
    "RUNTIME_ANALYSIS": "Runtime Analysis",
    "MUTATION": "Runtime Analysis",
    "REPRODUCING": "Reproduction",
    "MINIMIZING": "Reproduction",
    "TRIAGING": "Investigation",
    "COMPLETE": "Complete",
    "FAILED": "Complete",
    "CANCELLED": "Complete",
}


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def jobs_root() -> Path:
    root = repo_root() / "var" / "jobs"
    root.mkdir(parents=True, exist_ok=True)
    return root


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def new_job_id() -> str:
    for _ in range(8):
        job_id = "JR-" + secrets.token_hex(3).upper()
        if not job_dir(job_id).exists():
            return job_id
    raise RuntimeError("could not allocate a job id")


def require_job_id(job_id: str) -> str:
    if not isinstance(job_id, str) or not JOB_ID.match(job_id):
        raise ValueError("invalid job id")
    return job_id


def job_dir(job_id: str) -> Path:
    require_job_id(job_id)
    return jobs_root() / job_id


def job_lock(job_id: str) -> threading.Lock:
    with _LOCKS_GUARD:
        lock = _LOCKS.get(job_id)
        if lock is None:
            lock = threading.Lock()
            _LOCKS[job_id] = lock
        return lock


def _write_json(path: Path, payload: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def read_json(path: Path) -> dict:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def empty_metrics() -> dict:
    return {
        "jac_files": 0,
        "tests_discovered": 0,
        "checks_executed": 0,
        "runtime_executions": 0,
        "observations": 0,
        "reproduced_failures": 0,
        "findings": 0,
    }


def create_job_files(job_id: str, repository_url: str) -> dict:
    root = job_dir(job_id)
    for name in ("repository", "home", "tmp", "logs", "artifacts"):
        (root / name).mkdir(parents=True, exist_ok=True)
    state = {
        "schema": "jacrift.job.v1",
        "job_id": job_id,
        "status": "QUEUED",
        "phase": "QUEUED",
        "error": "",
        "repository_url": repository_url,
        "authorization_confirmed": True,
        "scope": "repository_only",
        "created_at": now_iso(),
        "updated_at": now_iso(),
        "metrics": empty_metrics(),
        "cancel_requested": False,
        "sandbox": "local",
    }
    _write_json(root / "state.json", state)
    (root / "events.jsonl").touch()
    (root / "logs" / "job.log").touch()
    (root / "findings.json").write_text("[]\n", encoding="utf-8")
    (root / "report.md").write_text("# JacRift report\n\nJob has not finished.\n", encoding="utf-8")
    (root / "job.lock").touch()
    return state


def load_state(job_id: str) -> dict:
    return read_json(job_dir(job_id) / "state.json")


def save_state(job_id: str, state: dict) -> None:
    state["updated_at"] = now_iso()
    _write_json(job_dir(job_id) / "state.json", state)


def update_state(job_id: str, **fields) -> dict:
    with job_lock(job_id):
        state = load_state(job_id)
        if not state:
            raise FileNotFoundError(job_id)
        state.update(fields)
        save_state(job_id, state)
        return state


def append_event(job_id: str, phase: str, event: str, **fields) -> dict:
    record = {
        "timestamp": now_iso(),
        "job_id": job_id,
        "phase": phase,
        "event": event,
    }
    for key, value in fields.items():
        if isinstance(value, str):
            record[key] = redact(value, 500)
        else:
            record[key] = value
    line = json.dumps(record, sort_keys=True)
    root = job_dir(job_id)
    with job_lock(job_id):
        with (root / "events.jsonl").open("a", encoding="utf-8") as handle:
            handle.write(line + "\n")
        detail = " ".join(f"{key}={record[key]}" for key in sorted(fields))
        text = redact(f"{record['timestamp']} {phase} {event} {detail}\n", 2000)
        with (root / "logs" / "job.log").open("a", encoding="utf-8") as handle:
            handle.write(text)
    return record


def display_stages(phase: str, status: str) -> list[dict]:
    current = _PHASE_TO_STAGE.get(phase, "Repository Received")
    if status in {"FAILED", "CANCELLED"}:
        current = _PHASE_TO_STAGE.get(phase, "Repository Received")
    names = list(DISPLAY_STAGES)
    if current not in names:
        current = names[0]
    index = names.index(current)
    rows = []
    for i, name in enumerate(names):
        if status == "COMPLETE" or i < index:
            state = "done"
        elif status in {"FAILED", "CANCELLED"} and i == index:
            state = status.lower()
        elif i == index and status not in TERMINAL:
            state = "current"
        elif status in {"FAILED", "CANCELLED"} and i > index:
            state = "pending"
        else:
            state = "pending"
        rows.append({"name": name, "state": state})
    return rows


def read_log(job_id: str, limit: int = 20000) -> str:
    path = job_dir(job_id) / "logs" / "job.log"
    if not path.is_file():
        return ""
    data = path.read_text(encoding="utf-8", errors="replace")
    return redact(data[-limit:], limit)


def read_events(job_id: str, limit: int = 200) -> list:
    path = job_dir(job_id) / "events.jsonl"
    if not path.is_file():
        return []
    rows = []
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows[-limit:]


def list_job_ids() -> list[str]:
    root = jobs_root()
    found = []
    for child in root.iterdir():
        if child.is_dir() and JOB_ID.match(child.name):
            found.append(child.name)
    found.sort(reverse=True)
    return found


def request_cancel(job_id: str) -> dict:
    state = load_state(job_id)
    if not state:
        raise FileNotFoundError(job_id)
    if state.get("status") in TERMINAL:
        return state
    return update_state(job_id, cancel_requested=True)


def cancelled(job_id: str) -> bool:
    return bool(load_state(job_id).get("cancel_requested"))
