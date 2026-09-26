"""Stable job API used by the Jac server and the tests."""

from __future__ import annotations

import json
import shutil
import threading

from jrlib.jobs import (
    job_dir,
    list_job_ids,
    load_state,
    read_events,
    read_log,
    request_cancel,
    require_job_id,
)
from jrlib.pipeline import run_job, start_job
from jrlib.sandbox import SandboxError, backend_for
from jrlib.validate import validate_submission


def _missing(job_id: str) -> dict:
    return {"ok": False, "error": "job_not_found", "job_id": job_id}


def create_job(repository_url: str, authorization_confirmed: bool, scope: str = "repository_only", background: bool = True) -> dict:
    checked = validate_submission(repository_url, authorization_confirmed, scope)
    if not checked["ok"]:
        return {"ok": False, "error": checked["error"], "job_id": "", "status": ""}
    started = start_job(repository_url, True, "repository_only")
    if not started["ok"]:
        return started
    job_id = started["job_id"]
    if background:
        threading.Thread(target=run_job, args=(job_id,), daemon=True).start()
        return {"ok": True, "error": "", "job_id": job_id, "status": "QUEUED"}
    final = run_job(job_id)
    return {"ok": final.get("status") == "COMPLETE", "error": final.get("error", ""), "job_id": job_id, "status": final.get("status", "")}


def list_jobs() -> dict:
    rows = []
    for job_id in list_job_ids():
        state = load_state(job_id)
        rows.append({
            "job_id": job_id,
            "status": state.get("status", ""),
            "phase": state.get("phase", ""),
            "repository_url": state.get("repository_url", ""),
            "error": state.get("error", ""),
        })
    return {"ok": True, "jobs": rows}


def get_job(job_id: str) -> dict:
    try:
        require_job_id(job_id)
    except ValueError:
        return {"ok": False, "error": "invalid_job_id", "job_id": str(job_id)}
    state = load_state(job_id)
    if not state:
        return _missing(job_id)
    root = job_dir(job_id)
    findings = _read_json_list(root / "findings.json")
    graph = _read_json_obj(root / "graph.json")
    manifest = _read_json_obj(root / "manifest.json")
    from jrlib.jobs import display_stages

    return {
        "ok": True,
        "error": "",
        "job_id": job_id,
        "status": state.get("status", ""),
        "phase": state.get("phase", ""),
        "job_error": state.get("error", ""),
        "repository_url": state.get("repository_url", ""),
        "authorization_confirmed": True,
        "scope": state.get("scope", "repository_only"),
        "created_at": state.get("created_at", ""),
        "updated_at": state.get("updated_at", ""),
        "metrics": state.get("metrics", {}),
        "stages": display_stages(state.get("phase", ""), state.get("status", "")),
        "manifest": {
            "project_type": manifest.get("project_type", ""),
            "jac_files": len(manifest.get("jac_files", [])),
            "tests": len(manifest.get("tests", [])),
            "entrypoints": manifest.get("safe_entrypoints", []),
            "recommended_checks": manifest.get("recommended_checks", []),
        },
        "findings": [_public_finding(item) for item in findings],
        "graph": graph,
        "log": read_log(job_id),
        "report": (root / "report.md").read_text(encoding="utf-8") if (root / "report.md").is_file() else "",
        "events": read_events(job_id),
    }


def get_log(job_id: str) -> dict:
    if not _exists(job_id):
        return _missing(job_id)
    return {"ok": True, "job_id": job_id, "log": read_log(job_id)}


def get_events(job_id: str) -> dict:
    if not _exists(job_id):
        return _missing(job_id)
    return {"ok": True, "job_id": job_id, "events": read_events(job_id)}


def get_findings(job_id: str) -> dict:
    if not _exists(job_id):
        return _missing(job_id)
    return {"ok": True, "job_id": job_id, "findings": _read_json_list(job_dir(job_id) / "findings.json")}


def get_report(job_id: str) -> dict:
    if not _exists(job_id):
        return _missing(job_id)
    path = job_dir(job_id) / "report.md"
    return {"ok": True, "job_id": job_id, "report": path.read_text(encoding="utf-8") if path.is_file() else ""}


def reproduce(job_id: str, finding_id: str) -> dict:
    if not _exists(job_id):
        return _missing(job_id)
    findings = _read_json_list(job_dir(job_id) / "findings.json")
    finding = None
    for item in findings:
        if item.get("finding_id") == finding_id:
            finding = item
            break
    if finding is None:
        return {"ok": False, "error": "finding_not_found", "job_id": job_id}
    command = (finding.get("reproducer") or {}).get("command") or []
    if not isinstance(command, list) or len(command) < 2:
        return {"ok": False, "error": "no_reproducer", "job_id": job_id}
    minimal = (finding.get("reproducer") or {}).get("minimal") or ""
    original = (finding.get("reproducer") or {}).get("original") or ""
    payload = minimal or original
    env = {"JACRIFT_INPUT": payload} if payload else None
    try:
        sandbox = backend_for()
        sandbox.create(job_dir(job_id))
        # Reuse the already cloned workspace. create() does not wipe it.
        attempts = []
        matched = 0
        for _ in range(3):
            result = sandbox.run([str(part) for part in command], timeout=40, env=env, network=False)
            ok = int(result.get("exit_code", 1)) == 0 or finding.get("category") not in {"STATE_INVARIANT_FAILURE", "WALKER_FAILURE"}
            text = (result.get("stdout") or "") + (result.get("stderr") or "")
            if finding.get("category") == "STATE_INVARIANT_FAILURE":
                ok = "complete_before_verification" in text or "STATE_INVARIANT_FAILURE" in text
            elif finding.get("category") == "WALKER_FAILURE":
                ok = "WALKER_FAILURE" in text
            elif finding.get("category") in {"TEST_FAILURE", "JAC_TYPE_ERROR", "JAC_SYNTAX_ERROR", "BROKEN_IMPORT", "UNHANDLED_EXCEPTION", "JAC_RUNTIME_ERROR"}:
                ok = int(result.get("exit_code", 0)) != 0
            if ok:
                matched += 1
            attempts.append({"exit_code": result.get("exit_code"), "matched": ok, "timed_out": result.get("timed_out", False)})
    except SandboxError as exc:
        return {"ok": False, "error": str(exc), "job_id": job_id}
    return {
        "ok": True,
        "job_id": job_id,
        "finding_id": finding_id,
        "matched": matched,
        "attempts": attempts,
        "reproducible": matched == 3,
    }


def delete_job(job_id: str) -> dict:
    try:
        require_job_id(job_id)
    except ValueError:
        return {"ok": False, "error": "invalid_job_id", "job_id": str(job_id)}
    state = load_state(job_id)
    if not state:
        return _missing(job_id)
    if state.get("status") not in {"COMPLETE", "FAILED", "CANCELLED"}:
        request_cancel(job_id)
        return {"ok": True, "job_id": job_id, "status": "CANCELLED", "deleted": False}
    shutil.rmtree(job_dir(job_id), ignore_errors=True)
    return {"ok": True, "job_id": job_id, "status": "CANCELLED", "deleted": True}


def _exists(job_id: str) -> bool:
    try:
        require_job_id(job_id)
    except ValueError:
        return False
    return bool(load_state(job_id))


def _read_json_list(path) -> list:
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    return data if isinstance(data, list) else []


def _read_json_obj(path) -> dict:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def _public_finding(item: dict) -> dict:
    hypothesis = item.get("hypothesis") or {}
    counter = item.get("counter_evidence") or {}
    reproducer = item.get("reproducer") or {}
    return {
        "finding_id": item.get("finding_id", ""),
        "category": item.get("category", ""),
        "status": item.get("status", ""),
        "title": item.get("title", ""),
        "file": item.get("file", ""),
        "line": item.get("line", 0),
        "claim": item.get("claim", ""),
        "reproducible": bool(item.get("reproducible")),
        "reproduction_count": item.get("reproduction_count", 0),
        "attempt_count": item.get("attempt_count", 0),
        "minimized": bool(item.get("minimized")),
        "hypothesis": hypothesis.get("text", "") if isinstance(hypothesis, dict) else "",
        "hypothesis_status": hypothesis.get("status", "") if isinstance(hypothesis, dict) else "",
        "counter_evidence": counter.get("text", "") if isinstance(counter, dict) else "",
        "counter_status": counter.get("status", "") if isinstance(counter, dict) else "",
        "limitations": item.get("limitations", []),
        "reproducer": reproducer,
        "stdout_excerpt": item.get("stdout_excerpt", ""),
        "stderr_excerpt": item.get("stderr_excerpt", ""),
    }
