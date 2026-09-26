"""One analysis job: sandbox, discovery, checks, replay, Jac investigation."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import traceback
from pathlib import Path

from jrlib.analyze import counter_verified, mutate_inputs, run_runtime, run_static, run_tests
from jrlib.discover import discover
from jrlib.jobs import (
    append_event,
    cancelled,
    create_job_files,
    job_dir,
    load_state,
    repo_root,
    update_state,
)
from jrlib.reproduce import minimize, replay
from jrlib.sandbox import SandboxError, backend_for, jac_binary
from jrlib.validate import FIXTURES, validate_submission


def start_job(repository_url: str, authorization_confirmed: object, scope: object) -> dict:
    checked = validate_submission(repository_url, authorization_confirmed, scope)
    if not checked["ok"]:
        return {"ok": False, "error": checked["error"], "job_id": "", "status": ""}
    from jrlib.jobs import new_job_id

    job_id = new_job_id()
    create_job_files(job_id, checked["repository_url"])
    append_event(job_id, "QUEUED", "JOB_CREATED", repository_url=checked["repository_url"])
    return {"ok": True, "error": "", "job_id": job_id, "status": "QUEUED", "request": checked}


def run_job(job_id: str) -> dict:
    state = load_state(job_id)
    if not state:
        raise FileNotFoundError(job_id)
    checked = validate_submission(state["repository_url"], True, "repository_only")
    root = job_dir(job_id)
    lock_path = root / "job.lock"
    lock_handle = lock_path.open("a")
    try:
        import fcntl

        fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        lock_handle.close()
        update_state(job_id, status="FAILED", error="job lock is already held")
        return load_state(job_id)
    sandbox = None
    try:
        if cancelled(job_id):
            return _finish_cancel(job_id)
        _phase(job_id, "PREPARING_SANDBOX")
        sandbox = backend_for(os.environ.get("JACRIFT_SANDBOX"))
        sandbox.create(root)
        append_event(job_id, "PREPARING_SANDBOX", "SANDBOX_CREATED", backend=type(sandbox).__name__)
        if cancelled(job_id):
            return _finish_cancel(job_id)
        _phase(job_id, "CLONING")
        if checked["kind"] == "fixture":
            source = repo_root() / FIXTURES[checked["fixture"]]
            if not source.is_dir():
                raise SandboxError("fixture directory is missing")
            sandbox.copy_tree(source)
            append_event(job_id, "CLONING", "FIXTURE_COPIED", fixture=checked["fixture"])
        else:
            sandbox.clone_repository(checked["repository_url"])
            append_event(job_id, "CLONING", "REPOSITORY_CLONED")
        if cancelled(job_id):
            return _finish_cancel(job_id)
        _phase(job_id, "INSPECTING")
        manifest = discover(root / "repository")
        (root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        metrics = load_state(job_id).get("metrics", {})
        metrics["jac_files"] = len(manifest["jac_files"])
        metrics["tests_discovered"] = len(manifest["tests"])
        update_state(job_id, metrics=metrics)
        append_event(job_id, "INSPECTING", "MANIFEST_WRITTEN", jac_files=len(manifest["jac_files"]), tests=len(manifest["tests"]))
        if cancelled(job_id):
            return _finish_cancel(job_id)
        _phase(job_id, "STATIC_ANALYSIS")
        static_evidence = run_static(job_id, sandbox, manifest["jac_files"])
        metrics = load_state(job_id)["metrics"]
        metrics["checks_executed"] = len(manifest["jac_files"][:24])
        update_state(job_id, metrics=metrics)
        _phase(job_id, "BUILDING")
        if manifest["build_files"]:
            append_event(
                job_id,
                "BUILDING",
                "BUILD_SKIPPED",
                reason="build files were recorded and not executed; repository instructions are untrusted",
            )
        else:
            append_event(job_id, "BUILDING", "BUILD_SKIPPED", reason="no recognized build file")
        if cancelled(job_id):
            return _finish_cancel(job_id)
        _phase(job_id, "TESTING")
        test_evidence = run_tests(job_id, sandbox, manifest["tests"])
        if cancelled(job_id):
            return _finish_cancel(job_id)
        _phase(job_id, "RUNTIME_ANALYSIS")
        runtime_input = {"verified": False, "action": "complete", "note": "padding", "unused": 1}
        entries = manifest.get("safe_entrypoints") or []
        runtime_evidence, _last = run_runtime(
            job_id,
            sandbox,
            entries,
            extra_env={"JACRIFT_INPUT": json.dumps(runtime_input)},
        )
        for item in runtime_evidence:
            if item["category"] == "STATE_INVARIANT_FAILURE":
                item["original_input"] = json.dumps(runtime_input)
                item["input_kind"] = "json"
        metrics = load_state(job_id)["metrics"]
        metrics["runtime_executions"] = len(entries)
        update_state(job_id, metrics=metrics)
        if cancelled(job_id):
            return _finish_cancel(job_id)
        _phase(job_id, "MUTATION")
        mutation_evidence = []
        experiments = []
        state_entry = _state_entry(entries, runtime_evidence)
        if state_entry:
            mutation_evidence, experiments = mutate_inputs(job_id, sandbox, state_entry, runtime_input)
            outcome = counter_verified(sandbox, state_entry)
            experiments.append(
                {
                    "id": "verified_true_control",
                    "hypothesis": "The COMPLETE marker depends on verification being false.",
                    "expected": "The same action with verified true does not emit the invariant.",
                    "observed": outcome,
                    "payload": {"verified": True, "action": "complete"},
                    "interpretation": "Supports the narrow verification hypothesis." if outcome == "disappears" else "The marker is not specific to an unverified order.",
                }
            )
            for item in runtime_evidence:
                if item["category"] == "STATE_INVARIANT_FAILURE":
                    item["counter_outcome"] = outcome
        else:
            append_event(job_id, "MUTATION", "MUTATION_SKIPPED", reason="no runtime entry accepted a bounded JSON input")
        evidence = _dedupe(static_evidence + test_evidence + runtime_evidence + mutation_evidence)
        if cancelled(job_id):
            return _finish_cancel(job_id)
        _phase(job_id, "REPRODUCING")
        interesting = [item for item in evidence if item.get("category")]
        interesting = interesting[:8]
        for item in interesting:
            replay(job_id, sandbox, item, attempts=5)
        if cancelled(job_id):
            return _finish_cancel(job_id)
        _phase(job_id, "MINIMIZING")
        for item in interesting:
            if item.get("reproducible"):
                minimize(job_id, sandbox, item)
        reproduced = len([item for item in interesting if item.get("reproducible")])
        metrics = load_state(job_id)["metrics"]
        metrics["observations"] = len(evidence)
        metrics["reproduced_failures"] = reproduced
        update_state(job_id, metrics=metrics)
        (root / "evidence.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
        (root / "experiments.json").write_text(json.dumps(experiments, indent=2) + "\n", encoding="utf-8")
        if cancelled(job_id):
            return _finish_cancel(job_id)
        _phase(job_id, "TRIAGING")
        _investigate(job_id, root)
        findings = json.loads((root / "findings.json").read_text(encoding="utf-8"))
        metrics = load_state(job_id)["metrics"]
        metrics["findings"] = len(findings)
        update_state(job_id, status="COMPLETE", phase="COMPLETE", error="", metrics=metrics)
        append_event(job_id, "COMPLETE", "JOB_COMPLETE", findings=len(findings))
        return load_state(job_id)
    except Exception as exc:
        message = str(exc) or exc.__class__.__name__
        append_event(job_id, load_state(job_id).get("phase", "FAILED"), "JOB_FAILED", error=message[:400])
        detail = traceback.format_exc()[-1500:]
        (root / "logs" / "traceback.log").write_text(detail, encoding="utf-8")
        update_state(job_id, status="FAILED", error=message[:500])
        if not (root / "report.md").is_file() or "has not finished" in (root / "report.md").read_text(encoding="utf-8"):
            (root / "report.md").write_text(
                "# JacRift report\n\nThe job failed before a finding report was written.\n\n"
                + message[:500]
                + "\n\nWhat remains unknown: the repository was not fully investigated.\n",
                encoding="utf-8",
            )
        return load_state(job_id)
    finally:
        lock_handle.close()


def _phase(job_id: str, phase: str) -> None:
    update_state(job_id, status=phase, phase=phase, error="")
    append_event(job_id, phase, "PHASE_STARTED")


def _finish_cancel(job_id: str) -> dict:
    phase = load_state(job_id).get("phase", "QUEUED")
    update_state(job_id, status="CANCELLED", error="cancelled")
    append_event(job_id, phase, "JOB_CANCELLED")
    return load_state(job_id)


def _dedupe(items: list[dict]) -> list[dict]:
    seen = set()
    out = []
    for item in items:
        key = item.get("signature") or item.get("evidence_id")
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
    return out


def _state_entry(entries: list[str], evidence: list[dict]) -> str:
    for item in evidence:
        if item.get("category") == "STATE_INVARIANT_FAILURE":
            command = item.get("command") or []
            if len(command) >= 3:
                return command[2]
    for rel in entries:
        if rel.endswith("runtime_entry.jac"):
            return rel
    return ""


def _investigate(job_id: str, root: Path) -> None:
    jac = jac_binary()
    script = repo_root() / "jac" / "investigate.jac"
    env = os.environ.copy()
    env["PATH"] = str(Path(jac).parent) + os.pathsep + env.get("PATH", "")
    proc = subprocess.run(
        [jac, "run", str(script), "--", "--job", str(root)],
        cwd=str(root),
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
        check=False,
    )
    log = (proc.stdout or "") + "\n" + (proc.stderr or "")
    (root / "logs" / "investigate.log").write_text(log[-20000:], encoding="utf-8")
    append_event(job_id, "TRIAGING", "INVESTIGATE_FINISHED", tool="jac", exit_code=proc.returncode)
    if proc.returncode != 0 or not (root / "findings.json").is_file():
        raise RuntimeError("Jac investigation failed: " + log[-400:])
