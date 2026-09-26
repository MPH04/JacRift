"""Replay a captured failure and drop input fields that are not required."""

from __future__ import annotations

import json

from jrlib.evidence import classify_output
from jrlib.jobs import append_event
from jrlib.sandbox import SandboxBackend


def _same(evidence: dict, result: dict) -> bool:
    if result.get("timed_out") and evidence.get("category") == "TIMEOUT":
        return True
    category = classify_output(
        _tool(evidence),
        result.get("stdout", ""),
        result.get("stderr", ""),
        int(result.get("exit_code", 1)),
        bool(result.get("timed_out")),
    )
    if evidence.get("category") in {"STATE_INVARIANT_FAILURE", "WALKER_FAILURE", "GRAPH_INCONSISTENCY"}:
        return category == evidence.get("category")
    if not category:
        return False
    return category == evidence.get("category") and int(result.get("exit_code", 1)) == int(evidence.get("exit_code", 1))


def _tool(evidence: dict) -> str:
    source = evidence.get("source", "")
    if source == "jac_test":
        return "jac_test"
    if source == "jac_check":
        return "jac_check"
    return "jac_run"


def replay(job_id: str, sandbox: SandboxBackend, evidence: dict, attempts: int = 5) -> dict:
    command = evidence.get("command") or []
    env = None
    if evidence.get("input_kind") == "json" and evidence.get("original_input"):
        env = {"JACRIFT_INPUT": evidence["original_input"]}
    success = 0
    last = {}
    for index in range(attempts):
        result = sandbox.run(command, timeout=40, env=env, network=False)
        last = result
        matched = _same(evidence, result)
        if matched:
            success += 1
        append_event(
            job_id,
            "REPRODUCING",
            "REPLAY_FINISHED",
            tool="jac",
            exit_code=result.get("exit_code", 1),
            attempt=index + 1,
            matched=matched,
            evidence_id=evidence.get("evidence_id", ""),
        )
    evidence["attempt_count"] = attempts
    evidence["success_count"] = success
    evidence["reproducible"] = attempts >= 3 and success * 5 >= attempts * 4
    evidence["replay_exit_code"] = last.get("exit_code", 1)
    return evidence


def minimize(job_id: str, sandbox: SandboxBackend, evidence: dict) -> dict:
    if not evidence.get("reproducible"):
        evidence["minimized"] = False
        evidence["minimize_reason"] = "not_reproducible"
        return evidence
    if evidence.get("input_kind") == "json" and evidence.get("original_input"):
        try:
            original = json.loads(evidence["original_input"])
        except json.JSONDecodeError:
            original = None
        if isinstance(original, dict) and original:
            reduced = _ddmin_keys(job_id, sandbox, evidence, original)
            evidence["minimal_input"] = json.dumps(reduced, sort_keys=True)
            evidence["minimized"] = True
            evidence["minimize_reason"] = "json_keys"
            append_event(
                job_id,
                "MINIMIZING",
                "MINIMIZED",
                evidence_id=evidence.get("evidence_id", ""),
                original=evidence["original_input"],
                minimal=evidence["minimal_input"],
            )
            return evidence
    command = evidence.get("command") or []
    if len(command) >= 3 and command[1] in {"check", "test", "run"}:
        evidence["minimized"] = True
        evidence["minimal_input"] = ""
        evidence["minimize_reason"] = "diagnostic_command"
        append_event(job_id, "MINIMIZING", "MINIMIZED", evidence_id=evidence.get("evidence_id", ""), reason="diagnostic_command")
        return evidence
    evidence["minimized"] = False
    evidence["minimize_reason"] = "not_attempted"
    return evidence


def _ddmin_keys(job_id: str, sandbox: SandboxBackend, evidence: dict, original: dict) -> dict:
    """Drop object keys, including the last one, while the failure signature holds.

    An empty object is a valid minimal input when the program's defaults still
    produce the same failure. A leftover unused key is not part of the trigger.
    """
    current = dict(original)
    for key in list(original.keys()):
        if key not in current:
            continue
        trial = dict(current)
        trial.pop(key, None)
        if _holds(sandbox, evidence, trial):
            current = trial
            append_event(job_id, "MINIMIZING", "DROPPED_FIELD", field=key, evidence_id=evidence.get("evidence_id", ""))
    if not _holds(sandbox, evidence, current):
        return original
    return current


def _holds(sandbox: SandboxBackend, evidence: dict, payload: dict) -> bool:
    result = sandbox.run(evidence.get("command") or [], timeout=40, env={"JACRIFT_INPUT": json.dumps(payload)}, network=False)
    return _same(evidence, result)
