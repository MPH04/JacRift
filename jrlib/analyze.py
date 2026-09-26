"""Static checks, tests, runtime, and bounded input mutation."""

from __future__ import annotations

import json
from pathlib import Path

from jrlib.evidence import classify_output, locate, make_evidence
from jrlib.jobs import append_event
from jrlib.sandbox import SandboxBackend, jac_binary

_MAX_FILES = 24
_MAX_MUTANTS = 6


def run_static(job_id: str, sandbox: SandboxBackend, jac_files: list[str]) -> list[dict]:
    jac = jac_binary()
    found = []
    for rel in jac_files[:_MAX_FILES]:
        if rel.startswith("tests/") or Path(rel).name.startswith("test_"):
            continue
        result = sandbox.run([jac, "check", rel], timeout=40, network=False)
        append_event(
            job_id,
            "STATIC_ANALYSIS",
            "COMMAND_FINISHED",
            tool="jac",
            exit_code=result.get("exit_code", 1),
            file=rel,
        )
        if result.get("exit_code") == 0 and not result.get("timed_out"):
            continue
        stdout = result.get("stdout", "")
        stderr = result.get("stderr", "")
        category = classify_output("jac_check", stdout, stderr, int(result.get("exit_code", 1)), bool(result.get("timed_out")))
        if not category:
            category = "CONFIGURATION_ERROR"
        file_name, line = locate(stdout, stderr, rel)
        found.append(
            make_evidence(
                job_id,
                "jac_check",
                category,
                [jac, "check", rel],
                int(result.get("exit_code", 1)),
                stdout,
                stderr,
                file_name or rel,
                line,
                "static-" + rel.replace("/", "-"),
                timed_out=bool(result.get("timed_out")),
            )
        )
    return found


def run_tests(job_id: str, sandbox: SandboxBackend, tests: list[str]) -> list[dict]:
    jac = jac_binary()
    found = []
    for rel in tests[:_MAX_FILES]:
        result = sandbox.run([jac, "test", rel], timeout=50, network=False)
        append_event(job_id, "TESTING", "COMMAND_FINISHED", tool="jac", exit_code=result.get("exit_code", 1), file=rel)
        if result.get("exit_code") == 0 and not result.get("timed_out"):
            continue
        stdout = result.get("stdout", "")
        stderr = result.get("stderr", "")
        category = classify_output("jac_test", stdout, stderr, int(result.get("exit_code", 1)), bool(result.get("timed_out")))
        if not category:
            category = "TEST_FAILURE"
        file_name, line = locate(stdout, stderr, rel)
        found.append(
            make_evidence(
                job_id,
                "jac_test",
                category,
                [jac, "test", rel],
                int(result.get("exit_code", 1)),
                stdout,
                stderr,
                file_name or rel,
                line,
                "test-" + rel.replace("/", "-"),
                timed_out=bool(result.get("timed_out")),
            )
        )
    return found


def run_runtime(job_id: str, sandbox: SandboxBackend, entries: list[str], extra_env: dict | None = None) -> tuple[list[dict], dict]:
    jac = jac_binary()
    found = []
    last = {}
    for rel in entries[:6]:
        result = sandbox.run([jac, "run", rel], timeout=25, env=extra_env, network=False)
        last = result
        append_event(job_id, "RUNTIME_ANALYSIS", "COMMAND_FINISHED", tool="jac", exit_code=result.get("exit_code", 1), file=rel)
        stdout = result.get("stdout", "")
        stderr = result.get("stderr", "")
        category = classify_output("jac_run", stdout, stderr, int(result.get("exit_code", 1)), bool(result.get("timed_out")))
        if not category:
            continue
        file_name, line = locate(stdout, stderr, rel)
        item = make_evidence(
            job_id,
            "jac_run",
            category,
            [jac, "run", rel],
            int(result.get("exit_code", 1)),
            stdout,
            stderr,
            file_name or rel,
            line,
            "run-" + rel.replace("/", "-"),
            timed_out=bool(result.get("timed_out")),
        )
        found.append(item)
    return found, last


def _still_fails(sandbox: SandboxBackend, entry: str, payload: dict) -> bool:
    jac = jac_binary()
    result = sandbox.run([jac, "run", entry], timeout=25, env={"JACRIFT_INPUT": json.dumps(payload)}, network=False)
    category = classify_output("jac_run", result.get("stdout", ""), result.get("stderr", ""), int(result.get("exit_code", 1)), bool(result.get("timed_out")))
    return category == "STATE_INVARIANT_FAILURE"


def mutate_inputs(job_id: str, sandbox: SandboxBackend, entry: str, base: dict) -> tuple[list[dict], list[dict]]:
    """Bounded mutations of one JSON object. Returns (new evidence, experiment rows)."""
    mutants = []
    if "note" in base:
        trial = dict(base)
        trial.pop("note", None)
        mutants.append(("drop_note", trial))
    if "unused" in base:
        trial = dict(base)
        trial.pop("unused", None)
        mutants.append(("drop_unused", trial))
    if "verified" in base:
        trial = dict(base)
        trial["verified"] = True
        mutants.append(("verified_true", trial))
    if "action" in base:
        trial = dict(base)
        trial["action"] = "verify"
        mutants.append(("action_verify", trial))
    trial = dict(base)
    trial["padding"] = "x"
    mutants.append(("add_padding", trial))
    experiments = []
    evidence = []
    jac = jac_binary()
    for name, payload in mutants[:_MAX_MUTANTS]:
        result = sandbox.run([jac, "run", entry], timeout=25, env={"JACRIFT_INPUT": json.dumps(payload)}, network=False)
        append_event(job_id, "MUTATION", "COMMAND_FINISHED", tool="jac", exit_code=result.get("exit_code", 1), mutation=name)
        category = classify_output(
            "jac_run",
            result.get("stdout", ""),
            result.get("stderr", ""),
            int(result.get("exit_code", 1)),
            bool(result.get("timed_out")),
        )
        experiments.append(
            {
                "id": "mut_" + name,
                "hypothesis": "Changing one field of the runtime input changes the failure.",
                "expected": "A field that is not part of the trigger can be removed without hiding the failure.",
                "observed": category or "no failure marker",
                "payload": payload,
                "interpretation": "Failure marker still present." if category else "Failure marker absent.",
            }
        )
        if category and category != "STATE_INVARIANT_FAILURE":
            file_name, line = locate(result.get("stdout", ""), result.get("stderr", ""), entry)
            item = make_evidence(
                job_id,
                "mutation",
                category,
                [jac, "run", entry],
                int(result.get("exit_code", 1)),
                result.get("stdout", ""),
                result.get("stderr", ""),
                file_name,
                line,
                "mut-" + name,
                timed_out=bool(result.get("timed_out")),
            )
            item["original_input"] = json.dumps(payload)
            item["input_kind"] = "json"
            evidence.append(item)
    return evidence, experiments


def counter_verified(sandbox: SandboxBackend, entry: str) -> str:
    payload = {"verified": True, "action": "complete"}
    jac = jac_binary()
    result = sandbox.run([jac, "run", entry], timeout=25, env={"JACRIFT_INPUT": json.dumps(payload)}, network=False)
    category = classify_output("jac_run", result.get("stdout", ""), result.get("stderr", ""), int(result.get("exit_code", 1)), bool(result.get("timed_out")))
    if category == "STATE_INVARIANT_FAILURE":
        return "persists"
    return "disappears"
