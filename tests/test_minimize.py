"""Key deletion keeps a failure and does not preserve unused fields."""

from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from jrlib.reproduce import minimize


class _ScriptedSandbox:
    def __init__(self) -> None:
        self.payloads: list[dict] = []

    def run(self, command, timeout=40, env=None, network=False):
        payload = json.loads((env or {}).get("JACRIFT_INPUT") or "{}")
        self.payloads.append(payload)
        # Defaults: missing action is complete, missing verified is false.
        action = payload.get("action", "complete")
        verified = payload.get("verified", False)
        stdout = ""
        if action == "complete" and verified is not True:
            stdout = 'JACRIFT_EVENT {"category":"STATE_INVARIANT_FAILURE","marker":"complete_before_verification"}'
        return {"exit_code": 0, "stdout": stdout, "stderr": "", "timed_out": False}


class MinimizeTests(unittest.TestCase):
    def test_empty_object_is_minimal_when_defaults_fail(self) -> None:
        evidence = {
            "reproducible": True,
            "input_kind": "json",
            "original_input": json.dumps(
                {"verified": False, "action": "complete", "note": "padding", "unused": 1}
            ),
            "command": ["jac", "run", "runtime_entry.jac"],
            "source": "jac_run",
            "category": "STATE_INVARIANT_FAILURE",
            "exit_code": 0,
            "evidence_id": "e1",
        }
        sandbox = _ScriptedSandbox()
        with patch("jrlib.reproduce.append_event"):
            minimize("JR-ABCDEF", sandbox, evidence)
        self.assertEqual(json.loads(evidence["minimal_input"]), {})
        self.assertEqual(evidence["minimize_reason"], "json_keys")
        self.assertTrue(evidence["minimized"])

    def test_required_key_is_kept(self) -> None:
        evidence = {
            "reproducible": True,
            "input_kind": "json",
            "original_input": json.dumps({"verified": False, "action": "complete", "note": "padding"}),
            "command": ["jac", "run", "runtime_entry.jac"],
            "source": "jac_run",
            "category": "STATE_INVARIANT_FAILURE",
            "exit_code": 0,
            "evidence_id": "e2",
        }

        class KeepVerified(_ScriptedSandbox):
            def run(self, command, timeout=40, env=None, network=False):
                payload = json.loads((env or {}).get("JACRIFT_INPUT") or "{}")
                stdout = ""
                if payload.get("verified") is False and payload.get("action") == "complete":
                    stdout = 'JACRIFT_EVENT {"category":"STATE_INVARIANT_FAILURE","marker":"complete_before_verification"}'
                return {"exit_code": 0, "stdout": stdout, "stderr": "", "timed_out": False}

        with patch("jrlib.reproduce.append_event"):
            minimize("JR-ABCDEF", KeepVerified(), evidence)
        self.assertEqual(
            json.loads(evidence["minimal_input"]),
            {"action": "complete", "verified": False},
        )


if __name__ == "__main__":
    unittest.main()
