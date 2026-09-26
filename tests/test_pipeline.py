"""Job lifecycle and the safe-buggy fixture, end to end."""

import json
import shutil
import unittest

from jrlib.api import create_job, delete_job, get_findings, get_job, get_log, reproduce
from jrlib.jobs import job_dir


class PipelineTests(unittest.TestCase):
    def test_rejects_bad_submissions_without_a_job_directory(self):
        missing = create_job("https://github.com/octocat/Hello-World", False, "repository_only", background=False)
        self.assertFalse(missing["ok"])
        self.assertEqual(missing["error"], "authorization_required")
        self.assertEqual(missing["job_id"], "")
        malformed = create_job("file:///tmp/nope", True, "repository_only", background=False)
        self.assertEqual(malformed["error"], "unsupported_scheme")

    def test_fixture_reaches_a_defensible_finding(self):
        created = create_job("fixture://safe-buggy", True, "repository_only", background=False)
        self.assertEqual(created["status"], "COMPLETE", created)
        job_id = created["job_id"]
        self.addCleanup(lambda: shutil.rmtree(job_dir(job_id), ignore_errors=True))
        snapshot = get_job(job_id)
        self.assertTrue(snapshot["ok"])
        self.assertGreater(snapshot["metrics"]["jac_files"], 0)
        self.assertGreater(snapshot["metrics"]["tests_discovered"], 0)
        self.assertGreater(snapshot["metrics"]["checks_executed"], 0)
        self.assertGreater(snapshot["metrics"]["reproduced_failures"], 0)
        findings = get_findings(job_id)["findings"]
        self.assertGreaterEqual(len(findings), 1)
        confirmed = [item for item in findings if item["status"] == "CONFIRMED_DEFENSIVE_FINDING"]
        self.assertGreaterEqual(len(confirmed), 1)
        state = next(item for item in findings if item["category"] == "STATE_INVARIANT_FAILURE")
        self.assertTrue(state["reproducible"])
        self.assertTrue(state["minimized"])
        self.assertIn("order_graph.jac", state["file"])
        self.assertIn("verification", state["claim"].lower())
        self.assertNotIn("remote code execution", state["claim"].lower())
        self.assertEqual(state["counter_evidence"]["status"], "contradicted")
        weak = [item for item in findings if item["status"] in {"OBSERVED", "ANOMALOUS"}]
        for item in weak:
            self.assertNotEqual(item["status"], "CONFIRMED_DEFENSIVE_FINDING")
        log = get_log(job_id)["log"]
        self.assertIn("STATIC_ANALYSIS", log)
        self.assertNotIn("CANARYSECRETVALUE", log)
        graph = snapshot["graph"]
        kinds = {edge["type"] for edge in graph.get("edges", [])}
        self.assertIn("observed", kinds)
        self.assertIn("contradicts", kinds)
        report = snapshot["report"]
        self.assertIn("What remains unknown", report)
        self.assertIn("does not claim remote code execution", report.lower())
        replay = reproduce(job_id, state["finding_id"])
        self.assertTrue(replay["ok"], replay)
        self.assertGreaterEqual(replay["matched"], 1)
        removed = delete_job(job_id)
        self.assertTrue(removed["deleted"])


if __name__ == "__main__":
    unittest.main()
