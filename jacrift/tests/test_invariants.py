"""Evidence invariants over a published campaign, when one exists on disk."""

import json
import unittest
from pathlib import Path

STATE = Path(__file__).resolve().parents[1] / "var" / "state.json"
BANNED = ("cve-", "cvss", "zero-day", "critical vulnerability", "exploitability score")


class PublishedStateTests(unittest.TestCase):
    def setUp(self):
        if not STATE.is_file():
            self.skipTest("no var/state.json; run scripts/demo.sh")
        self.state = json.loads(STATE.read_text(encoding="utf-8"))

    def test_schema_and_checks(self):
        self.assertEqual(self.state["schema"], "vectorrift.state.v1")
        self.assertEqual(self.state["campaign"]["status"], "complete")
        for name, ok in self.state["checks"].items():
            self.assertTrue(ok, name)

    def test_metrics_are_present_and_coverage_is_not_a_percentage(self):
        metrics = self.state["metrics"]
        self.assertGreater(metrics["executions"], 0)
        self.assertGreater(metrics["edges_hit"], 0)
        self.assertGreater(metrics["instrumented_edges"], metrics["edges_hit"])
        self.assertEqual(metrics["behavior_keys"], metrics["behavior_keys_engine"])
        self.assertEqual(metrics["behavior_disagreements"], 0)
        blob = json.dumps(metrics)
        self.assertNotIn("%", blob)

    def test_confirmed_findings_stay_narrow(self):
        confirmed = [
            item
            for item in self.state["findings"]
            if item["classification"] == "CONFIRMED_SECURITY_FINDING"
        ]
        self.assertGreaterEqual(len(confirmed), 1)
        for finding in confirmed:
            self.assertTrue(finding["reproducible"])
            self.assertTrue(finding["replay_matches"])
            self.assertTrue(finding["minimized"])
            self.assertIn("No control-flow hijack was demonstrated.", finding["claim"])
            lowered = finding["claim"].lower()
            for token in BANNED:
                self.assertNotIn(token, lowered)
            contradicted = [
                hyp["text"] for hyp in finding["hypotheses"] if hyp["status"] == "contradicted"
            ]
            self.assertTrue(any("arbitrary code execution" in text for text in contradicted))

    def test_behavior_only_corpus_rows_exist(self):
        reasons = {row["reason"] for row in self.state["corpus"]}
        self.assertIn("new_behavior", reasons)


if __name__ == "__main__":
    unittest.main()
