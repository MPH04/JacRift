"""Dashboard API checks. Skips unless VECTORRIFT_DASHBOARD_URL is set and the server answers."""

import json
import os
import unittest
import urllib.error
import urllib.request

BASE = os.environ.get("VECTORRIFT_DASHBOARD_URL", "").rstrip("/")


def request(method: str, path: str, body: dict | None = None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        BASE + path,
        data=data,
        method=method,
        headers={"content-type": "application/json"} if data else {},
    )
    try:
        with urllib.request.urlopen(req, timeout=8) as response:
            return response.status, json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        payload = exc.read().decode()
        try:
            parsed = json.loads(payload)
        except json.JSONDecodeError:
            parsed = {"raw": payload}
        return exc.code, parsed


class DashboardApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not BASE:
            raise unittest.SkipTest("VECTORRIFT_DASHBOARD_URL is unset")
        try:
            request("GET", "/api/state")
        except Exception as exc:
            raise unittest.SkipTest(f"dashboard is not reachable: {exc}") from exc

    def test_state_is_the_campaign_schema(self):
        status, body = request("GET", "/api/state")
        self.assertEqual(status, 200)
        self.assertEqual(body.get("schema"), "vectorrift.state.v1")
        self.assertIn("findings", body)
        self.assertIn("metrics", body)

    def test_campaign_rejects_a_zero_budget(self):
        status, body = request("POST", "/api/campaign", {"execs": 0, "seed": 1})
        self.assertEqual(status, 400)
        self.assertIn("execs", body.get("error", ""))

    def test_reproduce_rejects_a_path_shaped_id(self):
        status, _body = request("POST", "/api/reproduce", {"finding_id": "f-../../etc/passwd"})
        self.assertEqual(status, 400)

    def test_campaign_rejects_an_unknown_profile(self):
        status, body = request("POST", "/api/campaign", {"profile": "shell"})
        self.assertEqual(status, 400)
        self.assertIn("profile", body.get("error", ""))

    def test_campaign_rejects_a_zero_timeout(self):
        status, body = request("POST", "/api/campaign", {"execs": 80, "seed": 1, "timeout_ms": 0})
        self.assertEqual(status, 400)
        self.assertIn("timeout_ms", body.get("error", ""))

    def test_ready_reports_local_tools(self):
        status, body = request("GET", "/api/ready")
        self.assertEqual(status, 200)
        self.assertIsInstance(body.get("jac"), bool)
        self.assertIsInstance(body.get("binary"), bool)

    def test_log_and_report_are_text_payloads(self):
        log_status, log_body = request("GET", "/api/log")
        self.assertEqual(log_status, 200)
        self.assertIsInstance(log_body.get("tail"), str)
        report_status, report_body = request("GET", "/api/report")
        self.assertEqual(report_status, 200)
        self.assertIsInstance(report_body.get("report"), str)


if __name__ == "__main__":
    unittest.main()
