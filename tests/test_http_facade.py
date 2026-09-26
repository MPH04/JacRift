"""Job HTTP routes. These do not start ``jac start``; they exercise the router."""

from __future__ import annotations

import json
import unittest
from io import BytesIO

from jrlib.http_facade import install_job_routes, resolve


class ResolveTests(unittest.TestCase):
    def test_unknown_path_is_not_ours(self) -> None:
        self.assertIsNone(resolve("GET", "/functions"))
        self.assertIsNone(resolve("GET", "/api/jobsomething"))

    def test_missing_authorization_is_rejected(self) -> None:
        status, body = resolve(
            "POST",
            "/api/jobs",
            {
                "repository_url": "https://github.com/octo/demo",
                "authorization_confirmed": False,
                "scope": "repository_only",
            },
        )
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "authorization_required")

    def test_unsupported_scheme_and_scope(self) -> None:
        status, body = resolve(
            "POST",
            "/api/jobs",
            {
                "repository_url": "ssh://github.com/octo/demo",
                "authorization_confirmed": True,
                "scope": "repository_only",
            },
        )
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "unsupported_scheme")
        status, body = resolve(
            "POST",
            "/api/jobs?ignored=1",
            {
                "repository_url": "https://github.com/octo/demo",
                "authorization_confirmed": True,
                "scope": "internet",
            },
        )
        self.assertEqual(body["error"], "unsupported_scope")

    def test_unknown_job_and_extra_path(self) -> None:
        status, body = resolve("GET", "/api/jobs/JR-ABCDEF")
        self.assertEqual(status, 404)
        self.assertEqual(body["error"], "job_not_found")
        status, body = resolve("GET", "/api/jobs/JR-ABCDEF/nope/extra")
        self.assertEqual(status, 404)
        status, body = resolve("GET", "/api/jobs/not-an-id")
        self.assertEqual(status, 400)
        self.assertEqual(body["error"], "invalid_job_id")
        status, body = resolve("POST", "/api/jobs/JR-ABCDEF/log", {})
        self.assertEqual(status, 405)

    def test_list_is_get(self) -> None:
        status, body = resolve("GET", "/api/jobs")
        self.assertEqual(status, 200)
        self.assertTrue(body["ok"])
        self.assertIn("jobs", body)


class HandlerInstallTests(unittest.TestCase):
    def test_install_is_idempotent_and_serves_json(self) -> None:
        from jaclang.runtimelib.server import JacAPIServer

        from jrlib import http_facade

        saved = JacAPIServer.create_handler
        saved_flag = http_facade._INSTALLED

        class Handler:
            def do_GET(self):
                self.seen = "base-get"

            def do_POST(self):
                self.seen = "base-post"

        class Server:
            def create_handler(self):
                return Handler

        try:
            JacAPIServer.create_handler = Server.create_handler
            http_facade._INSTALLED = False
            self.assertTrue(install_job_routes())
            wrapped = JacAPIServer.create_handler
            self.assertTrue(getattr(wrapped, "_jacrift_wrapped", False))
            self.assertTrue(install_job_routes())
            self.assertIs(JacAPIServer.create_handler, wrapped)

            handler = wrapped(Server())()
            raw = json.dumps(
                {
                    "repository_url": "https://github.com/octo/demo",
                    "authorization_confirmed": False,
                    "scope": "repository_only",
                }
            ).encode()
            handler.path = "/api/jobs"
            handler.headers = {"Content-Length": str(len(raw))}
            handler.rfile = BytesIO(raw)
            handler.wfile = BytesIO()
            handler.status = None
            handler.send_response = lambda code, _reason=None: setattr(handler, "status", code)
            handler.send_header = lambda *args: None
            handler.end_headers = lambda: None
            handler.do_POST()
            self.assertEqual(handler.status, 400)
            body = json.loads(handler.wfile.getvalue().decode())
            self.assertEqual(body["error"], "authorization_required")

            other = wrapped(Server())()
            other.path = "/healthz"
            other.seen = ""
            other.do_GET()
            self.assertEqual(other.seen, "base-get")
        finally:
            JacAPIServer.create_handler = saved
            http_facade._INSTALLED = saved_flag


if __name__ == "__main__":
    unittest.main()
