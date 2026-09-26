"""Sandbox limits. These fixtures stay inside a disposable workspace."""

import os
import tempfile
import unittest
from pathlib import Path

from jrlib.sandbox import ContainerSandboxBackend, LocalSandboxBackend, SandboxError


class SandboxTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix="jr-sandbox-"))
        (self.root / "repository").mkdir()
        self.box = LocalSandboxBackend()
        self.box.create(self.root)

    def test_normal_process(self):
        result = self.box.run(["python3", "-c", "print('hello-sandbox')"], timeout=15)
        self.assertEqual(result["exit_code"], 0)
        self.assertIn("hello-sandbox", result["stdout"])
        self.assertFalse(result["timed_out"])

    def test_timeout(self):
        result = self.box.run(["python3", "-c", "import time; time.sleep(30)"], timeout=1)
        self.assertTrue(result["timed_out"])

    def test_output_flood_is_capped(self):
        result = self.box.run(["python3", "-c", "print('A'*2000000)"], timeout=15)
        self.assertTrue(result["stdout_truncated"] or len(result["stdout"]) < 100000)
        self.assertLess(len(result["stdout"]), 100000)

    def test_abnormal_termination(self):
        result = self.box.run(["python3", "-c", "import os; os.abort()"], timeout=15)
        self.assertNotEqual(result["exit_code"], 0)

    def test_excessive_subprocess_creation_is_bounded(self):
        script = (
            "import subprocess,sys\n"
            "ok=0\n"
            "procs=[]\n"
            "for i in range(400):\n"
            "    try:\n"
            "        procs.append(subprocess.Popen([sys.executable,'-c','import time; time.sleep(8)']))\n"
            "        ok+=1\n"
            "    except Exception:\n"
            "        break\n"
            "print('ok', ok)\n"
            "for p in procs:\n"
            "    p.kill()\n"
        )
        result = self.box.run(["python3", "-c", script], timeout=20)
        self.assertIn("ok", result["stdout"])
        count = int(result["stdout"].split("ok", 1)[1].split()[0])
        self.assertLess(count, 400)
        self.assertGreater(count, 0)

    def test_forbidden_path_is_hidden_and_read_artifact_stays_inside(self):
        secret = self.root / "secret.txt"
        secret.write_text("TOPSECRETVALUE", encoding="utf-8")
        result = self.box.run(
            ["python3", "-c", "p=%r\nimport pathlib\nprint(pathlib.Path(p).read_text() if pathlib.Path(p).exists() else 'MISSING')" % str(secret)],
            timeout=15,
            hide_paths=[str(secret)],
        )
        self.assertNotIn("TOPSECRETVALUE", result["stdout"])
        with self.assertRaises(SandboxError):
            self.box.read_artifact("/etc/passwd")

    def test_environment_does_not_inherit_secrets(self):
        previous = os.environ.get("AWS_SECRET_ACCESS_KEY")
        os.environ["AWS_SECRET_ACCESS_KEY"] = "CANARYSECRETVALUE"
        try:
            result = self.box.run(
                ["python3", "-c", "import os; print(os.environ.get('AWS_SECRET_ACCESS_KEY','NONE'))"],
                timeout=15,
            )
        finally:
            if previous is None:
                os.environ.pop("AWS_SECRET_ACCESS_KEY", None)
            else:
                os.environ["AWS_SECRET_ACCESS_KEY"] = previous
        self.assertNotIn("CANARYSECRETVALUE", result["stdout"])
        self.assertIn("NONE", result["stdout"])

    def test_container_backend_fails_closed_without_a_runtime(self):
        with self.assertRaises(SandboxError):
            ContainerSandboxBackend().create(self.root)

    def tearDown(self):
        self.box.destroy()


if __name__ == "__main__":
    unittest.main()
