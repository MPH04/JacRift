"""Native engine evidence tests. These talk to the built binaries, not to canned JSON."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
RIFT = ROOT / "native" / "build" / "vrfuzz_riftpacket"
HOSTILE = ROOT / "native" / "build" / "vrfuzz_hostile"


def require_binary(path: Path) -> None:
    if not path.is_file():
        raise unittest.SkipTest(f"missing {path}; run scripts/build.sh")


def replay(binary: Path, data: bytes, timeout_ms: str = "500") -> dict:
    with tempfile.NamedTemporaryFile(delete=False) as handle:
        handle.write(data)
        path = handle.name
    try:
        proc = subprocess.run(
            [str(binary), "replay", "--input", path, "--timeout-ms", timeout_ms],
            capture_output=True,
            timeout=8,
            check=False,
        )
    finally:
        os.unlink(path)
    line = next(
        item for item in proc.stdout.decode("utf-8", "replace").splitlines() if "vectorrift.execution.v1" in item
    )
    event = json.loads(line)
    event["_code"] = proc.returncode
    return event


class EngineTests(unittest.TestCase):
    def test_riftpacket_self_test_reports_guards(self):
        require_binary(RIFT)
        proc = subprocess.run([str(RIFT), "self-test"], capture_output=True, text=True, timeout=8, check=False)
        self.assertEqual(proc.returncode, 0)
        self.assertIn("guards=66", proc.stdout)
        self.assertIn("self-test ok", proc.stdout)

    def test_length_field_is_an_address_sanitizer_read(self):
        require_binary(RIFT)
        event = replay(RIFT, bytes.fromhex("56524c001441424344"))
        self.assertEqual(event["exit_type"], "SANITIZER")
        self.assertEqual(event["sanitizer"], "address")
        self.assertIn("consume_length", event["frame"])
        self.assertIn("heap-buffer-overflow", event.get("stderr_excerpt", "") + event.get("error_class", ""))

    def test_note_sibling_is_behavior_novel_without_new_edges(self):
        require_binary(RIFT)
        with tempfile.TemporaryDirectory() as tmp:
            before = Path(tmp) / "before.bin"
            after = Path(tmp) / "after.bin"
            before.write_bytes(b"VRN\x00")
            after.write_bytes(b"VRN\x01")
            proc = subprocess.run(
                [str(RIFT), "compare", "--before", str(before), "--input", str(after), "--timeout-ms", "500"],
                capture_output=True,
                text=True,
                timeout=8,
                check=False,
            )
        self.assertEqual(proc.returncode, 0, proc.stderr)
        event = json.loads(next(line for line in proc.stdout.splitlines() if "vectorrift.execution.v1" in line))
        self.assertEqual(event["new_edges"], 0)
        self.assertGreater(event["behavior_new"], 0)

    def test_hostile_flood_is_truncated_and_returns(self):
        require_binary(HOSTILE)
        event = replay(HOSTILE, b"FLOOD")
        self.assertEqual(event["exit_type"], "NORMAL")
        self.assertTrue(event["stderr_truncated"])
        self.assertLessEqual(len(event.get("stderr_excerpt", "")), 4096)

    def test_hostile_hang_is_killed(self):
        require_binary(HOSTILE)
        event = replay(HOSTILE, b"HANG", "200")
        self.assertEqual(event["exit_type"], "TIMEOUT")
        self.assertEqual(event["signal"], 9)

    def test_hostile_abort_is_a_crash_not_a_sanitizer(self):
        require_binary(HOSTILE)
        event = replay(HOSTILE, b"ABORT")
        self.assertEqual(event["exit_type"], "CRASH")
        self.assertEqual(event["signal"], 6)
        self.assertNotIn(event["sanitizer"], ("address", "undefined"))


if __name__ == "__main__":
    unittest.main()
