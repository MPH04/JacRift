"""Inner sandbox process. Trusted code. The repository command is argv-only."""

from __future__ import annotations

import json
import os
import resource
import signal
import subprocess
import sys
import threading
from pathlib import Path


def _drain(pipe, limit: int) -> tuple[bytes, bool]:
    chunks = []
    size = 0
    truncated = False
    while True:
        block = pipe.read(8192)
        if not block:
            break
        if size < limit:
            take = block[: limit - size]
            chunks.append(take)
            size += len(take)
            if len(block) > len(take):
                truncated = True
        else:
            truncated = True
    return b"".join(chunks), truncated


def _overlay(paths: list[str]) -> None:
    for raw in paths:
        if not raw or not os.path.exists(raw):
            continue
        if os.path.isfile(raw) or os.path.islink(raw):
            subprocess.run(["mount", "--bind", "/dev/null", raw], check=False, capture_output=True)
        elif os.path.isdir(raw):
            subprocess.run(["mount", "-t", "tmpfs", "-o", "size=64k,mode=000", "tmpfs", raw], check=False, capture_output=True)


def _nproc_ceiling() -> int:
    threads = 200
    try:
        listed = subprocess.check_output(["ps", "-u", str(os.getuid()), "-L", "--no-headers"], text=True)
        threads = max(threads, len(listed.splitlines()) + 48)
    except (OSError, subprocess.CalledProcessError):
        threads = 400
    return min(threads, 700)


def _limits(timeout: float, nproc: int) -> None:
    cpu = max(1, int(timeout))
    resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu + 1))
    resource.setrlimit(resource.RLIMIT_FSIZE, (8_000_000, 8_000_000))
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_NOFILE, (128, 128))
    resource.setrlimit(resource.RLIMIT_NPROC, (nproc, nproc))


def main() -> int:
    spec = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    cwd = spec["cwd"]
    os.chdir(cwd)
    hides = list(spec.get("hide_paths") or [])
    hides.extend(["/var/run/docker.sock", "/run/docker.sock", "/run/secrets"])
    _overlay(hides)
    timeout = float(spec["timeout"])
    argv = spec["argv"]
    nproc = _nproc_ceiling()
    proc = subprocess.Popen(
        argv,
        cwd=cwd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=os.environ.copy(),
        start_new_session=True,
        preexec_fn=lambda: _limits(timeout, nproc),
    )
    stdout_box: dict = {}
    stderr_box: dict = {}

    def read_out() -> None:
        data, truncated = _drain(proc.stdout, int(spec["stdout_limit"]))
        stdout_box["data"] = data
        stdout_box["truncated"] = truncated

    def read_err() -> None:
        data, truncated = _drain(proc.stderr, int(spec["stderr_limit"]))
        stderr_box["data"] = data
        stderr_box["truncated"] = truncated

    threads = [threading.Thread(target=read_out), threading.Thread(target=read_err)]
    for thread in threads:
        thread.start()
    timed_out = False
    try:
        proc.wait(timeout=timeout)
    except subprocess.TimeoutExpired:
        timed_out = True
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            proc.kill()
        proc.wait(timeout=5)
    for thread in threads:
        thread.join(timeout=5)
    result = {
        "argv": argv,
        "exit_code": 124 if timed_out else proc.returncode,
        "stdout": stdout_box.get("data", b"").decode("utf-8", "replace"),
        "stderr": stderr_box.get("data", b"").decode("utf-8", "replace"),
        "timed_out": timed_out,
        "stdout_truncated": bool(stdout_box.get("truncated")),
        "stderr_truncated": bool(stderr_box.get("truncated")),
        "duration_s": timeout if timed_out else 0,
        "error": "timeout" if timed_out else "",
    }
    Path(spec["result_path"]).write_text(json.dumps(result), encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        # Last-resort marker so the parent can see a runner failure.
        sys.stderr.write("sandbox_runner_failed: " + str(exc)[:300])
        raise SystemExit(1)
