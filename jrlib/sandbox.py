"""Execution isolation for untrusted repository commands.

The strongest mechanism this environment provides is an unprivileged user
namespace (unshare) plus rlimits, a scrubbed environment, and a network
namespace during execution. Docker is not assumed. If unshare is missing,
execution fails closed instead of running on the application host.
"""

from __future__ import annotations

import json
import os
import shutil
import signal
import site
import subprocess
import sys
from pathlib import Path

from jrlib.redact import redact

RUNNER = Path(__file__).resolve().parent / "sandbox_runner.py"
ALLOWED_PROGRAMS = {"jac", "python3", "python"}


class SandboxError(RuntimeError):
    pass


class SandboxBackend:
    def create(self, job_dir: Path) -> None:
        raise NotImplementedError

    def clone_repository(self, url: str) -> None:
        raise NotImplementedError

    def inspect(self) -> dict:
        raise NotImplementedError

    def run(self, argv: list, timeout: float | None = None, env: dict | None = None, network: bool = False) -> dict:
        raise NotImplementedError

    def read_artifact(self, path: str) -> str:
        raise NotImplementedError

    def collect_results(self) -> dict:
        raise NotImplementedError

    def destroy(self) -> None:
        raise NotImplementedError


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def jac_binary() -> str:
    found = shutil.which("jac") or shutil.which("jac", path=os.path.expanduser("~/.local/bin") + os.pathsep + os.environ.get("PATH", ""))
    if not found:
        local = Path.home() / ".local" / "bin" / "jac"
        if local.is_file():
            return str(local)
        raise SandboxError("jac is not installed")
    return found


class LocalSandboxBackend(SandboxBackend):
    """Disposable workspace executed through unshare."""

    def __init__(self) -> None:
        self.job_dir: Path | None = None
        self.workspace: Path | None = None
        self._seq = 0
        self._results: list[dict] = []

    def create(self, job_dir: Path) -> None:
        if shutil.which("unshare") is None:
            raise SandboxError("unshare is not available; refusing to execute repository code on the host")
        self.job_dir = job_dir.resolve()
        self.workspace = self.job_dir / "repository"
        self.workspace.mkdir(parents=True, exist_ok=True)
        (self.job_dir / "home").mkdir(parents=True, exist_ok=True)
        (self.job_dir / "tmp").mkdir(parents=True, exist_ok=True)
        (self.job_dir / "artifacts").mkdir(parents=True, exist_ok=True)

    def _require(self) -> tuple[Path, Path]:
        if self.job_dir is None or self.workspace is None:
            raise SandboxError("sandbox has not been created")
        return self.job_dir, self.workspace

    def clone_repository(self, url: str) -> None:
        job_dir, workspace = self._require()
        if any(workspace.iterdir()):
            raise SandboxError("workspace is not empty")
        if not url.startswith("https://github.com/"):
            raise SandboxError("clone accepts only https://github.com repositories")
        env = _base_env(job_dir)
        env["GIT_TERMINAL_PROMPT"] = "0"
        env["GIT_CONFIG_NOSYSTEM"] = "1"
        env["GIT_CONFIG_GLOBAL"] = "/dev/null"
        proc = subprocess.run(
            ["git", "clone", "--depth", "1", "--single-branch", "--", url, str(workspace)],
            capture_output=True,
            text=True,
            timeout=60,
            env=env,
            check=False,
        )
        self._results.append({"op": "clone", "exit_code": proc.returncode})
        if proc.returncode != 0:
            detail = redact((proc.stderr or proc.stdout or "git clone failed")[-500:])
            raise SandboxError("clone failed: " + detail)
        _reject_if_huge(workspace)

    def copy_tree(self, source: Path) -> None:
        _job, workspace = self._require()
        if any(workspace.iterdir()):
            raise SandboxError("workspace is not empty")
        shutil.copytree(source, workspace, dirs_exist_ok=True, ignore=shutil.ignore_patterns(".git", ".jac", "__pycache__", "node_modules"))
        _reject_if_huge(workspace)

    def inspect(self) -> dict:
        _job, workspace = self._require()
        files = []
        for dirpath, dirnames, filenames in os.walk(workspace):
            dirnames[:] = [name for name in dirnames if name not in {".git", "node_modules", ".jac", "__pycache__"}]
            for name in filenames:
                files.append(str(Path(dirpath, name).relative_to(workspace)))
        return {"files": sorted(files), "workspace": str(workspace)}

    def run(
        self,
        argv: list,
        timeout: float | None = None,
        env: dict | None = None,
        network: bool = False,
        hide_paths: list | None = None,
    ) -> dict:
        job_dir, workspace = self._require()
        timeout = 20.0 if timeout is None else float(timeout)
        if timeout <= 0 or timeout > 120:
            raise SandboxError("timeout out of range")
        _validate_argv(argv, workspace)
        self._seq += 1
        spec_path = job_dir / "artifacts" / f"spec-{self._seq}.json"
        result_path = job_dir / "artifacts" / f"result-{self._seq}.json"
        safe = _base_env(job_dir)
        if env:
            for key, value in env.items():
                if key == "JACRIFT_INPUT" and isinstance(value, str) and len(value) <= 4096:
                    safe[key] = value
        hides = [str(item) for item in (hide_paths or [])]
        real_home = str(Path.home())
        for rel in (".ssh", ".aws", ".azure", ".kube", ".config/gh", ".config/gcloud"):
            hides.append(str(Path(real_home) / rel))
        spec = {
            "argv": [str(item) for item in argv],
            "cwd": str(workspace),
            "timeout": timeout,
            "stdout_limit": 64000,
            "stderr_limit": 32000,
            "result_path": str(result_path),
            "hide_paths": hides,
            "real_home": real_home,
            "job_dir": str(job_dir),
        }
        spec_path.write_text(json.dumps(spec), encoding="utf-8")
        cmd = [
            "unshare",
            "--user",
            "--map-root-user",
            "--pid",
            "--fork",
            "--mount",
            "--mount-proc",
        ]
        if not network:
            cmd.append("--net")
        cmd.extend(["--", sys.executable, str(RUNNER), str(spec_path)])
        try:
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout + 8,
                env=safe,
                check=False,
            )
        except subprocess.TimeoutExpired:
            result = _empty_result(argv, timeout, timed_out=True, error="sandbox wrapper timed out")
            self._results.append(result)
            return result
        if result_path.is_file():
            try:
                result = json.loads(result_path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                result = _empty_result(argv, timeout, error="sandbox result was not json")
        else:
            result = _empty_result(
                argv,
                timeout,
                error=redact((proc.stderr or proc.stdout or "sandbox produced no result")[-400:]),
                exit_code=proc.returncode,
            )
        result["stdout"] = redact(str(result.get("stdout", "")), 8000)
        result["stderr"] = redact(str(result.get("stderr", "")), 8000)
        self._results.append(result)
        return result

    def read_artifact(self, path: str) -> str:
        _job, workspace = self._require()
        candidate = Path(path)
        target = candidate.resolve() if candidate.is_absolute() else (workspace / candidate).resolve()
        if not _inside(target, workspace):
            raise SandboxError("path is outside the sandbox workspace")
        if not target.is_file():
            raise SandboxError("artifact is not a file")
        data = target.read_bytes()[:200_000]
        return redact(data.decode("utf-8", "replace"), 20000)

    def collect_results(self) -> dict:
        return {"runs": len(self._results), "last": self._results[-1] if self._results else {}}

    def destroy(self) -> None:
        if self.workspace and self.workspace.exists():
            shutil.rmtree(self.workspace, ignore_errors=True)
        self.workspace = None


class JacHammerSandboxBackend(LocalSandboxBackend):
    """JacHammer deployment uses the same user-namespace backend.

    This environment does not expose a nested container runtime or a Docker
    socket. unshare is the isolation primitive that is actually present.
    """


class ContainerSandboxBackend(SandboxBackend):
    """Present so callers can request a container runtime. Fails closed here."""

    def create(self, job_dir: Path) -> None:
        if shutil.which("docker") is None and shutil.which("podman") is None:
            raise SandboxError("container runtime is not available; refusing to execute on the host instead")
        raise SandboxError("container backend is not enabled in this deployment")

    def clone_repository(self, url: str) -> None:
        raise SandboxError("container backend is not enabled")

    def inspect(self) -> dict:
        raise SandboxError("container backend is not enabled")

    def run(self, argv: list, timeout: float | None = None, env: dict | None = None, network: bool = False) -> dict:
        raise SandboxError("container backend is not enabled")

    def read_artifact(self, path: str) -> str:
        raise SandboxError("container backend is not enabled")

    def collect_results(self) -> dict:
        raise SandboxError("container backend is not enabled")

    def destroy(self) -> None:
        return None


def backend_for(name: str | None = None) -> SandboxBackend:
    choice = name or os.environ.get("JACRIFT_SANDBOX", "jachammer")
    if choice in {"local", "jachammer"}:
        if choice == "jachammer":
            return JacHammerSandboxBackend()
        return LocalSandboxBackend()
    if choice == "container":
        return ContainerSandboxBackend()
    raise SandboxError("unknown sandbox backend")


def _base_env(job_dir: Path) -> dict:
    jac = ""
    try:
        jac = str(Path(jac_binary()).parent)
    except SandboxError:
        jac = str(Path.home() / ".local" / "bin")
    path = os.pathsep.join(["/usr/bin", "/bin", jac])
    return {
        "PATH": path,
        "HOME": str(job_dir / "home"),
        "TMPDIR": str(job_dir / "tmp"),
        "LANG": "C",
        "LC_ALL": "C",
        "GIT_TERMINAL_PROMPT": "0",
        # HOME is the disposable job directory, so Python would otherwise miss
        # the operator's installed Jac toolchain.
        "PYTHONPATH": site.getusersitepackages(),
    }


def _trusted_bin_dirs() -> tuple[str, ...]:
    """Host toolchain directories. Never a job workspace."""
    candidates = (
        Path("/usr/bin"),
        Path("/bin"),
        Path.home() / ".local" / "bin",
        Path(__file__).resolve().parents[1] / ".jac" / "venv" / "bin",
        Path(sys.executable).resolve().parent,
    )
    found: list[str] = []
    for directory in candidates:
        try:
            resolved = directory.resolve()
        except OSError:
            continue
        if resolved.is_dir():
            prefix = str(resolved) + "/"
            if prefix not in found:
                found.append(prefix)
    return tuple(found)


def _program_allowed(program: str, workspace: Path | None = None) -> bool:
    name = Path(program).name
    if name not in ALLOWED_PROGRAMS:
        return False
    if not os.path.isabs(program):
        return True
    try:
        resolved = Path(program).resolve()
    except OSError:
        return False
    if workspace is not None and _inside(resolved, workspace):
        return False
    text = str(resolved)
    return any(text.startswith(prefix) for prefix in _trusted_bin_dirs())


def _validate_argv(argv: list, workspace: Path) -> None:
    if not isinstance(argv, list) or not argv or len(argv) > 24:
        raise SandboxError("argv rejected")
    for arg in argv:
        if not isinstance(arg, str) or arg == "" or "\x00" in arg or len(arg) > 4096:
            raise SandboxError("argv rejected")
    program = argv[0]
    if not _program_allowed(program, workspace):
        raise SandboxError("program is not allowed")
    skip_next = False
    for arg in argv[1:]:
        if skip_next:
            skip_next = False
            continue
        if arg == "-c":
            skip_next = True
            continue
        if arg.startswith("-"):
            continue
        if "/" in arg or arg.startswith("."):
            target = (workspace / arg).resolve()
            if not _inside(target, workspace):
                raise SandboxError("argument path escapes the workspace")


def _empty_result(argv: list, timeout: float, timed_out: bool = False, error: str = "", exit_code: int = 1) -> dict:
    return {
        "argv": argv,
        "exit_code": exit_code,
        "stdout": "",
        "stderr": error,
        "timed_out": timed_out,
        "stdout_truncated": False,
        "stderr_truncated": False,
        "duration_s": timeout if timed_out else 0,
        "error": error,
    }


def _reject_if_huge(workspace: Path) -> None:
    files = 0
    size = 0
    for dirpath, dirnames, filenames in os.walk(workspace):
        dirnames[:] = [name for name in dirnames if name not in {".git", "node_modules"}]
        for name in filenames:
            files += 1
            try:
                size += (Path(dirpath) / name).stat().st_size
            except OSError:
                continue
            if files > 2000 or size > 50_000_000:
                raise SandboxError("repository exceeds the size bound")
