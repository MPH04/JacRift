"""Map a repository without executing anything it asks for."""

from __future__ import annotations

import os
from pathlib import Path

_SKIP = {".git", "node_modules", ".jac", "__pycache__", ".next", "dist", "build"}
_DEP_NAMES = {
    "requirements.txt",
    "jac.toml",
    "pyproject.toml",
    "package.json",
    "Pipfile",
    "poetry.lock",
}
_BUILD_NAMES = {"CMakeLists.txt", "Makefile", "makefile", "justfile", "Dockerfile"}


def discover(root: Path) -> dict:
    jac_files = []
    python_files = []
    tests = []
    entrypoints = []
    dependency_manifests = []
    build_files = []
    frontend = {"files": [], "package_json": False}
    walkers = []
    nodes = []
    readme = ""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [name for name in dirnames if name not in _SKIP]
        for name in filenames:
            path = Path(dirpath) / name
            rel = str(path.relative_to(root))
            lower = name.lower()
            if name in _DEP_NAMES or lower in _DEP_NAMES:
                dependency_manifests.append(rel)
            if name in _BUILD_NAMES:
                build_files.append(rel)
            if lower == "package.json":
                frontend["package_json"] = True
            if path.suffix in {".tsx", ".jsx", ".vue", ".css"}:
                frontend["files"].append(rel)
            if path.suffix == ".py":
                python_files.append(rel)
            if path.suffix == ".jac":
                jac_files.append(rel)
                text = _read(path)
                if _looks_like_test(rel, text):
                    tests.append(rel)
                if "with entry" in text:
                    entrypoints.append(rel)
                for line_no, line in enumerate(text.splitlines(), start=1):
                    stripped = line.strip()
                    if stripped.startswith("walker ") or stripped.startswith("walker:"):
                        walkers.append({"file": rel, "line": line_no, "text": stripped[:120]})
                    if stripped.startswith("node ") or stripped.startswith("node:"):
                        nodes.append({"file": rel, "line": line_no, "text": stripped[:120]})
            if lower in {"readme.md", "readme"} and readme == "":
                readme = rel
    jac_files.sort()
    tests.sort()
    entrypoints.sort()
    project_type = "jac" if jac_files else ("python" if python_files else "unknown")
    checks = []
    if jac_files:
        checks.append("jac check")
    if tests:
        checks.append("jac test")
    safe_entries = [item for item in entrypoints if _safe_entry(root / item)]
    if safe_entries:
        checks.append("jac run")
    return {
        "project_type": project_type,
        "jac_files": jac_files,
        "tests": tests,
        "entrypoints": entrypoints,
        "safe_entrypoints": safe_entries,
        "python_files": python_files,
        "frontend": {"package_json": frontend["package_json"], "file_count": len(frontend["files"])},
        "dependency_manifests": sorted(dependency_manifests),
        "build_files": sorted(build_files),
        "walkers": walkers[:40],
        "nodes": nodes[:40],
        "readme": readme,
        "recommended_checks": checks,
        "note": "README text is recorded as a path only. Commands inside it are not executed.",
    }


def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8", errors="replace")[:200_000]
    except OSError:
        return ""


def _looks_like_test(rel: str, text: str) -> bool:
    name = Path(rel).name
    if name.startswith("test_") or name.endswith(".test.jac"):
        return True
    if "/tests/" in f"/{rel}" or rel.startswith("tests/"):
        return True
    return '\ntest "' in text or text.startswith('test "')


def _safe_entry(path: Path) -> bool:
    text = _read(path)
    if len(text) > 20_000:
        return False
    banned = ("subprocess", "os.system", "socket", "eval(", "exec(", "ctypes", "pty")
    return not any(token in text for token in banned)
