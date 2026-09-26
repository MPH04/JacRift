#!/usr/bin/env python3
"""Count meaningful source lines. Excludes blanks, comments, lockfiles, and vendored UI primitives."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def meaningful(path: Path) -> int:
    count = 0
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith(("//", "#", "/*", "*", "\"\"\"", "'''")):
            continue
        count += 1
    return count


def collect(base: Path, suffixes: tuple[str, ...], skip: tuple[str, ...] = ()) -> list[Path]:
    files = []
    if not base.exists():
        return files
    for path in base.rglob("*"):
        if not path.is_file() or path.suffix not in suffixes:
            continue
        rel = str(path.relative_to(ROOT))
        if any(part in rel for part in skip):
            continue
        files.append(path)
    return files


def main() -> None:
    groups = {
        "jac": collect(ROOT / "jac", (".jac",), (".jac/",)),
        "native": collect(ROOT / "native", (".c", ".h"), ("/build/",)),
        "dashboard_app": collect(
            ROOT / "dashboard" / "src",
            (".ts", ".tsx"),
            ("/components/ui/",),
        ),
    }
    # Drop the Jac data directory if a glob picked up stray files.
    groups["jac"] = [p for p in groups["jac"] if ".jac/" not in str(p) and p.name != ".jac"]
    totals = {}
    for name, files in groups.items():
        lines = sum(meaningful(path) for path in files)
        totals[name] = lines
        print(f"{name:16} {lines:5} lines  {len(files)} files")
    whole = sum(totals.values())
    jac = totals["jac"]
    ratio = (jac / whole) if whole else 0
    print(f"{'total':16} {whole:5}")
    print(f"jac_share        {ratio:.1%}")
    print("shadcn primitives under dashboard/src/components/ui are omitted as generated UI.")


if __name__ == "__main__":
    main()
