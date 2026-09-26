"""Run one authorized analysis from the command line."""

from __future__ import annotations

import argparse
import json

from jrlib.api import create_job


def main() -> int:
    parser = argparse.ArgumentParser(description="Analyze an authorized Jac repository with JacRift.")
    parser.add_argument("--repository", required=True)
    parser.add_argument("--scope", default="repository_only")
    args = parser.parse_args()
    result = create_job(args.repository, True, args.scope, background=False)
    print(json.dumps({"job_id": result.get("job_id", ""), "status": result.get("status", ""), "error": result.get("error", "")}))
    return 0 if result.get("status") == "COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
