#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/.local/bin:${PATH}"
cd "$ROOT"
fail=0
for f in jac/*.jac; do
  [[ -f "$f" ]] || continue
  echo "== jac test $f =="
  jac test "$f" || fail=1
done
python3 -m unittest discover -s tests -v || fail=1
exit "$fail"
