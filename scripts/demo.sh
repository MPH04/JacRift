#!/usr/bin/env bash
# Deterministic local campaign against the synthetic riftpacket target.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
export PATH="${HOME}/.local/bin:${PATH}"
if [[ ! -x "$ROOT/native/build/vrfuzz_riftpacket" ]]; then
  "$ROOT/scripts/build.sh"
fi
exec jac run "$ROOT/jac/main.jac" -- campaign --execs "${EXECS:-80}" --seed "${SEED:-1}" --timeout-ms "${TIMEOUT_MS:-300}"
