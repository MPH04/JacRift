#!/usr/bin/env bash
# Build the Clang-instrumented VectorRift engines and refresh demo seeds.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cmake -S "$ROOT/native" -B "$ROOT/native/build" -DCMAKE_C_COMPILER=clang-18
cmake --build "$ROOT/native/build" -j"$(nproc)"
python3 "$ROOT/scripts/make_seeds.py"
echo "built $ROOT/native/build/vrfuzz_riftpacket"
