# Experiment log

Entries below were measured in this environment (jaclang 0.16.7, Ubuntu clang 18.1.3). They are observations, not quotas the next run must hit.

## Coverage bitmap sees the target, not the engine

Hypothesis: compiling `trace-pc-guard` into every translation unit mixes engine edges into the target map.
Experiment: build `riftpacket` with coverage only on `targets/riftpacket.c`. Run `vrfuzz_riftpacket self-test`.
Expected result: a guard count that stays stable for this target file, and a non-zero edge count after the built-in inputs.
Observed result: `self-test ok guards=66 edges=6 behavior_keys=5` (exit 0). `vrfuzz_hostile self-test` reported `guards=29 edges=6 behavior_keys=0`.
Interpretation: parent-observed edges come from the instrumented target objects. Guard count includes sanitizer instrumentation inside that TU, so it is not a source-line percentage.
Confidence: high for this build. A compiler upgrade can change the guard count.
Next experiment: re-run self-test after any Clang upgrade and treat a guard-count change as a toolchain change, not as new program behavior.

## Campaign seed 1, 80 executions

Hypothesis: a short deterministic budget both grows coverage and leaves a reproducible sanitizer artifact.
Experiment: `jac run jac/main.jac -- campaign --execs 80 --seed 1 --timeout-ms 300`.
Expected result: status complete, `checks` all true, at least one confirmed sanitizer finding, behavior key count equal to the engine count.
Observed result (2026-09-26T18:40:45Z): status complete. Executions 80, elapsed 205 ms in the native summary, about 390 execs/s, corpus 18, edges 35 of 66 guards, behavior keys 26 and engine 26, disagreements 0, sanitizer failures during the fuzz phase 1, crashes 0, timeouts 0. Checks: coverage_guided, behavior_independent, agents_acted, reproduced, jac_graph. Confirmed findings: address / `consume_length` / heap-buffer-overflow minimized 9 → 5 bytes (`56524c4344`); undefined / `riftpacket:71` / signed-integer-overflow from the scale experiment (11 bytes, already minimal).
Interpretation: the fuzz phase found the length bug. The scale bug was staged by the next-experiment agent and then passed the same reproduction gate. Both claims include the control-flow disclaimer. Skeptic contradicted arbitrary code execution on both.
Confidence: high for seed 1 and this binary. A different seed can find the bugs in a different order.
Next experiment: an exec budget below the first length hit, to show the length-stretch experiment recovering the bug when the fuzzer has not reached it yet. The stretch unit test already replays that input and expects SANITIZER / address / consume_length.

## Behavior without new edges

Hypothesis: a note label is a new behavioral key and not a new instrumented edge.
Experiment: `vrfuzz_riftpacket compare --before VRN\x00 --input VRN\x01`.
Expected result: the second event has `new_edges == 0` and `behavior_new > 0`.
Observed result: the campaign note_sweep recorded “7 siblings had no new edges; 7 carried a new engine behavior key.” The engine self-test also requires a `VRN\x00` then `VRN\x01` pair with that shape. Corpus rows with reason `new_behavior` exist in the published state (for example end-state DATA and AUTH→CLOSED with `new_edges` 0).
Interpretation: edge coverage and behavior are different measurements. Replaying a single input in a fresh process resets the map and must not be used as the zero-edge proof.
Confidence: high.
Next experiment: keep the compare-based unit test in `tests/test_engine.py`.

## Dashboard campaign button, 120 executions

Hypothesis: `POST /api/campaign` with the board’s fixed budget runs the same Jac pipeline and publishes a new state file.
Experiment: the board button sends `{"execs":120,"seed":1}`. Observed after that request returned and the process exited.
Expected result: status complete, checks true, both seeded sanitizer classes confirmed.
Observed result: status complete at 2026-09-26T18:51:09Z. Executions 120, edges 35 of 66, behavior keys 27 matching the engine, disagreements 0, corpus 19, about 455 execs/s, sanitizer failures in the fuzz phase 1. Checks all true. Confirmed records remained the heap-buffer-overflow in `consume_length` (minimized) and the signed overflow at `riftpacket:71`. An additional novel transition `OPEN→CLOSED` appeared. Replay of the minimized length input from the board returned `Matched: SANITIZER address consume_length`.
Interpretation: the button is the campaign CLI, not a separate scoring path. Counts moved because the budget changed, which is what the metrics are for.
Confidence: high for this binary and seed.
Next experiment: none until the button’s budget or the target changes.

## Hostile isolation

Hypothesis: flood, hang, and abort cannot pin the parent or be mislabeled as sanitizer bugs.
Experiment: `vrfuzz_hostile replay` on `FLOOD`, `HANG` with timeout 200 ms, and `ABORT`.
Expected result: flood returns, hang is signal 9, abort is signal 6 with no sanitizer class.
Observed result: FLOOD `NORMAL` `stderr_truncated` true, excerpt length 2047. HANG `TIMEOUT` signal 9. ABORT `CRASH` signal 6, sanitizer field empty (not `address` or `undefined`).
Interpretation: the parent survives. Abort is not upgraded to a sanitizer finding.
Confidence: high for this fixture.
Next experiment: none until the isolation code changes.

## libFuzzer side binary

Hypothesis: LLVM’s libFuzzer, linked only to `riftpacket.c`, also moves coverage and can stop on the seeded overflow. This does not drive Jac.
Experiment A: 7 seeds, `-runs=40`, fresh corpus. Status captured without a pipe.
Observed result A: exit 0. Log shows `INITED cov: 31` then `NEW` lines up to `DONE cov: 37`. No crash artifact.
Experiment B: only `06_scale.bin`, `-runs=200`.
Observed result B: exit 1. UndefinedBehaviorSanitizer: `signed integer overflow` at `riftpacket.c:71:14`. Artifact `/tmp/lf-vr2/art-crash-b4ce8bbc996151a98542db2b00e08ffc22f7fa15`.
Interpretation: exit 0 means the run budget ended without a crash. Exit 1 means libFuzzer stopped on a sanitizer abort. An earlier note that “libFuzzer exited 0” was the status of `tail` on a pipe, and is withdrawn.
Confidence: high for these two invocations. libFuzzer’s own seed is nondeterministic, so the crash exec index will move.
Next experiment: do not merge libFuzzer into the Jac loop until it emits `vectorrift.execution.v1`.

## Failed or rejected ideas

- Symbolizing every fuzz execution. A 1500-exec run with `symbolize=1` took about 37 seconds and kept duplicate sanitizer hits until the corpus cap (192). `run` now sets `symbolize=0` and retains a failure signature once.
- Instrumenting the engine with `trace-pc-guard`. Guard counts stopped meaning “the target.”
- Classifying UBSan frames from the prose fragment “in type 'int32_t'”. The frame became the word `type`. The parser now uses stack lines and `file.c:line` only.
- Using a fresh replay as evidence that `new_edges == 0`. The map is empty at process start, so every input looks new or empty for the wrong reason.
- Setting `RLIMIT_AS` around AddressSanitizer. The child dies on the shadow mapping. The limit is not applied, and the product says so.
- Putting the letters `CVE` in the report disclaimer. The forbidden-claim scan matched the token. The disclaimer now says “vulnerability-database identifier.”
- Naming a Jac variable `root` for the repo path. `root` is the graph root. Campaign code uses `repo`.
- Treating invariant keys as both `SUSPICIOUS_DIVERGENCE` and `NOVEL_BEHAVIOR`. That duplicated `data_before_auth`. Novel findings are semantic and transition keys only.
- An LLM paragraph as triage. No model is called. The measurable agent actions are the scheduled experiments, the minimization delta, and the contradicted overclaim.
