# VectorRift

VectorRift is a local defensive fuzzing workbench. It runs an instrumented target, keeps the inputs that move coverage or behavior, and refuses to call something a security finding until a replay, a minimized input, and a narrow sanitizer fact all agree.

The question it is built to answer is not “did a score cross a threshold?” It is: what behavior showed up, why that behavior is new, whether the same input does it again, what the program state did, and which claim the evidence actually supports.

Authorized scope is this repository’s synthetic targets. VectorRift is not an offensive deployment tool. See [docs/threat-model.md](docs/threat-model.md).

## What a campaign shows

One recorded run (`--execs 80 --seed 1`) is written up in [docs/experiments.md](docs/experiments.md). The dashboard reads `var/state.json` produced by that run. Numbers on the page come from the campaign file, not from constants in the UI.

## Architecture

```text
                    ┌─────────────────────┐
                    │    Target Program   │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │ Instrumented Harness│
                    │ LLVM / Sanitizers   │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │ Coverage Fuzzer     │
                    └──────────┬──────────┘
                               │
                 execution + behavioral events
                               │
                    ┌──────────▼──────────┐
                    │ VectorRift Jac Core │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │ Investigation Graph │
                    └──────────┬──────────┘
                               │
             ┌─────────────────┼─────────────────┐
             │                 │                 │
      Reproduction        Skeptic Agent     Experiment Agent
             │                 │                 │
             └─────────────────┼─────────────────┘
                               │
                    ┌──────────▼──────────┐
                    │ Dashboard / Report  │
                    └─────────────────────┘
```

Detail, including what is deliberately not claimed, is in [docs/architecture.md](docs/architecture.md).

## Jac is the investigation runtime

Jac (`jaclang==0.16.7`) owns the parts that turn an execution log into a finding:

| Module | Responsibility |
| --- | --- |
| `jac/schema.jac` | Validates `vectorrift.execution.v1`. Drops malformed lines and sanitizes event fields. |
| `jac/novelty.jac` | Recomputes the behavioral fingerprint and decides whether a key is new. |
| `jac/classify.jac` | Evidence ladder. An anomaly stays an anomaly until reproduction and minimization exist. |
| `jac/hypotheses.jac` | Proposes a narrow cause and a skeptic that rejects broader claims. |
| `jac/experiments.jac` | Builds the next inputs (note siblings, stretched length, overflowing scale). |
| `jac/graph.jac` | Persists targets, inputs, executions, findings, and hypotheses. Walkers cluster, walk ancestry, and count support versus contradiction. |
| `jac/corpus.jac` | Dedup and lineage: seed → mutation → interesting child. |
| `jac/campaign.jac` | Schedules the native engine, ingests events, replays, minimizes, and publishes state plus the report. |
| `jac/report.jac` | Human-readable report from measured fields. |
| `jac/main.jac` | CLI entry. |

Removing the Jac tree removes classification, the investigation graph, experiment scheduling, the report, and the state file the dashboard renders. The C engine can still execute one input. It cannot finish an investigation.

`python3 scripts/language_ratio.py` prints the Jac share of meaningful lines in `jac/`, `native/`, and the dashboard application (generated shadcn primitives excluded). A count of this tree reported 2263 Jac lines of 4701 (48.1%). Re-run the script after edits; that figure is a measurement, not a constant in the product.

## Native fuzzing bridge

`native/` is a small C engine plus two targets, built with Clang 18:

- `vrfuzz_riftpacket` — demo parser. Coverage instrumentation (`-fsanitize-coverage=trace-pc-guard`) is compiled into `riftpacket.c` only. The engine is built with AddressSanitizer and UndefinedBehaviorSanitizer, and it implements `__sanitizer_cov_trace_pc_guard`. The coverage bitmap is `MAP_SHARED`, so the parent reads edges the child wrote.
- `vrfuzz_hostile` — isolation fixture (flood, hang, abort). Not a vulnerability demo.
- `riftpacket_libfuzzer` — the same parser linked with `-fsanitize=fuzzer`. It is a second engine check. It does not feed the Jac pipeline, and it does not instrument Jac.

libFuzzer is not claimed to guide coverage of Jac or Python. The campaign loop is `vrfuzz`.

## Behavioral novelty

Each target calls `vr_emit(kind, a, b)`. The engine fingerprints the event sequence. Jac recomputes the same fingerprint into a `BehaviorBook`. Coverage novelty (`new_edges`) and behavior novelty (`behavior_new`, new keys) are stored and drawn separately.

The note opcode changes a label and no extra branch. A sibling note can show `new_edges == 0` and `behavior_new > 0` in one process via `compare`. A fresh `replay` resets the coverage map, so it is not a valid zero-edge comparison.

## Agents

Agents are deterministic Jac rules and walkers. No remote model is called.

- Reproduction replays the stored input and records a match or a divergence.
- Minimization asks the engine for a ddmin input and checks the signature still matches.
- Hypothesis states a narrow cause. The skeptic contradicts “arbitrary code execution” on every confirmed record.
- Next-experiment schedules a note sweep and, when the fuzzer has not already produced it, a scale-overflow input.
- Cluster, evidence, and ancestry walkers group signatures, count support versus contradiction, and walk mutation parents.

Agent prose does not raise a classification. `classify.jac` does, from replay, minimization, and the sanitizer class string.

## Safety model

- Targets run in a forked child. The parent enforces a wall-clock deadline, then `SIGKILL`.
- The child sets `RLIMIT_CPU`, `RLIMIT_FSIZE`, and `RLIMIT_CORE`, closes extra fds, and `_exit`s. `RLIMIT_AS` is not set: AddressSanitizer’s shadow memory needs a large virtual address space. That limit is stated in the published limitations, not hidden.
- Stderr is capped. After the cap, the parent keeps reading so a flood cannot stall the pipe.
- Replay from the dashboard uses `spawn` with `shell: false` and an argv allowlist: only `vrfuzz_riftpacket` or `vrfuzz_hostile` under `native/build`, command `replay`, and an input path inside the repository.
- Target text is treated as untrusted. The UI renders it as text. Findings that contain CVE-style tokens are refused at publish time.
- Demonstrations use synthetic inputs. No network target is required.

## Install

Runtime used to develop this tree:

- Ubuntu clang 18.1.3, `libclang-rt-18-dev`, `llvm-18` (`llvm-symbolizer` at `/usr/lib/llvm-18/bin/llvm-symbolizer`)
- `libstdc++-14-dev` (libFuzzer link)
- Python 3.12 and `jaclang==0.16.7` (`pip install --user -r requirements.txt`)
- Node.js for the dashboard (`npm install` inside `dashboard/`)

```bash
pip install --user -r requirements.txt
export PATH="$HOME/.local/bin:$PATH"
./scripts/build.sh
```

If `clang-18` is missing, the native build stops with CMake’s compiler error. Behavioral Jac unit tests that do not touch the binary still run. The dashboard will show an empty campaign until `scripts/demo.sh` can spawn `vrfuzz_riftpacket`. Sanitizer findings are not claimed when the binary was not built with the sanitizer flags in `native/CMakeLists.txt`.

## Demo

```bash
export PATH="$HOME/.local/bin:$PATH"
./scripts/demo.sh
cd dashboard && npm install && npx next dev -p 43117 -H 0.0.0.0
```

Open the dashboard, read coverage and behavior as two series, open a confirmed finding, and use **Replay stored input**. The button re-executes the minimized artifact. The campaign report is `var/report.md`.

Walkthrough: [docs/demo.md](docs/demo.md). Finding rules: [docs/findings.md](docs/findings.md).

## Tests

```bash
export PATH="$HOME/.local/bin:$PATH"
./scripts/test.sh
```

That runs every `jac/*.jac` test file and `tests/test_*.py`. Engine tests skip if the binaries are absent. Invariant tests skip if `var/state.json` is absent. Dashboard API tests run when `VECTORRIFT_DASHBOARD_URL` is set (for example `http://127.0.0.1:43117`).

## Layout

```text
├── jac/            investigation runtime
├── native/         engine, riftpacket, hostile fixture, libFuzzer entry
├── dashboard/      Next.js board over var/state.json
├── corpus/seeds/   deterministic riftpacket seeds
├── tests/          Python checks against the binaries and published state
├── scripts/        build, demo, seeds, tests, language share
├── docs/           architecture, threat model, findings, demo, experiments
└── var/            generated campaign output (gitignored)
```

## Limitations

- One worker. A campaign does not run concurrent target executions.
- Coverage is “N of M SanitizerCoverage guards” in the target translation unit, not a percentage of source lines.
- Confirmed text names the sanitizer class and frame. It does not claim instruction-pointer control.
- Minimization is ddmin capped at 400 executions. Some inputs do not get smaller.
- The investigation graph stores an execution node per input. The board shows the neighborhood of the selected finding, not the full node list.
- Jac graph files under `jac/.jac/` persist across runs. Campaigns call `reset_graph()` before ingesting.

False-positive risks: a novel transition can be a legal protocol path; a sanitizer report can fire in a harness helper if the frame parser is wrong (the parser accepts `#` stack lines and `file.c:line` only); a timeout can be a slow input rather than a hang. Those records stay `NOVEL_BEHAVIOR`, `SUSPICIOUS_DIVERGENCE`, `CAPTURED`, or `TIMEOUT` until the evidence ladder moves them.

## Future work

- More than one worker, with a campaign lock that already rejects a second start.
- MemorySanitizer on a fully instrumented libc, which this environment does not provide.
- Jac Cloud / Jaseci deployment of the dashboard. Local `jac run` is the path that was executed. Unverified deploy commands are not documented as working.
- A coverage-guided loop inside libFuzzer that also emits `vectorrift.execution.v1`. Today libFuzzer is a side binary.
